import { Router } from "express"
import { z } from "zod"
import bcrypt from "bcryptjs"
import crypto from "crypto"
import { prisma } from "../lib/prisma"
import { signAccessToken } from "../lib/jwt"
import {
    generateRefreshToken,
    hashRefreshToken,
    refreshCookieOptions,
} from "../lib/refreshToken"
import { env } from "../lib/env"
import generateTokenPair from "../lib/tokenPair"
import { checkLoginRateLimit } from "../middleware/checkLoginRateLimit"
import { registerLoginFailure, clearLoginFailures } from "../lib/loginRateLimit"
import {getClientIp} from "../lib/clientIp";
import { HttpError } from "../lib/httpError"

export const authRouter = Router()


const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1),
})

authRouter.post("/login", checkLoginRateLimit, async (req, res) => {
    const parsed = loginSchema.safeParse(req.body)
    if (!parsed.success) {
        return res.status(400).json({ error: "Invalid payload" })
    }

    const { email, password } = parsed.data
    const ip = getClientIp(req)

    const user = await prisma.user.findUnique({
        where: { email },
        select: {
            id: true,
            passwordHash: true,
            tenants: {
                select: {
                    tenantId: true,
                    role: true,
                    tenant: { select: { id: true, name: true } },
                },
            },
        },
    })

    if (!user) {
        await registerLoginFailure(email, ip)
        return res.status(401).json({ error: "Invalid credentials" })
    }

    const ok = await bcrypt.compare(password, user.passwordHash)
    if (!ok) {
        await registerLoginFailure(email, ip)
        return res.status(401).json({ error: "Invalid credentials" })
    }

    await clearLoginFailures(email, ip)

    if (!user.tenants.length) {
        return res.status(403).json({ error: "User has no tenant membership" })
    }

    const { raw, hash } = generateTokenPair()
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000)

    await prisma.$transaction(async (tx) => {
        await tx.loginToken.deleteMany({
            where: { userId: user.id },
        })

        await tx.loginToken.create({
            data: {
                userId: user.id,
                tokenHash: hash,
                expiresAt,
            },
        })
    })

    return res.json({
        loginToken: raw,
        tenants: user.tenants,
    })
})

const selectTenantSchema = z.object({
    loginToken: z.string().min(20),
    tenantId: z.string().min(1),
})

authRouter.post("/select-tenant", async (req, res) => {
    const parsed = selectTenantSchema.safeParse(req.body)
    if (!parsed.success) {
        return res.status(400).json({ error: "Invalid payload" })
    }

    const { loginToken, tenantId } = parsed.data
    const tokenHash = crypto.createHash("sha256").update(loginToken).digest("hex")
    const now = new Date()

    try {
        const result = await prisma.$transaction(async (tx) => {
            const lt = await tx.loginToken.findUnique({
                where: { tokenHash },
            })

            if (!lt) throw new HttpError(401, "Invalid login token")
            if (lt.usedAt) throw new HttpError(401, "Login token already used")
            if (lt.expiresAt <= now) throw new HttpError(401, "Login token expired")

            const claimed = await tx.loginToken.updateMany({
                where: {
                    id: lt.id,
                    usedAt: null,
                    expiresAt: { gt: now },
                },
                data: { usedAt: now },
            })

            if (claimed.count === 0) {
                throw new HttpError(401, "Login token already used or expired")
            }

            const membership = await tx.userTenant.findUnique({
                where: {
                    userId_tenantId: {
                        userId: lt.userId,
                        tenantId,
                    },
                },
            })

            if (!membership) {
                throw new HttpError(403, "No access to tenant")
            }

            const user = await tx.user.findUnique({
                where: { id: lt.userId },
                select: { globalRole: true },
            })

            if (!user) throw new HttpError(401, "User not found")

            const accessToken = signAccessToken({
                sub: lt.userId,
                tid: tenantId,
                role: membership.role,
                gr: user.globalRole,
            })

            const rawRefresh = generateRefreshToken()
            const refreshHash = hashRefreshToken(rawRefresh)

            await tx.refreshToken.create({
                data: {
                    userId: lt.userId,
                    tenantId,
                    tokenHash: refreshHash,
                    expiresAt: new Date(
                        Date.now() + env.refreshDays * 24 * 60 * 60 * 1000
                    ),
                },
            })

            return { accessToken, rawRefresh }
        })

        res.cookie("refresh_token", result.rawRefresh, refreshCookieOptions())
        return res.json({ accessToken: result.accessToken })
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ error: e.message })
        }
        throw e
    }
})

authRouter.post("/refresh", async (req, res) => {
    const raw = req.cookies?.refresh_token
    if (!raw) return res.status(401).json({ error: "Missing refresh token" })

    const tokenHash = hashRefreshToken(raw)
    const now = new Date()

    try {
        const result = await prisma.$transaction(async (tx) => {
            const old = await tx.refreshToken.findFirst({
                where: {
                    tokenHash,
                    revokedAt: null,
                    expiresAt: { gt: now },
                },
                select: { id: true, userId: true, tenantId: true },
            })

            if (!old) throw new HttpError(401, "Refresh token invalid or already used")

            const claimed = await tx.refreshToken.updateMany({
                where: {
                    id: old.id,
                    revokedAt: null,
                    expiresAt: { gt: now },
                },
                data: { revokedAt: now },
            })

            if (claimed.count === 0) {
                throw new HttpError(401, "Refresh token invalid or already used")
            }

            const membership = await tx.userTenant.findUnique({
                where: {
                    userId_tenantId: {
                        userId: old.userId,
                        tenantId: old.tenantId,
                    },
                },
                select: { role: true },
            })
            if (!membership) throw new HttpError(401, "Membership not found")

            const user = await tx.user.findUnique({
                where: { id: old.userId },
                select: { globalRole: true },
            })
            if (!user) throw new HttpError(401, "User not found")

            const newRaw = generateRefreshToken()
            const newHash = hashRefreshToken(newRaw)

            const newToken = await tx.refreshToken.create({
                data: {
                    userId: old.userId,
                    tenantId: old.tenantId,
                    tokenHash: newHash,
                    expiresAt: new Date(Date.now() + env.refreshDays * 24 * 60 * 60 * 1000),
                },
                select: { id: true },
            })

            await tx.refreshToken.update({
                where: { id: old.id },
                data: { replacedByTokenId: newToken.id },
            })

            const accessToken = signAccessToken({
                sub: old.userId,
                tid: old.tenantId,
                role: membership.role,
                gr: user.globalRole,
            })

            return { accessToken, newRaw }
        })

        res.cookie("refresh_token", result.newRaw, refreshCookieOptions())
        return res.json({ accessToken: result.accessToken })
    } catch (e: any) {
        if (e instanceof HttpError) return res.status(e.status).json({ error: e.message })
        throw e
    }
})

authRouter.post("/logout", async (req, res) => {
    const raw = req.cookies?.refresh_token
    if (raw) {
        const tokenHash = hashRefreshToken(raw)
        await prisma.refreshToken.updateMany({
            where: { tokenHash, revokedAt: null },
            data: { revokedAt: new Date() },
        })
    }

    res.clearCookie("refresh_token", {
        ...refreshCookieOptions(),
        maxAge: undefined,
    })

    return res.json({ ok: true })
})

const acceptInviteSchema = z.object({
    token: z.string().min(20),
    password: z.string().min(8).optional(),
    name: z.string().min(1).optional(),
})

authRouter.post("/accept-invite", async (req, res) => {
    const parsed = acceptInviteSchema.safeParse(req.body)
    if (!parsed.success) {
        return res.status(400).json({ error: "Invalid payload" })
    }

    const { token, password, name } = parsed.data
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex")
    const now = new Date()

    try {
        const result = await prisma.$transaction(async (tx) => {
            const invite = await tx.inviteToken.findUnique({
                where: { tokenHash },
            })

            if (!invite) throw new HttpError(400, "Invalid invite")

            const claimed = await tx.inviteToken.updateMany({
                where: {
                    id: invite.id,
                    usedAt: null,
                    expiresAt: { gt: now },
                },
                data: { usedAt: now },
            })

            if (claimed.count === 0) {
                throw new HttpError(400, "Invite already used or expired")
            }

            const existingUser = await tx.user.findUnique({
                where: { email: invite.email },
            })

            if (existingUser) {
                const existingMembership = await tx.userTenant.findUnique({
                    where: {
                        userId_tenantId: {
                            userId: existingUser.id,
                            tenantId: invite.tenantId,
                        },
                    },
                })

                if (existingMembership) {
                    throw new HttpError(409, "User already in tenant")
                }

                await tx.userTenant.create({
                    data: {
                        userId: existingUser.id,
                        tenantId: invite.tenantId,
                        role: invite.role,
                    },
                })

                await tx.auditLog.create({
                    data: {
                        tenantId: invite.tenantId,
                        userId: existingUser.id,
                        action: "INVITE_ACCEPTED",
                        requestId: (req as any).requestId ?? null,
                        meta: {
                            inviteId: invite.id,
                            email: invite.email,
                            role: invite.role,
                            createdUser: false,
                            route: req.originalUrl,
                            method: req.method,
                            ip: req.ip,
                        },
                    },
                })

                return { userId: existingUser.id, createdUser: false }
            }

            if (!password || !name) {
                throw new HttpError(400, "Missing name or password")
            }

            const passwordHash = await bcrypt.hash(password, 12)

            const user = await tx.user.create({
                data: {
                    email: invite.email,
                    name,
                    passwordHash,
                },
            })

            await tx.userTenant.create({
                data: {
                    userId: user.id,
                    tenantId: invite.tenantId,
                    role: invite.role,
                },
            })

            await tx.auditLog.create({
                data: {
                    tenantId: invite.tenantId,
                    userId: user.id,
                    action: "INVITE_ACCEPTED",
                    requestId: (req as any).requestId ?? null,
                    meta: {
                        inviteId: invite.id,
                        email: invite.email,
                        role: invite.role,
                        createdUser: true,
                        route: req.originalUrl,
                        method: req.method,
                        ip: req.ip,
                    },
                },
            })

            return { userId: user.id, createdUser: true }
        })

        return res.status(201).json({ success: true, ...result })
    } catch (e: any) {
        if (e instanceof HttpError) {
            return res.status(e.status).json({ error: e.message })
        }
        throw e
    }
})
