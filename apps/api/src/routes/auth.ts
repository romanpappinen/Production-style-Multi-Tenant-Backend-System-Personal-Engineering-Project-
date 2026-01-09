import { Router } from "express"
import { z } from "zod"
import bcrypt from "bcryptjs"
import crypto from "crypto"
import { prisma } from "../lib/prisma"
import { signAccessToken } from "../lib/jwt"
import { generateRefreshToken, hashRefreshToken, refreshCookieOptions } from "../lib/refreshToken.js"
import { env } from "../lib/env"

export const authRouter = Router()

class HttpError extends Error {
    status: number
    constructor(status: number, message: string) {
        super(message)
        this.status = status
    }
}

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1),
})

authRouter.post("/login", async (req, res) => {
    const parsed = loginSchema.safeParse(req.body)
    if (!parsed.success) return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })

    const { email, password } = parsed.data

    const user = await prisma.user.findUnique({
        where: { email },
        include: { tenants: true },
    })

    if (!user) return res.status(401).json({ error: "Invalid credentials" })

    const ok = await bcrypt.compare(password, user.passwordHash)
    if (!ok) return res.status(401).json({ error: "Invalid credentials" })

    const membership = user.tenants[0]
    if (!membership) return res.status(403).json({ error: "User has no tenant membership" })

    const accessToken = signAccessToken({
        sub: user.id,
        tid: membership.tenantId,
        role: membership.role,
        gr: "none"
    })

    // Refresh token rotation-ready: store only hash
    const rawRefresh = generateRefreshToken()
    const tokenHash = hashRefreshToken(rawRefresh)

    const expiresAt = new Date(Date.now() + env.refreshDays * 24 * 60 * 60 * 1000)

    await prisma.refreshToken.create({
        data: {
            userId: user.id,
            tenantId: membership.tenantId,
            tokenHash,
            expiresAt,
        },
    })

    res.cookie("refresh_token", rawRefresh, refreshCookieOptions())
    return res.json({ accessToken })
})

authRouter.post("/refresh", async (req, res) => {
    const raw = req.cookies?.refresh_token as string | undefined
    if (!raw) return res.status(401).json({ error: "Missing refresh token" })

    const tokenHash = hashRefreshToken(raw)

    const existing = await prisma.refreshToken.findUnique({
        where: { tokenHash },
    })

    if (!existing) return res.status(401).json({ error: "Invalid refresh token" })
    if (existing.revokedAt) return res.status(401).json({ error: "Refresh token revoked" })
    if (existing.expiresAt.getTime() <= Date.now()) return res.status(401).json({ error: "Refresh token expired" })

    // Load membership to get role (authoritative)
    const membership = await prisma.userTenant.findUnique({
        where: { userId_tenantId: { userId: existing.userId, tenantId: existing.tenantId } },
    })

    if (!membership) return res.status(401).json({ error: "Membership not found" })

    // Rotate refresh token: revoke old, create new, link chain
    const newRaw = generateRefreshToken()
    const newHash = hashRefreshToken(newRaw)
    const newExpiresAt = new Date(Date.now() + env.refreshDays * 24 * 60 * 60 * 1000)

    const newToken = await prisma.refreshToken.create({
        data: {
            userId: existing.userId,
            tenantId: existing.tenantId,
            tokenHash: newHash,
            expiresAt: newExpiresAt,
        },
    })

        await prisma.refreshToken.update({
            where: { id: existing.id },
        data: {
            revokedAt: new Date(),
            replacedByTokenId: newToken.id,
        },
    })

    const accessToken = signAccessToken({
        sub: existing.userId,
        tid: existing.tenantId,
        role: membership.role,
        gr: "none"
    })

    res.cookie("refresh_token", newRaw, refreshCookieOptions())
    return res.json({ accessToken })
})

authRouter.post("/logout", async (req, res) => {
    const raw = req.cookies?.refresh_token as string | undefined
    if (raw) {
        const tokenHash = hashRefreshToken(raw)
        const existing = await prisma.refreshToken.findUnique({ where: { tokenHash } })
        if (existing && !existing.revokedAt) {
            await prisma.refreshToken.update({
                where: { id: existing.id },
                data: { revokedAt: new Date() },
            })
        }
    }

    res.clearCookie("refresh_token", { path: "/auth/refresh" })
    return res.json({ ok: true })
})

const acceptInviteSchema = z.object({
    token: z.string().min(20),
    password: z.string().min(8),
    name: z.string().trim().min(1).max(100),
})

authRouter.post(
    "/accept-invite",
    async (req, res) => {
        const parsed = acceptInviteSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({
                error: "Invalid payload",
                details: parsed.error.flatten(),
            })
        }

        const { token, password, name } = parsed.data
        const tokenHash = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex")

        try {
            const result = await prisma.$transaction(async (tx) => {
                const invite = await tx.inviteToken.findFirst({
                    where: {
                        tokenHash,
                        expiresAt: { gt: new Date() },
                        usedAt: null,
                    },
                })

                if (!invite) {
                    throw new HttpError(400, "Invalid or expired invite")
                }

                let user = await tx.user.findUnique({
                    where: { email: invite.email },
                })

                if (!user) {
                    const passwordHash = await bcrypt.hash(password, 12)

                    user = await tx.user.create({
                        data: {
                            email: invite.email,
                            name,
                            passwordHash,
                        },
                    })
                }

                const existingMembership = await tx.userTenant.findFirst({
                    where: {
                        userId: user.id,
                        tenantId: invite.tenantId,
                    },
                })

                if (existingMembership) {
                    throw new HttpError(409, "User already belongs to tenant")
                }

                await tx.userTenant.create({
                    data: {
                        userId: user.id,
                        tenantId: invite.tenantId,
                        role: invite.role,
                    },
                })

                await tx.inviteToken.update({
                    where: { id: invite.id },
                    data: { usedAt: new Date() },
                })

                await tx.auditLog.create({
                    data: {
                        tenantId: invite.tenantId,
                        userId: user.id,
                        action: "INVITE_ACCEPTED",
                        meta: {
                            inviteId: invite.id,
                            email: invite.email,
                            role: invite.role,
                        },
                    },
                })

                return { userId: user.id, tenantId: invite.tenantId }
            })

            return res.status(201).json({
                success: true,
                ...result,
            })
        } catch (e: any) {
            if (e instanceof HttpError) {
                return res.status(e.status).json({ error: e.message })
            }
            throw e
        }
    }
)
