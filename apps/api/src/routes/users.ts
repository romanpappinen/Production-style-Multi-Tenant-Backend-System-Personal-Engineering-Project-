import {Router} from "express"
import {z} from "zod"
import {prisma} from "../lib/prisma"
import {type AuthedRequest, requireAuth} from "../middleware/auth"
import {requireAnyRole} from "../middleware/rbac"
import parsePagination from "../lib/pagination";
import { TenantUserRole } from "@prisma/client"
import generateTokenPair from "../lib/tokenPair";

export const usersRouter = Router()

class HttpError extends Error {
    status: number
    constructor(status: number, message: string) {
        super(message)
        this.status = status
    }
}

const roleSchema = z.nativeEnum(TenantUserRole)

const userListSelect = (tenantId: string) =>
    ({
        id: true,
        email: true,
        name: true,
        createdAt: true,
        updatedAt: true,
        tenants: {
            where: { tenantId },
            select: {
                role: true,
                tenant: { select: { id: true, name: true } },
            },
        },
    }
) as const

usersRouter.get(
    "/",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const { skip, take, page, limit } = parsePagination(req)

        const [users, total] = await Promise.all([
            prisma.user.findMany({
                where: {
                    tenants: {
                        some: {
                            tenantId
                        },
                    },
                },
                orderBy: { createdAt: "desc" },
                skip,
                take,
                select: userListSelect(tenantId),
            }),
            prisma.user.count({
                where: {
                    tenants: {
                        some: {
                            tenantId
                        },
                    },
                },
            }),
        ])

        return res.json({ users, page, limit, total })
    }
)

usersRouter.get(
    "/:id",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const userId = req.params.id

        const user = await prisma.user.findFirst({
            where: {
                id: userId,
                tenants: { some: { tenantId } }
            },
            select: userListSelect(tenantId),
        })

        if (!user) return res.status(404).json({ error: "User not found" })

        return res.json({ user })
    }
)

const inviteSchema = z.object({
    email: z.string().email().toLowerCase(),
    name: z.string().trim().min(1).max(100).optional(),
    role: z.nativeEnum(TenantUserRole).refine((r) => r !== TenantUserRole.admin, {
        message: "Only superadmin can assign admin role",
    }),
})

usersRouter.post(
    "/invite",
    requireAuth,
    requireAnyRole(["admin"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const inviterId = req.auth!.sub

        const parsed = inviteSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        const { email, role } = parsed.data
        const { raw, hash } = generateTokenPair()

        const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7) // 7 days

        try {
            const invite = await prisma.$transaction(async (tx) => {

                const existingMembership = await tx.userTenant.findFirst({
                    where: {
                        tenantId,
                        user: { email },
                    },
                    select: { id: true },
                })

                if (existingMembership) {
                    throw new HttpError(409, "User already belongs to this tenant")
                }

                const created = await tx.inviteToken.create({
                    data: {
                        tenantId,
                        email,
                        role,
                        tokenHash: hash,
                        expiresAt,
                        createdByUserId: inviterId,
                    },
                    select: { id: true, email: true, role: true, expiresAt: true },
                })

                await tx.auditLog.create({
                    data: {
                        tenantId,
                        userId: inviterId,
                        action: "INVITE_CREATED",
                        requestId: req.requestId ?? null,
                        meta: { inviteId: created.id, email, role },
                    },
                })

                return created
            })

            return res.status(201).json({
                invite,
                inviteToken: raw,
                acceptUrl: `http://localhost:3000/auth/accept-invite?token=${raw}`,
            })
        } catch (e: any) {
            if (e instanceof HttpError) return res.status(e.status).json({ error: e.message })
            throw e
        }
    }
)


const updateRoleSchema = z.object({
    role: roleSchema,
})

usersRouter.patch(
    "/:id/role",
    requireAuth,
    requireAnyRole(["admin"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const targetUserId = req.params.id

        const selfUserId = req.auth!.sub
        const isSelf = targetUserId === selfUserId

        const parsed = updateRoleSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        try {
            const result = await prisma.$transaction(async (tx) => {
                const membership = await tx.userTenant.findUnique({
                    where: { userId_tenantId: { userId: targetUserId, tenantId } },
                    select: { userId: true, tenantId: true, role: true },
                })

                if (!membership) throw new HttpError(404, "User not found in this tenant")

                if (isSelf && membership.role === TenantUserRole.admin && parsed.data.role !== TenantUserRole.admin) {
                    throw new HttpError(400, "You cannot change your own admin role")
                }

                const isDemotingAdmin =
                    membership.role === TenantUserRole.admin &&
                    parsed.data.role !== TenantUserRole.admin

                if (isDemotingAdmin) {
                    const adminsCount = await tx.userTenant.count({
                        where: { tenantId, role: TenantUserRole.admin },
                    })

                    if (adminsCount <= 1) {
                        throw new HttpError(400, "Cannot remove the last admin from the tenant")
                    }
                }

                const updated = await tx.userTenant.update({
                    where: { userId_tenantId: { userId: targetUserId, tenantId } },
                    data: { role: parsed.data.role },
                    select: { userId: true, tenantId: true, role: true },
                })

                await tx.auditLog.create({
                    data: {
                        tenantId,
                        userId: req.auth!.sub,
                        action: "TENANT_USER_ROLE_UPDATED",
                        requestId: req.requestId ?? null,
                        meta: {
                            targetUserId,
                            fromRole: membership.role,
                            toRole: updated.role,
                            route: req.originalUrl,
                            method: req.method,
                            ip: req.ip,
                        },
                    },
                })

                return updated
            })

            return res.json({ membership: result })
        } catch (e: any) {
            if (e instanceof HttpError) {
                return res.status(e.status).json({ error: e.message })
            }
            throw e
        }
    }
)

usersRouter.delete(
    "/:id/membership",
    requireAuth,
    requireAnyRole(["admin"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const targetUserId = req.params.id

        const selfUserId = req.auth!.sub
        if (targetUserId === selfUserId) {
            return res.status(400).json({ error: "You cannot remove yourself from the tenant" })
        }

        try {
            await prisma.$transaction(async (tx) => {
                const membership = await tx.userTenant.findUnique({
                    where: { userId_tenantId: { userId: targetUserId, tenantId } },
                    select: { role: true },
                })

                if (!membership) throw new HttpError(404, "User not found in this tenant")

                if (membership.role === TenantUserRole.admin) {
                    const adminsCount = await tx.userTenant.count({
                        where: { tenantId, role: TenantUserRole.admin },
                    })

                    if (adminsCount <= 1) {
                        throw new HttpError(400, "Cannot remove the last admin from the tenant")
                    }
                }

                const deleted = await tx.userTenant.deleteMany({
                    where: { userId: targetUserId, tenantId },
                })

                if (deleted.count === 0) throw new HttpError(404, "User not found in this tenant")

                await tx.auditLog.create({
                    data: {
                        tenantId,
                        userId: req.auth!.sub,
                        action: "TENANT_USER_REMOVED",
                        requestId: req.requestId ?? null,
                        meta: {
                            targetUserId,
                            route: req.originalUrl,
                            method: req.method,
                            ip: req.ip,
                        },
                    },
                })
            })

            return res.sendStatus(204)
        } catch (e: any) {
            if (e instanceof HttpError) {
                return res.status(e.status).json({ error: e.message })
            }
            throw e
        }
    }
)
