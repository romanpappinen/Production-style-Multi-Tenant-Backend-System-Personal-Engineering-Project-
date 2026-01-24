import { Router } from "express"
import { prisma } from "../lib/prisma"
import { requireAuth, type AuthedRequest } from "../middleware/auth"
import { requireSuperAdmin } from "../middleware/superadmin"
import parsePagination from "../lib/pagination";
import {z} from "zod";
import {TenantUserRole} from "@prisma/client";
import generateTokenPair from "../lib/tokenPair";

export const adminTenantsRouter = Router()

class HttpError extends Error {
    status: number
    constructor(status: number, message: string) {
        super(message)
        this.status = status
    }
}

const userSelect = (tenantId: string) =>
    ({
        id: true,
        email: true,
        name: true,
        globalRole: true,
        tenants: {
            where: { tenantId },
            select: {
                role: true,
                tenant: { select: { id: true, name: true } },
            },
        }
}) as const

const orderListSelect = {
        id: true,
        status: true,
        createdByUserId: true,
        totalCents: true,
        createdAt: true,
        updatedAt: true
} as const

const orderDetailSelect = ({
        ...orderListSelect,
        items: {
            select: {
                id: true,
                quantity: true,
                unitPriceCents: true,
                lineTotalCents: true,
                product: {
                    select: {
                        id: true,
                        sku: true,
                        title: true,
                    },
                },
            },
        }
}) as const

async function getTenantOrNull(tenantId: string) {
    const tenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
        select: { id: true, name: true },
    })
    return tenant
}

adminTenantsRouter.get(
    "/",
    requireAuth,
    requireSuperAdmin,
    async (req: AuthedRequest, res) => {
        const { skip, take, page, limit } = parsePagination(req)

        const [tenants, total] = await Promise.all([
            prisma.tenant.findMany({
                skip,
                take,
                orderBy: { createdAt: "desc" },
                select: { id: true, name: true, createdAt: true, updatedAt: true },
            }),
            prisma.tenant.count(),
        ])

        return res.status(200).json({
            tenants,
            page,
            limit,
            total,
        })
    }
)

adminTenantsRouter.get(
    "/:id/users",
    requireAuth,
    requireSuperAdmin,
    async (req: AuthedRequest, res) => {
        const tenantId = req.params.id
        const tenant = await getTenantOrNull(tenantId)
        if (!tenant) return res.status(404).json({ error: "Tenant not found" })

        const { skip, take, page, limit } = parsePagination(req)

        const [users, total] = await Promise.all([
            prisma.user.findMany({
                where: {
                    tenants: { some: { tenantId } },
                },
                orderBy: { createdAt: "desc" },
                skip,
                take,
                select: userSelect(tenantId),
            }),
            prisma.user.count({
                where: {
                    tenants: { some: { tenantId } },
                },
            }),
        ])

        return res.status(200).json({
            tenant,
            users,
            page,
            limit,
            total,
        })
    }
)

adminTenantsRouter.get(
    "/:id/orders",
    requireAuth,
    requireSuperAdmin,
    async (req: AuthedRequest, res) => {
        const tenantId = req.params.id
        const tenant = await getTenantOrNull(tenantId)
        if (!tenant) return res.status(404).json({ error: "Tenant not found" })

        const { skip, take, page, limit } = parsePagination(req)

        const [orders, total] = await Promise.all([
            prisma.order.findMany({
                where: { tenantId },
                orderBy: { createdAt: "desc" },
                skip,
                take,
                select: orderListSelect,
            }),
            prisma.order.count({ where: { tenantId } }),
        ])

        return res.status(200).json({
            tenant,
            orders,
            page,
            limit,
            total,
        })
    }
)

adminTenantsRouter.get(
    "/:id/orders/:orderId",
    requireAuth,
    requireSuperAdmin,
    async (req: AuthedRequest, res) => {
        const tenantId = req.params.id
        const orderId = req.params.orderId

        const tenant = await getTenantOrNull(tenantId)
        if (!tenant) return res.status(404).json({ error: "Tenant not found" })

        const order = await prisma.order.findFirst({
            where: { id: orderId, tenantId },
            select: orderDetailSelect,
        })

        if (!order) return res.status(404).json({ error: "Order not found" })

        return res.status(200).json({ tenant, order })
    }
)

const inviteAdminSchema = z.object({
    email: z.string().email().toLowerCase(),
    name: z.string().trim().min(1).max(100).optional(),
})

adminTenantsRouter.post(
    "/:id/invite-admin",
    requireAuth,
    requireSuperAdmin,
    async (req: AuthedRequest, res) => {
        const tenantId = req.params.id
        const tenant = await getTenantOrNull(tenantId)
        if (!tenant) return res.status(404).json({ error: "Tenant not found" })

        const inviterId = req.auth!.sub

        const parsed = inviteAdminSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        const { email } = parsed.data
        const { raw, hash } = generateTokenPair()
        const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7)

        try {
            const invite = await prisma.$transaction(async (tx) => {
                const existingMembership = await tx.userTenant.findFirst({
                    where: { tenantId, user: { email } },
                    select: { id: true },
                })
                if (existingMembership) throw new HttpError(409, "User already belongs to this tenant")

                const created = await tx.inviteToken.create({
                    data: {
                        tenantId,
                        email,
                        role: TenantUserRole.admin,
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
                        meta: { inviteId: created.id, email, role: TenantUserRole.admin, by: "superadmin" },
                    },
                })

                return created
            })

            return res.status(201).json({
                tenant,
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

const patchUserRoleSchema = z.object({
    role: z.nativeEnum(TenantUserRole)
})

adminTenantsRouter.patch(
    "/:id/users/:userId/role",
    requireAuth,
    requireSuperAdmin,
    async (req: AuthedRequest, res) => {
        const tenantId = req.params.id
        const tenant = await getTenantOrNull(tenantId)
        if (!tenant) return res.status(404).json({ error: "Tenant not found" })

        const targetUserId = req.params.userId

        const parsed = patchUserRoleSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        try {
            const membership = await prisma.$transaction(async (tx) => {
                const current = await tx.userTenant.findUnique({
                    where: { userId_tenantId: { userId: targetUserId, tenantId } },
                    select: { userId: true, tenantId: true, role: true },
                })
                if (!current) throw new HttpError(404, "User not found in this tenant")

                const isDemotingAdmin =
                    current.role === TenantUserRole.admin &&
                    parsed.data.role !== TenantUserRole.admin

                if (isDemotingAdmin) {
                    const adminsCount = await tx.userTenant.count({
                        where: { tenantId, role: TenantUserRole.admin },
                    })
                    if (adminsCount <= 1) {
                        throw new HttpError(400, "Cannot remove the last admin from the tenant")
                    }
                }

                const updated = await tx.userTenant.updateMany({
                    where: { userId: targetUserId, tenantId },
                    data: { role: parsed.data.role },
                })
                if (updated.count === 0) throw new HttpError(404, "User not found in this tenant")

                const after = await tx.userTenant.findUnique({
                    where: { userId_tenantId: { userId: targetUserId, tenantId } },
                    select: { userId: true, tenantId: true, role: true },
                })
                if (!after) throw new HttpError(404, "User not found in this tenant")

                await tx.auditLog.create({
                    data: {
                        tenantId,
                        userId: req.auth!.sub,
                        action: "TENANT_USER_ROLE_UPDATED",
                        requestId: req.requestId ?? null,
                        meta: {
                            targetUserId,
                            fromRole: current.role,
                            toRole: after.role,
                            route: req.originalUrl,
                            method: req.method,
                            ip: req.ip,
                            by: "superadmin",
                        },
                    },
                })

                return after
            })

            return res.json({ membership })
        } catch (e) {
            if (e instanceof HttpError) {
                return res.status(e.status).json({ error: e.message })
            }
            throw e
        }
    }
)
