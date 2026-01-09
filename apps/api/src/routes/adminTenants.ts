import { Router } from "express"
import { prisma } from "../lib/prisma"
import { requireAuth, type AuthedRequest } from "../middleware/auth"
import { requireSuperAdmin } from "../middleware/superadmin"
import parsePagination from "../lib/pagination";

export const adminTenantsRouter = Router()

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

async function assertTenantExists(tenantId: string) {
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
        const tenant = await assertTenantExists(tenantId)
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
        const tenant = await assertTenantExists(tenantId)
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

        const tenant = await assertTenantExists(tenantId)
        if (!tenant) return res.status(404).json({ error: "Tenant not found" })

        const order = await prisma.order.findFirst({
            where: { id: orderId, tenantId },
            select: orderDetailSelect,
        })

        if (!order) return res.status(404).json({ error: "Order not found" })

        return res.status(200).json({ tenant, order })
    }
)
