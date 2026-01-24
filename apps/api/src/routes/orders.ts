import {Router} from "express"
import {z} from "zod"
import {prisma} from "../lib/prisma"
import {type AuthedRequest, requireAuth} from "../middleware/auth"
import {requireAnyRole} from "../middleware/rbac"
import parsePagination from "../lib/pagination";

class HttpError extends Error {
    status: number
    constructor(status: number, message: string) {
        super(message)
        this.status = status
    }
}

export const ordersRouter = Router()

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

const productSelect = {
    id: true,
    priceCents: true,
    sku: true,
    title: true
} as const

ordersRouter.get(
    "/",
    requireAuth,
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const { role, sub } = req.auth!
        const where = role === "user"
            ? { tenantId, createdByUserId: sub }
            : { tenantId }

        const { skip, take, page, limit } = parsePagination(req)

        const [orders, total] = await Promise.all([
            prisma.order.findMany({
                where,
                orderBy: { createdAt: "desc" },
                skip,
                take,
                select: orderListSelect,
            }),
            prisma.order.count({
                where,
            }),
        ])

        return res.json({ orders, page, limit, total })
    }
)

ordersRouter.get(
    "/:id",
    requireAuth,
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const orderId = req.params.id
        const { role, sub } = req.auth!
        const where = role === "user"
            ? { id: orderId, tenantId, createdByUserId: sub }
            : { id: orderId, tenantId }

        const order = await prisma.order.findFirst({
            where,
            select: orderDetailSelect
        })

        if(!order) {
            return res.status(404).json({ error: "Order not found" })
        }
        return res.json({ order })
    }
)

const createSchema = z.object({
    items: z.array(
        z.object({
            productId: z.string().min(1),
            quantity: z.number().int().positive(),
        })
    ).min(1),
})

ordersRouter.post(
    "/",
    requireAuth,
    requireAnyRole(["admin", "manager", "user"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const userId = req.auth!.sub

        const parsed = createSchema.safeParse(req.body)
        if(!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        const items = parsed.data.items.reduce<
            Array<{ productId: string; quantity: number }>
        >((acc, current) => {
            const existing = acc.find(item => item.productId === current.productId);
            if (existing) {
                existing.quantity += current.quantity;
            } else {
                acc.push({...current});
            }
            return acc;
        }, [])

        const uniqueProductIds = [...new Set(items.map(i => i.productId))]

        try {
            const order = await prisma.$transaction(async tx => {

                const products = await tx.product.findMany({
                    where: { id: { in: uniqueProductIds }, tenantId, isActive: true },
                    select: productSelect,
                })

                if (products.length !== uniqueProductIds.length) {
                    throw new HttpError(400, "Some products not found or inactive")
                }

                const productById = new Map(products.map(p => [p.id, p] as const))

                let totalCents = 0
                const orderItems: Array<{
                    productId: string
                    quantity: number
                    unitPriceCents: number
                    lineTotalCents: number
                }> = []

                for (const i of items) {
                    const product = productById.get(i.productId)
                    if (!product) {
                        throw new HttpError(400, `Product not found: ${i.productId}`)
                    }

                    const unitPriceCents = product.priceCents
                    const lineTotalCents = i.quantity * unitPriceCents

                    totalCents += lineTotalCents

                    orderItems.push({
                        productId: i.productId,
                        quantity: i.quantity,
                        unitPriceCents,
                        lineTotalCents,
                    })
                }

                const order = await tx.order.create({
                    data: {
                        tenantId,
                        createdByUserId: userId,
                        totalCents,
                        items: {
                            create: orderItems
                        }
                    },
                    select: orderDetailSelect
                })

                await tx.auditLog.create({
                    data: {
                        tenantId,
                        userId: req.auth!.sub,
                        action: "ORDER_CREATED",
                        requestId: req.requestId ?? null,
                        meta: {
                            orderId: order.id,
                            totalCents: order.totalCents,
                            orderItems: orderItems
                        }
                    }
                })

                return order
            })

            return res.status(201).json({ order })
        } catch (e: any) {
            if (e?.status) {
                return res.status(e.status).json({ error: e.message })
            }
            throw e
        }
    }
)

ordersRouter.patch(
    "/:id/cancel",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const orderId = req.params.id

        const order = await prisma.$transaction(async tx => {
            const updated = await tx.order.updateMany({
                where: {
                    id: orderId,
                    tenantId,
                    status: "created"
                },
                data: {
                    status: "cancelled"
                }
            })

            if (updated.count === 0) return null

            await tx.auditLog.create({
                data: {
                    tenantId,
                    userId: req.auth!.sub,
                    action: 'ORDER_CANCELLED',
                    requestId: req.requestId ?? null,
                    meta: {
                        orderId,
                        route: req.originalUrl,
                        method: req.method,
                        ip: req.ip
                    }
                }
            })

            return tx.order.findFirst({
                where: { id: orderId, tenantId },
                select: orderDetailSelect,
            })
        })

        if(!order) return res.status(404).json({ error: "Order not found or not cancellable" })

        return res.json({ order })
    }
)
