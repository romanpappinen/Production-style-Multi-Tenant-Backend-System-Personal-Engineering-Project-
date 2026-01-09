import {Router} from "express"
import {z} from "zod"
import {prisma} from "../lib/prisma"
import {type AuthedRequest, requireAuth} from "../middleware/auth"
import { requireAnyRole } from "../middleware/rbac"
import parsePagination from "../lib/pagination";

export const productsRouter = Router()

const productSelect = ({
    id: true,
    sku: true,
    title: true,
    priceCents: true,
    isActive: true,
    createdAt: true,
    updatedAt: true,
}) as const

// GET /products?active=true|false
productsRouter.get(
    "/",
    requireAuth,
    async (req: AuthedRequest, res) => {
    const tenantId = req.auth!.tid

    const activeParam = req.query.active
    const isActive =
        activeParam === undefined
            ? undefined
            : activeParam === "true"
                ? true
                : activeParam === "false"
                    ? false
                    : null

    if (isActive === null) {
        return res.status(400).json({ error: "Invalid query param: active must be true|false" })
    }

    const { skip, take, page, limit } = parsePagination(req)

    const [products, total] = await Promise.all([
        prisma.product.findMany({
            where: {
                tenantId,
                ...(isActive !== undefined ? { isActive } : {}),
            },
            orderBy: { createdAt: "desc" },
            skip,
            take,
            select: productSelect,
        }),
        prisma.product.count({
            where: {
                tenantId,
                ...(isActive !== undefined ? { isActive } : {}),
            },
        }),
    ])

    return res.json({ products, page, limit, total })
})

productsRouter.get(
    "/:id",
    requireAuth,
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const productId = req.params.id

        const product = await prisma.product.findFirst({
            where: { id: productId, tenantId },
            select: productSelect
        })

        if(!product) {
            return res.status(404).json({ error: "Product not found" })
        }

        return res.json({ product })
    }
)

const createSchema = z.object({
    sku: z.string().trim().min(1).max(64),
    title: z.string().trim().min(1).max(200),
    priceCents: z.number().int().min(0),
    isActive: z.boolean().optional(),
})

productsRouter.post(
    "/",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const parsed = createSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        try {
            const created = await prisma.$transaction(async (tx) => {
                const created = await tx.product.create({
                    data: {
                        tenantId,
                        sku: parsed.data.sku,
                        title: parsed.data.title,
                        priceCents: parsed.data.priceCents,
                        isActive: parsed.data.isActive ?? true,
                    },
                    select: productSelect
                })

                await tx.auditLog.create({
                    data: {
                        tenantId,
                        userId: req.auth!.sub,
                        action: "PRODUCT_CREATED",
                        requestId: req.requestId ?? null,
                        meta: {
                            productId: created.id,
                            sku: created.sku,
                            title: created.title,
                            priceCents: created.priceCents,
                        },
                    },
                })

                return created
            })


            return res.status(201).json({ product: created })
        } catch (e: any) {
            // Prisma unique constraint for @@unique([tenantId, sku])
            if (e?.code === "P2002") {
                return res.status(409).json({ error: "SKU already exists in this tenant" })
            }
            throw e
        }
    }
)

const updateSchema = z.object({
    title: z.string().trim().min(1).max(200).optional(),
    priceCents: z.number().int().min(0).optional(),
    isActive: z.boolean().optional(),
})

productsRouter.patch(
    "/:id",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const productId = req.params.id

        const parsed = updateSchema.safeParse(req.body)
        if (!parsed.success) {
            return res.status(400).json({ error: "Invalid payload", details: parsed.error.flatten() })
        }

        if (Object.keys(parsed.data).length === 0) {
            return res.status(400).json({ error: "No fields to update" })
        }

        // Tenant-scope update: updateMany enforces tenantId in WHERE
        const product = await prisma.$transaction(async (tx) => {
            const updated = await tx.product.updateMany({
                where: { id: productId, tenantId },
                data: parsed.data,
            })

            if (updated.count === 0) return null

            await tx.auditLog.create({
                data: {
                    tenantId,
                    userId: req.auth!.sub,
                    action: "PRODUCT_UPDATED",
                    requestId: req.requestId ?? null,
                    meta: {
                        productId,
                        patch: parsed.data,
                        route: req.originalUrl,
                        method: req.method,
                        ip: req.ip,
                    },
                }
            })

            return tx.product.findFirst({
                where: { id: productId, tenantId },
                select: productSelect,
            })
        })

        if (!product) return res.status(404).json({ error: "Product not found" })

        return res.json({ product })
    }
)

productsRouter.delete(
    "/:id",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid
        const productId = req.params.id

        // Tenant-scope delete: deleteMany enforces tenantId in WHERE
        const deleted = await prisma.$transaction(async (tx) => {
            const deleted = await tx.product.deleteMany({
                where: { id: productId, tenantId },
            })

            if (deleted.count === 0) return deleted

            await tx.auditLog.create({
                data: {
                    tenantId,
                    userId: req.auth!.sub,
                    action: "PRODUCT_DELETED",
                    requestId: req.requestId ?? null,
                    meta: {
                        productId,
                        route: req.originalUrl,
                        method: req.method,
                        ip: req.ip,
                    }
                }
            })

            return deleted
        })

        if (deleted.count === 0) {
            return res.status(404).json({ error: "Product not found" })
        }

        return res.sendStatus(204)
    }
)


