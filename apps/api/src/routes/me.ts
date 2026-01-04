import { Router } from "express"
import { prisma } from "../lib/prisma"
import { requireAuth, type AuthedRequest } from "../middleware/auth"

export const meRouter = Router()

meRouter.get("/", requireAuth, async (req: AuthedRequest, res) => {
    const auth = req.auth!
    const userId = auth.sub
    const tenantId = auth.tid

    // Load user (authoritative data from DB)
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            id: true,
            email: true,
            name: true,
        },
    })

    if (!user) {
        return res.status(401).json({ error: "User not found" })
    }

    // Load tenant membership (authoritative role)
    const membership = await prisma.userTenant.findUnique({
        where: {
            userId_tenantId: {
                userId,
                tenantId,
            },
        },
        select: {
            role: true,
            tenantId: true,
        },
    })

    if (!membership) {
        return res.status(403).json({ error: "No access to tenant" })
    }

    return res.json({
        user,
        tenant: {
            id: membership.tenantId,
            role: membership.role,
        },
    })
})
