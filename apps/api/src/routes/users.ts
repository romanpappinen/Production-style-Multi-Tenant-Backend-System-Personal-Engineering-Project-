import {Router} from "express"
import {z} from "zod"
import {prisma} from "../lib/prisma"
import {type AuthedRequest, requireAuth} from "../middleware/auth"
import {requireAnyRole} from "../middleware/rbac"
import {ordersRouter} from "./orders";

export const usersRouter = Router()

const userSelect = {
    id: true,
    email: true,
    name: true,
    tenants: {
        select: {
            role: true,
            tenant: { select: { id: true, name: true } }
        }
    }
} as const

usersRouter.get(
    "/",
    requireAuth,
    requireAnyRole(["admin", "manager"]),
    async (req: AuthedRequest, res) => {
        const tenantId = req.auth!.tid

        const users = await prisma.user.findMany({
            where: {
                tenants: {
                    some: {
                        tenantId
                    },
                },
            },
            select: userSelect
        });

        return res.json({ users })
    }
)
