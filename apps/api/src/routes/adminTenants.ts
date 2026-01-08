import {Router} from "express"
import {z} from "zod"
import {prisma} from "../lib/prisma"
import {type AuthedRequest, requireAuth} from "../middleware/auth"
import {requireAnyRole} from "../middleware/rbac"
import {requireSuperAdmin} from "../middleware/superadmin"

export const adminTenantsRouter = Router()


adminTenantsRouter.get(
    "/",
    requireAuth,
    requireSuperAdmin,
    requireAnyRole(["admin"]),
    async (req: AuthedRequest, res) => {

    }
)

adminTenantsRouter.get(
    "/:id/users",
    requireAuth,
    requireSuperAdmin,
    requireAnyRole(["admin"]),
    async (req: AuthedRequest, res) => {

    }
)


adminTenantsRouter.get(
    "/:id/orders",
    requireAuth,
    requireSuperAdmin,
    requireAnyRole(["admin"]),
    async (req: AuthedRequest, res) => {

    }
)
