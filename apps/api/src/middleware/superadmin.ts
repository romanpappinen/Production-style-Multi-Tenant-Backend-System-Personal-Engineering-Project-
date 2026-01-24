import type { Response, NextFunction } from "express"
import type { AuthedRequest } from "./auth"
import { prisma } from "../lib/prisma"

export async function requireSuperAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
    if (!req.auth?.sub) return res.status(401).json({ error: "Unauthorized" })

    const user = await prisma.user.findUnique({
        where: { id: req.auth.sub },
        select: {
            globalRole: true
        },
    })

    if (!user || user.globalRole !== "superadmin") {
        return res.status(403).json({ error: "Forbidden" })
    }

    return next()
}
