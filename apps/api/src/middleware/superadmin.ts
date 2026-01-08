import type { Response, NextFunction } from "express"
import type { AuthedRequest } from "./auth"

export function requireSuperAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
    if (req.auth?.gr !== "superadmin") {
        return res.status(403).json({ error: "Forbidden" })
    }
    return next()
}
