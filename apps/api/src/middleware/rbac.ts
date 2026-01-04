import type { Response, NextFunction } from "express"
import type { AuthedRequest } from "./auth.js"

type Role = "admin" | "manager" | "user"

export function requireRole(role: Role) {
    return (req: AuthedRequest, res: Response, next: NextFunction) => {
        const r = req.auth?.role
        if (!r) return res.status(401).json({ error: "Unauthorized" })
        if (r !== role) return res.status(403).json({ error: "Forbidden" })
        next()
    }
}

export function requireAnyRole(roles: Role[]) {
    const set = new Set(roles)
    return (req: AuthedRequest, res: Response, next: NextFunction) => {
        const r = req.auth?.role
        if (!r) return res.status(401).json({ error: "Unauthorized" })
        if (!set.has(r)) return res.status(403).json({ error: "Forbidden" })
        next()
    }
}
