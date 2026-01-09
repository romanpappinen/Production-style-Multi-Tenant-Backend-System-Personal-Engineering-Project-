import type { NextFunction, Request, Response } from "express"
import { verifyAccessToken, type AccessTokenPayload } from "../lib/jwt.js"

export type AuthedRequest = Request & { auth?: AccessTokenPayload }

const UNAUTHORIZED = { error: "Missing bearer token" }

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
    const header = req.header("authorization")
    if (!header) return res.status(401).json(UNAUTHORIZED)

    const match = header.match(/^Bearer\s+(.+)$/i)
    if (!match) return res.status(401).json(UNAUTHORIZED)

    const token = match[1]

    try {
        req.auth = verifyAccessToken(token)
        return next()
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" })
    }
}
