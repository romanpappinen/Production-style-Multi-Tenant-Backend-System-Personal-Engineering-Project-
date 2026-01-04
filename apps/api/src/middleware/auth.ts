import type { NextFunction, Request, Response } from "express"
import { verifyAccessToken, type AccessTokenPayload } from "../lib/jwt.js"

export type AuthedRequest = Request & { auth?: AccessTokenPayload }

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
    const header = req.header("authorization") ?? ""
    const [scheme, token] = header.split(" ")

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({ error: "Missing bearer token" })
    }

    try {
        req.auth = verifyAccessToken(token)
        return next()
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" })
    }
}
