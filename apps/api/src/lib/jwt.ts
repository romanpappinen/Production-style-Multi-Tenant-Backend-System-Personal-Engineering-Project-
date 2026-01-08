import jwt from "jsonwebtoken"
import { env } from "./env"

export type AccessTokenPayload = {
    sub: string // userId
    tid: string // tenantId
    role: "admin" | "manager" | "user",
    gr: "none" | "superadmin"
}

export function signAccessToken(payload: AccessTokenPayload): string {
    return jwt.sign(payload, env.jwtAccessSecret, { expiresIn: "15m" })
}

export function verifyAccessToken(token: string): AccessTokenPayload {
    return jwt.verify(token, env.jwtAccessSecret) as AccessTokenPayload
}
