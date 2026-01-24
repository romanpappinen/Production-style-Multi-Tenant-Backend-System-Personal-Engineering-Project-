import crypto from "crypto"
import { env } from "./env"

export function generateRefreshToken(): string {
    // Base64url-safe random token
    return crypto.randomBytes(32).toString("base64url")
}

export function hashRefreshToken(raw: string): string {
    // Hash pepper to prevent offline guessing if DB leaks
    const h = crypto.createHash("sha256")
    h.update(raw)
    h.update(env.refreshPepper)
    return h.digest("hex")
}

export function refreshCookieOptions() {
    const maxAgeMs = env.refreshDays * 24 * 60 * 60 * 1000
    return {
        httpOnly: true,
        secure: false, // set true on HTTPS in prod
        sameSite: "lax" as const,
        path: "/auth/refresh",
        maxAge: maxAgeMs,
    }
}
