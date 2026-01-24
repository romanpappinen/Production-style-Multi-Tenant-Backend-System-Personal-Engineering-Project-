import type { Request } from "express"

export function getClientIp(req: Request): string {
    const xff = req.headers["x-forwarded-for"]

    if (typeof xff === "string" && xff.length > 0) {
        const first = xff.split(",")[0]?.trim()
        if (first) return first
    }

    if (Array.isArray(xff) && xff.length > 0) {
        const first = xff[0]?.trim()
        if (first) return first
    }

    return (req.ip ?? req.socket?.remoteAddress ?? "unknown").toString()
}