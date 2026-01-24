import { Request, Response, NextFunction } from "express"
import { assertLoginAllowed, TooManyLoginAttemptsError } from "../lib/loginRateLimit"

export async function checkLoginRateLimit(
    req: Request,
    res: Response,
    next: NextFunction
) {
    const email = req.body?.email
    const ip = req.ip

    if (!email || !ip) {
        return res.status(400).json({ error: "Missing email or IP" })
    }

    try {
        await assertLoginAllowed(email, ip)
        next()
    } catch (e: any) {
        if (e instanceof TooManyLoginAttemptsError) {
            return res.status(429).json({
                error: "Too many login attempts. Try again later.",
                blockedUntil: e.blockedUntil,
            })
        }

        throw e
    }
}
