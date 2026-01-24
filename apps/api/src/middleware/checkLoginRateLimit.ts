import { Request, Response, NextFunction } from "express"
import { assertLoginAllowed, TooManyLoginAttemptsError } from "../lib/loginRateLimit"
import {getClientIp} from "../lib/clientIp";

export async function checkLoginRateLimit(req: Request, res: Response, next: NextFunction) {
    const email = req.body?.email
    const ip = getClientIp(req)

    if (!email) {
        return res.status(400).json({ error: "Missing email" })
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