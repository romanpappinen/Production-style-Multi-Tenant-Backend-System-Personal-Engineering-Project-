import { prisma } from "./prisma"

export class TooManyLoginAttemptsError extends Error {
    status = 429
    blockedUntil: Date

    constructor(blockedUntil: Date) {
        super(`Too many login attempts. Try again later.`)
        this.blockedUntil = blockedUntil
    }
}

const MAX_ATTEMPTS = 7

const BLOCK_STAGES_MS = [
    10 * 60 * 1000,        // after 7  -> 10 minutes
    60 * 60 * 1000,        // after 14 -> 1 hour
    24 * 60 * 60 * 1000,   // after 21 -> 1 day
]

const RESET_AFTER_IDLE_MS = 24 * 60 * 60 * 1000

function normalizeEmail(email: string) {
    return email.trim().toLowerCase()
}

export async function assertLoginAllowed(email: string, ip: string) {
    const attempt = await prisma.loginAttempt.findUnique({
        where: { email_ip: { email: normalizeEmail(email), ip } },
    })

    if (attempt?.blockedUntil && attempt.blockedUntil > new Date()) {
        throw new TooManyLoginAttemptsError(attempt.blockedUntil)
    }
}

export async function registerLoginFailure(email: string, ip: string) {
    const now = new Date()
    const normalizedEmail = normalizeEmail(email)

    await prisma.$transaction(async (tx) => {
        const existing = await tx.loginAttempt.findUnique({
            where: { email_ip: { email: normalizedEmail, ip } },
        })

        const shouldReset =
            existing?.lastFailAt &&
            now.getTime() - existing.lastFailAt.getTime() > RESET_AFTER_IDLE_MS

        const count = shouldReset ? 1 : (existing?.count ?? 0) + 1

        let blockedUntil: Date | null = null

        if (count % MAX_ATTEMPTS === 0) {
            const stage = Math.min(
                Math.floor(count / MAX_ATTEMPTS) - 1,
                BLOCK_STAGES_MS.length - 1
            )
            blockedUntil = new Date(now.getTime() + BLOCK_STAGES_MS[stage])
        }

        await tx.loginAttempt.upsert({
            where: { email_ip: { email: normalizedEmail, ip } },
            create: {
                email: normalizedEmail,
                ip,
                count,
                blockedUntil,
                lastFailAt: now,
            },
            update: {
                count,
                blockedUntil,
                lastFailAt: now,
            },
        })
    })
}

export async function clearLoginFailures(email: string, ip: string) {
    await prisma.loginAttempt.deleteMany({
        where: { email: normalizeEmail(email), ip },
    })
}
