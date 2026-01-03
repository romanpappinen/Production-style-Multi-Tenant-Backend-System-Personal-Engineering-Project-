import { PrismaClient } from "@prisma/client"
import { PrismaPg } from "@prisma/adapter-pg"
import { env } from "./env"
// Prisma v7 requires a non-empty PrismaClientOptions (adapter or accelerateUrl)
const adapter = new PrismaPg({
    connectionString: env.databaseUrl,
})

export const prisma = new PrismaClient({ adapter })
