import "dotenv/config"
import { PrismaClient, TenantUserRole } from "@prisma/client"
import { PrismaPg } from "@prisma/adapter-pg"
import * as bcrypt from "bcryptjs"

const adapter = new PrismaPg({
    connectionString: process.env.DATABASE_URL!,
})

const prisma = new PrismaClient({ adapter })

async function main() {
    const tenantName = "Demo Tenant"
    const adminEmail = "admin@demo.local"
    const adminPassword = "Admin123!" // dev only; will be replaced later via env
    const adminName = "Demo Admin"

    const tenant = await prisma.tenant.create({
        data: { name: tenantName },
    })

    const passwordHash = await bcrypt.hash(adminPassword, 12)

    const user = await prisma.user.create({
        data: {
            email: adminEmail,
            passwordHash,
            name: adminName,
            tenants: {
                create: {
                    tenantId: tenant.id,
                    role: TenantUserRole.admin,
                },
            },
        },
        include: { tenants: true },
    })

    console.log("Seed complete ✅")
    console.log({
        tenantId: tenant.id,
        adminUserId: user.id,
        adminEmail,
        adminPassword,
    })
}

main()
    .catch((e) => {
        console.error("Seed failed ❌", e)
        process.exit(1)
    })
    .finally(async () => {
        await prisma.$disconnect()
    })
