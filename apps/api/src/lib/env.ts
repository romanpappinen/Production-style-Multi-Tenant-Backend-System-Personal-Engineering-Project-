import dotenv from "dotenv"
dotenv.config({ path: "../../.env" })

function must(name: string): string {
    const v = process.env[name]
    if (!v || v.trim().length === 0) throw new Error(`Missing env: ${name}`)
    return v
}
console.log("DATABASE_URL:", process.env.DATABASE_URL)
export const env = {
    port: Number(process.env.API_PORT ?? "3001"),
    corsOrigin: process.env.CORS_ORIGIN ?? "http://localhost:5173",

    databaseUrl: must("DATABASE_URL"),

    jwtAccessSecret: must("JWT_ACCESS_SECRET"),
    refreshPepper: must("REFRESH_TOKEN_PEPPER"),
    refreshDays: Number(process.env.REFRESH_TOKEN_DAYS ?? "30"),
}
