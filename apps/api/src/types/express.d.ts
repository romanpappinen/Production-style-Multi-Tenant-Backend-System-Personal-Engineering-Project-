import "express"

declare global {
    namespace Express {
        interface Request {
            requestId?: string
            auth?: {
                sub: string
                tid: string
                role: "admin" | "manager" | "user"
                gr: "none" | "superadmin"
            }
        }
    }
}
