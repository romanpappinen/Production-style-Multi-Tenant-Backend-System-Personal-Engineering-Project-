import express from "express"
import cookieParser from "cookie-parser"
import {requestContext} from "./middleware/requestContext";
import cors from "cors"
import helmet from "helmet"
import { authRouter } from "./routes/auth"
import { meRouter } from "./routes/me"
import { productsRouter } from "./routes/products"
import { ordersRouter } from "./routes/orders"
import { adminTenantsRouter } from "./routes/adminTenants"
import { env } from "./lib/env"
import { notFound, errorHandler } from "./middleware/error"

export function createApp() {
    const app = express()

    app.use(requestContext)
    app.use(helmet())
    app.use(cors({ origin: env.corsOrigin, credentials: true }))
    app.use(express.json({ limit: "1mb" }))
    app.use(cookieParser())
    app.set("trust proxy", 1)

    app.get("/health", (_req, res) => res.json({ ok: true }))

    app.use("/auth", authRouter)
    app.use("/me", meRouter)
    app.use("/products", productsRouter)
    app.use("/orders", ordersRouter)
    app.use("/admin/tenants", adminTenantsRouter)

    app.use(notFound)
    app.use(errorHandler)

    return app
}
