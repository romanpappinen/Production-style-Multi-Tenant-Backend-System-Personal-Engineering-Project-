import express from "express"
import cookieParser from "cookie-parser"
import cors from "cors"
import helmet from "helmet"
import { env } from "./lib/env"
import { notFound, errorHandler } from "./middleware/error"

export function createApp() {
    const app = express()

    app.use(helmet())
    app.use(cors({ origin: env.corsOrigin, credentials: true }))
    app.use(express.json({ limit: "1mb" }))
    app.use(cookieParser())

    app.get("/health", (_req, res) => res.json({ ok: true }))


    app.use(notFound)
    app.use(errorHandler)

    return app
}
