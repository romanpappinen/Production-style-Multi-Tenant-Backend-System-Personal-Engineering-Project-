import type { NextFunction, Request, Response } from "express"

export function notFound(req: Request, res: Response) {
    res.status(404).json({ error: "Not found" })
}

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
    console.error(err)
    res.status(500).json({ error: "Internal server error" })
}
