import type {AuthedRequest} from "../middleware/auth";

export default function parsePagination(req: AuthedRequest) {
    const pageRaw = req.query.page
    const limitRaw = req.query.limit

    const page = Math.max(1, Number(pageRaw ?? 1) || 1)
    const limit = Math.min(100, Math.max(1, Number(limitRaw ?? 50) || 50))

    const skip = (page - 1) * limit
    const take = limit

    return {
        page,
        limit,
        skip,
        take
    }
}
