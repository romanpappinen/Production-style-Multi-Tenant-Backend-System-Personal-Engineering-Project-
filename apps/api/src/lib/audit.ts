import { prisma } from "./prisma.js"
import type { AuditAction } from "@prisma/client"

export async function writeAudit(params: {
    tenantId: string
    userId?: string | null
    action: AuditAction
    meta?: unknown
    requestId?: string | null
}) {
    await prisma.auditLog.create({
        data: {
            tenantId: params.tenantId,
            userId: params.userId ?? null,
            action: params.action,
            meta: params.meta as any,
            requestId: params.requestId ?? null,
        },
    })
}
