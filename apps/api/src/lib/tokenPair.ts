import crypto from "crypto";

export default function generateTokenPair() {
    const raw = crypto.randomBytes(32).toString("base64url")
    const hash = crypto.createHash("sha256").update(raw).digest("hex")
    return { raw, hash }
}
