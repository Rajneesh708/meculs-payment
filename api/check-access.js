/* ============================================================
   MECULS — /api/check-access
   ------------------------------------------------------------
   THE DOOR on the submit pages.

   cv-upgrade-submit.html and personality-profiling-submit.html
   call this on page load, sending the access token they were
   given after payment.

   This function re-checks the token's signature with the same
   secret. If the token is genuine, unexpired, and for the right
   product → it answers "ok". The page then shows the form.

   If the token is missing, forged, expired, or for the wrong
   product → it answers "denied". The page shows a polite
   "please pay first" screen instead of the form.

   Secret used (Vercel env var):
     ACCESS_TOKEN_SECRET   (same value as in verify-payment)
   ============================================================ */

import crypto from "crypto";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "https://meculs.com");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const tokenSecret = process.env.ACCESS_TOKEN_SECRET;
  if (!tokenSecret) {
    console.error("check-access: ACCESS_TOKEN_SECRET missing");
    res.status(500).json({ error: "Not configured" });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const token          = body && body.access_token;
  const expectProduct  = body && body.product ? String(body.product) : "";

  if (!token || token.indexOf(".") === -1) {
    res.status(200).json({ ok: false, reason: "no_token" });
    return;
  }

  const parts = token.split(".");
  const payloadB64 = parts[0];
  const givenSig   = parts[1];

  /* Recompute the signature over the payload and compare. */
  const expectedSig = crypto
    .createHmac("sha256", tokenSecret)
    .update(payloadB64)
    .digest("base64url");

  const sigOk =
    expectedSig.length === givenSig.length &&
    crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(givenSig));

  if (!sigOk) {
    res.status(200).json({ ok: false, reason: "bad_signature" });
    return;
  }

  /* Signature is good — read the payload. */
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    res.status(200).json({ ok: false, reason: "bad_payload" });
    return;
  }

  if (!payload.expires_at || Date.now() > payload.expires_at) {
    res.status(200).json({ ok: false, reason: "expired" });
    return;
  }

  /* If the page told us which product it is, make sure the token
     was issued for that same product. Stops a CV-upgrade token
     being reused on the profiling page. */
  if (expectProduct && payload.product && payload.product !== expectProduct) {
    res.status(200).json({ ok: false, reason: "wrong_product" });
    return;
  }

  res.status(200).json({
    ok: true,
    payment_id: payload.payment_id,
    order_id:   payload.order_id,
    product:    payload.product
  });
}
