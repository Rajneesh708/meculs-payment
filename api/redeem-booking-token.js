/* ============================================================
   MECULS — /api/redeem-booking-token
   ------------------------------------------------------------
   THE BOOKING GATE.

   After payment, the customer's browser arrives at book.html
   with a booking_token in the URL. book.html sends that token
   here. This function verifies the token's signature, checks
   it has not expired, and — only if everything checks out —
   returns the correct Cal.com URL for the product the token
   was issued for.

   The Cal.com URLs live ONLY in the map below. They never
   appear in HTML, JavaScript, or any browser-visible response
   until the moment the redemption succeeds.

   If invalid: the customer gets nothing. No URL, no booking.

   Secret used (Vercel env var, never in git):
     ACCESS_TOKEN_SECRET   (same secret used by verify-payment)
   ============================================================ */

import crypto from "crypto";

/* ============================================================
   The Cal.com URL map — the WHOLE point of this gate.
   These URLs were previously visible in pay-success.html. Moving
   them here means a page-source attacker can no longer read them.

   To change a Cal.com URL: change it here. Redeploy. Done.
   ============================================================ */
const CAL_URLS = {
  "single-coaching":     "https://cal.eu/meculs-founder-rajneesh-jain/single-coaching",
  "coaching-block":      "https://cal.eu/meculs-founder-rajneesh-jain/coaching-block",
  "retainer":            "https://cal.eu/meculs-founder-rajneesh-jain/retainer-session",
  "wellness-anxiety":    "https://cal.eu/meculs-founder-rajneesh-jain/wellness-anxiety",
  "wellness-pattern":    "https://cal.eu/meculs-founder-rajneesh-jain/wellness-pattern",
  "wellness-grief":      "https://cal.eu/meculs-founder-rajneesh-jain/wellness-grief",
  "wellness-addiction":  "https://cal.eu/meculs-founder-rajneesh-jain/wellness-addiction",
  "wellness-parent":     "https://cal.eu/meculs-founder-rajneesh-jain/wellness-parent",
  "wellness-child":      "https://cal.eu/meculs-founder-rajneesh-jain/wellness-child",
  "wellness-meditation": "https://cal.eu/meculs-founder-rajneesh-jain/wellness-meditation"
};

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
    console.error("redeem-booking-token: ACCESS_TOKEN_SECRET missing");
    res.status(500).json({ error: "Not configured" });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const token = body && body.booking_token;

  if (!token || typeof token !== "string" || token.indexOf(".") === -1) {
    res.status(200).json({ ok: false, reason: "no_token" });
    return;
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    res.status(200).json({ ok: false, reason: "bad_format" });
    return;
  }
  const payloadB64 = parts[0];
  const givenSig   = parts[1];

  /* Recompute the signature over the payload and compare. */
  const expectedSig = crypto
    .createHmac("sha256", tokenSecret)
    .update(payloadB64)
    .digest("base64url");

  /* Lengths must match before timingSafeEqual or it throws. */
  if (expectedSig.length !== givenSig.length) {
    res.status(200).json({ ok: false, reason: "bad_signature" });
    return;
  }

  const sigOk = crypto.timingSafeEqual(
    Buffer.from(expectedSig),
    Buffer.from(givenSig)
  );

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

  /* Look up the Cal.com URL for the signed-in product. */
  const calUrl = CAL_URLS[payload.product];
  if (!calUrl) {
    /* This should not happen — verify-payment.js only issues booking
       tokens for products in its CAL_BOOKING_PRODUCTS set, and that
       set must stay in sync with this CAL_URLS map. If you see this
       error, the two lists drifted apart. */
    console.error("redeem-booking-token: no Cal URL for product", payload.product);
    res.status(200).json({ ok: false, reason: "unknown_product" });
    return;
  }

  res.status(200).json({
    ok: true,
    cal_url: calUrl,
    product: payload.product
  });
}
