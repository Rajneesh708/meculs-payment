/* ============================================================
   MECULS — /api/verify-payment
   ------------------------------------------------------------
   STEP 2 of the secure payment flow — THE GATE.

   After the customer pays, Razorpay Checkout hands the browser
   three things: razorpay_order_id, razorpay_payment_id, and
   razorpay_signature.

   The browser sends those three here. This function — on the
   server, with the secret key — recomputes the signature and
   checks it matches. A correct signature is PROOF the payment
   is real and was not faked, because only someone holding the
   secret key could have produced it.

   If valid: we ALSO double-check with Razorpay's API that the
   payment is actually "captured" (money truly taken), then
   return a signed access token the submit page can trust.

   For products that lead to a Cal.com booking (coaching + 7
   wellness sessions), this function ALSO returns a separate,
   short-lived booking_token. The browser sends that token to
   /api/redeem-booking-token to receive the real Cal.com URL.
   The Cal.com URLs themselves are NEVER returned to the browser
   here — they live only in the server-side map below, and only
   in /api/redeem-booking-token.

   If invalid: the customer gets nothing. No token, no access.

   Secret used (Vercel env var, never in git):
     RAZORPAY_KEY_SECRET
     ACCESS_TOKEN_SECRET   (any long random string you choose)
   ============================================================ */

import crypto from "crypto";

/* ============================================================
   Products that route to a Cal.com booking after payment.
   This list lives on the server only. The browser never sees it.
   To add a new bookable product: add its product code here.
   ============================================================ */
const CAL_BOOKING_PRODUCTS = new Set([
  "single-coaching",
  "coaching-block",
  "retainer",
  "wellness-anxiety",
  "wellness-pattern",
  "wellness-grief",
  "wellness-addiction",
  "wellness-parent",
  "wellness-child",
  "wellness-meditation"
]);

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

  const keySecret   = process.env.RAZORPAY_KEY_SECRET;
  const keyId       = process.env.RAZORPAY_KEY_ID;
  const tokenSecret = process.env.ACCESS_TOKEN_SECRET;

  if (!keySecret || !keyId || !tokenSecret) {
    console.error("verify-payment: env vars missing");
    res.status(500).json({ error: "Payment system not configured" });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const orderId   = body && body.razorpay_order_id;
  const paymentId = body && body.razorpay_payment_id;
  const signature = body && body.razorpay_signature;

  if (!orderId || !paymentId || !signature) {
    res.status(400).json({ error: "Missing payment details" });
    return;
  }

  /* ---- Check 1: the signature ----
     Razorpay's rule: HMAC-SHA256 of "order_id|payment_id" using
     the key secret must equal the signature they sent. */
  const expected = crypto
    .createHmac("sha256", keySecret)
    .update(orderId + "|" + paymentId)
    .digest("hex");

  /* timingSafeEqual avoids a subtle timing attack on the compare. */
  const sigOk =
    expected.length === signature.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));

  if (!sigOk) {
    console.warn("verify-payment: signature mismatch", { orderId, paymentId });
    res.status(400).json({ error: "Payment could not be verified" });
    return;
  }

  /* ---- Check 2: ask Razorpay directly that money was captured ----
     The signature proves the data is authentic; this proves the
     payment actually went through (not just created/attempted). */
  const auth = Buffer.from(keyId + ":" + keySecret).toString("base64");
  let productCode = "";
  try {
    const payRes = await fetch(
      "https://api.razorpay.com/v1/payments/" + encodeURIComponent(paymentId),
      { headers: { "Authorization": "Basic " + auth } }
    );
    const payment = await payRes.json();

    if (!payRes.ok) {
      console.error("verify-payment: could not fetch payment", payment);
      res.status(502).json({ error: "Payment could not be verified" });
      return;
    }

    /* "captured" = money actually taken. "authorized" alone is not
       enough. Anything else → reject. */
    if (payment.status !== "captured") {
      console.warn("verify-payment: payment not captured", {
        paymentId, status: payment.status
      });
      res.status(400).json({ error: "Payment not completed" });
      return;
    }

    /* The product we put in notes at order-creation time. */
    productCode = (payment.notes && payment.notes.product) || "";
  } catch (err) {
    console.error("verify-payment: exception during payment fetch", err);
    res.status(500).json({ error: "Payment system error" });
    return;
  }

  const now = Date.now();

  /* ---- Issue a short-lived access token ----
     This token is what the submit page checks. It is signed with
     ACCESS_TOKEN_SECRET, so the submit page (via this same server)
     can later confirm it is genuine and unexpired. The customer
     cannot forge one — they don't have the secret. */
  const tokenPayload = {
    payment_id: paymentId,
    order_id:   orderId,
    product:    productCode,
    issued_at:  now,
    /* valid for 2 hours — long enough to fill the form, short
       enough that a leaked URL is not useful for long. */
    expires_at: now + 2 * 60 * 60 * 1000
  };

  const payloadB64 = Buffer.from(JSON.stringify(tokenPayload)).toString("base64url");
  const tokenSig = crypto
    .createHmac("sha256", tokenSecret)
    .update(payloadB64)
    .digest("base64url");
  const accessToken = payloadB64 + "." + tokenSig;

  /* ---- Issue a booking token (for Cal.com products only) ----
     Separate from the access token because:
       - shorter expiry (30 minutes vs 2 hours)
       - serves a different gate (book.html, not the submit pages)
       - keeps the two concerns cleanly separated

     The booking token contains ONLY the product code + expiry.
     It does NOT contain the Cal.com URL. The browser sends this
     token to /api/redeem-booking-token, which looks up the URL
     from its own server-side map and returns it.

     The customer cannot forge a token — they don't have the
     tokenSecret. They cannot use a token for a different product
     — the product code is signed in. They cannot reuse an old
     token — it expires in 30 minutes. */
  let bookingToken = null;
  if (productCode && CAL_BOOKING_PRODUCTS.has(productCode)) {
    const bookingPayload = {
      product:    productCode,
      payment_id: paymentId,
      issued_at:  now,
      expires_at: now + 30 * 60 * 1000   /* 30 minutes */
    };
    const bookingPayloadB64 = Buffer.from(JSON.stringify(bookingPayload)).toString("base64url");
    const bookingSig = crypto
      .createHmac("sha256", tokenSecret)
      .update(bookingPayloadB64)
      .digest("base64url");
    bookingToken = bookingPayloadB64 + "." + bookingSig;
  }

  res.status(200).json({
    verified: true,
    access_token: accessToken,
    booking_token: bookingToken,   /* null for non-Cal.com products */
    product: productCode,
    payment_id: paymentId
  });
}
