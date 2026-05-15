/* ============================================================
   MECULS — /api/create-order
   ------------------------------------------------------------
   STEP 1 of the secure payment flow.

   The browser calls this function with a product code (e.g.
   "cv-upgrade"). This function — running on Vercel's server,
   where the customer cannot see or tamper with it — creates a
   real Razorpay order for the correct, fixed price and returns
   the order id to the browser.

   Why this matters: the price is decided HERE, on the server,
   from a fixed list. The browser never gets to say "charge me
   ₹1 instead of ₹149" — it can only name a product.

   Secrets used (set in Vercel → Project → Settings →
   Environment Variables — NEVER in this file, NEVER in git):
     RAZORPAY_KEY_ID
     RAZORPAY_KEY_SECRET
   ============================================================ */

/* The ONLY source of truth for prices. Amounts are in paise
   (Razorpay's unit): ₹149 = 14900 paise. If you change a price,
   change it here — the browser cannot override it. */
const PRODUCTS = {
  /* Flow A — pay then submit a form (gated submit page) */
  "cv-upgrade":             { amount: 14900,   label: "MECULS — CV Upgrade" },
  "personality-profiling":  { amount: 949900,  label: "MECULS — Personality Profiling" },

  /* Flow B — pay then book a Cal.com session (no gate, lands on pay-success) */
  "single-coaching":        { amount: 144900,  label: "MECULS — Single Coaching Session" },
  "coaching-block":         { amount: 599900,  label: "MECULS — 4-Session Coaching Block" },
  "retainer":               { amount: 1199900, label: "MECULS — 3-Month Coaching Retainer" },

  "wellness-anxiety":       { amount: 99900,   label: "MECULS — Anxiety, Burnout & Emotional Weight" },
  "wellness-pattern":       { amount: 99900,   label: "MECULS — The Pattern That Keeps Coming Back" },
  "wellness-grief":         { amount: 99900,   label: "MECULS — Grief, Crisis & Relationship Loss" },
  "wellness-addiction":     { amount: 99900,   label: "MECULS — Breaking Free of an Addiction" },
  "wellness-parent":        { amount: 99900,   label: "MECULS — Parent Conversation" },
  "wellness-child":         { amount: 99900,   label: "MECULS — Child Session" },
  "wellness-meditation":    { amount: 14900,   label: "MECULS — Long-Held Pain Meditation" }
};

export default async function handler(req, res) {
  /* CORS: allow the live site to call this, answer the browser's
     preflight OPTIONS check. (vercel.json also sets these, but
     handling it here too makes the function self-contained.) */
  res.setHeader("Access-Control-Allow-Origin", "https://meculs.com");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  /* Only POST is allowed — a plain browser visit (GET) gets nothing. */
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const keyId     = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;

  if (!keyId || !keySecret) {
    console.error("create-order: Razorpay env vars are missing");
    res.status(500).json({ error: "Payment system not configured" });
    return;
  }

  /* req.body may arrive as a string on some setups — parse defensively. */
  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const productCode = (body && body.product) ? String(body.product) : "";

  const product = PRODUCTS[productCode];
  if (!product) {
    res.status(400).json({ error: "Unknown product" });
    return;
  }

  /* Build the Razorpay order. notes.product is stored ON the order
     at Razorpay's side, so later we can confirm what was paid for. */
  const orderPayload = {
    amount: product.amount,
    currency: "INR",
    receipt: "meculs_" + productCode + "_" + Date.now(),
    notes: { product: productCode, label: product.label }
  };

  /* Razorpay's REST API is called with HTTP Basic auth:
     username = key id, password = key secret. */
  const auth = Buffer.from(keyId + ":" + keySecret).toString("base64");

  try {
    const rzpRes = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        "Authorization": "Basic " + auth,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(orderPayload)
    });

    const order = await rzpRes.json();

    if (!rzpRes.ok) {
      console.error("create-order: Razorpay rejected order", order);
      res.status(502).json({ error: "Could not create payment order" });
      return;
    }

    /* Send the browser ONLY what Razorpay Checkout needs.
       The key secret never leaves the server. */
    res.status(200).json({
      order_id: order.id,
      amount:   order.amount,
      currency: order.currency,
      key_id:   keyId,
      label:    product.label,
      product:  productCode
    });
  } catch (err) {
    console.error("create-order: network/exception", err);
    res.status(500).json({ error: "Payment system error" });
  }
}
