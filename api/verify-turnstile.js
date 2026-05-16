/* ============================================================
   MECULS — /api/verify-turnstile
   ------------------------------------------------------------
   THE SPAM GATE for public forms.

   Before the browser writes a form submission to Supabase, it
   calls this function with the Turnstile token it received from
   the Cloudflare challenge widget. This function asks Cloudflare
   "is this a real human?" — using the SECRET key the customer
   cannot see.

   If Cloudflare says yes → we return { ok: true } and the form
   is allowed to write to Supabase.

   If Cloudflare says no → we return { ok: false } and the form
   refuses to write.

   Why server-side: the SITE key (public, in the HTML) just lets
   the widget render. The SECRET key (here only, never in HTML)
   is what proves the token is real. A bot can fake a token, but
   it cannot trick Cloudflare's API into validating it.

   Secret used (Vercel env var, never in git):
     TURNSTILE_SECRET_KEY
   ============================================================ */

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

  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  if (!secretKey) {
    console.error("verify-turnstile: TURNSTILE_SECRET_KEY missing");
    /* Fail closed — refuse the submission if we cannot verify. */
    res.status(500).json({ ok: false, reason: "not_configured" });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const token = body && body.turnstile_token;

  if (!token || typeof token !== "string") {
    res.status(200).json({ ok: false, reason: "no_token" });
    return;
  }

  /* Ask Cloudflare to verify the token. */
  try {
    const cfRes = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: secretKey,
          response: token
        })
      }
    );

    const cfData = await cfRes.json();

    if (!cfRes.ok || !cfData.success) {
      /* Cloudflare rejected the token — bot, expired, or tampered. */
      console.warn("verify-turnstile: cloudflare rejected", cfData);
      res.status(200).json({
        ok: false,
        reason: "challenge_failed",
        codes: cfData["error-codes"] || []
      });
      return;
    }

    /* Verified — the request is from a real human. */
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error("verify-turnstile: exception", err);
    /* Fail closed — if Cloudflare is unreachable, refuse the form. */
    res.status(502).json({ ok: false, reason: "verify_failed" });
  }
}
