const { createHmac, timingSafeEqual } = require("crypto");
const db = require("../config/db");

const SESSION_COOKIE = "student_session";
const SESSION_DURATION_SECONDS = 8 * 60 * 60;

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters.");
  }
  return secret;
}

function createSessionToken(userId) {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
  const payload = `${userId}.${expiresAt}`;
  const signature = createHmac("sha256", getSessionSecret())
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

function setSessionCookie(res, userId) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${createSessionToken(userId)}; Max-Age=${SESSION_DURATION_SECONDS}; Path=/; HttpOnly; SameSite=Lax${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secure}`
  );
}

function getSessionToken(req) {
  const cookies = (req.headers.cookie || "").split(";");
  const cookie = cookies.find((item) =>
    item.trim().startsWith(`${SESSION_COOKIE}=`)
  );
  return cookie ? cookie.trim().slice(SESSION_COOKIE.length + 1) : "";
}

function authenticate(req, res, next) {
  let secret;
  try {
    secret = getSessionSecret();
  } catch (error) {
    console.error("Authentication configuration error:", error.message);
    return res.status(500).json({ error: "Authentication is not configured." });
  }

  const [userId, expiration, signature, ...extra] = getSessionToken(req).split(".");
  if (
    extra.length ||
    !/^[1-9]\d*$/.test(userId || "") ||
    !/^\d+$/.test(expiration || "") ||
    !/^[a-f\d]{64}$/i.test(signature || "") ||
    Number(expiration) <= Math.floor(Date.now() / 1000)
  ) {
    return res.status(401).json({ error: "Sign in to continue." });
  }

  const payload = `${userId}.${expiration}`;
  const expectedSignature = createHmac("sha256", secret)
    .update(payload)
    .digest();
  const providedSignature = Buffer.from(signature, "hex");
  if (!timingSafeEqual(expectedSignature, providedSignature)) {
    return res.status(401).json({ error: "Sign in to continue." });
  }

  db.query(
    "SELECT id, name, email, role, approval_status FROM users WHERE id = ? LIMIT 1",
    [userId],
    (err, results) => {
      if (err) {
        console.error("Authentication database error:", err.message);
        return res.status(500).json({ error: "Unable to verify your account." });
      }

      if (!results[0]) {
        return res.status(401).json({ error: "Sign in to continue." });
      }

      if (results[0].approval_status !== "approved") {
        return res.status(403).json({
          error: "Your account is waiting for administrator approval."
        });
      }

      req.user = results[0];
      return next();
    }
  );
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Administrator access is required." });
  }
  return next();
}

module.exports = {
  authenticate,
  requireAdmin,
  createSessionToken,
  setSessionCookie,
  clearSessionCookie
};
