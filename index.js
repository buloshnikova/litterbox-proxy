import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());

const {
  TUYA_BASE_URL,
  TUYA_ACCESS_KEY,
  TUYA_SECRET_KEY,
  DEVICE_ID,
  PROXY_API_KEY,
  PORT = 3000,
} = process.env;

// ---- Basic validation (fail fast)
for (const k of ["TUYA_BASE_URL", "TUYA_ACCESS_KEY", "TUYA_SECRET_KEY", "DEVICE_ID", "PROXY_API_KEY"]) {
  if (!process.env[k]) {
    console.error(`Missing required env var: ${k}`);
    process.exit(1);
  }
}

// ---- Simple API key auth (protect your device!)
function requireApiKey(req, res, next) {
  const key = req.header("x-api-key");
  if (!key || key !== PROXY_API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function hmacSha256Hex(key, str) {
  return crypto.createHmac("sha256", key).update(str).digest("hex").toUpperCase();
}

/**
 * Tuya OpenAPI signing (works for v2.0 endpoints).
 * Notes:
 * - Includes body hash in stringToSign when body exists
 * - access_token is included when available
 */
function signRequest({ method, path, query = "", body = "", t, accessToken }) {
  const url = `${path}${query ? `?${query}` : ""}`;
  const bodyStr = body ? JSON.stringify(body) : "";
  const contentSha = sha256Hex(bodyStr);

  const stringToSign = [
    method.toUpperCase(),
    contentSha,
    "", // headers to sign (kept empty)
    url,
  ].join("\n");

  const signStr = accessToken
    ? `${TUYA_ACCESS_KEY}${accessToken}${t}${stringToSign}`
    : `${TUYA_ACCESS_KEY}${t}${stringToSign}`;

  return hmacSha256Hex(TUYA_SECRET_KEY, signStr);
}

let cachedToken = null;
let tokenExpireAt = 0;

async function tuyaFetch({ method, path, query, body, accessToken }) {
  const t = Date.now().toString();
  const sign = signRequest({ method, path, query, body, t, accessToken });

  const url = `${TUYA_BASE_URL}${path}${query ? `?${query}` : ""}`;

  const headers = {
    client_id: TUYA_ACCESS_KEY,
    sign_method: "HMAC-SHA256",
    t,
    sign,
    "Content-Type": "application/json",
  };
  if (accessToken) headers["access_token"] = accessToken;

  const resp = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const json = await resp.json().catch(() => ({}));
  return json;
}

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpireAt - 60_000) return cachedToken; // refresh 1 min early

  const r = await tuyaFetch({ method: "GET", path: "/v1.0/token", query: "grant_type=1" });
  if (!r?.success) throw new Error(`${r?.code || "TOKEN"}: ${r?.msg || "Failed to get token"}`);

  cachedToken = r.result.access_token;
  tokenExpireAt = now + r.result.expire_time * 1000;
  return cachedToken;
}

// ---- Tuya “issue properties” helper (this is what worked for you)
async function issueProperties(propsObj) {
  const accessToken = await getAccessToken();
  const properties = JSON.stringify(propsObj); // must be a STRING for this endpoint

  const r = await tuyaFetch({
    method: "POST",
    path: `/v2.0/cloud/thing/${DEVICE_ID}/shadow/properties/issue`,
    body: { properties },
    accessToken,
  });

  if (!r?.success) throw new Error(`${r?.code || "ISSUE"}: ${r?.msg || "Tuya issue failed"}`);
  return r.result;
}

// ---- Read current shadow properties (for safety checks)
async function getShadowProperties() {
  const accessToken = await getAccessToken();
  const r = await tuyaFetch({
    method: "GET",
    path: `/v2.0/cloud/thing/${DEVICE_ID}/shadow/properties`,
    accessToken,
  });
  if (!r?.success) throw new Error(`${r?.code || "STATUS"}: ${r?.msg || "Status failed"}`);
  return r.result;
}

// Tuya returns different shapes depending on endpoint/version.
// This extracts a DP value from common Tuya response shapes.
function extractDpValue(shadowResult, code) {
  // Most commonly: shadowResult.properties is an array of {code, value, ...}
  const props = shadowResult?.properties ?? shadowResult?.result?.properties ?? shadowResult;

  if (Array.isArray(props)) {
    const item = props.find((p) => p.code === code);
    return item?.value;
  }

  // Sometimes: object map { dpCode: value }
  if (props && typeof props === "object") {
    return props[code];
  }

  return undefined;
}

// ---- Routes
app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/litterbox/deodorization", requireApiKey, async (req, res) => {
  try {
    const { on } = req.body ?? {};
    if (typeof on !== "boolean") return res.status(400).json({ error: "`on` must be boolean" });

    const result = await issueProperties({ deodorization: on });
    res.json({ success: true, result });
  } catch (e) {
    res.status(500).json({ success: false, error: String(e.message || e) });
  }
});

// Original “unsafe” clean (kept for manual testing)
app.post("/litterbox/clean", requireApiKey, async (req, res) => {
  try {
    const { pulseMs = 0 } = req.body ?? {};

    await issueProperties({ Clean: true });

    if (typeof pulseMs === "number" && pulseMs > 0) {
      setTimeout(() => {
        issueProperties({ Clean: false }).catch(() => {});
      }, Math.min(pulseMs, 15000));
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: String(e.message || e) });
  }
});

// SAFE clean: refuses to clean if cat is detected or bin is full (or fault)
app.post("/litterbox/clean-safe", requireApiKey, async (req, res) => {
  try {
    const { pulseMs = 3000, allowIfCatDetected = false, allowIfTrashFull = false } = req.body ?? {};

    const shadow = await getShadowProperties();

    const monitoring = extractDpValue(shadow, "monitoring"); // cat detected (bool)
    const trashFull = extractDpValue(shadow, "trash_status"); // bin full (bool)
    const fault = extractDpValue(shadow, "fault"); // bitmap / may be number

    // Safety: don't clean while cat is inside
    if (!allowIfCatDetected && monitoring === true) {
      return res.status(409).json({
        success: false,
        blocked: true,
        reason: "CAT_DETECTED",
        precheck: { monitoring, trashFull, fault },
      });
    }

    // Safety: optional block if trash bin is full
    if (!allowIfTrashFull && trashFull === true) {
      return res.status(409).json({
        success: false,
        blocked: true,
        reason: "TRASH_BIN_FULL",
        precheck: { monitoring, trashFull, fault },
      });
    }

    // Safety: block if fault indicates problem (conservative)
    // If fault is a number/bitmap, non-zero usually means fault(s) present.
    if (typeof fault === "number" && fault !== 0) {
      return res.status(409).json({
        success: false,
        blocked: true,
        reason: "DEVICE_FAULT",
        precheck: { monitoring, trashFull, fault },
      });
    }

    // Trigger cleaning
    await issueProperties({ Clean: true });

    // Many devices behave like a trigger. Pulse-reset is safest.
    if (typeof pulseMs === "number" && pulseMs > 0) {
      setTimeout(() => {
        issueProperties({ Clean: false }).catch(() => {});
      }, Math.min(pulseMs, 15000));
    }

    return res.json({
      success: true,
      blocked: false,
      usedSafetyChecks: true,
      precheck: { monitoring, trashFull, fault },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: String(e.message || e) });
  }
});

app.get("/litterbox/status", requireApiKey, async (req, res) => {
  try {
    const data = await getShadowProperties();

    // Also return a small “friendly” summary for agent logic
    const monitoring = extractDpValue(data, "monitoring");
    const trashFull = extractDpValue(data, "trash_status");
    const fault = extractDpValue(data, "fault");

    res.json({
      success: true,
      data,
      summary: { monitoring, trashFull, fault },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: String(e.message || e) });
  }
});

// Bind 0.0.0.0 so it works for tunnels / LAN access
app.listen(PORT, "0.0.0.0", () => console.log(`Proxy running: http://localhost:${PORT}`));