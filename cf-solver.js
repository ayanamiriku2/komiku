// ============================================================
// CLOUDFLARE CHALLENGE SOLVER — puppeteer-extra + stealth
// Menggunakan anti-detection flags dari botasaurus untuk bypass Cloudflare
// ============================================================

const puppeteerExtra = require("puppeteer-extra");
const StealthPlugin = require("puppeteer-extra-plugin-stealth");
puppeteerExtra.use(StealthPlugin());

// --- Cloudflare cookie storage ---
const cfStore = {
  cookies: "",        // full cookie string
  cookieMap: {},      // name → value map
  userAgent: "",
  lastSolved: 0,
  solving: false,
  solvedProxy: null,  // proxy URL used during solve (cookies bound to that IP)
  // --- Cooldown / backoff tracking ---
  lastFailure: 0,           // timestamp of last failed solve
  consecutiveFailures: 0,   // how many solves have failed in a row
  cooldownUntil: 0,         // don't attempt solve until this timestamp
};

const CF_SOLVE_INTERVAL = 12 * 60 * 1000;  // refresh every 12 minutes
const CF_SOLVE_TIMEOUT  = 50000;            // 50s max to solve challenge
const CF_MIN_COOLDOWN   = 2 * 60 * 1000;   // 2 minutes min cooldown after failure
const CF_MAX_COOLDOWN   = 30 * 60 * 1000;  // 30 minutes max cooldown

// Anti-detection Chrome flags (from botasaurus page.ts)
const CHROME_FLAGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--start-maximized",
  "--remote-allow-origins=*",
  "--no-first-run",
  "--no-service-autorun",
  "--homepage=about:blank",
  "--no-pings",
  "--password-store=basic",
  "--disable-infobars",
  "--disable-breakpad",
  "--disable-session-crashed-bubble",
  "--disable-features=IsolateOrigins,site-per-process",
  "--disable-search-engine-choice-screen",
  "--disable-blink-features=AutomationControlled",
  "--window-size=1920,1080",
];

/**
 * Solve Cloudflare challenge for a target URL.
 * Optionally route through a proxy (cookies are IP-bound).
 * @param {string} targetUrl - URL to solve (e.g. https://img.komiku.org/)
 * @param {string|null} proxyUrl - Optional proxy in format http://user:pass@host:port
 * @returns {object|null} - { cookies, userAgent } or null on failure
 */
async function solveCfChallenge(targetUrl, proxyUrl = null) {
  // Check cooldown — don't retry if we recently failed
  if (Date.now() < cfStore.cooldownUntil) {
    const remaining = Math.round((cfStore.cooldownUntil - Date.now()) / 1000);
    console.log(`⏳ CF solve on cooldown, ${remaining}s remaining (${cfStore.consecutiveFailures} consecutive failures)`);
    return cfStore.cookies ? cfStore : null;
  }

  // Prevent concurrent solves
  if (cfStore.solving) {
    let waited = 0;
    while (cfStore.solving && waited < 60000) {
      await sleep(1000);
      waited += 1000;
    }
    return cfStore.cookies ? cfStore : null;
  }

  cfStore.solving = true;
  let browser;

  try {
    const args = [...CHROME_FLAGS];
    if (proxyUrl) {
      const parsed = new URL(proxyUrl);
      args.push(`--proxy-server=${parsed.hostname}:${parsed.port}`);
    }

    console.log(`🔓 Launching browser to solve Cloudflare for ${targetUrl}...`);

    browser = await puppeteerExtra.launch({
      headless: "new",
      args,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      protocolTimeout: CF_SOLVE_TIMEOUT + 10000,
    });

    const page = await browser.newPage();

    // Proxy authentication
    if (proxyUrl) {
      const parsed = new URL(proxyUrl);
      if (parsed.username) {
        await page.authenticate({
          username: decodeURIComponent(parsed.username),
          password: decodeURIComponent(parsed.password),
        });
      }
    }

    await page.setViewport({ width: 1920, height: 1080 });

    // Navigate to target
    await page.goto(targetUrl, {
      waitUntil: "domcontentloaded",
      timeout: CF_SOLVE_TIMEOUT,
    });

    // Wait for Cloudflare challenge to resolve (up to 40 seconds, polling every 2s)
    let solved = false;
    for (let i = 0; i < 20; i++) {
      const title = await page.title().catch(() => "");
      const url = page.url();

      // Challenge pages have these titles
      const isChallenge =
        title.includes("Just a moment") ||
        title.includes("Checking") ||
        title.includes("Attention Required") ||
        title.includes("Access denied") ||
        url.includes("challenges.cloudflare.com");

      if (!isChallenge) {
        solved = true;
        break;
      }

      // Try clicking Turnstile checkbox if present
      try {
        const frames = page.frames();
        for (const frame of frames) {
          if (frame.url().includes("challenges.cloudflare.com")) {
            await frame.click('input[type="checkbox"]').catch(() => {});
            await frame.click(".cb-lb").catch(() => {});
          }
        }
      } catch (_) {}

      await sleep(2000);
    }

    if (!solved) {
      const title = await page.title().catch(() => "unknown");
      console.warn(`⚠️ CF challenge not solved in ${CF_SOLVE_TIMEOUT / 1000}s (title: "${title}")`);
      return null;
    }

    // Extra wait for cookies to settle
    await sleep(1000);

    // Extract all cookies
    const cookies = await page.cookies();
    const cfSpecific = cookies.filter(
      (c) => c.name.includes("cf_") || c.name.includes("__cf") || c.name === "csrftoken"
    );

    const cookieStr = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    const cookieMap = {};
    for (const c of cookies) cookieMap[c.name] = c.value;

    const ua = await page.evaluate(() => navigator.userAgent);

    cfStore.cookies = cookieStr;
    cfStore.cookieMap = cookieMap;
    cfStore.userAgent = ua;
    cfStore.lastSolved = Date.now();
    cfStore.solvedProxy = proxyUrl;

    console.log(`✅ Cloudflare solved! ${cookies.length} cookies (${cfSpecific.length} CF-specific)`);
    if (cfSpecific.length > 0) {
      console.log(`   CF cookies: ${cfSpecific.map((c) => c.name).join(", ")}`);
    }

    // Reset failure tracking on success
    cfStore.consecutiveFailures = 0;
    cfStore.lastFailure = 0;
    cfStore.cooldownUntil = 0;

    return cfStore;
  } catch (err) {
    console.error(`❌ CF solve failed: ${err.message}`);

    // Track failure and set exponential cooldown
    cfStore.consecutiveFailures++;
    cfStore.lastFailure = Date.now();
    const backoff = Math.min(
      CF_MIN_COOLDOWN * Math.pow(2, cfStore.consecutiveFailures - 1),
      CF_MAX_COOLDOWN
    );
    cfStore.cooldownUntil = Date.now() + backoff;
    console.log(`⏳ CF solve cooldown set to ${Math.round(backoff / 1000)}s after ${cfStore.consecutiveFailures} failures`);

    return null;
  } finally {
    if (browser) {
      try { await browser.close(); } catch (_) {}
    }
    cfStore.solving = false;
  }
}

/** Get stored CF cookie string */
function getCfCookies() {
  return cfStore.cookies;
}

/** Get the User-Agent used during CF solve */
function getCfUserAgent() {
  return cfStore.userAgent;
}

/** Check if cookies need refresh */
function needsCfRefresh() {
  if (!cfStore.lastSolved) return true;
  return Date.now() - cfStore.lastSolved > CF_SOLVE_INTERVAL;
}

/** Get the proxy used during solve (needed for subsequent requests) */
function getCfProxy() {
  return cfStore.solvedProxy;
}

/** Invalidate cookies to force re-solve (respects cooldown) */
function invalidateCfCookies() {
  // Don't spam invalidations — if already invalid or on cooldown, skip
  if (!cfStore.cookies && !cfStore.lastSolved) return;
  cfStore.cookies = "";
  cfStore.cookieMap = {};
  cfStore.lastSolved = 0;
  console.log("🔄 CF cookies invalidated, will re-solve on next request");
}

/** Check if CF cookies are currently available */
function hasCfCookies() {
  return !!cfStore.cookies && !!cfStore.lastSolved;
}

/** Check if CF solver is on cooldown (no point retrying) */
function isCfOnCooldown() {
  return Date.now() < cfStore.cooldownUntil;
}

/** Get cooldown remaining in seconds */
function getCfCooldownRemaining() {
  if (Date.now() >= cfStore.cooldownUntil) return 0;
  return Math.round((cfStore.cooldownUntil - Date.now()) / 1000);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = {
  solveCfChallenge,
  getCfCookies,
  getCfUserAgent,
  needsCfRefresh,
  getCfProxy,
  invalidateCfCookies,
  hasCfCookies,
  isCfOnCooldown,
  getCfCooldownRemaining,
};
