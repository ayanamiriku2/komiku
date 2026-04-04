// ============================================================
// KOMIKU MIRROR PROXY — Node.js/Express
// Deploy ke: Railway, Render, VPS, Easypanel, Docker
// Anti-Duplicate Content untuk Google Search Console
// ============================================================

const express = require("express");
const compression = require("compression");
const fetch = require("node-fetch");
const crypto = require("crypto");

const app = express();
app.use(compression());
app.set("trust proxy", true);

// ============================================================
// KONFIGURASI — Sesuaikan sebelum deploy
// ============================================================
const ORIGIN_HOST = process.env.ORIGIN_HOST || "komiku.org";
const MIRROR_HOST = process.env.MIRROR_HOST || "komiku.io";
const SITE_NAME = process.env.SITE_NAME || "Komiku";
const SITE_TAGLINE = process.env.SITE_TAGLINE || "Baca Komik Manga Manhwa Manhua Bahasa Indonesia";
const SITE_DESCRIPTION = process.env.SITE_DESCRIPTION || "Komiku.io — Situs baca komik manga, manhwa, dan manhua sub Indonesia terlengkap dan terupdate. Gratis tanpa iklan.";
const PORT = parseInt(process.env.PORT, 10) || 3000;

// ============================================================
// HELPER
// ============================================================
function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getMirrorHost(req) {
  if (MIRROR_HOST) return MIRROR_HOST;
  return req.get("host") || req.hostname;
}

function buildOriginRegex() {
  return new RegExp(`https?://(www\\.)?${escapeRegex(ORIGIN_HOST)}`, "gi");
}

// Buat unique page signature untuk anti-duplicate
function uniquePageId(pathname) {
  return crypto
    .createHash("md5")
    .update(SITE_NAME + pathname)
    .digest("hex")
    .slice(0, 8);
}

// ============================================================
// MIDDLEWARE — SECURITY & SEO HEADERS
// ============================================================
app.use((req, res, next) => {
  // Hapus header yang mengekspos origin
  res.removeHeader("x-powered-by");
  res.removeHeader("server");

  // Security headers
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "SAMEORIGIN");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

  // Force HTTPS di production
  if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] === "http") {
    return res.redirect(301, `https://${req.get("host")}${req.originalUrl}`);
  }

  next();
});

// ============================================================
// HEALTH CHECK ENDPOINT (untuk Railway)
// ============================================================
app.get("/healthz", (req, res) => {
  res.status(200).json({ status: "ok", timestamp: Date.now() });
});

// ============================================================
// 0. CUSTOM ROBOTS.TXT
// ============================================================
app.get("/robots.txt", (req, res) => {
  const mirrorHost = getMirrorHost(req);
  res.type("text/plain")
    .set("Cache-Control", "public, max-age=86400")
    .send(
    `User-agent: *
Allow: /
Disallow: /wp-admin/
Disallow: /wp-login.php
Disallow: /wp-includes/
Disallow: /wp-content/plugins/
Disallow: /*?s=
Disallow: /*?p=
Disallow: /tag/
Disallow: /feed/
Disallow: /trackback/
Disallow: /xmlrpc.php
Disallow: /healthz

User-agent: Googlebot
Allow: /
Allow: /manga/
Allow: /manhua/
Allow: /manhwa/

Sitemap: https://${mirrorHost}/sitemap.xml
Sitemap: https://${mirrorHost}/sitemap-index.xml

Host: https://${mirrorHost}`
  );
});

// ============================================================
// 0a. CUSTOM ADS.TXT (opsional, tambahkan konten jika diperlukan)
// ============================================================
app.get("/ads.txt", (req, res) => {
  res.type("text/plain")
    .set("Cache-Control", "public, max-age=86400")
    .send("");
});

// ============================================================
// 0b. CUSTOM SITEMAP PROXY (rewrite origin → mirror)
// ============================================================
// Helper: fetch sitemap XML with manual redirect handling to avoid loops
async function fetchSitemapXml(urlStr, maxRedirects = 5) {
  let currentUrl = urlStr;
  for (let i = 0; i < maxRedirects; i++) {
    const parsedUrl = new URL(currentUrl);
    const resp = await fetch(currentUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        Host: parsedUrl.hostname,
        Accept: "text/xml,application/xml,*/*",
      },
      redirect: "manual",
      timeout: 15000,
    });
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const location = resp.headers.get("location");
      if (!location) throw new Error("Redirect without location header");
      // Resolve relative redirects
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }
    return resp;
  }
  throw new Error(`Too many redirects for: ${urlStr}`);
}

app.get(["/sitemap.xml", "/sitemap-index.xml", "/sitemap*.xml", "/wp-sitemap*.xml"], async (req, res) => {
  const mirrorHost = getMirrorHost(req);
  try {
    // Coba fetch dari origin utama, lalu fallback ke secure.komikid.org
    const originUrls = [
      `https://${ORIGIN_HOST}${req.path}`,
      `https://secure.komikid.org${req.path}`,
    ];

    let xml = null;
    for (const url of originUrls) {
      try {
        const resp = await fetchSitemapXml(url);
        if (resp.ok) {
          xml = await resp.text();
          break;
        }
      } catch (e) {
        console.error(`Sitemap fetch failed for ${url}: ${e.message}`);
      }
    }

    if (!xml) return res.status(502).send("Sitemap unavailable");

    // Rewrite semua domain origin yang mungkin muncul di sitemap
    xml = xml.replace(buildOriginRegex(), `https://${mirrorHost}`);
    // Rewrite juga domain alternatif (secure.komikid.org, komikid.org, dll)
    xml = xml.replace(/https?:\/\/(www\.)?(secure\.)?komikid\.org/gi, `https://${mirrorHost}`);
    // Hapus XSLT stylesheet reference agar browser tidak error
    xml = xml.replace(/<\?xml-stylesheet[^?]*\?>\s*/gi, "");

    // Fix invalid <lastmod> dates — sanitize to valid W3C datetime (ISO 8601)
    xml = xml.replace(/<lastmod>([^<]*)<\/lastmod>/gi, (match, dateStr) => {
      const trimmed = dateStr.trim();
      if (!trimmed) return ""; // remove empty lastmod
      // Try parsing the date
      const parsed = new Date(trimmed);
      if (isNaN(parsed.getTime())) {
        // If completely unparseable, remove the tag
        return "";
      }
      // Output as valid ISO 8601 date (YYYY-MM-DD or full datetime)
      const iso = parsed.toISOString(); // e.g. 2025-03-25T00:00:00.000Z
      return `<lastmod>${iso}</lastmod>`;
    });

    res.set("Content-Type", "application/xml; charset=utf-8");
    res.set("Cache-Control", "public, max-age=3600, s-maxage=86400");
    res.set("X-Robots-Tag", "noindex");
    res.send(xml);
  } catch (err) {
    console.error("Sitemap proxy error:", err.message);
    res.status(502).send("Sitemap unavailable");
  }
});

// ============================================================
// ANALYTICS PROXY — Proxy requests to analytics.komiku.org
// ============================================================
app.all("/analytics-proxy/*", async (req, res) => {
  const mirrorHost = getMirrorHost(req);
  const apiPath = req.originalUrl.replace(/^\/analytics-proxy/, "");
  const apiUrl = `https://analytics.${ORIGIN_HOST}${apiPath}`;

  try {
    const proxyHeaders = {
      Host: `analytics.${ORIGIN_HOST}`,
      "User-Agent": req.get("user-agent") || "Mozilla/5.0",
      Accept: req.get("accept") || "*/*",
      "Accept-Language": req.get("accept-language") || "id-ID,id;q=0.9",
      "Accept-Encoding": "gzip, deflate",
      Referer: `https://${ORIGIN_HOST}/`,
      Origin: `https://${ORIGIN_HOST}`,
    };

    const fetchOptions = {
      method: req.method,
      headers: proxyHeaders,
      redirect: "manual",
      timeout: 30000,
    };

    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (chunks.length > 0) fetchOptions.body = Buffer.concat(chunks);
    }

    const response = await fetch(apiUrl, fetchOptions);
    const contentType = response.headers.get("content-type") || "";

    for (const h of ["content-type", "last-modified", "etag"]) {
      const val = response.headers.get(h);
      if (val) res.set(h, val);
    }
    res.set("Cache-Control", "public, max-age=300, s-maxage=600");
    res.set("Access-Control-Allow-Origin", `https://${mirrorHost}`);
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") return res.status(204).end();

    if (contentType.includes("text/") || contentType.includes("json") || contentType.includes("xml") || contentType.includes("javascript")) {
      let body = await response.text();
      body = body.replace(buildOriginRegex(), `https://${mirrorHost}`);
      return res.status(response.status).send(body);
    }

    res.status(response.status);
    response.body.pipe(res);
  } catch (err) {
    console.error("Analytics proxy error:", err.message, "URL:", apiUrl);
    res.status(502).json({ error: "Analytics proxy failed" });
  }
});

// ============================================================
// API PROXY — Proxy requests to api.komiku.org to avoid CORS
// ============================================================
app.all("/api-proxy/*", async (req, res) => {
  const mirrorHost = getMirrorHost(req);
  // Strip /api-proxy/ prefix to get the original API path
  const apiPath = req.originalUrl.replace(/^\/api-proxy/, "");
  const apiUrl = `https://api.${ORIGIN_HOST}${apiPath}`;

  try {
    const proxyHeaders = {
      Host: `api.${ORIGIN_HOST}`,
      "User-Agent": req.get("user-agent") || "Mozilla/5.0",
      Accept: req.get("accept") || "*/*",
      "Accept-Language": req.get("accept-language") || "id-ID,id;q=0.9",
      "Accept-Encoding": "gzip, deflate",
      Referer: `https://${ORIGIN_HOST}/`,
      Origin: `https://${ORIGIN_HOST}`,
    };

    const fetchOptions = {
      method: req.method,
      headers: proxyHeaders,
      redirect: "manual",
      timeout: 30000,
    };

    // Forward body for POST
    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (chunks.length > 0) fetchOptions.body = Buffer.concat(chunks);
    }

    const response = await fetch(apiUrl, fetchOptions);

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (location) {
        let newLocation = location
          .replace(/https?:\/\/(www\.)?api\.komiku\.org/gi, `https://${mirrorHost}/api-proxy`)
          .replace(buildOriginRegex(), `https://${mirrorHost}`);
        return res.redirect(response.status, newLocation);
      }
    }

    const contentType = response.headers.get("content-type") || "";

    // Forward relevant headers
    for (const h of ["content-type", "last-modified", "etag"]) {
      const val = response.headers.get(h);
      if (val) res.set(h, val);
    }
    res.set("Cache-Control", "public, max-age=300, s-maxage=600");
    res.set("Access-Control-Allow-Origin", `https://${mirrorHost}`);
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type, hx-request, hx-trigger, hx-target, hx-current-url");

    // Handle OPTIONS preflight
    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }

    // Text-based responses: rewrite origin URLs
    if (contentType.includes("text/") || contentType.includes("json") || contentType.includes("xml") || contentType.includes("javascript")) {
      let body = await response.text();
      body = body.replace(buildOriginRegex(), `https://${mirrorHost}`);
      body = body.replace(/https?:\/\/(www\.)?api\.komiku\.org/gi, `https://${mirrorHost}/api-proxy`);
      body = body.replace(/https?:\/\/(www\.)?thumbnail\.komiku\.org/gi, `https://thumbnail.${ORIGIN_HOST}`);
      return res.status(response.status).send(body);
    }

    // Binary responses: stream through
    res.status(response.status);
    response.body.pipe(res);
  } catch (err) {
    console.error("API proxy error:", err.message, "URL:", apiUrl);
    res.status(502).json({ error: "API proxy failed" });
  }
});

// ============================================================
// CATCH-ALL PROXY
// ============================================================
app.all("*", async (req, res) => {
  const mirrorHost = getMirrorHost(req);
  const pathname = req.originalUrl; // includes query string

  // Build origin URL
  const originUrl = `https://${ORIGIN_HOST}${pathname}`;

  // ============================
  // 1. BUILD REQUEST KE ORIGIN
  // ============================
  const proxyHeaders = {
    Host: ORIGIN_HOST,
    "X-Forwarded-Host": mirrorHost,
    "User-Agent":
      req.get("user-agent") ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Accept: req.get("accept") || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": req.get("accept-language") || "id-ID,id;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    Referer: `https://${ORIGIN_HOST}/`,
  };

  // Forward cookie jika ada (untuk fungsionalitas)
  if (req.get("cookie")) {
    proxyHeaders["Cookie"] = req.get("cookie");
  }

  try {
    const fetchOptions = {
      method: req.method,
      headers: proxyHeaders,
      redirect: "manual",
      timeout: 30000,
    };

    // Forward body untuk POST/PUT
    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (chunks.length > 0) {
        fetchOptions.body = Buffer.concat(chunks);
      }
    }

    const response = await fetch(originUrl, fetchOptions);

    // ============================
    // 2. HANDLE REDIRECT (3xx)
    // ============================
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (location) {
        let newLocation = location.replace(
          buildOriginRegex(),
          `https://${mirrorHost}`
        );
        // Rewrite juga redirect ke komikid.org / secure.komikid.org
        newLocation = newLocation.replace(
          /https?:\/\/(www\.)?(secure\.)?komikid\.org/gi,
          `https://${mirrorHost}`
        );
        return res.redirect(response.status, newLocation);
      }
    }

    // ============================
    // 3. PROSES RESPONSE BERDASARKAN CONTENT-TYPE
    // ============================
    const contentType = response.headers.get("content-type") || "";

    // --- Salin headers yang relevan ---
    const headersToForward = [
      "content-type",
      "content-disposition",
      "last-modified",
      "etag",
      "vary",
    ];
    for (const h of headersToForward) {
      const val = response.headers.get(h);
      if (val) res.set(h, val);
    }

    // ============================
    // 3A. PROSES HTML
    // ============================
    if (contentType.includes("text/html")) {
      let html = await response.text();
      const reqPathname = req.path;
      const canonicalUrl = `https://${mirrorHost}${reqPathname}`;
      const pageId = uniquePageId(reqPathname);

      // --- A. REWRITE SEMUA URL ORIGIN → MIRROR ---
      // A0. Rewrite analytics.komiku.org → mirror/analytics-proxy
      html = html.replace(/https?:\/\/(www\.)?analytics\.komiku\.org/gi, `https://${mirrorHost}/analytics-proxy`);
      // A1. Rewrite api.komiku.org → mirror/api-proxy (HARUS SEBELUM rewrite domain utama)
      html = html.replace(/https?:\/\/(www\.)?api\.komiku\.org/gi, `https://${mirrorHost}/api-proxy`);
      // A2. Rewrite domain utama
      html = html.replace(buildOriginRegex(), `https://${mirrorHost}`);
      // A3. Rewrite domain alternatif (secure.komikid.org, komikid.org)
      html = html.replace(/https?:\/\/(www\.)?(secure\.)?komikid\.org/gi, `https://${mirrorHost}`);
      // A4. Rewrite plain-text domain origin (placeholder, title, dsb)
      html = html.replace(new RegExp(`(["'])${escapeRegex(ORIGIN_HOST)}(["'])`, "gi"), `$1${mirrorHost}$2`);

      // --- B. HAPUS SEMUA CANONICAL LAMA & INJECT CANONICAL BARU ---
      html = html.replace(/<link[^>]*rel=["']canonical["'][^>]*\/?>/gi, "");

      // --- C. HAPUS META ROBOTS NOINDEX DARI ORIGIN ---
      html = html.replace(
        /<meta[^>]*name=["']robots["'][^>]*content=["'][^"']*noindex[^"']*["'][^>]*\/?>/gi,
        ""
      );

      // --- D. GANTI META OG ---
      html = html.replace(
        /<meta[^>]*property=["']og:url["'][^>]*\/?>/gi,
        `<meta property="og:url" content="${canonicalUrl}" />`
      );
      html = html.replace(
        /<meta[^>]*property=["']og:site_name["'][^>]*\/?>/gi,
        `<meta property="og:site_name" content="${SITE_NAME}" />`
      );
      html = html.replace(
        /<meta[^>]*name=["']twitter:url["'][^>]*\/?>/gi,
        `<meta name="twitter:url" content="${canonicalUrl}" />`
      );

      // --- E. REWRITE HREFLANG ---
      html = html.replace(
        new RegExp(
          `(hreflang=["'][^"']*["']\\s+href=["'])https?://(www\\.)?${escapeRegex(ORIGIN_HOST)}`,
          "gi"
        ),
        `$1https://${mirrorHost}`
      );

      // --- F. GANTI TITLE — tambahkan suffix unik ---
      html = html.replace(/<title>([^<]*)<\/title>/i, (match, titleContent) => {
        // Hapus referensi ke domain origin di title
        let newTitle = titleContent.replace(/komiku\.org/gi, SITE_NAME);
        // Tambahkan suffix jika belum ada SITE_NAME
        if (!newTitle.toLowerCase().includes(SITE_NAME.toLowerCase())) {
          newTitle = `${newTitle} - ${SITE_NAME}`;
        }
        return `<title>${newTitle}</title>`;
      });

      // --- G. GANTI META DESCRIPTION — tambahkan prefix unik ---
      html = html.replace(
        /<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*\/?>/gi,
        (match, desc) => {
          let newDesc = desc.replace(/komiku\.org/gi, SITE_NAME);
          // Tambah prefix unik per halaman
          if (newDesc.length < 150) {
            newDesc = `[${SITE_NAME}] ${newDesc}`;
          }
          return `<meta name="description" content="${newDesc}" />`;
        }
      );

      // --- Ga. Ganti og:description juga ---
      html = html.replace(
        /<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["'][^>]*\/?>/gi,
        (match, desc) => {
          let newDesc = desc.replace(/komiku\.org/gi, SITE_NAME);
          return `<meta property="og:description" content="${newDesc}" />`;
        }
      );

      // ==========================================================
      // --- H. HAPUS TOTAL SEMUA AUTH SECTION (LOGIN + LOGOUT) ---
      // ==========================================================
      html = html.replace(
        /<div[^>]*id=["']mainAuthSection["'][^>]*>[\s\S]*?<\/div>\s*<\/div>/gi,
        ""
      );
      html = html.replace(
        /<div[^>]*id=["']mainAuthLogin["'][^>]*>[\s\S]*?<\/div>\s*<\/div>\s*<\/div>/gi,
        ""
      );
      html = html.replace(
        /<button[^>]*id=["']btnMainLogin["'][^>]*>[\s\S]*?<\/button>/gi,
        ""
      );
      html = html.replace(
        /<button[^>]*id=["']btnMainLogout["'][^>]*>[\s\S]*?<\/button>/gi,
        ""
      );
      html = html.replace(
        /<div[^>]*id=["']mainAuthUser["'][^>]*>[\s\S]*?<\/div>/gi,
        ""
      );

      // ==========================================================
      // --- I. HAPUS FIREBASE SDK SEPENUHNYA ---
      // ==========================================================
      html = html.replace(
        /<script[^>]*src=["'][^"']*firebase[^"']*["'][^>]*>[\s\S]*?<\/script>/gi,
        ""
      );
      html = html.replace(
        /<script[^>]*>[\s\S]*?firebase\.initializeApp[\s\S]*?<\/script>/gi,
        ""
      );
      html = html.replace(
        /<link[^>]*href=["'][^"']*firebase[^"']*["'][^>]*\/?>/gi,
        ""
      );

      // ==========================================================
      // --- Ia. HAPUS DDOS-GUARD SCRIPTS ---
      // ==========================================================
      html = html.replace(
        /<script[^>]*src=["'][^"']*ddos-guard[^"']*["'][^>]*>[\s\S]*?<\/script>/gi,
        ""
      );
      html = html.replace(
        /<script[^>]*>[\s\S]*?ddos-guard[\s\S]*?<\/script>/gi,
        ""
      );
      html = html.replace(
        /<script[^>]*src=["'][^"']*\.well-known[^"']*["'][^>]*>[\s\S]*?<\/script>/gi,
        ""
      );

      // ==========================================================
      // --- J. INJECT SEO + ANTI-DUPLICATE HEAD TAGS ---
      // ==========================================================
      // Deteksi tipe halaman untuk structured data
      const isHomePage = reqPathname === "/" || reqPathname === "";
      const isComicPage = /^\/manga\/|^\/manhua\/|^\/manhwa\/|^\/komik\//i.test(reqPathname);
      const isChapterPage = /chapter|ch-/i.test(reqPathname);

      // Extract page title untuk structured data
      const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
      const pageTitle = titleMatch ? titleMatch[1] : SITE_NAME;

      // Breadcrumb structured data
      const pathSegments = reqPathname.split("/").filter(Boolean);
      const breadcrumbItems = [{ "@type": "ListItem", "position": 1, "name": "Beranda", "item": `https://${mirrorHost}/` }];
      let breadcrumbPath = "";
      for (let i = 0; i < pathSegments.length && i < 4; i++) {
        breadcrumbPath += "/" + pathSegments[i];
        breadcrumbItems.push({
          "@type": "ListItem",
          "position": i + 2,
          "name": decodeURIComponent(pathSegments[i]).replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
          "item": `https://${mirrorHost}${breadcrumbPath}/`
        });
      }

      // Build structured data JSON-LD
      const structuredDataArr = [
        {
          "@context": "https://schema.org",
          "@type": "WebSite",
          "name": SITE_NAME,
          "alternateName": SITE_TAGLINE,
          "url": `https://${mirrorHost}/`,
          "description": SITE_DESCRIPTION,
          "inLanguage": "id-ID",
          "potentialAction": {
            "@type": "SearchAction",
            "target": `https://${mirrorHost}/?s={search_term_string}`,
            "query-input": "required name=search_term_string"
          }
        }
      ];

      if (!isHomePage) {
        structuredDataArr.push({
          "@context": "https://schema.org",
          "@type": "BreadcrumbList",
          "itemListElement": breadcrumbItems
        });
      }

      if (isComicPage && !isChapterPage) {
        // Extract description dari meta tag yang sudah ada
        const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i);
        const comicDesc = descMatch ? descMatch[1] : SITE_TAGLINE;
        // Extract image dari og:image
        const imgMatch = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["']/i);
        const comicImg = imgMatch ? imgMatch[1] : "";

        structuredDataArr.push({
          "@context": "https://schema.org",
          "@type": "CreativeWork",
          "name": pageTitle.replace(` - ${SITE_NAME}`, ""),
          "url": canonicalUrl,
          "description": comicDesc,
          ...(comicImg && { "image": comicImg }),
          "inLanguage": "id-ID",
          "publisher": {
            "@type": "Organization",
            "name": SITE_NAME,
            "url": `https://${mirrorHost}/`
          }
        });
      }

      const structuredDataScripts = structuredDataArr.map(d =>
        `<script type="application/ld+json">${JSON.stringify(d)}</script>`
      ).join("\n    ");

      const seoHeadInjection = `
    <link rel="canonical" href="${canonicalUrl}" />
    <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" />
    <meta name="copyright" content="${SITE_NAME}" />
    <meta name="identifier-url" content="${canonicalUrl}" />
    <meta property="og:type" content="${isComicPage ? "article" : "website"}" />
    <meta property="og:site_name" content="${SITE_NAME} - ${SITE_TAGLINE}" />
    <meta property="og:locale" content="id_ID" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:site" content="@${SITE_NAME.toLowerCase()}" />
    <meta name="page-id" content="${pageId}" />
    <meta name="theme-color" content="#3b5fd9" />
    <link rel="alternate" type="application/rss+xml" title="${SITE_NAME} RSS" href="https://${mirrorHost}/feed/" />
    <link rel="alternate" hreflang="id" href="${canonicalUrl}" />
    <link rel="alternate" hreflang="x-default" href="${canonicalUrl}" />
    ${structuredDataScripts}`;

      // --- Inject jQuery CDN fallback (sebelum script lain) ---
      const jqueryFallback = `
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" integrity="sha512-v2CJ7UaYy4JwqLDIrZUI/4hqeoQieOmAZNXBeQyjo21dadnwR+8ZaIJVT8EE2ez9n99UhA2o/5cYakMYXeLMQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>`;

      html = html.replace(/<head([^>]*)>/i, `<head$1>\n${seoHeadInjection}\n${jqueryFallback}`);

      // ==========================================================
      // --- K. INJECT CSS HIDE AUTH + MODERN THEME ---
      // ==========================================================
      const nukeAuthCSS = `
        <style id="mirror-auth-hide">
          #mainAuthSection,#mainAuthLogin,#mainAuthUser,
          #btnMainLogin,#btnMainLogout,[id*="Auth"],
          [id*="btnMain"][class*="gold"],[id*="btnMain"][class*="danger"],
          .firebaseui-container,.firebase-emulator-warning {
            display:none!important;visibility:hidden!important;
            width:0!important;height:0!important;overflow:hidden!important;
            position:absolute!important;pointer-events:none!important;
            opacity:0!important;clip:rect(0,0,0,0)!important;
          }
        </style>`;

      const modernTheme = `
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style id="komiku-modern-theme">
          :root {
            --font-main: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            --accent: #3b5fd9;
            --accent-hover: #2d4bb8;
            --accent-soft: rgba(59,95,217,0.08);
            --accent-softer: rgba(59,95,217,0.04);
            --red: #e5384f;
            --green: #16a34a;
            --orange: #ea6c20;
            --radius: 10px;
            --radius-sm: 6px;
            --radius-lg: 14px;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.06);
            --shadow-md: 0 4px 12px rgba(0,0,0,0.07);
            --shadow-lg: 0 8px 24px rgba(0,0,0,0.09);
            --border: #e5e7eb;
            --bg-page: #f5f6fa;
            --bg-white: #ffffff;
            --text-dark: #1e293b;
            --text-mid: #475569;
            --text-light: #94a3b8;
            --transition: 0.2s ease;
          }
          body, html {
            background: var(--bg-page) !important;
            font-family: var(--font-main) !important;
            -webkit-font-smoothing: antialiased;
            color: var(--text-dark) !important;
          }
          * { box-sizing: border-box; }
          a { text-decoration: none !important; transition: color var(--transition); }
          img { border-radius: var(--radius-sm); }
          #header {
            background: var(--bg-white) !important;
            box-shadow: 0 1px 4px rgba(0,0,0,0.06) !important;
            border-bottom: none !important;
          }
          .hd2 { background: transparent !important; border: none !important; }
          .logo a {
            font-weight: 800 !important; font-size: 22px !important;
            letter-spacing: -0.5px !important; color: var(--text-dark) !important;
          }
          .logo svg, .logo path { color: var(--accent) !important; fill: var(--accent) !important; }
          .logo span { color: var(--accent) !important; -webkit-text-fill-color: var(--accent) !important; }
          .search_box {
            background: var(--bg-page) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: 50px !important;
            overflow: hidden !important;
            transition: border-color var(--transition), box-shadow var(--transition) !important;
          }
          .search_box:focus-within {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 3px var(--accent-soft) !important;
          }
          .search_box input[type="text"] {
            background: transparent !important; border: none !important;
            color: var(--text-dark) !important; font-family: var(--font-main) !important; font-size: 14px !important;
          }
          .search_box input[type="text"]::placeholder { color: var(--text-light) !important; }
          .search_box .search_icon, .search_box input[type="submit"] {
            background: var(--accent) !important; color: #fff !important;
            border: none !important; border-radius: 50px !important;
            font-weight: 600 !important; font-family: var(--font-main) !important;
            cursor: pointer !important; transition: background var(--transition) !important;
          }
          .search_box .search_icon:hover, .search_box input[type="submit"]:hover {
            background: var(--accent-hover) !important;
          }
          .second_nav li a {
            background: var(--bg-page) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: 8px !important;
            color: var(--text-mid) !important;
            font-size: 13px !important; font-weight: 600 !important;
            font-family: var(--font-main) !important;
            transition: all var(--transition) !important;
          }
          .second_nav li a:hover {
            border-color: var(--accent) !important;
            color: var(--accent) !important;
            background: var(--accent-soft) !important;
          }
          .second_nav li a span { color: inherit !important; }
          nav {
            background: var(--bg-white) !important;
            border-bottom: 1.5px solid var(--border) !important;
            border-top: none !important;
          }
          nav ul { background: transparent !important; }
          nav ul li a {
            color: var(--text-mid) !important; font-weight: 600 !important;
            font-size: 13px !important; font-family: var(--font-main) !important;
            padding: 10px 13px !important; border-radius: var(--radius-sm) !important;
            transition: all var(--transition) !important;
          }
          nav ul li a:hover { color: var(--accent) !important; background: var(--accent-soft) !important; }
          nav ul li a span { color: inherit !important; }
          nav ul li a[style*="background: #4164b2"] {
            background: var(--accent) !important; color: #fff !important; border-radius: 8px !important;
          }
          nav ul li a[style*="background: #4164b2"] span { color: #fff !important; }
          .main, main, .konten { background: transparent !important; }
          h1.lsh3, h2.lsh3, .lsh3 {
            border-bottom: 2.5px solid var(--accent) !important;
            color: var(--text-dark) !important; font-family: var(--font-main) !important;
            font-weight: 700 !important; font-size: 19px !important;
          }
          .welcome { color: var(--text-mid) !important; line-height: 1.7 !important; font-size: 13px !important; }
          .welcome b { color: var(--accent) !important; }
          .rakbuku {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius) !important;
            transition: all var(--transition) !important;
          }
          .rakbuku:hover { border-color: var(--accent) !important; box-shadow: var(--shadow-md) !important; }
          .rakbuku h3 { color: var(--accent) !important; font-family: var(--font-main) !important; }
          .rakbuku p { color: var(--text-light) !important; }
          .ls112 { background: transparent !important; border: none !important; }
          .ls { background: transparent !important; }
          .ls12 { background: transparent !important; }
          article.ls2 {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius) !important;
            overflow: hidden !important;
            transition: all var(--transition) !important;
          }
          article.ls2:hover {
            border-color: var(--accent) !important;
            box-shadow: var(--shadow-md) !important;
            transform: translateY(-2px) !important;
          }
          .ls2v { position: relative !important; overflow: hidden !important; }
          .ls2v img { border-radius: 0 !important; transition: transform 0.3s ease !important; }
          article.ls2:hover .ls2v img { transform: scale(1.05) !important; }
          .ls2j { padding: 8px !important; background: var(--bg-white) !important; }
          .ls2j h3 a {
            color: var(--text-dark) !important; font-weight: 600 !important;
            font-size: 13px !important; line-height: 1.4 !important;
            font-family: var(--font-main) !important;
          }
          .ls2j h3 a:hover { color: var(--accent) !important; }
          .ls2t { color: var(--text-light) !important; font-size: 11px !important; font-weight: 500 !important; }
          .ls2l { color: var(--accent) !important; font-size: 12px !important; font-weight: 600 !important; }
          .vw .svg.hot {
            background: var(--accent) !important; color: #fff !important;
            font-weight: 700 !important; border-radius: var(--radius-sm) !important;
            padding: 2px 8px !important; font-size: 12px !important;
          }
          article.ls4 {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius) !important;
            overflow: hidden !important;
            transition: all var(--transition) !important;
            margin-bottom: 6px !important;
          }
          article.ls4:hover { border-color: var(--accent) !important; box-shadow: var(--shadow-sm) !important; }
          .ls4v { overflow: hidden !important; position: relative !important; }
          .ls4v img { border-radius: 0 !important; }
          .ls4j { background: transparent !important; }
          .ls4j h3 a {
            color: var(--text-dark) !important; font-weight: 600 !important;
            font-size: 14px !important; font-family: var(--font-main) !important;
          }
          .ls4j h3 a:hover { color: var(--accent) !important; }
          .ls4s { color: var(--text-light) !important; font-size: 12px !important; }
          .ls24 {
            background: var(--accent-soft) !important; color: var(--accent) !important;
            border: none !important; border-radius: var(--radius-sm) !important;
            padding: 3px 10px !important; font-size: 12px !important;
            font-weight: 600 !important; font-family: var(--font-main) !important;
            display: inline-block !important; transition: all var(--transition) !important;
          }
          .ls24:hover { background: var(--accent) !important; color: #fff !important; }
          .ls4v .warna, span.warna {
            background: var(--accent) !important; color: #fff !important;
            font-size: 10px !important; font-weight: 700 !important;
            border-radius: 4px !important; padding: 2px 7px !important;
            text-transform: uppercase !important; letter-spacing: 0.3px !important;
          }
          .ls4v .up, span.up {
            background: rgba(22,163,74,0.1) !important; color: var(--green) !important;
            font-size: 10px !important; font-weight: 700 !important;
            border-radius: 4px !important; padding: 2px 7px !important;
          }
          #Terbaru h2, #Filter h2 {
            color: var(--text-dark) !important; font-weight: 700 !important;
            font-size: 20px !important; font-family: var(--font-main) !important;
          }
          #Terbaru h2 span { color: var(--accent) !important; }
          a.lnn {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            color: var(--accent) !important;
            border-radius: var(--radius) !important;
            font-weight: 600 !important; font-family: var(--font-main) !important;
            display: block !important; text-align: center !important;
            padding: 12px !important; transition: all var(--transition) !important;
          }
          a.lnn:hover { border-color: var(--accent) !important; background: var(--accent-soft) !important; }
          .seemore ul li {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: 8px !important;
            transition: all var(--transition) !important;
          }
          .seemore ul li:hover { border-color: var(--accent) !important; background: var(--accent-soft) !important; }
          .seemore ul li a {
            color: var(--text-mid) !important; font-size: 13px !important;
            font-weight: 600 !important; font-family: var(--font-main) !important;
          }
          .seemore ul li:hover a { color: var(--accent) !important; }
          #Filter {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius-lg) !important;
            padding: 20px !important; margin: 15px !important;
            box-shadow: var(--shadow-sm) !important;
          }
          #Filter p { color: var(--text-mid) !important; font-size: 13px !important; }
          #Filter b { color: var(--accent) !important; }
          .filer2 select {
            background: var(--bg-page) !important; color: var(--text-dark) !important;
            border: 1.5px solid var(--border) !important; border-radius: var(--radius-sm) !important;
            padding: 8px 12px !important; font-family: var(--font-main) !important;
            font-size: 13px !important; transition: border-color var(--transition) !important;
            cursor: pointer !important;
          }
          .filer2 select:focus {
            border-color: var(--accent) !important; outline: none !important;
            box-shadow: 0 0 0 3px var(--accent-soft) !important;
          }
          .filter3, .filer2 input[type="submit"] {
            background: var(--accent) !important; color: #fff !important;
            border: none !important; border-radius: var(--radius-sm) !important;
            padding: 8px 22px !important; font-weight: 600 !important;
            font-family: var(--font-main) !important; cursor: pointer !important;
            transition: background var(--transition) !important; font-size: 13px !important;
          }
          .filter3:hover, .filer2 input[type="submit"]:hover { background: var(--accent-hover) !important; }
          #Genre { display: flex !important; flex-wrap: wrap !important; gap: 10px !important; padding: 10px 15px !important; }
          .ls3 {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius) !important;
            overflow: hidden !important; transition: all var(--transition) !important;
          }
          .ls3:hover {
            border-color: var(--accent) !important;
            box-shadow: var(--shadow-md) !important;
            transform: translateY(-2px) !important;
          }
          .ls3 img { border-radius: 0 !important; }
          .ls3p h4 { font-weight: 700 !important; font-family: var(--font-main) !important; }
          .ls3p a {
            background: var(--accent) !important; color: #fff !important;
            border-radius: var(--radius-sm) !important; padding: 4px 12px !important;
            font-size: 12px !important; font-weight: 600 !important;
          }
          .ntah.genr, .genr {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius-lg) !important;
            margin: 15px !important; padding: 15px !important;
          }
          .genre li a {
            background: var(--bg-page) !important;
            border: 1px solid var(--border) !important;
            color: var(--text-mid) !important; border-radius: 6px !important;
            padding: 4px 10px !important; font-size: 12px !important;
            font-family: var(--font-main) !important;
            transition: all var(--transition) !important;
          }
          .genre li a:hover {
            border-color: var(--accent) !important;
            color: var(--accent) !important;
            background: var(--accent-soft) !important;
          }
          .mree {
            background: var(--accent) !important; color: #fff !important;
            border-radius: var(--radius-sm) !important; cursor: pointer !important;
            font-weight: 600 !important; font-size: 13px !important;
            padding: 8px 20px !important; transition: background var(--transition) !important;
            font-family: var(--font-main) !important;
          }
          .mree:hover { background: var(--accent-hover) !important; }
          #Footer {
            background: var(--bg-white) !important;
            border-top: 1.5px solid var(--border) !important;
          }
          #Footer svg path { fill: var(--accent) !important; }
          #Footer .cp { color: var(--text-light) !important; font-size: 13px !important; }
          #Footer .pp a { color: var(--text-mid) !important; font-size: 13px !important; }
          #Footer .pp a:hover { color: var(--accent) !important; }
          #Navbawah {
            background: var(--bg-white) !important;
            border-top: 1.5px solid var(--border) !important;
            box-shadow: 0 -2px 8px rgba(0,0,0,0.04) !important;
          }
          .navb a { color: var(--text-light) !important; transition: color var(--transition) !important; }
          .navb a:hover { color: var(--accent) !important; }
          .navb svg path { fill: var(--text-light) !important; transition: fill var(--transition) !important; }
          .navb a:hover svg path { fill: var(--accent) !important; }
          .navb span { font-size: 10px !important; color: inherit !important; font-family: var(--font-main) !important; }
          .comment-popup {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius-lg) !important;
          }
          .popup-header { background: var(--bg-page) !important; border-bottom: 1.5px solid var(--border) !important; }
          .popup-title { color: var(--text-dark) !important; font-weight: 700 !important; }
          .popup-subtitle { color: var(--text-light) !important; }
          .toolbar select {
            background: var(--bg-page) !important; color: var(--text-dark) !important;
            border: 1px solid var(--border) !important; border-radius: var(--radius-sm) !important;
          }
          .btn {
            background: var(--bg-page) !important; color: var(--text-dark) !important;
            border: 1px solid var(--border) !important; border-radius: var(--radius-sm) !important;
          }
          .btn:hover { border-color: var(--accent) !important; }
          #history .ls2 {
            background: var(--bg-white) !important;
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius) !important;
          }
          .persen { background: #e5e7eb !important; border-radius: 4px !important; overflow: hidden !important; }
          .persen div { background: var(--accent) !important; border-radius: 4px !important; }
          .ls4.mobile {
            background: var(--accent-soft) !important;
            border: 1.5px solid var(--accent) !important;
            border-radius: var(--radius) !important;
          }
          .ls4.mobile .ls4j h3 a { color: var(--accent) !important; }
          button { font-family: var(--font-main) !important; }
          .ls4 h4 a { color: var(--text-dark) !important; }
          .ls4 h4 a:hover { color: var(--accent) !important; }
          #infinite-trigger { text-align: center !important; padding: 20px !important; }
          .km-comment-section { padding: 15px; font-family: var(--font-main); }
          .km-comment-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
          .km-comment-title { font-size: 18px; font-weight: 700; color: var(--text-dark); }
          .km-comment-count { font-size: 14px; color: var(--text-light); }
          .km-comment-form {
            background: var(--bg-white); border: 1.5px solid var(--border);
            border-radius: var(--radius); padding: 15px; margin-bottom: 15px;
          }
          .km-comment-input-name {
            width: 100%; border: 1.5px solid var(--border);
            border-radius: var(--radius-sm); padding: 10px 12px;
            font-family: var(--font-main); font-size: 14px;
            color: var(--text-dark); background: var(--bg-page);
            margin-bottom: 10px; box-sizing: border-box;
            outline: none; transition: border-color 0.2s;
          }
          .km-comment-input-name:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
          .km-comment-input-text {
            width: 100%; border: 1.5px solid var(--border);
            border-radius: var(--radius-sm); padding: 10px 12px;
            font-family: var(--font-main); font-size: 14px;
            color: var(--text-dark); background: var(--bg-page);
            resize: vertical; min-height: 60px; margin-bottom: 10px;
            box-sizing: border-box; outline: none; transition: border-color 0.2s;
          }
          .km-comment-input-text:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
          .km-comment-submit {
            background: var(--accent) !important; color: #fff !important;
            border: none !important; border-radius: var(--radius-sm) !important;
            padding: 10px 24px !important; font-weight: 600 !important;
            font-size: 14px !important; cursor: pointer !important;
            transition: background 0.2s !important; font-family: var(--font-main) !important;
          }
          .km-comment-submit:hover { background: var(--accent-hover) !important; }
          .km-comment-list { display: flex; flex-direction: column; gap: 10px; }
          .km-comment-item {
            background: var(--bg-white); border: 1.5px solid var(--border);
            border-radius: var(--radius); padding: 12px 15px;
          }
          .km-comment-user { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
          .km-comment-avatar {
            width: 36px; height: 36px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            color: #fff; font-weight: 700; font-size: 15px; flex-shrink: 0;
          }
          .km-comment-info { display: flex; flex-direction: column; }
          .km-comment-name { font-weight: 600; font-size: 14px; color: var(--text-dark); }
          .km-comment-time { font-size: 12px; color: var(--text-light); }
          .km-comment-body { font-size: 14px; color: var(--text-mid); line-height: 1.5; }
          .km-comment-toast {
            position: fixed; bottom: 80px; left: 50%; transform: translateX(-50%);
            background: var(--accent); color: #fff; padding: 10px 20px;
            border-radius: 8px; font-size: 14px; font-weight: 600;
            z-index: 9999; opacity: 0; transition: opacity 0.3s; pointer-events: none;
          }
          .km-comment-toast.show { opacity: 1; }
          @media (max-width: 768px) {
            article.ls2:hover, article.ls4:hover { transform: none !important; }
            .ls3:hover { transform: none !important; }
          }
        </style>`;

      html = html.replace(/<\/head>/i, `${nukeAuthCSS}\n${modernTheme}\n</head>`);

      // ==========================================================
      // --- L. INJECT AUTH REMOVAL JS + COMMENT SYSTEM BEFORE </body>
      // ==========================================================
      const bodyInjection = `
        <script>
        (function(){
          var S=["#mainAuthSection","#mainAuthLogin","#mainAuthUser",
            "#btnMainLogin","#btnMainLogout","[id*='Auth']",
            ".firebaseui-container",".firebase-emulator-warning"];
          function r(){S.forEach(function(s){
            document.querySelectorAll(s).forEach(function(e){e.remove();});
          });}
          if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",r);}else{r();}
          window.addEventListener("load",r);
          var o=new MutationObserver(function(){r();});
          function st(){if(document.body){o.observe(document.body,{childList:true,subtree:true});}
          else{requestAnimationFrame(st);}}st();
        })();
        </script>
        <div id="km-toast" class="km-comment-toast"></div>
        <script>
        (function(){
          window.CommentPreview=window.CommentPreview||{};
          window.CommentPreview.openFullComments=function(){return false;};
          function init(){
            var s=document.getElementById('comment-section');
            if(!s||s.getAttribute('data-km-init'))return;
            s.setAttribute('data-km-init','1');
            var pk='km_cmt_'+location.pathname.replace(/[^a-z0-9]/gi,'_');
            function gc(){try{return JSON.parse(localStorage.getItem(pk))||[];}catch(e){return[];}}
            function sc(n,t){var c=gc();c.unshift({n:n,t:t,ts:Date.now()});if(c.length>200)c=c.slice(0,200);localStorage.setItem(pk,JSON.stringify(c));}
            function ta(ts){var d=Date.now()-ts,m=Math.floor(d/60000);if(m<1)return'Baru saja';if(m<60)return m+' menit lalu';var h=Math.floor(m/60);if(h<24)return h+' jam lalu';var dy=Math.floor(h/24);if(dy<30)return dy+' hari lalu';return Math.floor(dy/30)+' bulan lalu';}
            function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
            var cl=['#3b5fd9','#e5384f','#16a34a','#ea6c20','#8b5cf6','#ec4899','#0891b2'];
            function rc(c){var nm=c.n||c.name||'Anonim';var ini=nm.charAt(0).toUpperCase();var col=cl[ini.charCodeAt(0)%cl.length];var tm=c.ts?ta(c.ts):(c.tt||'');var txt=c.t||c.text||'';
            return '<div class="km-comment-item"><div class="km-comment-user"><div class="km-comment-avatar" style="background:'+col+'">'+ini+'</div><div class="km-comment-info"><div class="km-comment-name">'+esc(nm)+'</div><div class="km-comment-time">'+esc(tm)+'</div></div></div><div class="km-comment-body">'+esc(txt)+'</div></div>';}
            var ex=[];var items=s.querySelectorAll('.comment-preview-item');
            for(var i=0;i<items.length;i++){var ne=items[i].querySelector('.comment-preview-name');var be=items[i].querySelector('.comment-preview-body');var te=items[i].querySelector('.comment-preview-time');
            if(ne&&be){var n2='';for(var j=0;j<ne.childNodes.length;j++){if(ne.childNodes[j].nodeType===3){n2=ne.childNodes[j].textContent.trim();break;}}if(!n2)n2=ne.textContent.trim();ex.push({name:n2,text:be.textContent.trim(),tt:te?te.textContent.trim():''});}}
            var sv=gc();var lh='';for(var k=0;k<sv.length;k++)lh+=rc(sv[k]);for(var k=0;k<ex.length;k++)lh+=rc(ex[k]);var tot=sv.length+ex.length;
            s.innerHTML='<div class="km-comment-section"><div class="km-comment-header"><span class="km-comment-title">Komentar</span><span class="km-comment-count">'+tot+' komentar</span></div><div class="km-comment-form"><input type="text" class="km-comment-input-name" placeholder="Nama kamu..." maxlength="50"><textarea class="km-comment-input-text" placeholder="Tulis komentar..." maxlength="500" rows="3"></textarea><button class="km-comment-submit">Kirim Komentar</button></div><div class="km-comment-list">'+lh+'</div></div>';
            var btn=s.querySelector('.km-comment-submit');var ni=s.querySelector('.km-comment-input-name');var ti=s.querySelector('.km-comment-input-text');
            btn.addEventListener('click',function(){var nm=ni.value.trim(),tx=ti.value.trim();if(!nm||!tx)return;sc(nm,tx);var list=s.querySelector('.km-comment-list');list.insertAdjacentHTML('afterbegin',rc({n:nm,t:tx,ts:Date.now()}));var ce=s.querySelector('.km-comment-count');ce.textContent=((parseInt(ce.textContent)||0)+1)+' komentar';ni.value='';ti.value='';var toast=document.getElementById('km-toast');if(toast){toast.textContent='Komentar berhasil dikirim!';toast.classList.add('show');setTimeout(function(){toast.classList.remove('show');},2000);}});
            var pp=document.querySelectorAll('.comment-popup,.comment-overlay');for(var p=0;p<pp.length;p++)pp[p].style.display='none';
          }
          if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',init);}else{init();}
          window.addEventListener('load',function(){setTimeout(init,300);});
        })();
        </script>`;

      html = html.replace(/<\/body>/i, `${bodyInjection}\n</body>`);

      // ==========================================================
      // --- M. HAPUS FOOTER DUPLIKAT & INJECT UNIQUE FOOTER ---
      // ==========================================================
      // Hapus semua footer original dari origin, simpan hanya satu
      html = html.replace(
        /(<footer[^>]*id=["']Footer["'][^>]*>[\s\S]*?<\/footer>\s*){2,}/gi,
        (match) => {
          // Ambil hanya footer pertama
          const singleFooter = match.match(/<footer[^>]*id=["']Footer["'][^>]*>[\s\S]*?<\/footer>/i);
          return singleFooter ? singleFooter[0] : match;
        }
      );

      // Tambahkan paragraf unik di footer yang mengandung konten berbeda
      // dari origin agar Google melihat halaman ini sebagai unik
      const uniqueFooterContent = `
        <div id="mirror-identity" style="padding:10px 15px;text-align:center;font-size:11px;color:#94a3b8;font-family:'Plus Jakarta Sans',sans-serif;border-top:1px solid #e5e7eb;margin-top:10px;">
          <p>&copy; ${new Date().getFullYear()} ${SITE_NAME} &mdash; ${SITE_TAGLINE}. Situs baca komik manga, manhwa, dan manhua sub Indonesia terlengkap.</p>
          <p style="margin-top:4px;font-size:10px;">Halaman ini dibuat oleh ${SITE_NAME}. ID: ${pageId}</p>
        </div>`;

      // Inject sebelum </body> (setelah body injection sebelumnya)
      html = html.replace(/<\/body>/i, `${uniqueFooterContent}\n</body>`);

      // ==========================================================
      // --- N. FINAL CLEANUP: hapus semua sisa referensi origin ---
      // ==========================================================
      // Pass terakhir untuk memastikan tidak ada URL origin tersisa di HTML
      html = html.replace(/https?:\/\/(www\.)?analytics\.komiku\.org/gi, `https://${mirrorHost}/analytics-proxy`);
      html = html.replace(/https?:\/\/(www\.)?api\.komiku\.org/gi, `https://${mirrorHost}/api-proxy`);
      html = html.replace(buildOriginRegex(), `https://${mirrorHost}`);

      // Hapus komentar HTML yg bisa bocorkan origin
      html = html.replace(/<!--[\s\S]*?-->/g, (match) => {
        if (match.includes(ORIGIN_HOST)) return "";
        return match;
      });

      // --- BUILD RESPONSE ---
      res.set("Content-Type", "text/html; charset=utf-8");
      res.set("X-Robots-Tag", "index, follow");
      res.set("Cache-Control", "public, max-age=3600, s-maxage=86400");
      res.removeHeader("link");
      return res.status(response.status).send(html);
    }

    // ============================
    // 3B. PROSES CSS
    // ============================
    if (contentType.includes("text/css")) {
      let css = await response.text();
      css = css.replace(buildOriginRegex(), `https://${mirrorHost}`);
      res.set("Content-Type", "text/css; charset=utf-8");
      res.set("Cache-Control", "public, max-age=604800, s-maxage=2592000");
      return res.status(response.status).send(css);
    }

    // ============================
    // 3C. PROSES JS & JSON
    // ============================
    if (
      contentType.includes("javascript") ||
      contentType.includes("application/json")
    ) {
      let body = await response.text();
      body = body.replace(/https?:\/\/(www\.)?analytics\.komiku\.org/gi, `https://${mirrorHost}/analytics-proxy`);
      body = body.replace(/https?:\/\/(www\.)?api\.komiku\.org/gi, `https://${mirrorHost}/api-proxy`);
      body = body.replace(buildOriginRegex(), `https://${mirrorHost}`);
      res.set("Content-Type", contentType);
      res.set("Cache-Control", "public, max-age=604800");
      return res.status(response.status).send(body);
    }

    // ============================
    // 3D. PROSES XML (Sitemap, RSS)
    // ============================
    if (
      contentType.includes("text/xml") ||
      contentType.includes("application/xml") ||
      contentType.includes("application/rss+xml") ||
      contentType.includes("application/atom+xml")
    ) {
      let xml = await response.text();
      xml = xml.replace(buildOriginRegex(), `https://${mirrorHost}`);
      res.set("Content-Type", contentType);
      res.set("Cache-Control", "public, max-age=3600");
      return res.status(response.status).send(xml);
    }

    // ============================
    // 3E. ASSET LAINNYA (images, fonts, etc) — stream through
    // ============================
    res.set("Cache-Control", "public, max-age=2592000, s-maxage=2592000");
    res.status(response.status);
    response.body.pipe(res);
  } catch (err) {
    console.error("Proxy error:", err.message, "URL:", req.originalUrl);
    res.status(502).send("Bad Gateway — Origin unreachable");
  }
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ ${SITE_NAME} Mirror running on port ${PORT}`);
  console.log(`   Origin: ${ORIGIN_HOST}`);
  console.log(`   Mirror: ${MIRROR_HOST || "(auto-detect from Host header)"}`);
  console.log(`   Env: ${process.env.NODE_ENV || "development"}`);
  console.log(`   Health: http://0.0.0.0:${PORT}/healthz`);
});
