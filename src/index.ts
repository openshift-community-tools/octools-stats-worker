/**
 * OCTools Stats API — Cloudflare Worker + D1
 *
 * Aggregates download counts and 5-star ratings for OpenShift Community Tools
 * extensions across all clusters.  No PII is collected; the only identifier is
 * a SHA-256 hash of the cluster UUID used for rating dedup.
 *
 * Endpoints:
 *   GET  /v1/stats              — aggregated stats for all tools
 *   POST /v1/stats/download     — increment download counter
 *   POST /v1/stats/rating       — upsert a cluster's rating
 *   DELETE /v1/stats/rating     — remove a cluster's rating
 *   GET  /v1/versions           — all tool versions grouped by tool_id
 *   GET  /v1/versions/:toolId   — versions for a single tool
 *   POST /v1/versions           — upsert a version row (admin-only)
 *   GET  /v1/catalog            — catalog format with stats + versions
 *   GET  /health                — health check
 *
 * Writes from storefronts (downloads, ratings) are accepted only for tool ids that
 * have published version rows, so the counters can't be filled with arbitrary ids.
 */

export interface Env {
  DB: D1Database;
  ADMIN_TOKEN: string;
  /**
   * Optional Workers Rate Limiting binding ([[ratelimits]] in wrangler.toml).
   * When bound, write limits are counted per Cloudflare location (shared by the
   * isolates there) instead of per isolate. Not a global limit.
   */
  WRITE_LIMITER?: RateLimit;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function json(data: unknown, status = 200, cacheSeconds = 0): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
  if (cacheSeconds > 0) {
    headers['Cache-Control'] = `public, max-age=${cacheSeconds}`;
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(status: number, message: string): Response {
  return json({ error: message }, status);
}

const SHA256_RE = /^[a-f0-9]{64}$/i;
/** Catalog ids are Kubernetes names (DNS-1123 labels), e.g. oct-baremetal. */
const TOOL_ID_RE = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const SEMVER_RE = /^v?\d+\.\d+\.\d+$/;
/** Same cap the storefront applies to unknown declaration keys. */
const SECURITY_MAX_BYTES = 16 * 1024;

/** True when toolId is well-formed and has at least one published version row. */
async function isKnownTool(db: D1Database, toolId: string): Promise<boolean> {
  if (!TOOL_ID_RE.test(toolId)) return false;
  const row = await db.prepare('SELECT 1 AS ok FROM tool_versions WHERE tool_id = ? LIMIT 1').bind(toolId).first<{ ok: number }>();
  return !!row;
}

/**
 * A security declaration from seed.js, stored as JSON text. Returns undefined when
 * absent, null to clear, or an error message.
 */
function securityJson(v: unknown): string | null | undefined | { error: string } {
  if (v === undefined) return undefined;
  if (v === null) return null;
  if (typeof v !== 'object' || Array.isArray(v)) return { error: 'security must be an object' };
  const text = JSON.stringify(v);
  if (text.length > SECURITY_MAX_BYTES) return { error: `security is larger than ${SECURITY_MAX_BYTES} bytes` };
  return text;
}

function parseJsonColumn(text: string | null): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/* ------------------------------------------------------------------ */
/*  Rate limiters                                                     */
/* ------------------------------------------------------------------ */

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 20; // max writes per IP per minute
const ADMIN_FAIL_MAX = 10; // max failed admin auth attempts per IP per minute

/** In-memory fixed-window limiter. Per isolate, so only a fallback/extra layer. */
function makeLimiter(max: number) {
  const entries = new Map<string, { count: number; resetAt: number }>();
  return (key: string): boolean => {
    const now = Date.now();
    // Drop expired entries now and then so the map can't grow without bound.
    if (entries.size > 10_000) {
      for (const [k, e] of entries) if (now > e.resetAt) entries.delete(k);
    }
    const entry = entries.get(key);
    if (!entry || now > entry.resetAt) {
      entries.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
      return false;
    }
    entry.count++;
    return entry.count > max;
  };
}

const isLocallyRateLimited = makeLimiter(RATE_LIMIT_MAX);

/**
 * Failed admin attempts per IP. Checked BEFORE the token, so a blocked IP can't
 * keep guessing (a right guess while blocked still gets 429), and only failures
 * count, so seed.js posting many rows isn't slowed down. Per isolate: put a
 * Cloudflare WAF rate-limiting rule on POST /v1/versions for a limit across isolates.
 */
const adminFailures = new Map<string, { count: number; resetAt: number }>();
function adminBlocked(ip: string): boolean {
  const e = adminFailures.get(ip);
  return !!e && Date.now() <= e.resetAt && e.count >= ADMIN_FAIL_MAX;
}
function recordAdminFailure(ip: string): void {
  const now = Date.now();
  if (adminFailures.size > 10_000) {
    for (const [k, e] of adminFailures) if (now > e.resetAt) adminFailures.delete(k);
  }
  const e = adminFailures.get(ip);
  if (!e || now > e.resetAt) adminFailures.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
  else e.count++;
}

/**
 * Write rate limit: global when the WRITE_LIMITER binding is configured,
 * otherwise the per-isolate fallback (same limit as before).
 */
async function isRateLimited(ip: string, env: Env): Promise<boolean> {
  if (env.WRITE_LIMITER) {
    try {
      const { success } = await env.WRITE_LIMITER.limit({ key: ip });
      return !success;
    } catch {
      // Binding misconfigured or unavailable: fall back rather than fail open entirely.
    }
  }
  return isLocallyRateLimited(ip);
}

/* ------------------------------------------------------------------ */
/*  Auth helper                                                       */
/* ------------------------------------------------------------------ */

async function sha256(value: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
}

/**
 * Admin bearer token check. Fails closed when ADMIN_TOKEN is unset or empty, and
 * compares fixed-length digests in constant time so response timing doesn't leak
 * how much of a guess was right.
 */
async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  const expected = (env.ADMIN_TOKEN || '').trim();
  if (!expected) return false;
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return false;
  const [a, b] = await Promise.all([sha256(token), sha256(expected)]);
  return crypto.subtle.timingSafeEqual(a, b);
}

/* ------------------------------------------------------------------ */
/*  Version types                                                     */
/* ------------------------------------------------------------------ */

interface ToolVersionRow {
  tool_id: string;
  version: string;
  channel: string;
  openshift: string;
  image: string;
  git_ref: string | null;
  deploy_url: string | null;
  min_storefront?: string | null;
  security?: string | null;
  updated_at: string;
}

interface VersionEntry {
  version: string;
  channel: string;
  openshift: string;
  image: string;
  gitRef: string | null;
  deployUrl: string | null;
}

/* ------------------------------------------------------------------ */
/*  Handlers                                                          */
/* ------------------------------------------------------------------ */

/**
 * Returns stats in the PublicCatalog format expected by the storefront sidecar.
 * Now includes versions[] per extension, grouped by (tool_id, version, channel)
 * with openshift values collected into an array.
 */
async function handleGetCatalog(db: D1Database): Promise<Response> {
  const statsRows = await db
    .prepare('SELECT tool_id, downloads, category, description, display_name, href, icon, git, security FROM tools_stats')
    .all<{ tool_id: string; downloads: number; category: string | null; description: string | null; display_name: string | null; href: string | null; icon: string | null; git: string | null; security: string | null }>();

  const ratingRows = await db
    .prepare(
      `SELECT tool_id,
              COUNT(*) as rating_count,
              ROUND(AVG(stars), 2) as rating_avg
       FROM ratings
       GROUP BY tool_id`
    )
    .all<{ tool_id: string; rating_count: number; rating_avg: number }>();

  const versionRows = await db
    .prepare('SELECT tool_id, version, channel, openshift, image, git_ref, deploy_url, min_storefront, security FROM tool_versions ORDER BY tool_id, version')
    .all<ToolVersionRow>();

  interface CatalogToolEntry {
    downloads: number;
    ratingCount: number;
    ratingAvg: number;
    category: string | null;
    description: string | null;
    displayName: string | null;
    href: string | null;
    icon: string | null;
    git: string | null;
    security?: unknown;
  }
  const toolMap = new Map<string, CatalogToolEntry>();
  for (const row of statsRows.results) {
    toolMap.set(row.tool_id, {
      downloads: row.downloads, ratingCount: 0, ratingAvg: 0,
      category: row.category || null,
      description: row.description || null,
      displayName: row.display_name || null,
      href: row.href || null,
      icon: row.icon || null,
      git: row.git || null,
      security: parseJsonColumn(row.security),
    });
  }
  for (const row of ratingRows.results) {
    const existing = toolMap.get(row.tool_id);
    if (existing) {
      existing.ratingCount = row.rating_count;
      existing.ratingAvg = row.rating_avg;
    } else {
      toolMap.set(row.tool_id, {
        downloads: 0, ratingCount: row.rating_count, ratingAvg: row.rating_avg,
        category: null, description: null, displayName: null, href: null, icon: null, git: null,
      });
    }
  }

  // Group versions by (tool_id, version, channel) and collect openshift into arrays
  const versionsByTool = new Map<string, Map<string, { version: string; channel: string; openshift: string[]; image: string; gitRef: string | null; deployUrl: string | null; minStorefront: string | null; security: unknown }>>();
  for (const row of versionRows.results) {
    if (!versionsByTool.has(row.tool_id)) {
      versionsByTool.set(row.tool_id, new Map());
    }
    const toolVersions = versionsByTool.get(row.tool_id)!;
    const key = `${row.version}|${row.channel}`;
    const existing = toolVersions.get(key);
    if (existing) {
      existing.openshift.push(row.openshift);
    } else {
      toolVersions.set(key, {
        version: row.version,
        channel: row.channel,
        openshift: [row.openshift],
        image: row.image,
        gitRef: row.git_ref,
        deployUrl: row.deploy_url,
        minStorefront: row.min_storefront || null,
        security: parseJsonColumn(row.security || null),
      });
    }
    if (!toolMap.has(row.tool_id)) {
      toolMap.set(row.tool_id, {
        downloads: 0, ratingCount: 0, ratingAvg: 0,
        category: null, description: null, displayName: null, href: null, icon: null, git: null,
      });
    }
  }

  const extensions = Array.from(toolMap.entries()).map(([id, data]) => {
    const toolVersions = versionsByTool.get(id);
    const versions = toolVersions
      ? Array.from(toolVersions.values()).map(v => ({
          version: v.version,
          channel: v.channel,
          openshift: v.openshift,
          image: v.image,
          ...(v.gitRef ? { gitRef: v.gitRef } : {}),
          ...(v.deployUrl ? { deployUrl: v.deployUrl } : {}),
          ...(v.minStorefront ? { minStorefront: v.minStorefront } : {}),
          ...(v.security ? { security: v.security } : {}),
        }))
      : [];

    return {
      id,
      consolePlugin: id,
      ...(data.category ? { category: data.category } : {}),
      ...(data.description ? { description: data.description } : {}),
      ...(data.displayName ? { displayName: data.displayName } : {}),
      ...(data.href ? { href: data.href } : {}),
      ...(data.icon ? { icon: data.icon } : {}),
      ...(data.git ? { git: data.git } : {}),
      ...(data.security ? { security: data.security } : {}),
      downloads: data.downloads,
      rating: {
        average: data.ratingAvg,
        count: data.ratingCount,
      },
      versions,
    };
  });

  return json({
    extensions,
    generatedAt: new Date().toISOString(),
  }, 200, 300);
}

async function handleGetStats(db: D1Database): Promise<Response> {
  const statsRows = await db
    .prepare('SELECT tool_id, downloads FROM tools_stats')
    .all<{ tool_id: string; downloads: number }>();

  const ratingRows = await db
    .prepare(
      `SELECT tool_id,
              COUNT(*) as rating_count,
              ROUND(AVG(stars), 2) as rating_avg
       FROM ratings
       GROUP BY tool_id`
    )
    .all<{ tool_id: string; rating_count: number; rating_avg: number }>();

  const toolMap = new Map<string, { downloads: number; ratingCount: number; ratingAvg: number }>();

  for (const row of statsRows.results) {
    toolMap.set(row.tool_id, {
      downloads: row.downloads,
      ratingCount: 0,
      ratingAvg: 0,
    });
  }

  for (const row of ratingRows.results) {
    const existing = toolMap.get(row.tool_id);
    if (existing) {
      existing.ratingCount = row.rating_count;
      existing.ratingAvg = row.rating_avg;
    } else {
      toolMap.set(row.tool_id, {
        downloads: 0,
        ratingCount: row.rating_count,
        ratingAvg: row.rating_avg,
      });
    }
  }

  const tools: Record<string, { downloads: number; ratingCount: number; ratingAvg: number }> = {};
  for (const [id, data] of toolMap) {
    tools[id] = data;
  }

  return json({ tools, timestamp: new Date().toISOString() }, 200, 300);
}

async function handlePostDownload(request: Request, db: D1Database): Promise<Response> {
  let body: { toolId?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, 'Invalid JSON body');
  }

  const toolId = body.toolId?.trim();
  if (!toolId || !TOOL_ID_RE.test(toolId)) {
    return errorResponse(400, 'Missing or invalid toolId');
  }
  if (!(await isKnownTool(db, toolId))) {
    return errorResponse(404, 'Unknown toolId (no published versions)');
  }

  await db
    .prepare(
      `INSERT INTO tools_stats (tool_id, downloads) VALUES (?, 1)
       ON CONFLICT(tool_id) DO UPDATE SET downloads = downloads + 1`
    )
    .bind(toolId)
    .run();

  return json({ ok: true, toolId });
}

async function handlePostRating(request: Request, db: D1Database): Promise<Response> {
  let body: { toolId?: string; clusterHash?: string; stars?: number };
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, 'Invalid JSON body');
  }

  const toolId = body.toolId?.trim();
  const clusterHash = body.clusterHash?.trim();
  const stars = body.stars;

  if (!toolId || !TOOL_ID_RE.test(toolId)) {
    return errorResponse(400, 'Missing or invalid toolId');
  }
  if (!clusterHash || !SHA256_RE.test(clusterHash)) {
    return errorResponse(400, 'clusterHash must be a 64-character hex SHA-256 hash');
  }
  if (typeof stars !== 'number' || stars < 1 || stars > 5 || !Number.isInteger(stars)) {
    return errorResponse(400, 'stars must be an integer between 1 and 5');
  }
  if (!(await isKnownTool(db, toolId))) {
    return errorResponse(404, 'Unknown toolId (no published versions)');
  }

  await db
    .prepare(
      `INSERT INTO ratings (tool_id, cluster_hash, stars, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(tool_id, cluster_hash)
       DO UPDATE SET stars = excluded.stars, updated_at = datetime('now')`
    )
    .bind(toolId, clusterHash, stars)
    .run();

  return json({ ok: true, toolId, stars });
}

async function handleDeleteRating(request: Request, db: D1Database): Promise<Response> {
  let body: { toolId?: string; clusterHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, 'Invalid JSON body');
  }

  const toolId = body.toolId?.trim();
  const clusterHash = body.clusterHash?.trim();

  if (!toolId || !TOOL_ID_RE.test(toolId)) {
    return errorResponse(400, 'Missing or invalid toolId');
  }
  if (!clusterHash || !SHA256_RE.test(clusterHash)) {
    return errorResponse(400, 'Invalid clusterHash');
  }

  await db
    .prepare('DELETE FROM ratings WHERE tool_id = ? AND cluster_hash = ?')
    .bind(toolId, clusterHash)
    .run();

  return json({ ok: true, toolId });
}

/* ------------------------------------------------------------------ */
/*  Version handlers                                                  */
/* ------------------------------------------------------------------ */

async function handleGetVersions(db: D1Database): Promise<Response> {
  const rows = await db
    .prepare('SELECT tool_id, version, channel, openshift, image, git_ref, deploy_url, updated_at FROM tool_versions ORDER BY tool_id, version')
    .all<ToolVersionRow>();

  const versions: Record<string, VersionEntry[]> = {};
  for (const row of rows.results) {
    if (!versions[row.tool_id]) {
      versions[row.tool_id] = [];
    }
    versions[row.tool_id].push({
      version: row.version,
      channel: row.channel,
      openshift: row.openshift,
      image: row.image,
      gitRef: row.git_ref,
      deployUrl: row.deploy_url,
    });
  }

  return json({ versions }, 200, 300);
}

async function handleGetVersionsByTool(db: D1Database, toolId: string): Promise<Response> {
  const rows = await db
    .prepare('SELECT tool_id, version, channel, openshift, image, git_ref, deploy_url, updated_at FROM tool_versions WHERE tool_id = ? ORDER BY version')
    .bind(toolId)
    .all<ToolVersionRow>();

  const versions: VersionEntry[] = rows.results.map(row => ({
    version: row.version,
    channel: row.channel,
    openshift: row.openshift,
    image: row.image,
    gitRef: row.git_ref,
    deployUrl: row.deploy_url,
  }));

  return json({ toolId, versions }, 200, 300);
}

async function handlePostVersion(request: Request, db: D1Database, env: Env, ip: string): Promise<Response> {
  if (adminBlocked(ip)) {
    return errorResponse(429, 'Too many failed admin attempts. Try again later.');
  }
  if (!(await isAuthorized(request, env))) {
    recordAdminFailure(ip);
    return errorResponse(401, 'Unauthorized: invalid or missing admin token');
  }

  let body: {
    toolId?: string;
    version?: string;
    channel?: string;
    openshift?: string;
    image?: string;
    gitRef?: string;
    deployUrl?: string;
    category?: string;
    description?: string;
    displayName?: string;
    href?: string;
    icon?: string;
    git?: string;
    minStorefront?: string;
    /** spec.security of the tool (object), or null to clear it. */
    security?: unknown;
    /** versions[].security of this row (object), or null to clear it. */
    versionSecurity?: unknown;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, 'Invalid JSON body');
  }

  const toolId = body.toolId?.trim();
  const version = body.version?.trim();
  const channel = body.channel?.trim() || 'stable';
  const openshift = body.openshift?.trim();
  const image = body.image?.trim();
  const gitRef = body.gitRef?.trim() || null;
  const deployUrl = body.deployUrl?.trim() || null;
  const category = body.category?.trim() || null;
  const description = body.description?.trim() || null;
  const displayName = body.displayName?.trim() || null;
  const href = body.href?.trim() || null;
  const icon = body.icon?.trim() || null;
  const git = body.git?.trim() || null;
  const minStorefront = body.minStorefront?.trim() || null;
  const security = securityJson(body.security);
  const versionSecurity = securityJson(body.versionSecurity);

  if (!toolId || !TOOL_ID_RE.test(toolId)) {
    return errorResponse(400, 'Missing or invalid toolId (a DNS-1123 name such as oct-my-tool)');
  }
  if (minStorefront && !SEMVER_RE.test(minStorefront)) {
    return errorResponse(400, 'minStorefront must be a semver such as 1.6.0');
  }
  for (const [name, v] of [['security', security], ['versionSecurity', versionSecurity]] as const) {
    if (v && typeof v === 'object') return errorResponse(400, `${name}: ${v.error}`);
  }
  if (!version) {
    return errorResponse(400, 'Missing version');
  }
  if (!openshift) {
    return errorResponse(400, 'Missing openshift');
  }
  if (!image) {
    return errorResponse(400, 'Missing image');
  }

  // Like the tool-level declaration: an object sets the row's security, null clears
  // it, and omitting versionSecurity leaves the stored value alone.
  const keepRowSecurity = body.versionSecurity === undefined;
  await db
    .prepare(
      `INSERT INTO tool_versions (tool_id, version, channel, openshift, image, git_ref, deploy_url, min_storefront, security, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(tool_id, version, openshift)
       DO UPDATE SET channel = excluded.channel, image = excluded.image,
                     git_ref = excluded.git_ref, deploy_url = excluded.deploy_url,
                     min_storefront = excluded.min_storefront,
                     security = ${keepRowSecurity ? 'tool_versions.security' : 'excluded.security'},
                     updated_at = datetime('now')`
    )
    .bind(toolId, version, channel, openshift, image, gitRef, deployUrl, minStorefront, (versionSecurity as string | null | undefined) ?? null)
    .run();

  // The tool-level declaration is replaced whenever seed.js sends the field
  // (an object sets it, null clears it); omitting the field leaves it alone.
  if (security !== undefined) {
    await db
      .prepare(
        `INSERT INTO tools_stats (tool_id, downloads, security) VALUES (?, 0, ?)
         ON CONFLICT(tool_id) DO UPDATE SET security = excluded.security`
      )
      .bind(toolId, security as string | null)
      .run();
  }

  const hasMetadata = category || description || displayName || href || icon || git;
  if (hasMetadata) {
    await db
      .prepare(
        `INSERT INTO tools_stats (tool_id, downloads, category, description, display_name, href, icon, git)
         VALUES (?, 0, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(tool_id) DO UPDATE SET
           category = COALESCE(excluded.category, tools_stats.category),
           description = COALESCE(excluded.description, tools_stats.description),
           display_name = COALESCE(excluded.display_name, tools_stats.display_name),
           href = COALESCE(excluded.href, tools_stats.href),
           icon = COALESCE(excluded.icon, tools_stats.icon),
           git = COALESCE(excluded.git, tools_stats.git)`
      )
      .bind(toolId, category, description, displayName, href, icon, git)
      .run();
  }

  return json({ ok: true, toolId, version, openshift });
}

/* ------------------------------------------------------------------ */
/*  Router                                                            */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // Health check
    if (pathname === '/health' && method === 'GET') {
      return json({ ok: true, version: '1.2.0' });
    }

    // GET stats (read-only, cached)
    if (pathname === '/v1/stats' && method === 'GET') {
      return handleGetStats(env.DB);
    }

    // GET catalog-format stats (for storefront sidecar public-catalog fetch)
    if ((pathname === '/v1/catalog' || pathname === '/') && method === 'GET') {
      return handleGetCatalog(env.DB);
    }

    // GET /v1/versions — all tool versions
    if (pathname === '/v1/versions' && method === 'GET') {
      return handleGetVersions(env.DB);
    }

    // GET /v1/versions/:toolId — versions for a single tool
    const versionMatch = pathname.match(/^\/v1\/versions\/([^/]+)$/);
    if (versionMatch && method === 'GET') {
      return handleGetVersionsByTool(env.DB, decodeURIComponent(versionMatch[1]));
    }

    // Write endpoints — rate limit
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    // POST /v1/versions — admin-only upsert (failed auth attempts are throttled)
    if (pathname === '/v1/versions' && method === 'POST') {
      return handlePostVersion(request, env.DB, env, ip);
    }

    if (pathname === '/v1/stats/download' && method === 'POST') {
      if (await isRateLimited(ip, env)) {
        return errorResponse(429, 'Rate limited. Try again later.');
      }
      return handlePostDownload(request, env.DB);
    }

    if (pathname === '/v1/stats/rating' && method === 'POST') {
      if (await isRateLimited(ip, env)) {
        return errorResponse(429, 'Rate limited. Try again later.');
      }
      return handlePostRating(request, env.DB);
    }

    if (pathname === '/v1/stats/rating' && method === 'DELETE') {
      if (await isRateLimited(ip, env)) {
        return errorResponse(429, 'Rate limited. Try again later.');
      }
      return handleDeleteRating(request, env.DB);
    }

    return errorResponse(404, 'Not found');
  },
} satisfies ExportedHandler<Env>;
