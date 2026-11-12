# octools-stats-worker

Cloudflare Worker behind **https://api.octools.net**: the public catalog API for OpenShift Community Tools (OCT). It serves version rows, download counts and ratings, backed by a D1 database. The public API reference is https://octools.net/api/.

**Community project. Not officially supported by Red Hat.**

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | none | `{"ok":true,"version":...}` |
| GET | `/v1/catalog` | none | All tools with stats, metadata and version rows; installed storefronts sync from this (hourly) |
| GET | `/v1/stats` | none | Downloads and ratings |
| GET | `/v1/versions`, `/v1/versions/:toolId` | none | Version rows |
| POST | `/v1/versions` | **admin** | Upsert one version row |
| POST | `/v1/stats/download` | none, rate-limited | Count an install (storefront Add; known tools only). With `clusterHash` (storefront 1.6.1+) each cluster counts once per tool; without it every call counts |
| POST / DELETE | `/v1/stats/rating` | none, rate-limited | Upsert / remove a rating (deduped by cluster hash; known tools only) |

Version rows are keyed by `(toolId, version, openshift)`: **one row per OpenShift minor**, `openshift` is a single string and `image` is that minor's combined tag. Optional fields: `channel`, `gitRef`, `deployUrl`, `minStorefront` (semver), `versionSecurity` (the row's `versions[].security`; like `security`, an object sets it, `null` clears it, omitting it leaves it unchanged), tile metadata (`category`, `description`, `displayName`, `href`, `icon`, `git`), and `security` (the tool's `spec.security`; an object sets it, `null` clears it, omitting it leaves it unchanged). Declarations are capped at 16 KB. `/v1/catalog` returns `security` per tool and `minStorefront` / `security` per version; storefronts older than 1.6 ignore them.

**Writes from storefronts are accepted only for known tools:** a `toolId` must be a DNS-1123 name with at least one published version row, otherwise downloads and ratings get 404. Seed a new tool's rows before announcing it, or its first downloads won't count (storefronts ignore the error).

## Publishing a release (seeding)

Run after the storefront PR that adds the rows is merged, against the storefront's `catalog/community.yaml`:

```bash
DRY_RUN=1 TOOL=<tool-id> CATALOG_PATH=../oct-storefront/catalog/community.yaml node seed.js
ADMIN_TOKEN=<admin token> TOOL=<tool-id> CATALOG_PATH=../oct-storefront/catalog/community.yaml node seed.js
curl -s https://api.octools.net/v1/versions/<tool-id>
```

- `TOOL` limits the run to one tool; without it every catalog row is upserted (idempotent).
- Catalog rows listing several minors are posted as one row per minor; the catalog's `deployURL` is sent as `deployUrl`.
- Use `curl` to check results: Cloudflare rejects some default client user agents (Python `urllib` gets 403).

## The admin token

`ADMIN_TOKEN` is a **Worker secret**, never a `[vars]` entry and never committed (`seed.js` refuses to write without it). Maintainers keep it in a password manager. To rotate:

```bash
openssl rand -hex 32 > <private file, mode 600>
npx wrangler secret put ADMIN_TOKEN < <that file>
```

An old value that was ever committed must be treated as public and rotated, not just moved.

The worker compares the token in constant time and **fails closed** if `ADMIN_TOKEN` is unset or empty. Repeated failed admin attempts from one IP are throttled (10 per minute, then HTTP 429); successful requests, such as a full `seed.js` run, are not limited.

## Rate limits

Writes (`/v1/stats/download`, `/v1/stats/rating`) are limited to 20 per minute per client IP, counted per Cloudflare location (see below).

- With the `WRITE_LIMITER` binding in `wrangler.toml` (Workers Rate Limiting), the limit is shared by all isolates in a Cloudflare location. It is counted per location, not globally.
- Without it, the worker falls back to a per-isolate in-memory limiter. That is weaker, because each isolate counts separately.
- **Admin endpoints:** after 10 failed token attempts in a minute an IP gets 429 from that isolate, even with the right token, until the minute is over. Successful requests don't count, so seeding isn't slowed. This counter is per isolate; for a real limit add a Cloudflare WAF rate-limiting rule for `POST /v1/versions`.

Known limits: ratings accept any well-formed cluster hash, so someone rotating IPs can still add rows (at most 20 writes per minute per IP); downloads and ratings are only accepted for tools with published versions.

## Testing locally

Nothing here touches production:

```bash
npm ci
# In order: a plain glob sorts schema-v2.sql before schema.sql.
for f in schema.sql schema-v2.sql schema-v3.sql schema-v4.sql schema-v5.sql schema-v6.sql; do npx wrangler d1 execute octools-stats --local --file=$f; done
npx wrangler dev --local --var ADMIN_TOKEN:local-test-token
curl -s localhost:8787/health
```

## Deploying

There is no CI; deploys are manual with a Cloudflare API token that has Workers and D1 permissions:

```bash
export CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=...
npx wrangler deploy --dry-run --outdir /tmp/w   # check bindings first
npx wrangler deploy
```

### Database migrations

Schema files are applied in order: `schema.sql`, `schema-v2.sql`, `schema-v3.sql`, `schema-v4.sql` (v4 adds the tile metadata columns `/v1/catalog` selects), `schema-v5.sql` (v5 adds the security and `min_storefront` columns that worker 1.2 selects), `schema-v6.sql` (v6 adds the `installs` table worker 1.3 uses to count each cluster once). **Apply a migration before deploying code that needs it**, and record a restore point first:

```bash
npx wrangler d1 time-travel info octools-stats            # note the bookmark
npx wrangler d1 execute octools-stats --remote --file=./schema-vN.sql
npx wrangler d1 execute octools-stats --remote --command "SELECT name FROM pragma_table_info('tools_stats')"
# rollback if needed: npx wrangler d1 time-travel restore octools-stats --bookmark=<bookmark>
```

After a deploy, re-run `seed.js` without `TOOL` if new columns need to be filled for every tool.

## Related repositories

- `oct-storefront` — the in-console storefront and the canonical `catalog/community.yaml`
- `octools-website` — octools.net (API docs, developer guide)
