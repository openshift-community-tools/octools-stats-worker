-- v5: security declarations and storefront compatibility in the public catalog.
--   tools_stats.security         spec.security as JSON (NULL = not declared)
--   tool_versions.security       versions[].security as JSON
--   tool_versions.min_storefront versions[].minStorefront (oldest storefront that can install the row)
-- Existing rows get NULL; seed.js re-posts them. Apply before deploying the v1.2 worker.
ALTER TABLE tools_stats ADD COLUMN security TEXT;
ALTER TABLE tool_versions ADD COLUMN security TEXT;
ALTER TABLE tool_versions ADD COLUMN min_storefront TEXT;
