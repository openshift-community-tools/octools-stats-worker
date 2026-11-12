-- v6: count each cluster once per tool.
--   installs(tool_id, cluster_hash)  one row per tool and anonymous cluster hash
--                                    (the same SHA-256 the storefront already sends with ratings).
-- POST /v1/stats/download with a clusterHash adds 1 to tools_stats.downloads only when that
-- cluster had not been counted for the tool yet. Requests without a hash (storefronts
-- before 1.6.1) still add 1, as before. Existing counters are kept.
-- Apply before deploying the v1.3 worker.
CREATE TABLE IF NOT EXISTS installs (
  tool_id      TEXT NOT NULL,
  cluster_hash TEXT NOT NULL,
  first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (tool_id, cluster_hash)
);
