# Beta Changelog

This document tracks beta releases and pre-release versions.

## [1.1.0-beta] - 2026-08-07

### Added
- Fail2ban SQLite database reader (`--collector.f2b.database`) using a pure Go driver (`modernc.org/sqlite`, no cgo) — logs a warning and continues if the database cannot be opened
- Time-based ban metrics: `f2b_ban_duration_remaining_seconds`, `f2b_ban_age_seconds`, `f2b_ban_expiry_timestamp`
- Historical ban metrics: `f2b_ban_history_total`, `f2b_ip_ban_count_total`, `f2b_ip_first_seen_timestamp`, `f2b_ip_last_seen_timestamp`, `f2b_repeat_offender`
- Geographic aggregate metrics: `f2b_attacks_by_country_total`, `f2b_attacks_by_city_total`, `f2b_top_attack_countries`, `f2b_geographic_attack_rate`
- Heuristic attack-pattern metrics: `f2b_attack_pattern_type` (brute_force / port_scan / distributed, per jail), `f2b_attacks_by_hour`, `f2b_attacks_by_day_of_week`, `f2b_attack_velocity`, `f2b_suspicious_pattern_score`
- Alert gauges with configurable thresholds (`--alert.ban-rate-threshold`, `--alert.coordinated-min-ips`, `--alert.jail-inactivity-hours`): `f2b_alert_high_ban_rate`, `f2b_alert_new_country_attack`, `f2b_alert_coordinated_attack`, `f2b_alert_jail_inactive`, `f2b_alert_repeat_offender_spike`
- Multi-tenant labels `customer_id`, `customer_name`, `tenant_id` on all metrics (`--customer.id`, `--customer.name`, `--tenant.id`)
- Collector self-metrics: `f2b_collection_duration_seconds`, `f2b_database_query_duration_seconds`, `f2b_geo_lookup_duration_seconds`, `f2b_metrics_exported_total`, `f2b_collection_errors_total`
- Per-IP series cap `--collector.f2b.max-ip-metrics` (default 500, most recent first, 0 = unlimited) to bound metric cardinality on busy hosts
- Database query cache `--collector.f2b.database-cache-ttl` (default 60s) so frequent Prometheus scrapes do not run full-table SQLite scans every time
- Unit tests for the database reader and pattern detectors; release workflow now runs tests before building
- Reworked example Grafana dashboard covering the new metric families
- `.gitattributes` enforcing LF line endings (repo syncs through Windows)

### Changed
- **Breaking/behavioral:** module path and repository moved from `github.com/Kvrnn/...` to `github.com/NightSquawk/fail2ban-prometheus-exporter`
- **Behavioral:** database-backed metrics are opt-in — `--collector.f2b.database` defaults to empty instead of `/var/lib/fail2ban/fail2ban.sqlite3`, so upgrading does not silently create hundreds of new per-IP series on hosts with a readable fail2ban database
- All metrics now carry the customer/tenant label set (empty strings when unset); dashboards matching on exact label sets may need updating

### Fixed
- Active-ban database queries compared an integer timestamp against a text value, so they never matched any rows; the timestamp is now cast correctly
- Attack-pattern detection rebuilt per scrape — previously bans were re-added to a persistent detector on every scrape, inflating pattern counts and growing memory

## [1.0.0-beta] - 2025-12-12

### Added
- Initial beta release of fail2ban-prometheus-exporter with geo-tagging support
- System name (hostname) label on all metrics
- Per-IP banned metrics (`f2b_banned_ip`) with geo-tagging support
- MaxMind GeoIP2 integration for location data (city, latitude, longitude, country, country_code)
- Support for reading banned IPs from fail2ban socket
- Comprehensive Prometheus metrics including:
  - Jail statistics (banned/failed counts)
  - Jail configuration (ban time, find time, max retries)
  - Error tracking
  - Version information
- GitHub Actions workflows for automated builds and releases
- Support for Linux (amd64) and Windows (amd64) builds

### Changed
- Forked from original GitLab repository and updated for GitHub
- Integrated geo-tagging functionality from fail2ban-geo-exporter
- Enhanced metrics with system labels for multi-instance monitoring