# Beta Changelog

This document tracks beta releases and pre-release versions.

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