package cfg

import "github.com/NightSquawk/fail2ban-prometheus-exporter/auth"

type GeoSettings struct {
	Enabled  bool
	DBPath   string
	Provider string
}

type CustomerSettings struct {
	ID       string
	Name     string
	TenantID string
}

type AlertSettings struct {
	HighBanRateThreshold    float64
	CoordinatedAttackMinIPs int
	JailInactivityHours     int
}

type AppSettings struct {
	VersionMode           bool
	DryRunMode            bool
	MetricsAddress        string
	Fail2BanSocketPath    string
	Fail2BanDatabasePath  string
	MaxIPMetrics          int
	DatabaseCacheTTL      int
	FileCollectorPath     string
	AuthProvider          auth.AuthProvider
	ExitOnSocketConnError bool
	Geo                   GeoSettings
	Customer              CustomerSettings
	Alert                 AlertSettings
}
