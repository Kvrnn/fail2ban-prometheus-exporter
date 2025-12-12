package cfg

import "github.com/Kvrnn/fail2ban-prometheus-exporter/auth"

type GeoSettings struct {
	Enabled  bool
	DBPath   string
	Provider string
}

type AppSettings struct {
	VersionMode           bool
	DryRunMode            bool
	MetricsAddress        string
	Fail2BanSocketPath    string
	FileCollectorPath     string
	AuthProvider          auth.AuthProvider
	ExitOnSocketConnError bool
	Geo                   GeoSettings
}
