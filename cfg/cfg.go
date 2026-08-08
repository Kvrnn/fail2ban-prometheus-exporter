package cfg

import (
	"fmt"
	"log"
	"os"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/auth"
	"github.com/alecthomas/kong"
)

var cliStruct struct {
	VersionMode              bool    `name:"version" short:"v" help:"Show version info and exit"`
	DryRunMode               bool    `name:"dry-run" help:"Attempt to connect to the fail2ban socket then exit before starting the server"`
	ServerAddress            string  `name:"web.listen-address" env:"F2B_WEB_LISTEN_ADDRESS" help:"Address to use for the metrics server" default:"${default_address}"`
	F2bSocketPath            string  `name:"collector.f2b.socket" env:"F2B_COLLECTOR_SOCKET" help:"Path to the fail2ban server socket" default:"${default_socket}"`
	F2bDatabasePath          string  `name:"collector.f2b.database" env:"F2B_COLLECTOR_DATABASE" help:"Path to the fail2ban SQLite database (e.g. /var/lib/fail2ban/fail2ban.sqlite3). Empty disables database-backed metrics" default:"${default_database}"`
	F2bMaxIPMetrics          int     `name:"collector.f2b.max-ip-metrics" env:"F2B_COLLECTOR_MAX_IP_METRICS" help:"Maximum number of per-IP series to export per metric family, most recent first (0 = unlimited)" default:"500"`
	F2bDatabaseCacheTTL      int     `name:"collector.f2b.database-cache-ttl" env:"F2B_COLLECTOR_DATABASE_CACHE_TTL" help:"Seconds to cache fail2ban database query results between scrapes (0 = query on every scrape)" default:"60"`
	ExitOnSocketError        bool    `name:"collector.f2b.exit-on-socket-connection-error" env:"F2B_EXIT_ON_SOCKET_CONN_ERROR" help:"When set to true the exporter will immediately exit on a fail2ban socket connection error"`
	TextFileExporterPath     string  `name:"collector.textfile.directory" env:"F2B_COLLECTOR_TEXT_PATH" help:"Directory to read text files with metrics from"`
	BasicAuthUser            string  `name:"web.basic-auth.username" env:"F2B_WEB_BASICAUTH_USER" help:"Username to use to protect endpoints with basic auth"`
	BasicAuthPass            string  `name:"web.basic-auth.password" env:"F2B_WEB_BASICAUTH_PASS" help:"Password to use to protect endpoints with basic auth"`
	GeoEnabled               bool    `name:"geo.enabled" env:"F2B_GEO_ENABLED" help:"Enable geo-tagging of banned IPs"`
	GeoDBPath                string  `name:"geo.db-path" env:"F2B_GEO_DB_PATH" help:"Path to MaxMind GeoLite2-City.mmdb database file"`
	GeoProvider              string  `name:"geo.provider" env:"F2B_GEO_PROVIDER" help:"Geo provider to use (default: maxmind)" default:"maxmind"`
	CustomerID               string  `name:"customer.id" env:"F2B_CUSTOMER_ID" help:"Customer identifier for multi-tenant support"`
	CustomerName             string  `name:"customer.name" env:"F2B_CUSTOMER_NAME" help:"Customer name for multi-tenant support"`
	TenantID                 string  `name:"tenant.id" env:"F2B_TENANT_ID" help:"Tenant identifier for multi-tenant support"`
	AlertBanRateThreshold    float64 `name:"alert.ban-rate-threshold" env:"F2B_ALERT_BAN_RATE_THRESHOLD" help:"Ban rate threshold (bans per minute) for high ban rate alert" default:"10"`
	AlertCoordinatedMinIPs   int     `name:"alert.coordinated-min-ips" env:"F2B_ALERT_COORDINATED_MIN_IPS" help:"Minimum number of IPs for coordinated attack alert" default:"5"`
	AlertJailInactivityHours int     `name:"alert.jail-inactivity-hours" env:"F2B_ALERT_JAIL_INACTIVITY_HOURS" help:"Hours of inactivity before jail inactivity alert" default:"24"`
}

func Parse() *AppSettings {
	ctx := kong.Parse(
		&cliStruct,
		kong.Vars{
			"default_socket":   "/var/run/fail2ban/fail2ban.sock",
			"default_address":  ":9191",
			"default_database": "",
		},
		kong.Name("fail2ban_exporter"),
		kong.Description("🚀 Export prometheus metrics from a running Fail2Ban instance"),
		kong.UsageOnError(),
	)

	validateFlags(ctx)
	settings := &AppSettings{
		VersionMode:           cliStruct.VersionMode,
		DryRunMode:            cliStruct.DryRunMode,
		MetricsAddress:        cliStruct.ServerAddress,
		Fail2BanSocketPath:    cliStruct.F2bSocketPath,
		Fail2BanDatabasePath:  cliStruct.F2bDatabasePath,
		MaxIPMetrics:          cliStruct.F2bMaxIPMetrics,
		DatabaseCacheTTL:      cliStruct.F2bDatabaseCacheTTL,
		FileCollectorPath:     cliStruct.TextFileExporterPath,
		ExitOnSocketConnError: cliStruct.ExitOnSocketError,
		AuthProvider:          createAuthProvider(),
		Geo: GeoSettings{
			Enabled:  cliStruct.GeoEnabled,
			DBPath:   cliStruct.GeoDBPath,
			Provider: cliStruct.GeoProvider,
		},
		Customer: CustomerSettings{
			ID:       cliStruct.CustomerID,
			Name:     cliStruct.CustomerName,
			TenantID: cliStruct.TenantID,
		},
		Alert: AlertSettings{
			HighBanRateThreshold:    cliStruct.AlertBanRateThreshold,
			CoordinatedAttackMinIPs: cliStruct.AlertCoordinatedMinIPs,
			JailInactivityHours:     cliStruct.AlertJailInactivityHours,
		},
	}
	return settings
}

func createAuthProvider() auth.AuthProvider {
	username := cliStruct.BasicAuthUser
	password := cliStruct.BasicAuthPass

	if len(username) == 0 && len(password) == 0 {
		return auth.NewEmptyAuthProvider()
	}
	log.Print("basic auth enabled")
	return auth.NewBasicAuthProvider(username, password)
}

func validateFlags(cliCtx *kong.Context) {
	var flagsValid = true
	var messages = []string{}
	if !cliStruct.VersionMode {
		if cliStruct.F2bSocketPath == "" {
			messages = append(messages, "error: fail2ban socket path must not be blank")
			flagsValid = false
		}
		if cliStruct.ServerAddress == "" {
			messages = append(messages, "error: invalid server address, must not be blank")
			flagsValid = false
		}
		if (len(cliStruct.BasicAuthUser) > 0) != (len(cliStruct.BasicAuthPass) > 0) {
			messages = append(messages, "error: to enable basic auth both the username and the password must be provided")
			flagsValid = false
		}
	}
	if !flagsValid {
		cliCtx.PrintUsage(false)
		fmt.Println()
		for i := 0; i < len(messages); i++ {
			fmt.Println(messages[i])
		}
		os.Exit(1)
	}
}
