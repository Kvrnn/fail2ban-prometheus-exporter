package f2b

import (
	"log"
	"os"

	"github.com/Kvrnn/fail2ban-prometheus-exporter/cfg"
	"github.com/Kvrnn/fail2ban-prometheus-exporter/geo"
	"github.com/Kvrnn/fail2ban-prometheus-exporter/socket"
	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	socketPath                 string
	exporterVersion            string
	hostname                   string
	lastError                  error
	socketConnectionErrorCount int
	socketRequestErrorCount    int
	exitOnSocketConnError      bool
	geoProvider                geo.Provider
	geoEnabled                 bool
}

func NewExporter(appSettings *cfg.AppSettings, exporterVersion string) *Collector {
	log.Printf("reading fail2ban metrics from socket file: %s", appSettings.Fail2BanSocketPath)
	printFail2BanServerVersion(appSettings.Fail2BanSocketPath)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("warning: failed to get hostname: %v, using 'unknown'", err)
		hostname = "unknown"
	}

	collector := &Collector{
		socketPath:                 appSettings.Fail2BanSocketPath,
		exporterVersion:            exporterVersion,
		hostname:                   hostname,
		lastError:                  nil,
		socketConnectionErrorCount: 0,
		socketRequestErrorCount:    0,
		exitOnSocketConnError:      appSettings.ExitOnSocketConnError,
		geoEnabled:                 appSettings.Geo.Enabled,
	}

	// Initialize geo provider if enabled
	if appSettings.Geo.Enabled {
		if appSettings.Geo.DBPath == "" {
			log.Printf("warning: geo-tagging enabled but no database path provided")
		} else {
			if appSettings.Geo.Provider == "maxmind" {
				geoProvider, err := geo.NewMaxMindProvider(appSettings.Geo.DBPath)
				if err != nil {
					log.Printf("warning: failed to initialize MaxMind geo provider: %v", err)
				} else {
					collector.geoProvider = geoProvider
					log.Printf("geo-tagging enabled with MaxMind database: %s", appSettings.Geo.DBPath)
				}
			} else {
				log.Printf("warning: unknown geo provider: %s", appSettings.Geo.Provider)
			}
		}
	}

	return collector
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricServerUp
	ch <- metricJailCount
	ch <- metricJailFailedCurrent
	ch <- metricJailFailedTotal
	ch <- metricJailBannedCurrent
	ch <- metricJailBannedTotal
	ch <- metricErrorCount
	ch <- metricBannedIP
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		if c.exitOnSocketConnError {
			os.Exit(1)
		}
	} else {
		defer s.Close()
	}

	c.collectServerUpMetric(ch, s)
	if err == nil && s != nil {
		c.collectJailMetrics(ch, s)
		c.collectVersionMetric(ch, s)
	}
	c.collectBannedIPMetrics(ch)
	c.collectErrorCountMetric(ch)
}

func (c *Collector) IsHealthy() bool {
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		return false
	}
	pingSuccess, err := s.Ping()
	if err != nil {
		log.Printf("error pinging fail2ban server: %v", err)
		c.socketRequestErrorCount++
		return false
	}
	return pingSuccess
}

func (c *Collector) collectBannedIPMetrics(ch chan<- prometheus.Metric) {
	// Get banned IPs from socket
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("failed to connect to socket for banned IP collection: %v", err)
		return
	}
	defer s.Close()

	// Get all jails first
	jails, err := s.GetJails()
	if err != nil {
		log.Printf("failed to get jails for banned IP collection: %v", err)
		return
	}

	// Get banned IPs for each jail
	seenIPs := make(map[string]bool)
	for _, jail := range jails {
		bannedIPs, err := s.GetBannedIPs(jail)
		if err != nil {
			log.Printf("failed to get banned IPs for jail %s: %v", jail, err)
			continue
		}

		for _, ip := range bannedIPs {
			// Create unique key for this jail+IP combination
			key := jail + ":" + ip
			if seenIPs[key] {
				continue
			}
			seenIPs[key] = true

			c.createBannedIPMetric(ch, jail, ip)
		}
	}
}

func (c *Collector) createBannedIPMetric(ch chan<- prometheus.Metric, jail, ip string) {
	// Base labels: jail, ip, system
	labels := []string{jail, ip, c.hostname}

	// Add geo labels if geo provider is available
	// Always include all geo label positions, using empty strings if not available
	var city, latitude, longitude, country, countryCode string

	if c.geoEnabled && c.geoProvider != nil {
		geoLabels := c.geoProvider.Annotate(ip)
		if geoLabels != nil {
			if val, ok := geoLabels["city"]; ok {
				city = val
			}
			if val, ok := geoLabels["latitude"]; ok {
				latitude = val
			}
			if val, ok := geoLabels["longitude"]; ok {
				longitude = val
			}
			if val, ok := geoLabels["country"]; ok {
				country = val
			}
			if val, ok := geoLabels["country_code"]; ok {
				countryCode = val
			}
		}
	}

	// Append geo labels in the order defined in the metric descriptor
	labels = append(labels, city, latitude, longitude, country, countryCode)

	ch <- prometheus.MustNewConstMetric(
		metricBannedIP, prometheus.GaugeValue, float64(1), labels...,
	)
}

func printFail2BanServerVersion(socketPath string) {
	s, err := socket.ConnectToSocket(socketPath)
	if err != nil {
		log.Printf("error connecting to socket: %v", err)
	} else {
		version, err := s.GetServerVersion()
		if err != nil {
			log.Printf("error interacting with socket: %v", err)
		} else {
			log.Printf("successfully connected to fail2ban socket! fail2ban version: %s", version)
		}
	}
}
