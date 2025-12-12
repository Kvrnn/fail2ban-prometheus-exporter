package f2b

import (
	"log"

	"github.com/Kvrnn/fail2ban-prometheus-exporter/socket"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "f2b"
)

var (
	metricErrorCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "errors"),
		"Number of errors found since startup",
		[]string{"type", "system"}, nil,
	)
	metricServerUp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Check if the fail2ban server is up",
		[]string{"system"}, nil,
	)
	metricJailCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_count"),
		"Number of defined jails",
		[]string{"system"}, nil,
	)
	metricJailFailedCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_failed_current"),
		"Number of current failures on this jail's filter",
		[]string{"jail", "system"}, nil,
	)
	metricJailFailedTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_failed_total"),
		"Number of total failures on this jail's filter",
		[]string{"jail", "system"}, nil,
	)
	metricJailBannedCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_banned_current"),
		"Number of IPs currently banned in this jail",
		[]string{"jail", "system"}, nil,
	)
	metricJailBannedTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_banned_total"),
		"Total number of IPs banned by this jail (includes expired bans)",
		[]string{"jail", "system"}, nil,
	)
	metricJailBanTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_ban_time"),
		"How long an IP is banned for in this jail (in seconds)",
		[]string{"jail", "system"}, nil,
	)
	metricJailFindTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_find_time"),
		"How far back will the filter look for failures in this jail (in seconds)",
		[]string{"jail", "system"}, nil,
	)
	metricJailMaxRetry = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_max_retries"),
		"The number of failures allowed until the IP is banned by this jail",
		[]string{"jail", "system"}, nil,
	)
	metricVersionInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "version"),
		"Version of the exporter and fail2ban server",
		[]string{"exporter", "fail2ban", "system"}, nil,
	)
	metricBannedIP = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "banned_ip"),
		"Currently banned IP address (value is 1 if banned, 0 otherwise)",
		[]string{"jail", "ip", "system", "city", "latitude", "longitude", "country", "country_code"}, nil,
	)
)

func (c *Collector) collectErrorCountMetric(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		metricErrorCount, prometheus.CounterValue, float64(c.socketConnectionErrorCount), "socket_conn", c.hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		metricErrorCount, prometheus.CounterValue, float64(c.socketRequestErrorCount), "socket_req", c.hostname,
	)
}

func (c *Collector) collectServerUpMetric(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {
	var serverUp float64 = 0
	if s != nil {
		pingSuccess, err := s.Ping()
		if err != nil {
			c.socketRequestErrorCount++
			log.Print(err)
		}
		if err == nil && pingSuccess {
			serverUp = 1
		}
	}
	ch <- prometheus.MustNewConstMetric(
		metricServerUp, prometheus.GaugeValue, serverUp, c.hostname,
	)
}

func (c *Collector) collectJailMetrics(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {
	jails, err := s.GetJails()
	var count float64 = 0
	if err != nil {
		c.socketRequestErrorCount++
		log.Print(err)
	}
	if err == nil {
		count = float64(len(jails))
	}
	ch <- prometheus.MustNewConstMetric(
		metricJailCount, prometheus.GaugeValue, count, c.hostname,
	)

	for i := range jails {
		c.collectJailStatsMetric(ch, s, jails[i])
		c.collectJailConfigMetrics(ch, s, jails[i])
	}
}

func (c *Collector) collectJailStatsMetric(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket, jail string) {
	stats, err := s.GetJailStats(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get stats for jail %s: %v", jail, err)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		metricJailFailedCurrent, prometheus.GaugeValue, float64(stats.FailedCurrent), jail, c.hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		metricJailFailedTotal, prometheus.GaugeValue, float64(stats.FailedTotal), jail, c.hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		metricJailBannedCurrent, prometheus.GaugeValue, float64(stats.BannedCurrent), jail, c.hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		metricJailBannedTotal, prometheus.GaugeValue, float64(stats.BannedTotal), jail, c.hostname,
	)
}

func (c *Collector) collectJailConfigMetrics(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket, jail string) {
	banTime, err := s.GetJailBanTime(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get ban time for jail %s: %v", jail, err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			metricJailBanTime, prometheus.GaugeValue, float64(banTime), jail, c.hostname,
		)
	}
	findTime, err := s.GetJailFindTime(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get find time for jail %s: %v", jail, err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			metricJailFindTime, prometheus.GaugeValue, float64(findTime), jail, c.hostname,
		)
	}
	maxRetry, err := s.GetJailMaxRetries(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get max retries for jail %s: %v", jail, err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			metricJailMaxRetry, prometheus.GaugeValue, float64(maxRetry), jail, c.hostname,
		)
	}
}

func (c *Collector) collectVersionMetric(ch chan<- prometheus.Metric, s *socket.Fail2BanSocket) {
	fail2banVersion, err := s.GetServerVersion()
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get fail2ban server version: %v", err)
	}

	ch <- prometheus.MustNewConstMetric(
		metricVersionInfo, prometheus.GaugeValue, float64(1), c.exporterVersion, fail2banVersion, c.hostname,
	)
}
