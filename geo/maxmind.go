package geo

import (
	"fmt"
	"log"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// MaxMindProvider implements geo-tagging using MaxMind GeoIP2 database
type MaxMindProvider struct {
	db *geoip2.Reader
}

// NewMaxMindProvider creates a new MaxMind geo provider
func NewMaxMindProvider(dbPath string) (*MaxMindProvider, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open MaxMind database at %s: %w", dbPath, err)
	}

	return &MaxMindProvider{db: db}, nil
}

// Close closes the MaxMind database
func (p *MaxMindProvider) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// Annotate returns geo labels for the given IP address
func (p *MaxMindProvider) Annotate(ip string) map[string]string {
	if p.db == nil {
		return nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("invalid IP address: %s", ip)
		return nil
	}

	record, err := p.db.City(parsedIP)
	if err != nil {
		log.Printf("failed to lookup IP %s in MaxMind database: %v", ip, err)
		return nil
	}

	labels := make(map[string]string)

	// City name
	if record.City.Names != nil && len(record.City.Names) > 0 {
		if city, ok := record.City.Names["en"]; ok && city != "" {
			labels["city"] = city
		}
	}

	// Latitude and Longitude
	if record.Location.Latitude != 0 || record.Location.Longitude != 0 {
		labels["latitude"] = fmt.Sprintf("%.6f", record.Location.Latitude)
		labels["longitude"] = fmt.Sprintf("%.6f", record.Location.Longitude)
	}

	// Country information (optional but useful)
	if record.Country.Names != nil && len(record.Country.Names) > 0 {
		if country, ok := record.Country.Names["en"]; ok && country != "" {
			labels["country"] = country
		}
	}
	if record.Country.IsoCode != "" {
		labels["country_code"] = record.Country.IsoCode
	}

	// Only return labels if we have at least city or coordinates
	if len(labels) == 0 {
		return nil
	}

	return labels
}

// GetLabels returns the list of label names this provider returns
func (p *MaxMindProvider) GetLabels() []string {
	return []string{"city", "latitude", "longitude", "country", "country_code"}
}
