package database

import (
	"fmt"
)

// BannedIP represents a banned IP address with its jail and timing information
type BannedIP struct {
	Jail       string
	IP         string
	TimeOfBan  int64 // Unix timestamp when ban was issued
	BanTime    int64 // Ban duration in seconds
	ExpiryTime int64 // Calculated: timeofban + bantime
}

// GetBannedIPs retrieves all currently banned IPs from the fail2ban database
// The fail2ban database schema uses a 'bans' table with columns: jail, ip, timeofban, bantime
func (d *Database) GetBannedIPs() ([]BannedIP, error) {
	// Query to get currently banned IPs with timing information
	// We need to check if the ban is still active by comparing timeofban + bantime with current time
	// Note: strftime returns TEXT and integers always compare below text in
	// SQLite, so the timestamp must be cast for the filter to match anything.
	query := `
		SELECT DISTINCT jail, ip, timeofban, bantime
		FROM bans
		WHERE (timeofban + bantime) > CAST(strftime('%s', 'now') AS INTEGER)
		ORDER BY jail, ip
	`

	rows, err := d.GetDB().Query(query)
	if err != nil {
		// If the query fails, try a simpler query without time check
		// Some fail2ban versions may have different schema
		return d.getBannedIPsSimple()
	}
	defer rows.Close()

	var bannedIPs []BannedIP
	for rows.Next() {
		var jail, ip string
		var timeOfBan, banTime int64
		if err := rows.Scan(&jail, &ip, &timeOfBan, &banTime); err != nil {
			return nil, fmt.Errorf("failed to scan banned IP row: %w", err)
		}
		bannedIPs = append(bannedIPs, BannedIP{
			Jail:       jail,
			IP:         ip,
			TimeOfBan:  timeOfBan,
			BanTime:    banTime,
			ExpiryTime: timeOfBan + banTime,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating banned IP rows: %w", err)
	}

	return bannedIPs, nil
}

// getBannedIPsSimple tries a simpler query without time filtering
// This is a fallback for different database schemas
func (d *Database) getBannedIPsSimple() ([]BannedIP, error) {
	query := `SELECT DISTINCT jail, ip, timeofban, bantime FROM bans ORDER BY jail, ip`

	rows, err := d.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query banned IPs: %w", err)
	}
	defer rows.Close()

	var bannedIPs []BannedIP
	for rows.Next() {
		var jail, ip string
		var timeOfBan, banTime int64
		if err := rows.Scan(&jail, &ip, &timeOfBan, &banTime); err != nil {
			// If time fields don't exist, use zero values
			if err := rows.Scan(&jail, &ip); err != nil {
				return nil, fmt.Errorf("failed to scan banned IP row: %w", err)
			}
			timeOfBan = 0
			banTime = 0
		}
		bannedIPs = append(bannedIPs, BannedIP{
			Jail:       jail,
			IP:         ip,
			TimeOfBan:  timeOfBan,
			BanTime:    banTime,
			ExpiryTime: timeOfBan + banTime,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating banned IP rows: %w", err)
	}

	return bannedIPs, nil
}

// GetAllBans retrieves all bans (active and expired) from the database
func (d *Database) GetAllBans() ([]BannedIP, error) {
	query := `
		SELECT DISTINCT jail, ip, timeofban, bantime 
		FROM bans 
		ORDER BY jail, ip, timeofban DESC
	`

	rows, err := d.GetDB().Query(query)
	if err != nil {
		// Fallback to simple query
		return d.getBannedIPsSimple()
	}
	defer rows.Close()

	var bannedIPs []BannedIP
	for rows.Next() {
		var jail, ip string
		var timeOfBan, banTime int64
		if err := rows.Scan(&jail, &ip, &timeOfBan, &banTime); err != nil {
			// If time fields don't exist, use zero values
			if err := rows.Scan(&jail, &ip); err != nil {
				return nil, fmt.Errorf("failed to scan banned IP row: %w", err)
			}
			timeOfBan = 0
			banTime = 0
		}
		bannedIPs = append(bannedIPs, BannedIP{
			Jail:       jail,
			IP:         ip,
			TimeOfBan:  timeOfBan,
			BanTime:    banTime,
			ExpiryTime: timeOfBan + banTime,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating banned IP rows: %w", err)
	}

	return bannedIPs, nil
}

// GetIPBanHistory retrieves all bans for a specific IP
func (d *Database) GetIPBanHistory(ip string) ([]BannedIP, error) {
	query := `
		SELECT DISTINCT jail, ip, timeofban, bantime 
		FROM bans 
		WHERE ip = ?
		ORDER BY timeofban DESC
	`

	rows, err := d.GetDB().Query(query, ip)
	if err != nil {
		return nil, fmt.Errorf("failed to query ban history for IP %s: %w", ip, err)
	}
	defer rows.Close()

	var bannedIPs []BannedIP
	for rows.Next() {
		var jail, ipAddr string
		var timeOfBan, banTime int64
		if err := rows.Scan(&jail, &ipAddr, &timeOfBan, &banTime); err != nil {
			// If time fields don't exist, use zero values
			if err := rows.Scan(&jail, &ipAddr); err != nil {
				return nil, fmt.Errorf("failed to scan banned IP row: %w", err)
			}
			timeOfBan = 0
			banTime = 0
		}
		bannedIPs = append(bannedIPs, BannedIP{
			Jail:       jail,
			IP:         ipAddr,
			TimeOfBan:  timeOfBan,
			BanTime:    banTime,
			ExpiryTime: timeOfBan + banTime,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating banned IP rows: %w", err)
	}

	return bannedIPs, nil
}

// GetBannedIPsByJail retrieves banned IPs for a specific jail
func (d *Database) GetBannedIPsByJail(jail string) ([]string, error) {
	query := `
		SELECT DISTINCT ip
		FROM bans
		WHERE jail = ? AND (timeofban + bantime) > CAST(strftime('%s', 'now') AS INTEGER)
		ORDER BY ip
	`

	rows, err := d.GetDB().Query(query, jail)
	if err != nil {
		// Fallback to simple query
		return d.getBannedIPsByJailSimple(jail)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("failed to scan IP: %w", err)
		}
		ips = append(ips, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating IP rows: %w", err)
	}

	return ips, nil
}

// getBannedIPsByJailSimple tries a simpler query without time filtering
func (d *Database) getBannedIPsByJailSimple(jail string) ([]string, error) {
	query := `SELECT DISTINCT ip FROM bans WHERE jail = ? ORDER BY ip`

	rows, err := d.GetDB().Query(query, jail)
	if err != nil {
		return nil, fmt.Errorf("failed to query banned IPs for jail %s: %w", jail, err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("failed to scan IP: %w", err)
		}
		ips = append(ips, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating IP rows: %w", err)
	}

	return ips, nil
}
