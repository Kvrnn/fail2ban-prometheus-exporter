package database

import (
	"path/filepath"
	"testing"
	"time"
)

// newTestDB creates a temporary SQLite database with the fail2ban bans schema
// and the given rows, and returns an open Database handle.
func newTestDB(t *testing.T, rows []BannedIP) *Database {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "fail2ban.sqlite3")
	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.GetDB().Exec(`CREATE TABLE bans (jail TEXT, ip TEXT, timeofban INTEGER, bantime INTEGER)`); err != nil {
		t.Fatalf("failed to create bans table: %v", err)
	}
	for _, row := range rows {
		if _, err := db.GetDB().Exec(
			`INSERT INTO bans (jail, ip, timeofban, bantime) VALUES (?, ?, ?, ?)`,
			row.Jail, row.IP, row.TimeOfBan, row.BanTime,
		); err != nil {
			t.Fatalf("failed to insert test ban: %v", err)
		}
	}
	return db
}

func TestNewDatabaseInvalidPath(t *testing.T) {
	_, err := NewDatabase(filepath.Join(t.TempDir(), "missing-dir", "fail2ban.sqlite3"))
	if err == nil {
		t.Fatal("expected error opening database in nonexistent directory, got nil")
	}
}

func TestGetBannedIPsFiltersExpired(t *testing.T) {
	now := time.Now().Unix()
	db := newTestDB(t, []BannedIP{
		{Jail: "sshd", IP: "192.0.2.1", TimeOfBan: now - 60, BanTime: 3600},   // active
		{Jail: "sshd", IP: "192.0.2.2", TimeOfBan: now - 7200, BanTime: 3600}, // expired
	})

	active, err := db.GetBannedIPs()
	if err != nil {
		t.Fatalf("GetBannedIPs failed: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active ban, got %d", len(active))
	}
	got := active[0]
	if got.IP != "192.0.2.1" || got.Jail != "sshd" {
		t.Errorf("unexpected ban returned: %+v", got)
	}
	if got.ExpiryTime != got.TimeOfBan+got.BanTime {
		t.Errorf("ExpiryTime = %d, want %d", got.ExpiryTime, got.TimeOfBan+got.BanTime)
	}
}

func TestGetAllBansIncludesExpired(t *testing.T) {
	now := time.Now().Unix()
	db := newTestDB(t, []BannedIP{
		{Jail: "sshd", IP: "192.0.2.1", TimeOfBan: now - 60, BanTime: 3600},
		{Jail: "sshd", IP: "192.0.2.2", TimeOfBan: now - 7200, BanTime: 3600},
		{Jail: "recidive", IP: "192.0.2.1", TimeOfBan: now - 30, BanTime: 86400},
	})

	all, err := db.GetAllBans()
	if err != nil {
		t.Fatalf("GetAllBans failed: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 bans, got %d", len(all))
	}
}

func TestGetBannedIPsByJail(t *testing.T) {
	now := time.Now().Unix()
	db := newTestDB(t, []BannedIP{
		{Jail: "sshd", IP: "192.0.2.1", TimeOfBan: now - 60, BanTime: 3600},
		{Jail: "recidive", IP: "192.0.2.2", TimeOfBan: now - 60, BanTime: 3600},
		{Jail: "sshd", IP: "192.0.2.3", TimeOfBan: now - 7200, BanTime: 3600}, // expired
	})

	ips, err := db.GetBannedIPsByJail("sshd")
	if err != nil {
		t.Fatalf("GetBannedIPsByJail failed: %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("expected active sshd ban [192.0.2.1], got %v", ips)
	}
}

func TestGetIPBanHistory(t *testing.T) {
	now := time.Now().Unix()
	db := newTestDB(t, []BannedIP{
		{Jail: "sshd", IP: "192.0.2.1", TimeOfBan: now - 7200, BanTime: 3600},
		{Jail: "recidive", IP: "192.0.2.1", TimeOfBan: now - 60, BanTime: 86400},
		{Jail: "sshd", IP: "192.0.2.9", TimeOfBan: now - 60, BanTime: 3600},
	})

	history, err := db.GetIPBanHistory("192.0.2.1")
	if err != nil {
		t.Fatalf("GetIPBanHistory failed: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 bans for 192.0.2.1, got %d", len(history))
	}
	for _, ban := range history {
		if ban.IP != "192.0.2.1" {
			t.Errorf("history contains ban for wrong IP: %+v", ban)
		}
	}
}
