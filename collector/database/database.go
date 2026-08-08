package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // Pure Go SQLite driver - blank import to register driver
)

// Database wraps SQLite database access for fail2ban
type Database struct {
	db *sql.DB
}

// NewDatabase opens a connection to the fail2ban SQLite database
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database at %s: %w", dbPath, err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{db: db}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// GetDB returns the underlying sql.DB for direct queries if needed
func (d *Database) GetDB() *sql.DB {
	return d.db
}
