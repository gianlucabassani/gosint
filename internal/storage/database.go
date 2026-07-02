package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	db   *gorm.DB
	path string // on-disk path of the SQLite file (for size/backup)
}

var dbInstance *Database

// Initialize creates/opens the SQLite database
func Initialize(dbPath string) (*Database, error) {
	if dbInstance != nil {
		return dbInstance, nil
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// Open database connection
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// Auto-migrate schemas
	if err := db.AutoMigrate(
		&Target{},
		&ScanResult{},
		&FuzzResult{},
		&Subdomain{},
		&Technology{},
		&EmailProfile{},
		&BreachEntry{},
		&SocialProfile{},
		// OSINT/entity hub (browsint consolidation — see CONSOLIDATION.md)
		&Entity{},
		&DomainInfo{},
		&OSINTProfile{},
		&Contact{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	dbInstance = &Database{db: db, path: dbPath}
	return dbInstance, nil
}

// GetInstance returns the singleton database instance
func GetInstance() *Database {
	if dbInstance == nil {
		panic("database not initialized - call Initialize() first")
	}
	return dbInstance
}

// Close closes the database connection
func (d *Database) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetDatabaseSize returns the size of the SQLite file in bytes.
func (d *Database) GetDatabaseSize() (int64, error) {
	if d.path == "" {
		return 0, fmt.Errorf("database path unknown")
	}
	info, err := os.Stat(d.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Backup writes a consistent snapshot of the database to destPath using SQLite's
// `VACUUM INTO`, which is safe to run against a live connection. Parent dirs are
// created as needed. Returns the destination path on success.
func (d *Database) Backup(destPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("creating backup directory: %w", err)
	}
	// VACUUM INTO refuses to overwrite an existing file.
	if _, err := os.Stat(destPath); err == nil {
		return "", fmt.Errorf("backup target already exists: %s", destPath)
	}
	if err := d.db.Exec("VACUUM INTO ?", destPath).Error; err != nil {
		return "", fmt.Errorf("vacuum into %q: %w", destPath, err)
	}
	return destPath, nil
}

// GetTargetReportData fetches all data related to a target for reporting
func (d *Database) GetTargetReportData(targetInput string) (*Target, error) {
	var target Target

	result := d.db.Preload("ScanResults").
		Preload("FuzzResults").
		Preload("Subdomains").
		Preload("Technologies").
		Where("domain = ?", targetInput).
		First(&target)

	if result.Error != nil {
		return nil, result.Error
	}

	return &target, nil
}
