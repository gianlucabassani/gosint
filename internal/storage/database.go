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
	db *gorm.DB
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
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	dbInstance = &Database{db: db}
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
