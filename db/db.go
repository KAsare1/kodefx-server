package db

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/gorm"
	"gorm.io/driver/postgres"
)

func NewPSQLStorage() (*gorm.DB, error) {

	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}


	connString := os.Getenv("DB_URL")


	db, err := gorm.Open(postgres.Open(connString), &gorm.Config{

	})

	if err != nil {
		return nil, err
	}

	// Optional: Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)

	sqlDB.SetMaxIdleConns(25)

	return db, nil
}