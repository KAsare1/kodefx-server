package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KAsare1/Kodefx-server/cmd/api"
	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/db"
	"gorm.io/gorm"
)

func main() {
	// Check for command-line arguments
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			runMigrations()
			return
		default:
			log.Fatalf("Unknown command: %s", os.Args[1])
		}
	}

	// Start the server
	startServer()
}

func runMigrations() {
	// Initialize database connection
	DB, err := db.NewPSQLStorage()
	if err != nil {
		log.Fatalf("Database initialization error: %v", err)
	}
	defer func() {
		sqlDB, _ := DB.DB()
		sqlDB.Close()
		log.Println("Database connection closed")
	}()
	log.Println("Connected to the database for migrations")

	// Perform migrations
	if err := performMigrations(DB); err != nil {
		log.Fatalf("Migration error: %v", err)
	}
	log.Println("Migrations completed successfully")
}

func performMigrations(DB *gorm.DB) error {
	// Define migrations
	migrations := map[interface{}]string{
		&models.User{}:              "User",
		&models.Expert{}:            "Expert",
		&models.Availability{}:      "Availability",
		&models.Appointment{}:       "Appointment",
		&models.Post{}:              "Post",
		&models.Image{}:             "Image",
		&models.Comment{}:           "Comment",
		&models.Like{}:              "Like",
		&models.Share{}:             "Share",
		&models.Message{}:           "Message",
		&models.CertificationFile{}: "CertificationFile",
        &models.PasswordResetToken{}: "PasswordResetToken",
	}

	log.Println("Starting database migrations...")
	for model, name := range migrations {
		log.Printf("Migrating %s table...", name)
		if err := DB.AutoMigrate(model); err != nil {
			return fmt.Errorf("error migrating %s table: %w", name, err)
		}
		log.Printf("%s migration successful", name)
	}


	directories := []string{
		"uploads/images",               
		"uploads/certifications",      
	}

	for _, dir := range directories {
		if err := createDirectoryIfNotExist(dir); err != nil {
			log.Fatalf("Error creating directory %s: %v", dir, err)
		}
		log.Printf("Directory %s created/verified", dir)
	}

	log.Println("All migrations and directory setup completed successfully")
	return nil
}


func createDirectoryIfNotExist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("could not create directory %s: %w", path, err)
		}
	}
	return nil
}


func startServer() {
	// Initialize database connection
	DB, err := db.NewPSQLStorage()
	if err != nil {
		log.Fatalf("Database initialization error: %v", err)
	}
	defer func() {
		sqlDB, _ := DB.DB()
		sqlDB.Close()
		log.Println("Database connection closed")
	}()
	log.Println("Connected to the database")

	// Graceful shutdown setup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start the API server
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	server := api.NewApiServer(":"+port, DB)
	go func() {
		if err := server.Run(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()
	log.Printf("Server running on port %s", port)

	<-quit
	log.Println("Shutting down server...")
}
