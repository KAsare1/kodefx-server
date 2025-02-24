package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
        case "clear-db":
            runDatabaseClear()
            return
        default:
            log.Fatalf("Unknown command: %s", os.Args[1])
        }
    }

    // Start the server
    startServer()
}

func runMigrations() {
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
		&models.PeerMessage{}:           "Message",
		&models.CertificationFile{}: "CertificationFile",
        &models.PasswordResetToken{}: "PasswordResetToken",
        &models.Channel{}:           "Channel",
		&models.ChannelMessage{}:    "ChannelMessage",
		&models.Client{}:            "Client",
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


func clearDatabase(DB *gorm.DB, tables []interface{}) error {
    if len(tables) == 0 {
        // Default: Drop all tables
        tables = []interface{}{
            &models.Like{},
            &models.Comment{},
            &models.Share{},
            &models.PeerMessage{},
            &models.Appointment{},
            &models.Availability{},
            &models.Post{},
            &models.Image{},
            &models.CertificationFile{},
            &models.PasswordResetToken{},
            &models.Expert{},
            &models.User{},

            &models.Channel{},           
            &models.ChannelMessage{},  
            &models.Client{},     
        }
    }

    log.Println("Dropping tables...")

    for _, table := range tables {
        if err := DB.Migrator().DropTable(table); err != nil {
            log.Printf("Warning dropping table %T: %v", table, err)
        } else {
            log.Printf("Table %T dropped", table)
        }
    }

    return nil
}

func runDatabaseClear() {
    DB, err := db.NewPSQLStorage()
    if err != nil {
        log.Fatalf("Database initialization error: %v", err)
    }
    defer func() {
        sqlDB, _ := DB.DB()
        sqlDB.Close()
        log.Println("Database connection closed")
    }()

    log.Println("Preparing to clear database...")

    // Optional: Add a confirmation prompt
    var confirmation string
    fmt.Print("Are you sure you want to clear the database? (yes/no): ")
    fmt.Scanln(&confirmation)

    if confirmation != "yes" {
        log.Println("Database clearing cancelled.")
        return
    }

    // Ask for specific tables to clear
    var tableNames string
    fmt.Print("Enter table names to clear (comma separated) or leave blank to clear all: ")
    fmt.Scanln(&tableNames)

    var tables []interface{}
    if tableNames != "" {
        tableList := splitTableNames(tableNames)
        for _, table := range tableList {
            switch table {
            case "User":
                tables = append(tables, &models.User{})
            case "Expert":
                tables = append(tables, &models.Expert{})
            case "Availability":
                tables = append(tables, &models.Availability{})
            case "Appointment":
                tables = append(tables, &models.Appointment{})
            case "Post":
                tables = append(tables, &models.Post{})
            case "Image":
                tables = append(tables, &models.Image{})
            case "Comment":
                tables = append(tables, &models.Comment{})
            case "Like":
                tables = append(tables, &models.Like{})
            case "Share":
                tables = append(tables, &models.Share{})
            case "Message":
                tables = append(tables, &models.PeerMessage{})
            case "CertificationFile":
                tables = append(tables, &models.CertificationFile{})
            case "PasswordResetToken":
                tables = append(tables, &models.PasswordResetToken{})
            case "Channel":
                tables = append(tables, &models.Channel{})
            case "ChannelMessage":
                tables = append(tables, &models.ChannelMessage{})
            case "Client":
                tables = append(tables, &models.Client{})
            default:
                log.Printf("Unknown table: %s", table)
            }
        }
    }

    // Clear the specified tables (or all tables if none specified)
    if err := clearDatabase(DB, tables); err != nil {
        log.Fatalf("Error clearing database: %v", err)
    }

    log.Println("Database cleared successfully")
}

func splitTableNames(tableNames string) []string {
    return strings.Split(tableNames, ",")
}



