package main

import (
	"log"
	"os"

	"github.com/KAsare1/Kodefx-server/cmd/api"
	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/db"
)

func main() {    DB, err := db.NewPSQLStorage()
    if err != nil {
        log.Fatalf("Database initialization error: %v", err)
    }
    

    sqlDB, err := DB.DB()
    if err != nil {
        log.Fatalf("Failed to get SQL database: %v", err)
    }
    defer sqlDB.Close()
    log.Println("Connected to the database")

    // Create tables in correct order
    migrations := map[interface{}]string{
        &models.User{}: "User",
        &models.Expert{}: "Expert",
        &models.Availability{}: "Availability",
        &models.Appointment{}: "Appointment",
        &models.Post{}: "Post",
        &models.Image{}: "Image",
        &models.Comment{}: "Comment",
        &models.Like{}: "Like",
        &models.Share{}: "Share",
		&models.Message{}: "Message",
    }


    log.Println("Starting database migrations...")
    for model, name := range migrations {
        if err := DB.AutoMigrate(model); err != nil {
            log.Fatalf("Error migrating %s table: %v", name, err)
        }
        log.Printf("%s migration successful", name)
    }


    if err := os.MkdirAll("uploads/images", 0755); err != nil {
        log.Fatalf("Error creating uploads directory: %v", err)
    }
    log.Println("Image uploads directory created/verified")


    server := api.NewApiServer(":8080", DB)
    if err := server.Run(); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}