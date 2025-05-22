package models

import (
	"time"

	"gorm.io/gorm"
)

type Device struct {
    gorm.Model // This already includes ID, CreatedAt, UpdatedAt, DeletedAt
    Token      string `gorm:"not null;uniqueIndex:idx_token_user" json:"token"`
    UserID     string `gorm:"not null;index;uniqueIndex:idx_token_user" json:"userId"`
    DeviceType string `gorm:"type:varchar(50)" json:"deviceType"` // New field
    DeviceName string `gorm:"type:varchar(100)" json:"deviceName,omitempty"` // New field
}

// NotificationRequest represents a request to send a notification
type NotificationRequest struct {
    Token string                 `json:"token"`
    Title string                 `json:"title"`
    Body  string                 `json:"body"`
    Data  map[string]interface{} `json:"data,omitempty"`
}

// BroadcastRequest represents a request to broadcast to all devices
type BroadcastRequest struct {
    Title   string                 `json:"title"`
    Body    string                 `json:"body"`
    Data    map[string]interface{} `json:"data,omitempty"`
    UserIDs []string               `json:"userIds,omitempty"` // Optional: specific users to notify
}


type NotificationHistory struct {
    gorm.Model
    UserID  string    `gorm:"index" json:"userId"`
    Title   string    `json:"title"`
    Body    string    `json:"body"`
    Data    string    `gorm:"type:text" json:"data,omitempty"` // JSON string of additional data
    Status  string    `gorm:"type:varchar(20)" json:"status"`  // sent, delivered, failed
    SentAt  time.Time `json:"sentAt"`
}