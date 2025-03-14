package models

import (
	"time"

	"gorm.io/gorm"
)


type SignalSubscription struct {
	gorm.Model
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	Plan      string    `json:"plan"`
	Amount    float64   `json:"amount"`
	Status    string    `json:"status"`     
	PaymentID string    `gorm:"unique;not null" json:"payment_id"`
	StartDate time.Time `gorm:"index" json:"start_date"`
	EndDate   time.Time `gorm:"index" json:"end_date"`

	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"user,omitempty"`
}
