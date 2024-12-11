package models


import (
    "gorm.io/gorm"
    "time"
)

type Appointment struct {
    gorm.Model
    TraderID         uint      `gorm:"not null" json:"trader_id"`
    ExpertID         uint      `gorm:"not null" json:"expert_id"`
    AvailabilityID   uint      `gorm:"not null" json:"availability_id"`
    AppointmentDate  time.Time `gorm:"not null" json:"appointment_date"`
    StartTime        time.Time `gorm:"not null" json:"start_time"`
    EndTime          time.Time `gorm:"not null" json:"end_time"`
    Status           string    `gorm:"default:'Pending'" json:"status"`
    PaymentStatus    string    `gorm:"not null;default:unpaid" json:"payment_status"`
    Amount           float64   `gorm:"not null" json:"amount"`
    PaymentID        string    `gorm:"size:255" json:"payment_id,omitempty"`
    EventName        string    `gorm:"size:255;not null" json:"event_name"`
    Category         string    `gorm:"size:50" json:"category"`
    
    Trader           *User         `gorm:"foreignKey:TraderID" json:"trader,omitempty"`
    Expert           *Expert       `gorm:"foreignKey:ExpertID" json:"expert,omitempty"`
    Availability     *Availability `gorm:"foreignKey:AvailabilityID" json:"availability,omitempty"`
}