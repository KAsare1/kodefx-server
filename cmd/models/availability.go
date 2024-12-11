package models

import (
	"time"

	"gorm.io/gorm"
)

type Availability struct {
	gorm.Model
	ExpertID  uint      `gorm:"column:expert_id;not null" json:"expert_id"`
	EventName string    `gorm:"column:event_name;size:255;not null" json:"event_name"`
	Note      string    `gorm:"column:note;type:text" json:"note"`
	Date      time.Time `gorm:"column:date;not null" json:"date"`
	StartTime time.Time `gorm:"column:start_time;not null" json:"start_time"`
	EndTime   time.Time `gorm:"column:end_time;not null" json:"end_time"`
	Reminder  bool      `gorm:"column:reminder;default:false" json:"reminder"`
	Category  string    `gorm:"column:category;size:50" json:"category"`
	Price     float64   `gorm:"column:price;not null" json:"price"`

	Expert    *Expert   `gorm:"foreignKey:ExpertID" json:"-"`
}

func (Availability) TableName() string {
	return "availabilities"
}