package models

import (
	"gorm.io/gorm"
)

type Transaction struct {
    gorm.Model
    UserID       uint      `gorm:"column:user_id;not null" json:"user_id"`
    Amount       float64   `gorm:"column:amount;type:float;not null" json:"amount"` 
    Method       string    `gorm:"column:method;type:text;not null" json:"method"` 
    Purpose      string    `gorm:"column:purpose;type:text;not null" json:"purpose"`

    User         User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
