package models

import (
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type Signal struct {
    gorm.Model
    UserID       uint      `gorm:"column:user_id;not null" json:"user_id"`
    Pair         string    `gorm:"column:pair;type:text;not null" json:"pair"`
    Action       string    `gorm:"column:action;type:text;not null" json:"action"` 
    StopLoss     float64   `gorm:"column:stop_loss;not null" json:"stop_loss"`
    
	TakeProfits pq.Float64Array `gorm:"type:float[];column:take_profits" json:"take_profits,omitempty"`

    Commentary   string    `gorm:"column:commentary;type:text" json:"commentary,omitempty"`

    User         User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
