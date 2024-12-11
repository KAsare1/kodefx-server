package models

import (
	"time"

	"gorm.io/gorm"
)

type Message struct {
	gorm.Model
	SenderID   uint      `gorm:"column:sender_id;not null" json:"sender_id"`
	ReceiverID uint      `gorm:"column:receiver_id;not null" json:"receiver_id"`
	Content    string    `gorm:"column:content;type:text;not null" json:"content"`
	ReadAt     time.Time `gorm:"column:read_at" json:"read_at,omitempty"`

	// Relations
	Sender   *User `gorm:"foreignKey:SenderID" json:"sender,omitempty"`
	Receiver *User `gorm:"foreignKey:ReceiverID" json:"receiver,omitempty"`
}

func (Message) TableName() string {
	return "messages"
}