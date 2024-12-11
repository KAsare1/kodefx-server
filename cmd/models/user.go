package models

import (
	"time"

	"gorm.io/gorm"
)


type User struct {
    gorm.Model
    FullName       string    `gorm:"column:full_name;size:255;not null" json:"full_name"`
    Email          string    `gorm:"column:email;size:255;uniqueIndex;not null" json:"email"`
    PasswordHash   string    `gorm:"column:password_hash;size:255;not null" json:"password_hash"`
    Role           string    `gorm:"column:role;size:50;not null" json:"role"`
    Phone          string    `gorm:"column:phone;size:20;unique" json:"phone"`
    PhoneVerified  bool      `gorm:"column:phone_verified;default:false" json:"phone_verified"` 
    OtpCode        string    `gorm:"column:otp_code;size:10" json:"otp_code"`
	Status         string    `gorm:"column:status;size:50;not null;default:inactive" json:"status"`
	Refresh        string    `gorm:"column:refresh_token;size:255" json:"refresh_token"`
	RefreshTokenExpiredAt time.Time `gorm:"column:refresh_token_expired_at" json:"refresh_token_expired_at"`
	Expert         *Expert   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;nullable" json:"expert,omitempty"`
}


type Expert struct {
    gorm.Model
    UserID         uint      `gorm:"column:user_id;not null" json:"user_id"` 
    Expertise      string    `gorm:"column:expertise;size:255" json:"expertise"`
    Certifications string    `gorm:"column:certifications;size:500" json:"certifications"`
    Bio            string    `gorm:"column:bio;type:text" json:"bio"`
	Verified		  bool      `gorm:"column:verified;default:false" json:"verified"`

	User           *User     `gorm:"foreignKey:UserID" json:"-"`   
}

func (Expert) TableName() string {
    return "experts"
}