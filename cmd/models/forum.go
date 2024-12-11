package models

import "gorm.io/gorm"


type Post struct {
    gorm.Model
    UserID      uint      `gorm:"column:user_id;not null" json:"user_id"`
    Content     string    `gorm:"column:content;type:text;not null" json:"content"`
    LikesCount  int       `gorm:"column:likes_count;default:0" json:"likes_count"`
    SharesCount int       `gorm:"column:shares_count;default:0" json:"shares_count"`
    User        *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
    Images      []Image   `gorm:"foreignKey:PostID" json:"images,omitempty"`
    Likes       []Like    `gorm:"foreignKey:PostID" json:"likes,omitempty"`
    Comments    []Comment `gorm:"foreignKey:PostID" json:"comments,omitempty"`
    Shares      []Share   `gorm:"foreignKey:PostID" json:"shares,omitempty"`
}

type Image struct {
    gorm.Model
    PostID  uint   `gorm:"column:post_id;not null" json:"post_id"`
    URL     string `gorm:"column:url;not null" json:"url"`
    Caption string `gorm:"column:caption" json:"caption,omitempty"`
}


type Like struct {
    gorm.Model
    UserID uint  `gorm:"column:user_id;not null" json:"user_id"`
    PostID uint  `gorm:"column:post_id;not null" json:"post_id"`
    User   *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

type Comment struct {
    gorm.Model
    UserID  uint   `gorm:"column:user_id;not null" json:"user_id"`
    PostID  uint   `gorm:"column:post_id;not null" json:"post_id"`
    Content string `gorm:"column:content;type:text;not null" json:"content"`
    User    *User  `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

type Share struct {
    gorm.Model
    UserID    uint   `gorm:"column:user_id;not null" json:"user_id"`
    PostID    uint   `gorm:"column:post_id;not null" json:"post_id"`
    ShareText string `gorm:"column:share_text;type:text" json:"share_text"`
    User      *User  `gorm:"foreignKey:UserID" json:"user,omitempty"`
}




