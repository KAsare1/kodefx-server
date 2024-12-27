package forum

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type PostHandler struct {
    db *gorm.DB
}

func NewPostHandler(db *gorm.DB) *PostHandler {
    return &PostHandler{db: db}
}

func (h *PostHandler) RegisterRoutes(router *mux.Router) {
    // Post routes
    router.HandleFunc("/posts", utils.AuthMiddleware(h.CreatePost)).Methods("POST")
    router.HandleFunc("/posts", h.GetPosts).Methods("GET")
    router.HandleFunc("/posts/{id}", h.GetPost).Methods("GET")
    // router.HandleFunc("/posts/{id}", h.UpdatePost).Methods("PUT")
    router.HandleFunc("/posts/{id}", h.DeletePost).Methods("DELETE")
    
    // Like routes
    router.HandleFunc("/posts/{id}/like", h.LikePost).Methods("POST")
    router.HandleFunc("/posts/{id}/unlike", h.UnlikePost).Methods("POST")
    
    // Comment routes
    router.HandleFunc("/posts/{id}/comments", utils.AuthMiddleware(h.AddComment)).Methods("POST")
    router.HandleFunc("/posts/{id}/comments", h.GetComments).Methods("GET")
    router.HandleFunc("/posts/{id}/comments/{commentId}", h.UpdateComment).Methods("PUT")
    router.HandleFunc("/posts/{id}/comments/{commentId}", h.DeleteComment).Methods("DELETE")
    
    // Share routes
    router.HandleFunc("/posts/{id}/share", h.SharePost).Methods("POST")
    router.HandleFunc("/posts/{id}/shares", h.GetShares).Methods("GET")
}

// CreatePost creates a new post
func (h *PostHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
    // Step 1: Get the user ID from the request context
    userID, err := utils.GetUserIDFromContext(r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Step 2: Parse the JSON request body
    var request struct {
        Content string   `json:"content"`
        Images  []string `json:"images"` // Array of image URLs
    }
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    // Step 3: Validate content
    if request.Content == "" {
        http.Error(w, "Content is required", http.StatusBadRequest)
        return
    }

    // Step 4: Begin a new transaction
    tx := h.db.Begin()

    // Step 5: Create the post record
    post := models.Post{
        UserID:  userID,
        Content: request.Content,
    }

    if err := tx.Create(&post).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error creating post", http.StatusInternalServerError)
        return
    }

    // Step 6: Handle image URLs
    for i, imageURL := range request.Images {
        // You can perform additional validation on the URLs if needed

        image := models.Image{
            PostID: post.ID,
            URL:    imageURL,
            // Optional: You can handle image captions here if provided in the request
            Caption: r.FormValue(fmt.Sprintf("caption_%d", i)),
        }

        if err := tx.Create(&image).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Error saving image record", http.StatusInternalServerError)
            return
        }
    }

    // Step 7: Commit the transaction
    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Error saving post", http.StatusInternalServerError)
        return
    }

    // Step 8: Preload related data and send response
    h.db.Preload("User").Preload("Images").Preload("Likes").Preload("Comments").First(&post, post.ID)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(post)
}


// GetPosts retrieves all posts with pagination
func (h *PostHandler) GetPosts(w http.ResponseWriter, r *http.Request) {
    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    var posts []models.Post
    var total int64

    query := h.db.Model(&models.Post{}).Preload("User").Preload("Likes").Preload("Comments").Preload("Images")
    query.Count(&total)

    if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&posts).Error; err != nil {
        http.Error(w, "Error retrieving posts", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "posts":       posts,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

// LikePost handles liking a post
func (h *PostHandler) LikePost(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    // TODO: Get user ID from JWT token
    userID := uint(1) // Replace with actual user ID from token

    // Start transaction
    tx := h.db.Begin()

    // Check if already liked
    var existingLike models.Like
    if err := tx.Where("user_id = ? AND post_id = ?", userID, postID).First(&existingLike).Error; err == nil {
        tx.Rollback()
        http.Error(w, "Post already liked", http.StatusConflict)
        return
    }

    // Create like
    like := models.Like{
        UserID: userID,
        PostID: uint(postID),
    }

    if err := tx.Create(&like).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error liking post", http.StatusInternalServerError)
        return
    }

    // Increment likes count
    if err := tx.Model(&models.Post{}).Where("id = ?", postID).
        UpdateColumn("likes_count", gorm.Expr("likes_count + ?", 1)).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error updating likes count", http.StatusInternalServerError)
        return
    }

    tx.Commit()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Post liked successfully",
    })
}

// AddComment adds a comment to a post
func (h *PostHandler) AddComment(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    var comment models.Comment
    if err := json.NewDecoder(r.Body).Decode(&comment); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }



    comment.UserID, err = utils.GetUserIDFromContext(r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    comment.PostID = uint(postID)

    if err := h.db.Create(&comment).Error; err != nil {
        http.Error(w, "Error creating comment", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(comment)
}

// SharePost handles sharing a post
func (h *PostHandler) SharePost(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    var share models.Share
    if err := json.NewDecoder(r.Body).Decode(&share); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    share.UserID, err = utils.GetUserIDFromContext(r.Context()) 
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    share.PostID = uint(postID)

    // Start transaction
    tx := h.db.Begin()

    if err := tx.Create(&share).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error sharing post", http.StatusInternalServerError)
        return
    }

    // Increment shares count
    if err := tx.Model(&models.Post{}).Where("id = ?", postID).
        UpdateColumn("shares_count", gorm.Expr("shares_count + ?", 1)).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error updating shares count", http.StatusInternalServerError)
        return
    }

    tx.Commit()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(share)
}



// GetPost retrieves a specific post with its likes and comments
func (h *PostHandler) GetPost(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    var post models.Post
    if err := h.db.Preload("User").Preload("Likes").Preload("Images").Preload("Comments.User").First(&post, postID).Error; err != nil {
        http.Error(w, "Post not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(post)
}

// UpdatePost updates a post's content
// func (h *PostHandler) UpdatePost(w http.ResponseWriter, r *http.Request) {
//     vars := mux.Vars(r)
//     postID, err := strconv.ParseUint(vars["id"], 10, 64)
//     if err != nil {
//         http.Error(w, "Invalid post ID", http.StatusBadRequest)
//         return
//     }

//     var updateData struct {
//         Content  string `json:"content"`
//         MediaURL string `json:"media_url,omitempty"`
//     }
//     if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
//         http.Error(w, "Invalid request body", http.StatusBadRequest)
//         return
//     }

//     var post models.Post
//     if err := h.db.First(&post, postID).Error; err != nil {
//         http.Error(w, "Post not found", http.StatusNotFound)
//         return
//     }

//     // TODO: Verify user owns this post
//     // if post.UserID != getUserIDFromToken(r) {
//     //     http.Error(w, "Unauthorized", http.StatusUnauthorized)
//     //     return
//     // }

//     post.Content = updateData.Content
//     if updateData.MediaURL != "" {
//         post.MediaURL = updateData.MediaURL
//     }

//     if err := h.db.Save(&post).Error; err != nil {
//         http.Error(w, "Error updating post", http.StatusInternalServerError)
//         return
//     }

//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(post)
// }

// DeletePost deletes a post and its associated likes and comments
func (h *PostHandler) DeletePost(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    var post models.Post
    if err := h.db.First(&post, postID).Error; err != nil {
        http.Error(w, "Post not found", http.StatusNotFound)
        return
    }

    // TODO: Verify user owns this post
    // if post.UserID != getUserIDFromToken(r) {
    //     http.Error(w, "Unauthorized", http.StatusUnauthorized)
    //     return
    // }

    tx := h.db.Begin()

    // Delete likes
    if err := tx.Where("post_id = ?", postID).Delete(&models.Like{}).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error deleting likes", http.StatusInternalServerError)
        return
    }

    // Delete comments
    if err := tx.Where("post_id = ?", postID).Delete(&models.Comment{}).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error deleting comments", http.StatusInternalServerError)
        return
    }

    // Delete shares
    if err := tx.Where("post_id = ?", postID).Delete(&models.Share{}).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error deleting shares", http.StatusInternalServerError)
        return
    }

    // Delete post
    if err := tx.Delete(&post).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error deleting post", http.StatusInternalServerError)
        return
    }

    tx.Commit()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Post deleted successfully",
    })
}

// UnlikePost removes a like from a post
func (h *PostHandler) UnlikePost(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    // TODO: Get user ID from JWT token
    userID := uint(1) // Replace with actual user ID from token

    tx := h.db.Begin()

    // Find and delete the like
    result := tx.Where("user_id = ? AND post_id = ?", userID, postID).Delete(&models.Like{})
    if result.Error != nil {
        tx.Rollback()
        http.Error(w, "Error unliking post", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        tx.Rollback()
        http.Error(w, "Post was not liked", http.StatusBadRequest)
        return
    }

    // Decrement likes count
    if err := tx.Model(&models.Post{}).Where("id = ?", postID).
        UpdateColumn("likes_count", gorm.Expr("likes_count - ?", 1)).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error updating likes count", http.StatusInternalServerError)
        return
    }

    tx.Commit()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Post unliked successfully",
    })
}

// GetComments retrieves comments for a post with pagination
func (h *PostHandler) GetComments(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    var comments []models.Comment
    var total int64

    query := h.db.Model(&models.Comment{}).Where("post_id = ?", postID).Preload("User")
    query.Count(&total)

    if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Order("created_at DESC").Find(&comments).Error; err != nil {
        http.Error(w, "Error retrieving comments", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "comments":    comments,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

// UpdateComment updates a comment
func (h *PostHandler) UpdateComment(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    commentID, err := strconv.ParseUint(vars["commentId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid comment ID", http.StatusBadRequest)
        return
    }

    var updateData struct {
        Content string `json:"content"`
    }
    if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var comment models.Comment
    if err := h.db.First(&comment, commentID).Error; err != nil {
        http.Error(w, "Comment not found", http.StatusNotFound)
        return
    }

    // TODO: Verify user owns this comment
    // if comment.UserID != getUserIDFromToken(r) {
    //     http.Error(w, "Unauthorized", http.StatusUnauthorized)
    //     return
    // }

    comment.Content = updateData.Content
    if err := h.db.Save(&comment).Error; err != nil {
        http.Error(w, "Error updating comment", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(comment)
}

// DeleteComment deletes a comment
func (h *PostHandler) DeleteComment(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    commentID, err := strconv.ParseUint(vars["commentId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid comment ID", http.StatusBadRequest)
        return
    }

    var comment models.Comment
    if err := h.db.First(&comment, commentID).Error; err != nil {
        http.Error(w, "Comment not found", http.StatusNotFound)
        return
    }

    // TODO: Verify user owns this comment
    // if comment.UserID != getUserIDFromToken(r) {
    //     http.Error(w, "Unauthorized", http.StatusUnauthorized)
    //     return
    // }

    if err := h.db.Delete(&comment).Error; err != nil {
        http.Error(w, "Error deleting comment", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Comment deleted successfully",
    })
}

// GetShares retrieves shares for a post with pagination
func (h *PostHandler) GetShares(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    var shares []models.Share
    var total int64

    query := h.db.Model(&models.Share{}).Where("post_id = ?", postID).Preload("User")
    query.Count(&total)

    if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Order("created_at DESC").Find(&shares).Error; err != nil {
        http.Error(w, "Error retrieving shares", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "shares":      shares,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}