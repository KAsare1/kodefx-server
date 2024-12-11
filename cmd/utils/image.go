package utils

import (
    "fmt"
    "io"
    "mime/multipart"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/google/uuid"
)

const (
    MaxImageSize = 10 << 20 // 10 MB
    ImagePath    = "uploads/images"
)

// SaveImage saves an uploaded image and returns its URL path
func SaveImage(file multipart.File, header *multipart.FileHeader) (string, error) {
    // Validate file size
    if header.Size > MaxImageSize {
        return "", fmt.Errorf("file size exceeds maximum limit of %d MB", MaxImageSize/(1<<20))
    }


    ext := strings.ToLower(filepath.Ext(header.Filename))
    if !isValidImageType(ext) {
        return "", fmt.Errorf("invalid file type: %s", ext)
    }


    if err := os.MkdirAll(ImagePath, 0755); err != nil {
        return "", fmt.Errorf("failed to create upload directory: %v", err)
    }


    filename := fmt.Sprintf("%s-%s%s", 
        time.Now().Format("20060102"),
        uuid.New().String(),
        ext,
    )
    filePath := filepath.Join(ImagePath, filename)


    dst, err := os.Create(filePath)
    if err != nil {
        return "", fmt.Errorf("failed to create file: %v", err)
    }
    defer dst.Close()


    if _, err := io.Copy(dst, file); err != nil {
        return "", fmt.Errorf("failed to save file: %v", err)
    }


    return fmt.Sprintf("/images/%s", filename), nil
}


func isValidImageType(ext string) bool {
    validTypes := map[string]bool{
        ".jpg":  true,
        ".jpeg": true,
        ".png":  true,
        ".gif":  true,
    }
    return validTypes[ext]
}


func DeleteImage(imageURL string) error {

    filename := filepath.Base(imageURL)
    filePath := filepath.Join(ImagePath, filename)


    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return nil
    }

    return os.Remove(filePath)
}