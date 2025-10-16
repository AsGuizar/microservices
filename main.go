// main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// MODELS
// ============================================================================

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Created      time.Time `json:"created"`
}

type File struct {
	ID       string    `json:"id"`
	UserID   string    `json:"user_id"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Path     string    `json:"-"`
	MimeType string    `json:"mime_type"`
	Created  time.Time `json:"created"`
}

type AuditLog struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	IP        string                 `json:"ip"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// ============================================================================
// SECURITY CONTROLLER
// ============================================================================

type SecurityController struct {
	secret []byte
	mu     sync.RWMutex
}

func NewSecurityController(secret string) *SecurityController {
	return &SecurityController{
		secret: []byte(secret),
	}
}

func (sc *SecurityController) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (sc *SecurityController) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (sc *SecurityController) GenerateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sc.secret)
}

func (sc *SecurityController) ValidateToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return sc.secret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return "", fmt.Errorf("invalid token claims")
		}
		return userID, nil
	}

	return "", fmt.Errorf("invalid token")
}

func (sc *SecurityController) Authorize(userID, resource, action string) bool {
	// Simple authorization - can be extended with RBAC
	return true
}

// ============================================================================
// DATABASE LAYER (In-Memory - Replace with DynamoDB/PostgreSQL)
// ============================================================================

type Database struct {
	users map[string]*User
	files map[string]*File
	logs  []AuditLog
	mu    sync.RWMutex
}

func NewDatabase() *Database {
	return &Database{
		users: make(map[string]*User),
		files: make(map[string]*File),
		logs:  make([]AuditLog, 0),
	}
}

func (db *Database) CreateUser(user *User) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.users[user.ID] = user
	return nil
}

func (db *Database) GetUserByEmail(email string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, u := range db.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (db *Database) GetUserByID(id string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, ok := db.users[id]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func (db *Database) CreateFile(file *File) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.files[file.ID] = file
	return nil
}

func (db *Database) GetFilesByUserID(userID string) ([]*File, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	files := make([]*File, 0)
	for _, f := range db.files {
		if f.UserID == userID {
			files = append(files, f)
		}
	}
	return files, nil
}

func (db *Database) GetFileByID(id string) (*File, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	file, ok := db.files[id]
	if !ok {
		return nil, fmt.Errorf("file not found")
	}
	return file, nil
}

func (db *Database) CreateAuditLog(log AuditLog) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.logs = append(db.logs, log)
	return nil
}

func (db *Database) GetAuditLogs(userID string) ([]AuditLog, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	logs := make([]AuditLog, 0)
	for _, l := range db.logs {
		if l.UserID == userID {
			logs = append(logs, l)
		}
	}
	return logs, nil
}

// ============================================================================
// AUDIT SERVICE
// ============================================================================

type AuditService struct {
	db *Database
	ch chan AuditLog
}

func NewAuditService(db *Database) *AuditService {
	svc := &AuditService{
		db: db,
		ch: make(chan AuditLog, 1000),
	}
	go svc.processLogs()
	return svc
}

func (a *AuditService) processLogs() {
	for log := range a.ch {
		if err := a.db.CreateAuditLog(log); err != nil {
			fmt.Printf("[AUDIT ERROR] Failed to save log: %v\n", err)
		}
		fmt.Printf("[AUDIT] %s | User: %s | Action: %s | Resource: %s | IP: %s\n",
			log.Timestamp.Format(time.RFC3339), log.UserID, log.Action, log.Resource, log.IP)
	}
}

func (a *AuditService) Log(userID, action, resource, ip, userAgent string, metadata map[string]interface{}) {
	log := AuditLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		IP:        ip,
		UserAgent: userAgent,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}
	select {
	case a.ch <- log:
	default:
		fmt.Println("[AUDIT WARNING] Audit channel full, dropping log")
	}
}

func (a *AuditService) Close() {
	close(a.ch)
}

// ============================================================================
// USER API
// ============================================================================

type UserAPI struct {
	db       *Database
	security *SecurityController
	audit    *AuditService
}

func NewUserAPI(db *Database, security *SecurityController, audit *AuditService) *UserAPI {
	return &UserAPI{
		db:       db,
		security: security,
		audit:    audit,
	}
}

func (u *UserAPI) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Check if user exists
	if _, err := u.db.GetUserByEmail(req.Email); err == nil {
		respondError(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash password
	hash, err := u.security.HashPassword(req.Password)
	if err != nil {
		respondError(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	user := &User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		PasswordHash: hash,
		Created:      time.Now(),
	}

	if err := u.db.CreateUser(user); err != nil {
		respondError(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	token, _ := u.security.GenerateToken(user.ID)

	u.audit.Log(user.ID, "USER_REGISTER", "users", r.RemoteAddr, r.UserAgent(), map[string]interface{}{
		"email": user.Email,
	})

	respondJSON(w, map[string]interface{}{
		"user":  user,
		"token": token,
	}, http.StatusCreated)
}

func (u *UserAPI) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := u.db.GetUserByEmail(req.Email)
	if err != nil {
		respondError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !u.security.CheckPassword(req.Password, user.PasswordHash) {
		respondError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, _ := u.security.GenerateToken(user.ID)

	u.audit.Log(user.ID, "USER_LOGIN", "users", r.RemoteAddr, r.UserAgent(), map[string]interface{}{
		"email": user.Email,
	})

	respondJSON(w, map[string]interface{}{
		"user":  user,
		"token": token,
	}, http.StatusOK)
}

func (u *UserAPI) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	user, err := u.db.GetUserByID(userID)
	if err != nil {
		respondError(w, "User not found", http.StatusNotFound)
		return
	}

	respondJSON(w, user, http.StatusOK)
}

// ============================================================================
// FILE API
// ============================================================================

type FileAPI struct {
	db          *Database
	security    *SecurityController
	audit       *AuditService
	storagePath string
}

func NewFileAPI(db *Database, security *SecurityController, audit *AuditService, storagePath string) *FileAPI {
	os.MkdirAll(storagePath, 0755)
	return &FileAPI{
		db:          db,
		security:    security,
		audit:       audit,
		storagePath: storagePath,
	}
}

func (f *FileAPI) Upload(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// Parse multipart form (max 50MB)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		respondError(w, "File too large", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		respondError(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create file record
	fileRecord := &File{
		ID:       uuid.New().String(),
		UserID:   userID,
		Name:     handler.Filename,
		Size:     handler.Size,
		Path:     fmt.Sprintf("%s/%s_%s", f.storagePath, userID, handler.Filename),
		MimeType: handler.Header.Get("Content-Type"),
		Created:  time.Now(),
	}

	// Save to disk
	dst, err := os.Create(fileRecord.Path)
	if err != nil {
		respondError(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		respondError(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Save to database
	if err := f.db.CreateFile(fileRecord); err != nil {
		respondError(w, "Failed to save file metadata", http.StatusInternalServerError)
		return
	}

	f.audit.Log(userID, "FILE_UPLOAD", fileRecord.ID, r.RemoteAddr, r.UserAgent(), map[string]interface{}{
		"filename": fileRecord.Name,
		"size":     fileRecord.Size,
	})

	respondJSON(w, fileRecord, http.StatusCreated)
}

func (f *FileAPI) List(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	files, err := f.db.GetFilesByUserID(userID)
	if err != nil {
		respondError(w, "Failed to retrieve files", http.StatusInternalServerError)
		return
	}

	f.audit.Log(userID, "FILE_LIST", "files", r.RemoteAddr, r.UserAgent(), nil)

	respondJSON(w, files, http.StatusOK)
}

func (f *FileAPI) Download(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	fileID := chi.URLParam(r, "fileID")

	file, err := f.db.GetFileByID(fileID)
	if err != nil {
		respondError(w, "File not found", http.StatusNotFound)
		return
	}

	if file.UserID != userID {
		respondError(w, "Unauthorized", http.StatusForbidden)
		return
	}

	f.audit.Log(userID, "FILE_DOWNLOAD", fileID, r.RemoteAddr, r.UserAgent(), map[string]interface{}{
		"filename": file.Name,
	})

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.Name))
	w.Header().Set("Content-Type", file.MimeType)
	http.ServeFile(w, r, file.Path)
}

// ============================================================================
// AUDIT API
// ============================================================================

type AuditAPI struct {
	db       *Database
	security *SecurityController
}

func NewAuditAPI(db *Database, security *SecurityController) *AuditAPI {
	return &AuditAPI{
		db:       db,
		security: security,
	}
}

func (a *AuditAPI) GetLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	logs, err := a.db.GetAuditLogs(userID)
	if err != nil {
		respondError(w, "Failed to retrieve logs", http.StatusInternalServerError)
		return
	}

	respondJSON(w, logs, http.StatusOK)
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

func AuthMiddleware(security *SecurityController) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token == "" {
				respondError(w, "Missing authorization token", http.StatusUnauthorized)
				return
			}

			if len(token) > 7 && token[:7] == "Bearer " {
				token = token[7:]
			}

			userID, err := security.ValidateToken(token)
			if err != nil {
				respondError(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "user_id", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ============================================================================
// HELPERS
// ============================================================================

func respondJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, message string, status int) {
	respondJSON(w, map[string]string{"error": message}, status)
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Configuration
	port := getEnv("PORT", "8080")
	jwtSecret := getEnv("JWT_SECRET", "change-this-in-production-use-env-var")
	storagePath := getEnv("STORAGE_PATH", "./storage")

	// Initialize components
	db := NewDatabase()
	security := NewSecurityController(jwtSecret)
	audit := NewAuditService(db)
	defer audit.Close()

	// Initialize APIs
	userAPI := NewUserAPI(db, security, audit)
	fileAPI := NewFileAPI(db, security, audit, storagePath)
	auditAPI := NewAuditAPI(db, security)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now(),
		}, http.StatusOK)
	})

	// Public routes
	r.Route("/api/users", func(r chi.Router) {
		r.Post("/register", userAPI.Register)
		r.Post("/login", userAPI.Login)
	})

	// Protected routes
	r.Route("/api", func(r chi.Router) {
		r.Use(AuthMiddleware(security))

		// User routes
		r.Get("/users/me", userAPI.GetProfile)

		// File routes
		r.Post("/files", fileAPI.Upload)
		r.Get("/files", fileAPI.List)
		r.Get("/files/{fileID}", fileAPI.Download)

		// Audit routes
		r.Get("/audit/logs", auditAPI.GetLogs)
	})

	// Server setup
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	log.Printf("Server is starting on port %s...", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on port %s: %v\n", port, err)
	}

	<-done
	log.Println("Server stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}