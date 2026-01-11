package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// Структуры данных
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username     string             `bson:"username" json:"username"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	Role         string             `bson:"role" json:"role"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	LastLogin    *time.Time         `bson:"last_login,omitempty" json:"last_login,omitempty"`
}

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	User         User      `json:"user"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type VerifyRequest struct {
	Token string `json:"token"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type UpdateUserRequest struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

// Глобальные переменные
var (
	db         *mongo.Database
	usersColl  *mongo.Collection
	jwtSecret  []byte
	redisClient interface{} // Placeholder for Redis if needed
	
	// OAuth credentials
	yandexClientID     string
	yandexClientSecret string
	githubClientID     string
	githubClientSecret string
	oauthRedirectURL   string
)

// Инициализация OAuth credentials
func initOAuth() {
	yandexClientID = os.Getenv("YANDEX_CLIENT_ID")
	yandexClientSecret = os.Getenv("YANDEX_CLIENT_SECRET")
	githubClientID = os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	oauthRedirectURL = os.Getenv("OAUTH_REDIRECT_URL")
	if oauthRedirectURL == "" {
		oauthRedirectURL = "http://localhost/api/auth/oauth/callback"
	}
}

// Инициализация MongoDB
func initDB() {
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://admin:admin123@localhost:27017/auth_db?authSource=admin"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	// Проверяем подключение
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}

	db = client.Database("auth_db")
	usersColl = db.Collection("users")

	// Создаем индексы
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	usersColl.Indexes().CreateOne(ctx, indexModel)

	// Создаем админа по умолчанию, если его нет
	createDefaultAdmin(ctx)

	log.Println("✅ MongoDB connected successfully")
}

// Создание админа по умолчанию
func createDefaultAdmin(ctx context.Context) {
	var admin User
	err := usersColl.FindOne(ctx, bson.M{"username": "admin"}).Decode(&admin)
	if err == mongo.ErrNoDocuments {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		admin = User{
			Username:     "admin",
			Email:        "admin@survey.local",
			PasswordHash: string(hashedPassword),
			Role:         "admin",
			CreatedAt:    time.Now(),
		}
		_, err := usersColl.InsertOne(ctx, admin)
		if err != nil {
			log.Printf("Warning: Failed to create default admin: %v", err)
		} else {
			log.Println("✅ Default admin user created (username: admin, password: password)")
		}
	}
}

// Middleware для CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"time":         time.Now().Format(time.RFC3339),
		"auth_methods": []string{"traditional_auth", "code_auth"},
	})
}

// Генерация JWT токена
func generateToken(user User) (string, error) {
	claims := jwt.MapClaims{
		"id":       user.ID.Hex(),
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Верификация JWT токена
func verifyToken(tokenString string) (*User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["id"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid token claims")
		}

		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user User
		err = usersColl.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user)
		if err != nil {
			return nil, err
		}

		return &user, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// Традиционная авторизация
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := usersColl.FindOne(ctx, bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Проверяем пароль
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Обновляем время последнего входа
	now := time.Now()
	usersColl.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"last_login": now}})
	user.LastLogin = &now

	// Генерируем токен
	token, err := generateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Убираем пароль из ответа
	userResponse := user
	userResponse.PasswordHash = ""

	response := TokenResponse{
		AccessToken:  token,
		RefreshToken: fmt.Sprintf("refresh.%s.%d", user.ID.Hex(), time.Now().Unix()+3600),
		TokenType:    "Bearer",
		ExpiresIn:    86400,
		User:         userResponse,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Верификация токена
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := verifyToken(req.Token)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"user":  user,
	})
}

// Получение списка пользователей (только для админа)
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем авторизацию
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")
	user, err := verifyToken(token)
	if err != nil || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := usersColl.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var users []User
	if err = cursor.All(ctx, &users); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Убираем пароли из всех пользователей
	for i := range users {
		users[i].PasswordHash = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Создание пользователя (только для админа)
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем авторизацию
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")
	admin, err := verifyToken(token)
	if err != nil || admin.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		req.Role = "user"
	}

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
		CreatedAt:    time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = usersColl.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Убираем пароль из ответа
	user.PasswordHash = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Обновление пользователя (только для админа)
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем авторизацию
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")
	admin, err := verifyToken(token)
	if err != nil || admin.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Извлекаем ID из пути
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	userID, err := primitive.ObjectIDFromHex(pathParts[len(pathParts)-1])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{}
	if req.Username != "" {
		update["username"] = req.Username
	}
	if req.Email != "" {
		update["email"] = req.Email
	}
	if req.Role != "" {
		update["role"] = req.Role
	}
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		update["password_hash"] = string(hashedPassword)
	}

	if len(update) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	result := usersColl.FindOneAndUpdate(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$set": update},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var user User
	if err := result.Decode(&user); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Удаление пользователя (только для админа)
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем авторизацию
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")
	admin, err := verifyToken(token)
	if err != nil || admin.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Извлекаем ID из пути
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	userID, err := primitive.ObjectIDFromHex(pathParts[len(pathParts)-1])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := usersColl.DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User deleted successfully",
	})
}

// Code authentication (демо)
func codeAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
		Code  string `json:"code,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Code == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":  "Code sent to email",
			"demo_code": "123456",
		})
		return
	}

	// В демо-режиме любой код подходит
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	username := strings.Split(req.Email, "@")[0]
	var user User
	err := usersColl.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		// Создаем нового пользователя
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		user = User{
			Username:     username,
			Email:        req.Email,
			PasswordHash: string(hashedPassword),
			Role:         "user",
			CreatedAt:    time.Now(),
		}
		usersColl.InsertOne(ctx, user)
	}

	token, err := generateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Убираем пароль из ответа
	userResponse := user
	userResponse.PasswordHash = ""

	response := TokenResponse{
		AccessToken:  token,
		RefreshToken: fmt.Sprintf("refresh.%s.%d", user.ID.Hex(), time.Now().Unix()+3600),
		TokenType:    "Bearer",
		ExpiresIn:    86400,
		User:         userResponse,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// OAuth URL handler
func oauthURLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		http.Error(w, "Invalid provider", http.StatusBadRequest)
		return
	}

	provider := pathParts[4]
	var authURL string

	switch provider {
	case "yandex":
		if yandexClientID == "" {
			http.Error(w, "Yandex OAuth not configured", http.StatusServiceUnavailable)
			return
		}
		authURL = fmt.Sprintf("https://oauth.yandex.ru/authorize?response_type=code&client_id=%s&redirect_uri=%s",
			yandexClientID, url.QueryEscape(oauthRedirectURL))
	case "github":
		if githubClientID == "" {
			http.Error(w, "GitHub OAuth not configured", http.StatusServiceUnavailable)
			return
		}
		authURL = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user:email",
			githubClientID, url.QueryEscape(oauthRedirectURL))
	default:
		http.Error(w, "Unknown provider", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": authURL})
}

// OAuth callback handler
func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	provider := r.URL.Query().Get("state") // Use state as provider identifier
	if provider == "" {
		// Try to detect from redirect URI
		if strings.Contains(r.URL.Path, "yandex") {
			provider = "yandex"
		} else if strings.Contains(r.URL.Path, "github") {
			provider = "github"
		}
	}

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}
	
	if provider == "" {
		http.Error(w, "Missing provider", http.StatusBadRequest)
		return
	}

	var userEmail, userName string
	var err error

	switch provider {
	case "yandex":
		userEmail, userName, err = handleYandexCallback(code)
	case "github":
		userEmail, userName, err = handleGitHubCallback(code)
	default:
		http.Error(w, "Unknown provider", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("OAuth callback error: %v", err)
		html := fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head><title>OAuth Error</title></head>
			<body>
				<script>
					if (window.opener) {
						window.opener.postMessage({
							type: 'oauth_error',
							error: 'OAuth authentication failed'
						}, '*');
						window.close();
					} else {
						alert('OAuth authentication failed');
						window.close();
					}
				</script>
			</body>
			</html>
		`)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}

	// Find or create user
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err = usersColl.FindOne(ctx, bson.M{"email": userEmail}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		// Create new user
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(fmt.Sprintf("oauth_%s_%d", provider, time.Now().Unix())), bcrypt.DefaultCost)
		user = User{
			Username:     userName,
			Email:        userEmail,
			PasswordHash: string(hashedPassword),
			Role:         "user",
			CreatedAt:    time.Now(),
		}
		result, err := usersColl.InsertOne(ctx, user)
		if err != nil {
			log.Printf("Failed to create user: %v", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		user.ID = result.InsertedID.(primitive.ObjectID)
	} else if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate token
	token, err := generateToken(user)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return HTML page that sends message to parent window
	html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head><title>OAuth Success</title></head>
		<body>
			<script>
				if (window.opener) {
					window.opener.postMessage({
						type: 'oauth_success',
						token: '%s',
						user: {
							id: '%s',
							username: '%s',
							email: '%s',
							role: '%s'
						}
					}, '*');
					window.close();
				} else {
					window.location.href = '/?token=%s';
				}
			</script>
		</body>
		</html>
	`, token, user.ID.Hex(), user.Username, user.Email, user.Role, token)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Handle Yandex OAuth callback
func handleYandexCallback(code string) (email, username string, err error) {
	// Exchange code for token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", yandexClientID)
	data.Set("client_secret", yandexClientSecret)

	resp, err := http.PostForm("https://oauth.yandex.ru/token", data)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", "", err
	}

	// Get user info
	req, _ := http.NewRequest("GET", "https://login.yandex.ru/info", nil)
	req.Header.Set("Authorization", "OAuth "+tokenResp.AccessToken)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err = client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email    string `json:"default_email"`
		RealName string `json:"real_name"`
		Login    string `json:"login"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	email = userInfo.Email
	if email == "" {
		email = userInfo.Login + "@yandex.ru"
	}
	username = userInfo.RealName
	if username == "" {
		username = userInfo.Login
	}

	return email, username, nil
}

// Handle GitHub OAuth callback
func handleGitHubCallback(code string) (email, username string, err error) {
	// Exchange code for token
	data := url.Values{}
	data.Set("client_id", githubClientID)
	data.Set("client_secret", githubClientSecret)
	data.Set("code", code)

	resp, err := http.PostForm("https://github.com/login/oauth/access_token", data)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", err
	}

	accessToken := params.Get("access_token")
	if accessToken == "" {
		return "", "", fmt.Errorf("no access token")
	}

	// Get user info
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+accessToken)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err = client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	// Get email if not in public profile
	if userInfo.Email == "" {
		req, _ = http.NewRequest("GET", "https://api.github.com/user/emails", nil)
		req.Header.Set("Authorization", "token "+accessToken)
		resp, err = client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var emails []struct {
				Email   string `json:"email"`
				Primary bool   `json:"primary"`
			}
			if err = json.NewDecoder(resp.Body).Decode(&emails); err == nil {
				for _, e := range emails {
					if e.Primary {
						userInfo.Email = e.Email
						break
					}
				}
				if userInfo.Email == "" && len(emails) > 0 {
					userInfo.Email = emails[0].Email
				}
			}
		}
	}

	email = userInfo.Email
	if email == "" {
		email = userInfo.Login + "@users.noreply.github.com"
	}
	username = userInfo.Name
	if username == "" {
		username = userInfo.Login
	}

	return email, username, nil
}

// Роутер
func router(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"service": "Auth Module",
			"version": "1.0.0",
			"status":  "running",
		})
	case path == "/api/v1/health":
		healthHandler(w, r)
	case path == "/api/v1/login":
		loginHandler(w, r)
	case path == "/api/v1/verify":
		verifyHandler(w, r)
	case path == "/api/v1/code/send" || path == "/api/v1/code/verify":
		codeAuthHandler(w, r)
	case strings.HasPrefix(path, "/api/v1/oauth/") && strings.HasSuffix(path, "/url"):
		oauthURLHandler(w, r)
	case path == "/api/v1/oauth/callback" || strings.Contains(path, "/oauth/callback"):
		oauthCallbackHandler(w, r)
	case path == "/api/v1/users" && method == "GET":
		getUsersHandler(w, r)
	case path == "/api/v1/users" && method == "POST":
		createUserHandler(w, r)
	case strings.HasPrefix(path, "/api/v1/users/") && method == "PUT":
		updateUserHandler(w, r)
	case strings.HasPrefix(path, "/api/v1/users/") && method == "DELETE":
		deleteUserHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

func main() {
	// Инициализация JWT секрета
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "your-super-secret-jwt-key-change-in-production"
	}
	jwtSecret = []byte(secret)

	// Инициализация OAuth
	initOAuth()

	// Инициализация базы данных
	initDB()

	// Настраиваем сервер
	mux := http.NewServeMux()
	mux.HandleFunc("/", router)

	// Обертываем в CORS middleware
	handler := corsMiddleware(mux)

	port := ":8080"

	log.Println("🚀 Auth Module starting on port 8080")
	log.Println("📚 API Documentation:")
	log.Println("  GET  /                    - Service info")
	log.Println("  GET  /api/v1/health       - Health check")
	log.Println("  POST /api/v1/login        - Traditional auth")
	log.Println("  POST /api/v1/verify       - Token verification")
	log.Println("  POST /api/v1/code/send    - Send code to email")
	log.Println("  POST /api/v1/code/verify  - Verify code")
	log.Println("  GET  /api/v1/users        - Get users (admin)")
	log.Println("  POST /api/v1/users        - Create user (admin)")
	log.Println("  PUT  /api/v1/users/{id}    - Update user (admin)")
	log.Println("  DELETE /api/v1/users/{id}  - Delete user (admin)")

	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
