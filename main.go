package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"database/sql"
)

var db *sql.DB

func initDB() {
	var err error
	connStr := os.Getenv("POSTGRES_URL")
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to ping PostgreSQL: %v", err)
	}
	log.Println("Connected to PostgreSQL")
}

func migrateSchema() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS dids (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			did TEXT UNIQUE NOT NULL,
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			doc JSONB DEFAULT '{}'::jsonb NOT NULL,
			alias TEXT UNIQUE,
			password_hash TEXT NOT NULL,
			name TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			log.Fatalf("Failed to execute migration query: %v", err)
		}
	}
	log.Println("Database schema migration complete")
}

func generateUUIDv5(namespace, input string) string {
	namespaceBytes, _ := hex.DecodeString(namespace)
	inputBytes := []byte(input)

	hash := sha256.Sum256(append(namespaceBytes, inputBytes...))
	uuid := hash[:16]

	uuid[6] = (uuid[6] & 0x0f) | 0x50
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4],
		uuid[4:6],
		uuid[6:8],
		uuid[8:10],
		uuid[10:])
}

func registerUser(c *gin.Context) {
	var req struct {
		Name     string `json:"name"`
		Alias    string `json:"alias"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.Password == "" || req.Alias == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Alias and password are required"})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Error generating keys: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate keys"})
		return
	}

	pubKeyHex := hex.EncodeToString(pub)
	uuid := generateUUIDv5("5b6e0c88-6867-598c-a7e1-c4c5d10e9c4a", pubKeyHex)
	did := fmt.Sprintf("did:nice:%s", uuid)

	_, err = db.Exec(`
		INSERT INTO dids (did, public_key, private_key, alias, password_hash, name, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		did, pubKeyHex, hex.EncodeToString(priv), req.Alias, string(passwordHash), req.Name, time.Now())
	if err != nil {
		log.Printf("Error inserting DID into database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save registration data"})
		return
	}

	log.Printf("User registered successfully: %s", did)
	c.JSON(http.StatusOK, gin.H{
		"did":        did,
		"public_key": pubKeyHex,
	})
}

func userLogin(c *gin.Context) {
	var req struct {
		Alias    string `json:"alias"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var storedHash, did string
	err := db.QueryRow(`SELECT password_hash, did FROM dids WHERE alias = $1`, req.Alias).Scan(&storedHash, &did)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	session := sessions.Default(c)
	session.Set("did", did)
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "did": did})
}

func sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		did := session.Get("did")
		if did == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not logged in"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func main() {
	_ = godotenv.Load()
	initDB()
	migrateSchema()

	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(cors.Default(), sessions.Sessions("my-session", store))

	// Static files
	r.StaticFile("/", "./static/index.html")
	r.StaticFile("/login.html", "./static/login.html")
	r.StaticFile("/registration.html", "./static/registration.html")
	r.StaticFile("/dashboard.html", "./static/dashboard.html") // Added this route

	// API routes
	r.POST("/register", registerUser)
	r.POST("/login", userLogin)

	// Secure routes
	secure := r.Group("/secure")
	secure.Use(sessionMiddleware())
	secure.GET("/dashboard", func(c *gin.Context) {
		c.File("./static/dashboard.html") // Serve the dashboard only for logged-in users
	})

	log.Println("Server running on https://nivenly.nym.st:8080")
	r.RunTLS(":8080", os.Getenv("TLS_CERT_PATH"), os.Getenv("TLS_KEY_PATH"))
}

