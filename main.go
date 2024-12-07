package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"database/sql"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ed25519"
)

var db *sql.DB

// Initialize PostgreSQL connection
func initDB() {
	var err error
	connStr := "postgres://diduser:password@localhost:5432/diddb?sslmode=disable" // Replace with your database connection string
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
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS attributes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			did_id UUID REFERENCES dids(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS signatures (
			id SERIAL PRIMARY KEY,
			attribute_id UUID REFERENCES attributes(id) ON DELETE CASCADE,
			signed_by_did TEXT NOT NULL,
			signature TEXT NOT NULL,
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


// Generate UUIDv5 for deterministic DID generation
func generateUUIDv5(namespace, input string) string {
	namespaceBytes, _ := hex.DecodeString(namespace)
	inputBytes := []byte(input)

	hash := sha1.New()
	hash.Write(namespaceBytes)
	hash.Write(inputBytes)
	uuid := hash.Sum(nil)

	uuid[6] = (uuid[6] & 0x0f) | 0x50
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4],
		uuid[4:6],
		uuid[6:8],
		uuid[8:10],
		uuid[10:])
}

// Endpoint to generate a new DID
func generateDID(c *gin.Context) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Error generating keys: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate keys"})
		return
	}

	pubKeyHex := hex.EncodeToString(pub)
	uuid := generateUUIDv5("5b6e0c88-6867-598c-a7e1-c4c5d10e9c4a", pubKeyHex)
	did := fmt.Sprintf("did:nice:%s", uuid)

	_, err = db.Exec(`INSERT INTO dids (did, public_key, private_key, created_at) VALUES ($1, $2, $3, $4)`,
		did, pubKeyHex, hex.EncodeToString(priv), time.Now())
	if err != nil {
		log.Printf("Error inserting DID into database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save DID to database"})
		return
	}

	log.Printf("DID created successfully: %s", did)
	c.JSON(http.StatusOK, gin.H{
		"did":         did,
		"public_key":  pubKeyHex,
		"private_key": hex.EncodeToString(priv),
	})
}

// Endpoint to sign an attribute
func signAttribute(c *gin.Context) {
	var req struct {
		DID          string `json:"did"`
		TargetDID    string `json:"target_did"`
		Attribute    string `json:"attribute"`
		AttributeVal string `json:"attribute_val"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Invalid request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Validate that the signing DID exists
	var signerPrivateKey string
	err := db.QueryRow(`SELECT private_key FROM dids WHERE did = $1`, req.DID).Scan(&signerPrivateKey)
	if err != nil {
		log.Printf("Signing DID not found: %s", req.DID)
		c.JSON(http.StatusNotFound, gin.H{"error": "signing DID not found"})
		return
	}

	// Validate that the target DID exists
	var targetDIDID string
	err = db.QueryRow(`SELECT id FROM dids WHERE did = $1`, req.TargetDID).Scan(&targetDIDID)
	if err == sql.ErrNoRows {
		log.Printf("Target DID not found: %s", req.TargetDID)
		c.JSON(http.StatusNotFound, gin.H{"error": "target DID not found"})
		return
	} else if err != nil {
		log.Printf("Error querying target DID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error querying target DID"})
		return
	}

	// Check if the attribute already exists for the target DID
	var attributeID string
	err = db.QueryRow(`
        SELECT id FROM attributes 
        WHERE did_id = $1 AND name = $2 AND value = $3
    `, targetDIDID, req.Attribute, req.AttributeVal).Scan(&attributeID)

	if err == sql.ErrNoRows {
		// If the attribute doesn't exist, insert it
		err = db.QueryRow(`
            INSERT INTO attributes (did_id, name, value, created_at) 
            VALUES ($1, $2, $3, $4) RETURNING id
        `, targetDIDID, req.Attribute, req.AttributeVal, time.Now()).Scan(&attributeID)
		if err != nil {
			log.Printf("Failed to insert attribute: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to insert attribute"})
			return
		}
	} else if err != nil {
		log.Printf("Failed to query attribute: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query attribute"})
		return
	}

	// Generate the signature
	privKey, _ := hex.DecodeString(signerPrivateKey)
	message := fmt.Sprintf("%s:%s:%s", req.Attribute, req.AttributeVal, req.TargetDID)
	signature := ed25519.Sign(privKey, []byte(message))
	signatureHex := hex.EncodeToString(signature)

	// Store the signature
	_, err = db.Exec(`
        INSERT INTO signatures (attribute_id, signed_by_did, signature, created_at)
        VALUES ($1, $2, $3, $4)
    `, attributeID, req.DID, signatureHex, time.Now())
	if err != nil {
		log.Printf("Failed to store signature: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store signature"})
		return
	}

	log.Printf("Attribute signed: %s:%s by %s (signature: %s)", req.Attribute, req.AttributeVal, req.DID, signatureHex)
	c.JSON(http.StatusOK, gin.H{
		"attribute": req.Attribute,
		"value":     req.AttributeVal,
		"signed_by": req.DID,
		"signature": signatureHex,
	})
}

func listDIDsAndAttributes(c *gin.Context) {
	rows, err := db.Query(`
		SELECT d.did, d.public_key, a.name, a.value, s.signed_by_did, s.signature, s.created_at
		FROM dids d
		LEFT JOIN attributes a ON d.id = a.did_id
		LEFT JOIN signatures s ON a.id = s.attribute_id
		ORDER BY d.did, a.name, s.created_at
	`)
	if err != nil {
		log.Printf("Error querying DIDs and attributes: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query DIDs and attributes"})
		return
	}
	defer rows.Close()

	results := make(map[string]map[string]interface{})
	for rows.Next() {
		var did, publicKey, name, value, signedBy, signature string
		var createdAt time.Time

		if err := rows.Scan(&did, &publicKey, &name, &value, &signedBy, &signature, &createdAt); err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		if _, ok := results[did]; !ok {
			results[did] = map[string]interface{}{
				"public_key": publicKey,
				"attributes": []map[string]interface{}{},
			}
		}

		if name != "" && value != "" {
			attributes := results[did]["attributes"].([]map[string]interface{})
			attributes = append(attributes, map[string]interface{}{
				"name":      name,
				"value":     value,
				"signed_by": signedBy,
				"signature": signature,
				"created_at": createdAt.Format(time.RFC3339),
			})
			results[did]["attributes"] = attributes
		}
	}

	c.JSON(http.StatusOK, results)
}


func main() {
	initDB()
	migrateSchema()

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://nivenly.nym.st"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		AllowCredentials: true,
	}))

	r.POST("/dids", generateDID)
	r.POST("/attributes/sign", signAttribute)
	r.GET("/dids", listDIDsAndAttributes)


	r.Static("/static", "./static")
	r.StaticFile("/", "./static/frontend.html")
	r.StaticFile("/dids.html", "./static/dids.html")

	certFile := "/etc/letsencrypt/live/nivenly.nym.st/fullchain.pem"
	keyFile := "/etc/letsencrypt/live/nivenly.nym.st/privkey.pem"
	log.Println("Server running on https://nivenly.nym.st:8080")
	if err := r.RunTLS(":8080", certFile, keyFile); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
