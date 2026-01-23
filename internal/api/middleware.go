package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"proxmox-nat/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// cleanupExpiredCSRFTokens periodically removes expired CSRF tokens
func (a *API) cleanupExpiredCSRFTokens() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.csrfMutex.Lock()
		now := time.Now()
		for token, expiry := range a.csrfTokens {
			if now.After(expiry) {
				delete(a.csrfTokens, token)
			}
		}
		a.csrfMutex.Unlock()
	}
}

// corsMiddleware handles CORS
func (a *API) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// rateLimitMiddleware implements rate limiting
func (a *API) rateLimitMiddleware() gin.HandlerFunc {
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
		once    sync.Once
	)

	// Start cleanup goroutine only once
	once.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()

			for range ticker.C {
				mu.Lock()
				for ip, client := range clients {
					if time.Since(client.lastSeen) > 3*time.Minute {
						delete(clients, ip)
					}
				}
				mu.Unlock()
			}
		}()
	})

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		if _, exists := clients[ip]; !exists {
			clients[ip] = &client{
				limiter: rate.NewLimiter(rate.Every(time.Second), 100),
			}
		}
		clients[ip].lastSeen = time.Now()
		limiter := clients[ip].limiter
		mu.Unlock()

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, models.APIResponse{
				Success: false,
				Error:   "Too many requests",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// csrfMiddleware implements CSRF protection
func (a *API) csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip CSRF for safe methods
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Check if CSRF is enabled in config
		if !a.config.Security.CSRFEnabled {
			c.Next()
			return
		}

		// Get CSRF token from header
		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "CSRF token required",
			})
			c.Abort()
			return
		}

		// Validate token
		a.csrfMutex.RLock()
		expiry, exists := a.csrfTokens[token]
		a.csrfMutex.RUnlock()

		if !exists {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "Invalid CSRF token",
			})
			c.Abort()
			return
		}

		// Check if token is expired
		if time.Now().After(expiry) {
			a.csrfMutex.Lock()
			delete(a.csrfTokens, token)
			a.csrfMutex.Unlock()

			c.JSON(http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "CSRF token expired",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getCSRFToken generates and returns a new CSRF token
func (a *API) getCSRFToken(c *gin.Context) {
	// Generate random token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to generate CSRF token",
		})
		return
	}

	token := base64.URLEncoding.EncodeToString(b)
	expiry := time.Now().Add(1 * time.Hour)

	// Store token with 1 hour expiry
	a.csrfMutex.Lock()
	a.csrfTokens[token] = expiry
	a.csrfMutex.Unlock()

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: gin.H{
			"token":      token,
			"expires_in": 3600, // 1 hour in seconds
		},
	})
}
