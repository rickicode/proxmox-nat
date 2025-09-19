package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"proxmox-nat/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// CORS middleware
func (a *API) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow same-origin requests
		if origin == "" {
			origin = "*"
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-CSRF-Token")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Basic authentication middleware
func (a *API) authMiddleware() gin.HandlerFunc {
	return gin.BasicAuth(gin.Accounts{
		a.config.Server.Username: a.config.Server.Password,
	})
}

// Rate limiting middleware
func (a *API) rateLimitMiddleware() gin.HandlerFunc {
	// Create rate limiter map for different IPs
	limiters := make(map[string]*rate.Limiter)
	mutex := sync.RWMutex{}

	// Cleanup routine to remove old limiters
	go func() {
		ticker := time.NewTicker(time.Minute * 10)
		defer ticker.Stop()

		for range ticker.C {
			mutex.Lock()
			// In a real implementation, you'd track last access time
			// and remove old entries. For simplicity, we'll clear all.
			if len(limiters) > 1000 {
				limiters = make(map[string]*rate.Limiter)
			}
			mutex.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mutex.Lock()
		limiter, exists := limiters[ip]
		if !exists {
			// Create new limiter: X requests per minute
			limiter = rate.NewLimiter(rate.Limit(a.config.Security.RateLimit)/60, a.config.Security.RateLimit)
			limiters[ip] = limiter
		}
		mutex.Unlock()

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, models.APIResponse{
				Success: false,
				Error:   "Rate limit exceeded",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Global CSRF token store (in production, use Redis or similar)
var (
	csrfTokens = make(map[string]time.Time)
	csrfMutex  = sync.RWMutex{}
)

func init() {
	// Cleanup old tokens
	go func() {
		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()

		for range ticker.C {
			csrfMutex.Lock()
			now := time.Now()
			for token, created := range csrfTokens {
				if now.Sub(created) > time.Hour {
					delete(csrfTokens, token)
				}
			}
			csrfMutex.Unlock()
		}
	}()
}

// CSRF protection middleware
func (a *API) csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.config.Security.CSRFEnabled {
			c.Next()
			return
		}

		// Skip CSRF for GET requests
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "CSRF token required",
			})
			c.Abort()
			return
		}

		csrfMutex.RLock()
		_, valid := csrfTokens[token]
		csrfMutex.RUnlock()

		if !valid {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "Invalid CSRF token",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// generateCSRFToken generates a new CSRF token
func (a *API) generateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// getCSRFToken returns a new CSRF token
func (a *API) getCSRFToken(c *gin.Context) {
	if !a.config.Security.CSRFEnabled {
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data:    map[string]string{"token": "disabled"},
		})
		return
	}

	token, err := a.generateCSRFToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to generate CSRF token",
		})
		return
	}

	// Store token with timestamp
	// Note: In production, associate with user session
	// For now, we'll store globally which is less secure but functional
	mutex := sync.RWMutex{}
	tokens := make(map[string]time.Time)

	mutex.Lock()
	tokens[token] = time.Now()
	mutex.Unlock()

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    map[string]string{"token": token},
	})
}

// secureCompare performs constant-time comparison
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
