package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"proxmox-nat/internal/models"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

// rateLimitMiddleware implements rate limiting for Echo
func (a *API) rateLimitMiddleware() echo.MiddlewareFunc {
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

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()

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
				return c.JSON(http.StatusTooManyRequests, models.APIResponse{
					Success: false,
					Error:   "Too many requests",
				})
			}

			return next(c)
		}
	}
}

// csrfMiddleware implements CSRF protection for Echo
func (a *API) csrfMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip CSRF for safe methods
			if c.Request().Method == "GET" || c.Request().Method == "HEAD" || c.Request().Method == "OPTIONS" {
				return next(c)
			}

			// Check if CSRF is enabled in config
			if !a.config.Security.CSRFEnabled {
				return next(c)
			}

			// Get CSRF token from header
			token := c.Request().Header.Get("X-CSRF-Token")
			if token == "" {
				return c.JSON(http.StatusForbidden, models.APIResponse{
					Success: false,
					Error:   "CSRF token required",
				})
			}

			// Validate token
			a.csrfMutex.RLock()
			expiry, exists := a.csrfTokens[token]
			a.csrfMutex.RUnlock()

			if !exists {
				return c.JSON(http.StatusForbidden, models.APIResponse{
					Success: false,
					Error:   "Invalid CSRF token",
				})
			}

			// Check if token is expired
			if time.Now().After(expiry) {
				a.csrfMutex.Lock()
				delete(a.csrfTokens, token)
				a.csrfMutex.Unlock()

				return c.JSON(http.StatusForbidden, models.APIResponse{
					Success: false,
					Error:   "CSRF token expired",
				})
			}

			return next(c)
		}
	}
}

// getCSRFToken generates and returns a new CSRF token
func (a *API) getCSRFToken(c echo.Context) error {
	// Generate random token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to generate CSRF token",
		})
	}

	token := base64.URLEncoding.EncodeToString(b)
	expiry := time.Now().Add(1 * time.Hour)

	// Store token with 1 hour expiry
	a.csrfMutex.Lock()
	a.csrfTokens[token] = expiry
	a.csrfMutex.Unlock()

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"token":      token,
			"expires_in": 3600, // 1 hour in seconds
		},
	})
}
