package api

import (
	"net/http"
	"strings"
	"time"

	"proxmox-nat/internal/auth"
	"proxmox-nat/internal/models"

	"github.com/gin-gonic/gin"
)

// LoginRequest represents login request
type LoginRequest struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RememberMe bool   `json:"remember_me"`
}

// LoginResponse represents login response
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

// login handles user login
func (a *API) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	// Validate credentials
	if req.Username != a.config.Server.Username || req.Password != a.config.Server.Password {
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "Invalid username or password",
		})
		return
	}

	// Generate JWT token
	token, err := a.jwtManager.GenerateToken(req.Username, req.RememberMe)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to generate token",
		})
		return
	}

	// Calculate expiration
	expiresIn := int64(24 * time.Hour.Seconds()) // 24 hours
	if req.RememberMe {
		expiresIn = int64(30 * 24 * time.Hour.Seconds()) // 30 days
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: LoginResponse{
			Token:     token,
			ExpiresIn: expiresIn,
		},
	})
}

// logout handles user logout
func (a *API) logout(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Logged out successfully",
	})
}

// validateToken validates JWT token
func (a *API) validateToken(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "Unauthorized",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"username": username,
			"valid":    true,
		},
	})
}

// jwtAuthMiddleware validates JWT token
func (a *API) jwtAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Error:   "Authorization header required",
			})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Error:   "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := a.jwtManager.ValidateToken(tokenString)
		if err != nil {
			if err == auth.ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, models.APIResponse{
					Success: false,
					Error:   "Token expired",
				})
			} else {
				c.JSON(http.StatusUnauthorized, models.APIResponse{
					Success: false,
					Error:   "Invalid token",
				})
			}
			c.Abort()
			return
		}

		// Set username in context
		c.Set("username", claims.Username)
		c.Next()
	}
}
