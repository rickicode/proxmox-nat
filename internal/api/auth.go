package api

import (
	"net/http"
	"strings"
	"time"

	"proxmox-nat/internal/auth"
	"proxmox-nat/internal/models"

	"github.com/labstack/echo/v4"
)

// LoginRequest represents login request payload
type LoginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

// LoginResponse represents login response payload
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

// login handles user login
func (a *API) login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request format",
		})
	}

	// Validate credentials
	if req.Username != a.config.Server.Username || req.Password != a.config.Server.Password {
		return c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "Invalid username or password",
		})
	}

	// Generate JWT token
	token, err := a.jwtManager.GenerateToken(req.Username, req.RememberMe)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Failed to generate token",
		})
	}

	// Calculate expiration
	expiresIn := int64(24 * time.Hour.Seconds()) // 24 hours
	if req.RememberMe {
		expiresIn = int64(30 * 24 * time.Hour.Seconds()) // 30 days
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data: LoginResponse{
			Token:     token,
			ExpiresIn: expiresIn,
		},
	})
}

// logout handles user logout
func (a *API) logout(c echo.Context) error {
	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Logged out successfully",
	})
}

// jwtAuthMiddleware validates JWT token
func (a *API) jwtAuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get token from Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Success: false,
					Error:   "Authorization header required",
				})
			}

			// Extract token from "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Success: false,
					Error:   "Invalid authorization header format",
				})
			}

			tokenString := parts[1]

			// Validate token
			claims, err := a.jwtManager.ValidateToken(tokenString)
			if err != nil {
				if err == auth.ErrExpiredToken {
					return c.JSON(http.StatusUnauthorized, models.APIResponse{
						Success: false,
						Error:   "Token expired",
					})
				}
				return c.JSON(http.StatusUnauthorized, models.APIResponse{
					Success: false,
					Error:   "Invalid token",
				})
			}

			// Set username in context
			c.Set("username", claims.Username)
			return next(c)
		}
	}
}
