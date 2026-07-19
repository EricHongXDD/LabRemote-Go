package model

import (
	"encoding/json"
	"fmt"
)

type AppError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Stage     string         `json:"stage,omitempty"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func NewAppError(code, message, stage string, retryable bool) *AppError {
	return &AppError{Code: code, Message: message, Stage: stage, Retryable: retryable}
}

func (e *AppError) WithDetails(details map[string]any) *AppError {
	e.Details = SanitizeDetails(details)
	return e
}

func (e *AppError) Error() string {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return "APPERROR:" + string(data)
}

func SanitizeDetails(details map[string]any) map[string]any {
	clean := make(map[string]any, len(details))
	for key, value := range details {
		switch key {
		case "password", "psk", "pre_shared_key", "authorization", "token", "secret":
			clean[key] = "[REDACTED]"
		default:
			clean[key] = value
		}
	}
	return clean
}
