package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type measurement struct {
	TemperatureCelsius      float64 `json:"temperature_celsius"`
	RelativeHumidityPercent float64 `json:"relative_humidity_percent"`
	Sensor                  string  `json:"sensor"`
	I2CAddress              string  `json:"i2c_address"`
	MeasuredAtMS            int64   `json:"measured_at_ms"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	deviceURL := strings.TrimRight(mustLoadEnv("DEVICE_URL"), "/")
	tokenURL := mustLoadEnv("OIDC_TOKEN_URL")
	clientID := mustLoadEnv("OIDC_CLIENT_ID")
	clientSecret := mustLoadEnv("OIDC_CLIENT_SECRET")

	params := url.Values{}
	if audience, ok := os.LookupEnv("OIDC_AUDIENCE"); ok && audience != "" {
		params.Set("audience", audience)
	}

	config := clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		Scopes:         splitEnv("OIDC_SCOPES"),
		EndpointParams: params,
		AuthStyle:      oauth2.AuthStyleInHeader,
	}

	token, err := config.TokenSource(ctx).Token()
	if err != nil {
		slog.Error("failed to get access token", "error", err)
		os.Exit(1)
	}
	logAccessTokenDiagnostics(token.AccessToken, token.TokenType, token.Expiry)

	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	measureURL, err := url.JoinPath(deviceURL, "/v1/measurements/latest")
	if err != nil {
		slog.Error("failed to join URL", "error", err)
		os.Exit(1)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, measureURL, nil)
	if err != nil {
		slog.Error("failed to create request", "error", err)
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("failed to call measurement API", "error", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.Error("unexpected status",
			"status", resp.Status,
			"body", strings.TrimSpace(string(body)),
		)
		os.Exit(1)
	}

	var latest measurement
	if err := json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		slog.Error("failed to decode response", "error", err)
		os.Exit(1)
	}

	slog.Info("latest measurement",
		"temperature_celsius", latest.TemperatureCelsius,
		"relative_humidity_percent", latest.RelativeHumidityPercent,
		"sensor", latest.Sensor,
		"i2c_address", latest.I2CAddress,
		"measured_at_ms", latest.MeasuredAtMS,
	)
}

func logAccessTokenDiagnostics(accessToken, tokenType string, expiry time.Time) {
	slog.Info("access token acquired",
		"token_type", tokenType,
		"access_token_length", len(accessToken),
		"authorization_header_length", len("Bearer ")+len(accessToken),
		"expiry", expiry.Format(time.RFC3339),
	)

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		slog.Warn("access token is not a JWT", "segments", len(parts))
		return
	}

	slog.Info("access token JWT segments",
		"header_length", len(parts[0]),
		"payload_length", len(parts[1]),
		"signature_length", len(parts[2]),
	)
	logJWTPart("access token header", parts[0])
	logJWTPart("access token payload", parts[1])
}

func logJWTPart(message, raw string) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		slog.Warn("failed to decode JWT segment", "segment", message, "error", err)
		return
	}
	slog.Info(message, "json", string(decoded))
}

func mustLoadEnv(name string) string {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		slog.Error("environment variable is required", "name", name)
		os.Exit(1)
	}
	return value
}

func splitEnv(name string) []string {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}
