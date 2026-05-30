package main

import (
	"context"
	"encoding/json"
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

	client := config.Client(ctx)
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
		slog.Error("unexpected status", "status", resp.Status)
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
