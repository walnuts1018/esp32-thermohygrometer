#pragma once

#include <stdbool.h>
#include "esp_err.h"

/* Wi-Fi lengths are max payload bytes and exclude the terminating NUL. */
#define APP_CONFIG_MAX_SSID_LEN 32
#define APP_CONFIG_MAX_PASSWORD_LEN 64

/* Auth lengths are struct buffer sizes and include the terminating NUL. */
#define APP_CONFIG_MAX_URL_LEN 128
#define APP_CONFIG_MAX_AUDIENCE_LEN 96
#define APP_CONFIG_MAX_ROLE_LEN 64

typedef struct {
    char ssid[APP_CONFIG_MAX_SSID_LEN + 1];
    char password[APP_CONFIG_MAX_PASSWORD_LEN + 1];
    char issuer[APP_CONFIG_MAX_URL_LEN];
    char audience[APP_CONFIG_MAX_AUDIENCE_LEN];
    char role[APP_CONFIG_MAX_ROLE_LEN];
} app_config_t;

esp_err_t app_config_init(void);
esp_err_t app_config_load(app_config_t *config);
esp_err_t app_config_save_wifi(const char *ssid, const char *password);
esp_err_t app_config_save_auth(const char *issuer, const char *audience, const char *role);
bool app_config_has_wifi(const app_config_t *config);
bool app_config_has_auth_audience(const app_config_t *config);
