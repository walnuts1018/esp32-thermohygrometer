#include "app_config.h"

#include <string.h>
#include "nvs.h"
#include "nvs_flash.h"

#define APP_CONFIG_NAMESPACE "app"
#define APP_CONFIG_DEFAULT_ISSUER "https://auth.walnuts.dev"
#define APP_CONFIG_DEFAULT_ROLE "thermohygrometer.read"

static bool app_config_fits_string(const char *value, size_t buffer_size)
{
    return value != NULL && strnlen(value, buffer_size) < buffer_size;
}

static esp_err_t app_config_read_string(nvs_handle_t handle, const char *key, char *value, size_t value_size)
{
    size_t required_size = value_size;
    esp_err_t err = nvs_get_str(handle, key, value, &required_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }

    return err;
}

static esp_err_t app_config_set_default(char *value, size_t value_size, const char *default_value)
{
    if (!app_config_fits_string(default_value, value_size)) {
        return ESP_ERR_INVALID_SIZE;
    }

    strlcpy(value, default_value, value_size);
    return ESP_OK;
}

esp_err_t app_config_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        err = nvs_flash_erase();
        if (err != ESP_OK) {
            return err;
        }
        err = nvs_flash_init();
    }

    return err;
}

esp_err_t app_config_load(app_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(config, 0, sizeof(*config));

    esp_err_t err = app_config_set_default(config->issuer, sizeof(config->issuer), APP_CONFIG_DEFAULT_ISSUER);
    if (err != ESP_OK) {
        return err;
    }

    err = app_config_set_default(config->role, sizeof(config->role), APP_CONFIG_DEFAULT_ROLE);
    if (err != ESP_OK) {
        return err;
    }

    nvs_handle_t handle;
    err = nvs_open(APP_CONFIG_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }

    err = app_config_read_string(handle, "wifi_ssid", config->ssid, sizeof(config->ssid));
    if (err == ESP_OK) {
        err = app_config_read_string(handle, "wifi_pass", config->password, sizeof(config->password));
    }
    if (err == ESP_OK) {
        err = app_config_read_string(handle, "auth_issuer", config->issuer, sizeof(config->issuer));
    }
    if (err == ESP_OK) {
        err = app_config_read_string(handle, "auth_aud", config->audience, sizeof(config->audience));
    }
    if (err == ESP_OK) {
        err = app_config_read_string(handle, "auth_role", config->role, sizeof(config->role));
    }

    nvs_close(handle);
    return err;
}

esp_err_t app_config_save_wifi(const char *ssid, const char *password)
{
    if (!app_config_fits_string(ssid, APP_CONFIG_MAX_SSID_LEN + 1) ||
        !app_config_fits_string(password, APP_CONFIG_MAX_PASSWORD_LEN + 1)) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(APP_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(handle, "wifi_ssid", ssid);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, "wifi_pass", password);
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}

esp_err_t app_config_save_auth(const char *issuer, const char *audience, const char *role)
{
    if (!app_config_fits_string(issuer, APP_CONFIG_MAX_URL_LEN) ||
        !app_config_fits_string(audience, APP_CONFIG_MAX_AUDIENCE_LEN) ||
        !app_config_fits_string(role, APP_CONFIG_MAX_ROLE_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(APP_CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(handle, "auth_issuer", issuer);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, "auth_aud", audience);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(handle, "auth_role", role);
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}

bool app_config_has_wifi(const app_config_t *config)
{
    return config != NULL && config->ssid[0] != '\0' && config->password[0] != '\0';
}

bool app_config_has_auth_audience(const app_config_t *config)
{
    return config != NULL && config->audience[0] != '\0';
}
