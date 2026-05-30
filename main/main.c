#include "app_config.h"
#include "esp_log.h"

static const char *TAG = "main";

void app_main(void)
{
    ESP_ERROR_CHECK(app_config_init());

    app_config_t config;
    ESP_ERROR_CHECK(app_config_load(&config));
    ESP_LOGI(TAG, "config loaded: wifi=%s auth_audience=%s",
             app_config_has_wifi(&config) ? "set" : "missing",
             app_config_has_auth_audience(&config) ? "set" : "missing");
}
