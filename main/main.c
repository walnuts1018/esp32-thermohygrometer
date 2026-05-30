#include "api_server.h"
#include "app_config.h"
#include "esp_log.h"
#include "sensor_task.h"

static const char *TAG = "main";

void app_main(void)
{
    ESP_ERROR_CHECK(app_config_init());

    app_config_t config;
    ESP_ERROR_CHECK(app_config_load(&config));
    ESP_LOGI(TAG, "config loaded: wifi=%s auth_audience=%s",
             app_config_has_wifi(&config) ? "set" : "missing",
             app_config_has_auth_audience(&config) ? "set" : "missing");

    ESP_ERROR_CHECK(sensor_task_start());
    ESP_ERROR_CHECK(api_server_start());
}
