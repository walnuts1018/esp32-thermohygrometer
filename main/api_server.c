#include "api_server.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "auth_oidc.h"
#include "app_status.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "json_util.h"
#include "sensor_sht31.h"
#include "sensor_task.h"

#define API_AUTH_HEADER_MAX CONFIG_HTTPD_MAX_REQ_HDR_LEN

static httpd_handle_t s_server;
static bool s_server_starting;
static portMUX_TYPE s_server_lock = portMUX_INITIALIZER_UNLOCKED;

static const char *json_bool(bool value)
{
    return value ? "true" : "false";
}

static esp_err_t healthz_handler(httpd_req_t *req)
{
    app_status_t status = app_status_get();
    sensor_latest_reading_t latest = {0};
    esp_err_t latest_err = sensor_latest_get(&latest);
    bool sensor_valid = latest_err == ESP_OK;
    esp_err_t sensor_last_error = latest.last_error;
    if (!sensor_valid && sensor_last_error == ESP_OK) {
        sensor_last_error = latest_err;
    }

    char body[384];
    int len = snprintf(body, sizeof(body),
                       "{"
                       "\"firmware\":\"dev\","
                       "\"wifi_connected\":%s,"
                       "\"time_synced\":%s,"
                       "\"auth_ready\":%s,"
                       "\"sensor_valid\":%s,"
                       "\"sensor_last_error\":\"%s\","
                       "\"uptime_ms\":%lld"
                       "}",
                       json_bool(status.wifi_connected),
                       json_bool(status.time_synced),
                       json_bool(status.auth_ready),
                       json_bool(sensor_valid),
                       esp_err_to_name(sensor_last_error),
                       (long long)(esp_timer_get_time() / 1000));
    if (len < 0 || len >= (int)sizeof(body)) {
        return json_send_error(req, 500, "internal_error", "response too large");
    }

    return json_send(req, body);
}

static esp_err_t latest_handler(httpd_req_t *req)
{
    char *auth_header = NULL;
    size_t auth_header_len = httpd_req_get_hdr_value_len(req, "Authorization");
    esp_err_t hdr_err = ESP_ERR_NOT_FOUND;
    if (auth_header_len > 0 && auth_header_len < API_AUTH_HEADER_MAX) {
        auth_header = calloc(1, auth_header_len + 1);
        if (auth_header == NULL) {
            return json_send_error(req, 500, "internal_error", "out of memory");
        }
        hdr_err = httpd_req_get_hdr_value_str(req, "Authorization", auth_header,
                                              auth_header_len + 1);
    }

    auth_result_t auth =
        auth_oidc_validate_authorization_header(hdr_err == ESP_OK ? auth_header : NULL);
    free(auth_header);
    if (auth == AUTH_RESULT_MISSING || auth == AUTH_RESULT_INVALID) {
        return json_send_error(req, 401, "unauthorized", "missing or invalid bearer token");
    }
    if (auth == AUTH_RESULT_FORBIDDEN) {
        return json_send_error(req, 403, "forbidden", "token lacks required audience or role");
    }
    if (auth == AUTH_RESULT_NOT_READY) {
        return json_send_error(req, 503, "auth_not_ready", "auth metadata is not ready");
    }

    sensor_latest_reading_t latest = {0};
    esp_err_t err = sensor_latest_get(&latest);
    if (err != ESP_OK) {
        return json_send_error(req, 503, "sensor_unavailable", "no valid sensor reading is available");
    }

    char body[256];
    int len = snprintf(body, sizeof(body),
                       "{"
                       "\"temperature_celsius\":%.2f,"
                       "\"relative_humidity_percent\":%.2f,"
                       "\"sensor\":\"sht31\","
                       "\"i2c_address\":\"0x%02X\","
                       "\"measured_at_ms\":%lld"
                       "}",
                       latest.temperature_celsius,
                       latest.relative_humidity_percent,
                       SHT31_I2C_ADDR,
                       (long long)latest.measured_at_ms);
    if (len < 0 || len >= (int)sizeof(body)) {
        return json_send_error(req, 500, "internal_error", "response too large");
    }

    return json_send(req, body);
}

esp_err_t api_server_start(void)
{
    while (true) {
        taskENTER_CRITICAL(&s_server_lock);
        if (s_server != NULL) {
            taskEXIT_CRITICAL(&s_server_lock);
            return ESP_OK;
        }

        if (!s_server_starting) {
            s_server_starting = true;
            taskEXIT_CRITICAL(&s_server_lock);
            break;
        }
        taskEXIT_CRITICAL(&s_server_lock);

        vTaskDelay(1);
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 12288;
    if (config.max_uri_handlers < 8) {
        config.max_uri_handlers = 8;
    }

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err == ESP_OK) {
        const httpd_uri_t healthz_uri = {
            .uri = "/healthz",
            .method = HTTP_GET,
            .handler = healthz_handler,
            .user_ctx = NULL,
        };
        err = httpd_register_uri_handler(server, &healthz_uri);
    }

    if (err == ESP_OK) {
        const httpd_uri_t latest_uri = {
            .uri = "/v1/measurements/latest",
            .method = HTTP_GET,
            .handler = latest_handler,
            .user_ctx = NULL,
        };
        err = httpd_register_uri_handler(server, &latest_uri);
    }

    if (err != ESP_OK && server != NULL) {
        httpd_stop(server);
        server = NULL;
    }

    taskENTER_CRITICAL(&s_server_lock);
    if (err == ESP_OK) {
        s_server = server;
    }
    s_server_starting = false;
    taskEXIT_CRITICAL(&s_server_lock);

    return err;
}
