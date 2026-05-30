#include "auth_oidc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_status.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define AUTH_TASK_STACK_SIZE 12288
#define AUTH_TASK_PRIORITY 5
#define AUTH_RESPONSE_MAX 8192
#define AUTH_REFRESH_INTERVAL_MS (5 * 60 * 1000)
#define AUTH_DISCOVERY_SUFFIX "/.well-known/openid-configuration"
#define AUTH_HTTPS_SCHEME "https://"

static const char *TAG = "auth_oidc";

static app_config_t s_config;
static SemaphoreHandle_t s_auth_mutex;
static TaskHandle_t s_auth_task_handle;
static bool s_auth_task_starting;
static char *s_jwks_json;
static char s_jwks_uri[APP_CONFIG_MAX_URL_LEN];
static portMUX_TYPE s_auth_lock = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    char *data;
    int len;
    int capacity;
    bool overflow;
} auth_http_buffer_t;

static esp_err_t auth_oidc_ensure_mutex(void)
{
    taskENTER_CRITICAL(&s_auth_lock);
    if (s_auth_mutex != NULL) {
        taskEXIT_CRITICAL(&s_auth_lock);
        return ESP_OK;
    }
    taskEXIT_CRITICAL(&s_auth_lock);

    SemaphoreHandle_t new_mutex = xSemaphoreCreateMutex();
    if (new_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    taskENTER_CRITICAL(&s_auth_lock);
    if (s_auth_mutex == NULL) {
        s_auth_mutex = new_mutex;
        new_mutex = NULL;
    }
    taskEXIT_CRITICAL(&s_auth_lock);

    if (new_mutex != NULL) {
        vSemaphoreDelete(new_mutex);
    }

    return ESP_OK;
}

static bool auth_url_is_https(const char *url)
{
    return url != NULL && strncmp(url, AUTH_HTTPS_SCHEME, strlen(AUTH_HTTPS_SCHEME)) == 0;
}

static bool auth_issuer_has_trailing_slash(const char *issuer)
{
    if (issuer == NULL || issuer[0] == '\0') {
        return false;
    }

    return issuer[strlen(issuer) - 1] == '/';
}

static esp_err_t auth_validate_issuer(const char *issuer)
{
    if (!auth_url_is_https(issuer) || auth_issuer_has_trailing_slash(issuer)) {
        return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
}

static void auth_oidc_copy_config_locked(const app_config_t *config)
{
    if (config == NULL) {
        return;
    }

    s_config = *config;
}

static esp_err_t auth_oidc_get_config_copy(app_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = auth_oidc_ensure_mutex();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    *config = s_config;
    xSemaphoreGive(s_auth_mutex);
    return ESP_OK;
}

static esp_err_t auth_http_event_handler(esp_http_client_event_t *event)
{
    auth_http_buffer_t *buffer = (auth_http_buffer_t *)event->user_data;
    if (event->event_id != HTTP_EVENT_ON_DATA || buffer == NULL || event->data_len <= 0) {
        return ESP_OK;
    }

    if (event->data_len > buffer->capacity - buffer->len - 1) {
        buffer->overflow = true;
        if (buffer->capacity > 0) {
            buffer->data[buffer->capacity - 1] = '\0';
        }
        return ESP_ERR_NO_MEM;
    }

    memcpy(buffer->data + buffer->len, event->data, event->data_len);
    buffer->len += event->data_len;
    buffer->data[buffer->len] = '\0';
    return ESP_OK;
}

static esp_err_t auth_https_get_json(const char *url, char *out, int out_len)
{
    if (url == NULL || out == NULL || out_len <= 1) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!auth_url_is_https(url)) {
        return ESP_ERR_INVALID_ARG;
    }

    out[0] = '\0';
    auth_http_buffer_t buffer = {
        .data = out,
        .len = 0,
        .capacity = out_len,
        .overflow = false,
    };
    esp_http_client_config_t http_config = {
        .url = url,
        .event_handler = auth_http_event_handler,
        .user_data = &buffer,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (client == NULL) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        return err;
    }
    if (buffer.overflow) {
        return ESP_ERR_NO_MEM;
    }
    if (status_code != 200) {
        ESP_LOGW(TAG, "HTTPS GET failed url=%s status=%d", url, status_code);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t auth_build_discovery_url(const char *issuer, char *out, size_t out_size)
{
    if (issuer == NULL || out == NULL || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = auth_validate_issuer(issuer);
    if (err != ESP_OK) {
        return err;
    }

    int len = snprintf(out, out_size, "%s%s", issuer, AUTH_DISCOVERY_SUFFIX);
    if (len < 0 || len >= (int)out_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

static esp_err_t auth_parse_discovery(const char *discovery_json,
                                      const app_config_t *config,
                                      char *jwks_uri,
                                      size_t jwks_uri_size)
{
    if (discovery_json == NULL || config == NULL || jwks_uri == NULL || jwks_uri_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *root = cJSON_Parse(discovery_json);
    if (root == NULL) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    esp_err_t err = ESP_OK;
    const cJSON *issuer = cJSON_GetObjectItemCaseSensitive(root, "issuer");
    const cJSON *jwks = cJSON_GetObjectItemCaseSensitive(root, "jwks_uri");
    if (!cJSON_IsString(issuer) || strcmp(issuer->valuestring, config->issuer) != 0 ||
        !cJSON_IsString(jwks) || !auth_url_is_https(jwks->valuestring)) {
        err = ESP_ERR_INVALID_RESPONSE;
    } else if (strnlen(jwks->valuestring, jwks_uri_size) >= jwks_uri_size) {
        err = ESP_ERR_INVALID_SIZE;
    } else {
        strlcpy(jwks_uri, jwks->valuestring, jwks_uri_size);
    }

    cJSON_Delete(root);
    return err;
}

static esp_err_t auth_validate_jwks(const char *jwks_json)
{
    if (jwks_json == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *root = cJSON_Parse(jwks_json);
    if (root == NULL) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    esp_err_t err = ESP_OK;
    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(root, "keys");
    if (!cJSON_IsObject(root) || !cJSON_IsArray(keys) || cJSON_GetArraySize(keys) <= 0) {
        err = ESP_ERR_INVALID_RESPONSE;
    }

    cJSON_Delete(root);
    return err;
}

static esp_err_t auth_discover_and_fetch_jwks(void)
{
    app_config_t config;
    esp_err_t err = auth_oidc_get_config_copy(&config);
    if (err != ESP_OK) {
        return err;
    }

    char discovery_url[APP_CONFIG_MAX_URL_LEN + sizeof(AUTH_DISCOVERY_SUFFIX)];
    err = auth_build_discovery_url(config.issuer, discovery_url, sizeof(discovery_url));
    if (err != ESP_OK) {
        return err;
    }

    char *discovery_json = calloc(1, AUTH_RESPONSE_MAX);
    char *jwks_json = calloc(1, AUTH_RESPONSE_MAX);
    if (discovery_json == NULL || jwks_json == NULL) {
        free(discovery_json);
        free(jwks_json);
        return ESP_ERR_NO_MEM;
    }

    char jwks_uri[APP_CONFIG_MAX_URL_LEN] = {0};
    err = auth_https_get_json(discovery_url, discovery_json, AUTH_RESPONSE_MAX);
    if (err == ESP_OK) {
        err = auth_parse_discovery(discovery_json, &config, jwks_uri, sizeof(jwks_uri));
    }
    if (err == ESP_OK) {
        err = auth_https_get_json(jwks_uri, jwks_json, AUTH_RESPONSE_MAX);
    }
    if (err == ESP_OK) {
        err = auth_validate_jwks(jwks_json);
    }
    if (err == ESP_OK) {
        xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
        free(s_jwks_json);
        s_jwks_json = jwks_json;
        jwks_json = NULL;
        strlcpy(s_jwks_uri, jwks_uri, sizeof(s_jwks_uri));
        app_status_set_auth_ready(true);
        xSemaphoreGive(s_auth_mutex);
    }

    free(discovery_json);
    free(jwks_json);
    return err;
}

static void auth_oidc_task(void *arg)
{
    (void)arg;

    while (true) {
        esp_err_t err = auth_discover_and_fetch_jwks();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "OIDC discovery/JWKS refresh failed: %s", esp_err_to_name(err));
            app_status_set_auth_ready(false);
        }

        vTaskDelay(pdMS_TO_TICKS(AUTH_REFRESH_INTERVAL_MS));
    }
}

esp_err_t auth_oidc_start(const app_config_t *config)
{
    if (config == NULL || !app_config_has_auth_audience(config)) {
        ESP_LOGW(TAG, "auth audience is missing; protected API will stay unavailable");
        app_status_set_auth_ready(false);
        return ESP_OK;
    }
    esp_err_t err = auth_validate_issuer(config->issuer);
    if (err != ESP_OK) {
        app_status_set_auth_ready(false);
        return err;
    }

    err = auth_oidc_ensure_mutex();
    if (err != ESP_OK) {
        app_status_set_auth_ready(false);
        return err;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    auth_oidc_copy_config_locked(config);
    xSemaphoreGive(s_auth_mutex);

    app_status_set_auth_ready(false);

    while (true) {
        taskENTER_CRITICAL(&s_auth_lock);
        if (s_auth_task_handle != NULL) {
            taskEXIT_CRITICAL(&s_auth_lock);
            return ESP_OK;
        }

        if (!s_auth_task_starting) {
            s_auth_task_starting = true;
            taskEXIT_CRITICAL(&s_auth_lock);
            break;
        }
        taskEXIT_CRITICAL(&s_auth_lock);

        vTaskDelay(1);
    }

    TaskHandle_t task_handle = NULL;
    BaseType_t created = xTaskCreate(auth_oidc_task, "auth_oidc", AUTH_TASK_STACK_SIZE, NULL,
                                     AUTH_TASK_PRIORITY, &task_handle);
    taskENTER_CRITICAL(&s_auth_lock);
    if (created != pdPASS) {
        s_auth_task_starting = false;
        taskEXIT_CRITICAL(&s_auth_lock);
        return ESP_ERR_NO_MEM;
    }

    s_auth_task_handle = task_handle;
    s_auth_task_starting = false;
    taskEXIT_CRITICAL(&s_auth_lock);

    return ESP_OK;
}

auth_result_t auth_oidc_validate_authorization_header(const char *header)
{
    if (header == NULL || strncmp(header, "Bearer ", 7) != 0) {
        return AUTH_RESULT_MISSING;
    }
    if (!app_status_get().auth_ready) {
        return AUTH_RESULT_NOT_READY;
    }

    return AUTH_RESULT_INVALID;
}

void auth_oidc_set_config_for_test(const app_config_t *config)
{
    if (config == NULL || auth_oidc_ensure_mutex() != ESP_OK) {
        return;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    auth_oidc_copy_config_locked(config);
    xSemaphoreGive(s_auth_mutex);
}
