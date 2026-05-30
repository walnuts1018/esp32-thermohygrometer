#include "wifi_manager.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app_status.h"
#include "cJSON.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "network_provisioning/manager.h"
#include "network_provisioning/scheme_softap.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define TIME_SYNC_BIT BIT2
#define TIME_FAIL_BIT BIT3
#define MAX_RETRY 5
#define WIFI_WAIT_MS 30000
#define SNTP_WAIT_MS 30000
#define SANE_EPOCH_TIME 1700000000
#define AUTH_HTTPS_SCHEME "https://"

static const char *TAG = "wifi_manager";

static EventGroupHandle_t s_wifi_events;
static esp_netif_t *s_sta_netif;
static esp_netif_t *s_ap_netif;
static bool s_netif_initialized;
static bool s_event_loop_initialized;
static bool s_wifi_initialized;
static bool s_handlers_registered;
static bool s_provisioning_started;
static bool s_provisioning_completed;
static bool s_sntp_sync_running;
static int s_retry_count;
static wifi_sta_config_t s_pending_wifi_config;
static bool s_pending_wifi_config_valid;
static portMUX_TYPE s_init_lock = portMUX_INITIALIZER_UNLOCKED;

static void wifi_manager_sntp_task(void *arg);

static bool wifi_manager_fits_string(const char *value, size_t buffer_size)
{
    return value != NULL && strnlen(value, buffer_size) < buffer_size;
}

static bool wifi_manager_valid_issuer(const char *issuer)
{
    if (!wifi_manager_fits_string(issuer, APP_CONFIG_MAX_URL_LEN)) {
        return false;
    }

    size_t len = strlen(issuer);
    return strncmp(issuer, AUTH_HTTPS_SCHEME, strlen(AUTH_HTTPS_SCHEME)) == 0 &&
           len > strlen(AUTH_HTTPS_SCHEME) &&
           issuer[len - 1] != '/';
}

static esp_err_t wifi_manager_save_custom_auth(const char *json, size_t json_len)
{
    if (json == NULL || json_len == 0 || memchr(json, '\0', json_len) != NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char *body = strndup(json, json_len);
    if (body == NULL) {
        return ESP_ERR_NO_MEM;
    }

    cJSON *root = cJSON_ParseWithOpts(body, NULL, true);
    free(body);
    if (root == NULL || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    app_config_t config = {0};
    esp_err_t err = app_config_load(&config);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        return err;
    }

    const cJSON *issuer = cJSON_GetObjectItemCaseSensitive(root, "issuer");
    const cJSON *audience = cJSON_GetObjectItemCaseSensitive(root, "audience");
    const cJSON *role = cJSON_GetObjectItemCaseSensitive(root, "role");

    if (issuer != NULL) {
        if (!cJSON_IsString(issuer) || !wifi_manager_valid_issuer(issuer->valuestring)) {
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        strlcpy(config.issuer, issuer->valuestring, sizeof(config.issuer));
    }
    if (audience != NULL) {
        if (!cJSON_IsString(audience) ||
            !wifi_manager_fits_string(audience->valuestring, APP_CONFIG_MAX_AUDIENCE_LEN)) {
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        strlcpy(config.audience, audience->valuestring, sizeof(config.audience));
    }
    if (role != NULL) {
        if (!cJSON_IsString(role) ||
            !wifi_manager_fits_string(role->valuestring, APP_CONFIG_MAX_ROLE_LEN)) {
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        strlcpy(config.role, role->valuestring, sizeof(config.role));
    }

    if (!app_config_has_auth_audience(&config)) {
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    err = app_config_save_auth(config.issuer, config.audience, config.role);

cleanup:
    cJSON_Delete(root);
    return err;
}

static esp_err_t wifi_manager_custom_data_handler(uint32_t session_id,
                                                  const uint8_t *inbuf,
                                                  ssize_t inlen,
                                                  uint8_t **outbuf,
                                                  ssize_t *outlen,
                                                  void *priv_data)
{
    (void)session_id;
    (void)priv_data;

    if (outbuf == NULL || outlen == NULL || inlen < 0) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = wifi_manager_save_custom_auth((const char *)inbuf, (size_t)inlen);
    const char *response = (err == ESP_OK) ? "{\"status\":\"ok\"}" : "{\"status\":\"error\"}";
    *outbuf = (uint8_t *)strdup(response);
    if (*outbuf == NULL) {
        return ESP_ERR_NO_MEM;
    }
    *outlen = strlen(response) + 1;
    return err;
}

static void wifi_manager_request_time_sync(void)
{
    bool should_start = false;

    taskENTER_CRITICAL(&s_init_lock);
    if (!s_sntp_sync_running) {
        s_sntp_sync_running = true;
        should_start = true;
    }
    taskEXIT_CRITICAL(&s_init_lock);

    if (!should_start) {
        return;
    }

    BaseType_t created = xTaskCreate(wifi_manager_sntp_task,
                                     "wifi_sntp",
                                     4096,
                                     NULL,
                                     tskIDLE_PRIORITY + 1,
                                     NULL);
    if (created != pdPASS) {
        taskENTER_CRITICAL(&s_init_lock);
        s_sntp_sync_running = false;
        taskEXIT_CRITICAL(&s_init_lock);
        app_status_set_time_synced(false);
        xEventGroupSetBits(s_wifi_events, TIME_FAIL_BIT);
        ESP_LOGE(TAG, "failed to create SNTP task");
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;

    if (event_base == NETWORK_PROV_EVENT) {
        if (event_id == NETWORK_PROV_WIFI_CRED_RECV && event_data != NULL) {
            taskENTER_CRITICAL(&s_init_lock);
            s_pending_wifi_config = *(wifi_sta_config_t *)event_data;
            s_pending_wifi_config_valid = true;
            taskEXIT_CRITICAL(&s_init_lock);
            return;
        }

        if (event_id == NETWORK_PROV_WIFI_CRED_SUCCESS) {
            wifi_sta_config_t wifi_config = {0};
            bool has_pending = false;
            taskENTER_CRITICAL(&s_init_lock);
            wifi_config = s_pending_wifi_config;
            has_pending = s_pending_wifi_config_valid;
            s_provisioning_completed = true;
            taskEXIT_CRITICAL(&s_init_lock);

            if (has_pending) {
                char ssid[APP_CONFIG_MAX_SSID_LEN + 1] = {0};
                char password[APP_CONFIG_MAX_PASSWORD_LEN + 1] = {0};
                size_t ssid_len = strnlen((const char *)wifi_config.ssid, sizeof(wifi_config.ssid));
                size_t password_len = strnlen((const char *)wifi_config.password, sizeof(wifi_config.password));
                memcpy(ssid, wifi_config.ssid, ssid_len);
                memcpy(password, wifi_config.password, password_len);

                esp_err_t err = app_config_save_wifi(ssid, password);
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "failed to save provisioned Wi-Fi credentials: %s", esp_err_to_name(err));
                }
            }
            return;
        }

        if (event_id == NETWORK_PROV_END) {
            esp_err_t err = network_prov_mgr_deinit();
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "provisioning manager deinit failed: %s", esp_err_to_name(err));
            }

            taskENTER_CRITICAL(&s_init_lock);
            bool should_restart = s_provisioning_completed;
            taskEXIT_CRITICAL(&s_init_lock);
            if (should_restart) {
                ESP_LOGI(TAG, "restarting after provisioning to load saved configuration");
                esp_restart();
            }
            return;
        }

        return;
    }

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        return;
    }

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        app_status_set_wifi_connected(false);
        if (s_retry_count < MAX_RETRY) {
            s_retry_count++;
            ESP_LOGI(TAG, "retrying Wi-Fi connection, attempt %d/%d", s_retry_count, MAX_RETRY);
            esp_wifi_connect();
            return;
        }

        xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        return;
    }

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_retry_count = 0;
        app_status_set_wifi_connected(true);
        wifi_manager_request_time_sync();
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_manager_ensure_event_group(void)
{
    taskENTER_CRITICAL(&s_init_lock);
    if (s_wifi_events != NULL) {
        taskEXIT_CRITICAL(&s_init_lock);
        return ESP_OK;
    }
    taskEXIT_CRITICAL(&s_init_lock);

    EventGroupHandle_t events = xEventGroupCreate();
    if (events == NULL) {
        return ESP_ERR_NO_MEM;
    }

    taskENTER_CRITICAL(&s_init_lock);
    if (s_wifi_events == NULL) {
        s_wifi_events = events;
        events = NULL;
    }
    taskEXIT_CRITICAL(&s_init_lock);

    if (events != NULL) {
        vEventGroupDelete(events);
    }

    return ESP_OK;
}

static esp_err_t wifi_manager_init_stack(void)
{
    ESP_RETURN_ON_ERROR(wifi_manager_ensure_event_group(), TAG, "event group init failed");

    if (!s_netif_initialized) {
        esp_err_t err = esp_netif_init();
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGE(TAG, "netif init failed: %s", esp_err_to_name(err));
            return err;
        }
        s_netif_initialized = true;
    }

    if (!s_event_loop_initialized) {
        esp_err_t err = esp_event_loop_create_default();
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGE(TAG, "event loop init failed: %s", esp_err_to_name(err));
            return err;
        }
        s_event_loop_initialized = true;
    }

    if (s_sta_netif == NULL) {
        s_sta_netif = esp_netif_create_default_wifi_sta();
        if (s_sta_netif == NULL) {
            return ESP_FAIL;
        }
    }

    if (!s_wifi_initialized) {
        wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
        ESP_RETURN_ON_ERROR(esp_wifi_init(&init_config), TAG, "wifi init failed");
        s_wifi_initialized = true;
    }

    if (!s_handlers_registered) {
        ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT,
                                                               ESP_EVENT_ANY_ID,
                                                               wifi_event_handler,
                                                               NULL,
                                                               NULL),
                            TAG,
                            "wifi handler register failed");
        ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT,
                                                               IP_EVENT_STA_GOT_IP,
                                                               wifi_event_handler,
                                                               NULL,
                                                               NULL),
                            TAG,
                            "ip handler register failed");
        ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(NETWORK_PROV_EVENT,
                                                               ESP_EVENT_ANY_ID,
                                                               wifi_event_handler,
                                                               NULL,
                                                               NULL),
                            TAG,
                            "provisioning handler register failed");
        s_handlers_registered = true;
    }

    return ESP_OK;
}

static void wifi_manager_sntp_task(void *arg)
{
    (void)arg;

    app_status_set_time_synced(false);

    if (esp_sntp_enabled()) {
        esp_sntp_stop();
    }

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(SNTP_WAIT_MS);
    while (xTaskGetTickCount() < deadline) {
        time_t now = 0;
        time(&now);
        if (now > SANE_EPOCH_TIME) {
            app_status_set_time_synced(true);
            ESP_LOGI(TAG, "SNTP time synchronized");
            xEventGroupSetBits(s_wifi_events, TIME_SYNC_BIT);
            taskENTER_CRITICAL(&s_init_lock);
            s_sntp_sync_running = false;
            taskEXIT_CRITICAL(&s_init_lock);
            vTaskDelete(NULL);
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    app_status_set_time_synced(false);
    ESP_LOGW(TAG, "SNTP sync timed out");
    xEventGroupSetBits(s_wifi_events, TIME_FAIL_BIT);
    taskENTER_CRITICAL(&s_init_lock);
    s_sntp_sync_running = false;
    taskEXIT_CRITICAL(&s_init_lock);
    vTaskDelete(NULL);
    return;
}

static esp_err_t wifi_manager_start_station(const app_config_t *config)
{
    wifi_config_t wifi_config = {0};

    strlcpy((char *)wifi_config.sta.ssid, config->ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, config->password, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    s_retry_count = 0;
    app_status_set_wifi_connected(false);
    app_status_set_time_synced(false);
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT | TIME_SYNC_BIT | TIME_FAIL_BIT);

    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set sta mode failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_config), TAG, "set sta config failed");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "wifi start failed");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           pdMS_TO_TICKS(WIFI_WAIT_MS));
    if ((bits & WIFI_CONNECTED_BIT) == 0) {
        app_status_set_wifi_connected(false);
        ESP_LOGW(TAG, "Wi-Fi station connection failed or timed out");
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGI(TAG, "Wi-Fi station connected to SSID %s", config->ssid);
    bits = xEventGroupWaitBits(s_wifi_events,
                               TIME_SYNC_BIT | TIME_FAIL_BIT,
                               pdFALSE,
                               pdFALSE,
                               pdMS_TO_TICKS(SNTP_WAIT_MS + 1000));
    if ((bits & TIME_SYNC_BIT) != 0) {
        return ESP_OK;
    }

    app_status_set_time_synced(false);
    ESP_LOGW(TAG, "continuing after SNTP sync failure");
    return ESP_OK;
}

static esp_err_t wifi_manager_start_provisioning(void)
{
    if (s_provisioning_started) {
        return ESP_OK;
    }

    if (s_ap_netif == NULL) {
        s_ap_netif = esp_netif_create_default_wifi_ap();
        if (s_ap_netif == NULL) {
            return ESP_FAIL;
        }
    }

    network_prov_mgr_config_t prov_config = {
        .scheme = network_prov_scheme_softap,
        .scheme_event_handler = NETWORK_PROV_EVENT_HANDLER_NONE,
    };
    ESP_RETURN_ON_ERROR(network_prov_mgr_init(prov_config), TAG, "provisioning manager init failed");
    ESP_RETURN_ON_ERROR(network_prov_mgr_endpoint_create("custom-data"), TAG, "custom endpoint create failed");

    const char *service_name = "thermohygrometer-setup";
    const char *pop = "thermohygrometer";

    app_status_set_wifi_connected(false);
    app_status_set_time_synced(false);
    ESP_LOGI(TAG, "starting Wi-Fi provisioning service %s", service_name);
    ESP_RETURN_ON_ERROR(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
                                                         pop,
                                                         service_name,
                                                         NULL),
                        TAG,
                        "start provisioning failed");
    ESP_RETURN_ON_ERROR(network_prov_mgr_endpoint_register("custom-data",
                                                           wifi_manager_custom_data_handler,
                                                           NULL),
                        TAG,
                        "custom endpoint register failed");
    s_provisioning_started = true;
    return ESP_OK;
}

esp_err_t wifi_manager_start(const app_config_t *config)
{
    ESP_RETURN_ON_ERROR(wifi_manager_init_stack(), TAG, "wifi stack init failed");

    if (app_config_has_wifi(config)) {
        esp_err_t err = wifi_manager_start_station(config);
        if (err == ESP_OK) {
            return ESP_OK;
        }

        ESP_LOGW(TAG, "falling back to Wi-Fi provisioning");
        esp_wifi_disconnect();
        esp_wifi_stop();
    } else {
        ESP_LOGI(TAG, "Wi-Fi credentials missing, starting provisioning");
    }

    return wifi_manager_start_provisioning();
}

bool wifi_manager_is_provisioning(void)
{
    taskENTER_CRITICAL(&s_init_lock);
    bool provisioning = s_provisioning_started;
    taskEXIT_CRITICAL(&s_init_lock);
    return provisioning;
}
