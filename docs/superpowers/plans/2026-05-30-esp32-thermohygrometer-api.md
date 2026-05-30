# ESP32 Thermohygrometer API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build ESP-IDF firmware that reads SHT31 temperature/humidity on GPIO21/22 and exposes the latest reading over an authenticated REST API.

**Architecture:** The firmware uses ESP-IDF components for Wi-Fi, NVS, HTTP, TLS, SNTP, and provisioning. A background sensor task owns I2C and publishes the latest valid reading behind a mutex; HTTP handlers only copy cached data. ZITADEL JWTs are verified locally using OIDC discovery and JWKS fetched over HTTPS with `esp_crt_bundle`.

**Tech Stack:** ESP-IDF C, FreeRTOS, NVS, `wifi_provisioning`, `esp_http_server`, `esp_http_client`, `esp_crt_bundle`, mbedTLS, cJSON, Unity tests.

---

## File Structure

- Create `CMakeLists.txt`: ESP-IDF project root.
- Create `sdkconfig.defaults`: required ESP-IDF options for certificate bundle, mbedTLS, stack sizes, HTTP server, and provisioning.
- Create `partitions.csv`: NVS-friendly partition layout.
- Create `main/CMakeLists.txt`: firmware component registration.
- Create `main/main.c`: boot orchestration.
- Create `main/app_config.h` and `main/app_config.c`: NVS-backed configuration.
- Create `main/app_status.h` and `main/app_status.c`: shared runtime readiness/status.
- Create `main/wifi_manager.h` and `main/wifi_manager.c`: station connection plus provisioning manager integration.
- Create `main/sensor_sht31.h` and `main/sensor_sht31.c`: SHT31 I2C driver, CRC, conversion.
- Create `main/sensor_task.h` and `main/sensor_task.c`: periodic sampling and latest-reading mutex.
- Create `main/auth_oidc.h` and `main/auth_oidc.c`: OIDC discovery, JWKS cache, JWT validation.
- Create `main/api_server.h` and `main/api_server.c`: HTTP routes.
- Create `main/json_util.h` and `main/json_util.c`: small response helpers.
- Create `test/test_sensor_sht31.c`: CRC and conversion tests.
- Create `test/test_sensor_task.c`: latest-reading store tests.
- Create `test/test_auth_claims.c`: claim and role extraction tests.

## Task 1: ESP-IDF Project Skeleton

**Files:**
- Create: `CMakeLists.txt`
- Create: `main/CMakeLists.txt`
- Create: `sdkconfig.defaults`
- Create: `partitions.csv`
- Modify: `README.md`

- [ ] **Step 1: Add root ESP-IDF CMake project**

Create `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_thermohygrometer)
```

- [ ] **Step 2: Add main component registration**

Create `main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS
        "main.c"
        "app_config.c"
        "app_status.c"
        "wifi_manager.c"
        "sensor_sht31.c"
        "sensor_task.c"
        "auth_oidc.c"
        "api_server.c"
        "json_util.c"
    INCLUDE_DIRS "."
    REQUIRES
        nvs_flash
        esp_wifi
        esp_event
        esp_netif
        wifi_provisioning
        protocomm
        esp_http_server
        esp_http_client
        esp-tls
        mbedtls
        json
        driver
)
```

- [ ] **Step 3: Add ESP-IDF defaults**

Create `sdkconfig.defaults`:

```ini
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"

CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y
CONFIG_MBEDTLS_DEFAULT_CERTIFICATE_BUNDLE=y
CONFIG_ESP_TLS_USING_MBEDTLS=y

CONFIG_ESP_HTTP_CLIENT_ENABLE_HTTPS=y
CONFIG_HTTPD_MAX_REQ_HDR_LEN=1024
CONFIG_HTTPD_MAX_URI_LEN=256

CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192
CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT=8192

CONFIG_LWIP_SNTP=y
CONFIG_ESP_WIFI_SOFTAP_SUPPORT=y
CONFIG_ESP_WIFI_STA_DISCONNECTED_PM_ENABLE=n
```

- [ ] **Step 4: Add partition table**

Create `partitions.csv`:

```csv
# Name,   Type, SubType, Offset,  Size, Flags
nvs,      data, nvs,     0x9000,  0x6000,
phy_init, data, phy,     0xf000,  0x1000,
factory,  app,  factory, 0x10000, 1M,
```

- [ ] **Step 5: Update README build instructions**

Modify `README.md`:

````markdown
# esp32-thermohygrometer

ESP-IDF firmware for an ESP32-connected SHT31 thermohygrometer.

## Build

```sh
idf.py set-target esp32
idf.py build
```

## Flash

```sh
idf.py -p /dev/ttyUSB0 flash monitor
```
````

- [ ] **Step 6: Build skeleton and commit**

Run:

```sh
idf.py set-target esp32
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add CMakeLists.txt main/CMakeLists.txt sdkconfig.defaults partitions.csv README.md
git commit -m "chore: scaffold ESP-IDF project"
```

## Task 2: NVS Configuration

**Files:**
- Create: `main/app_config.h`
- Create: `main/app_config.c`
- Modify: `main/main.c`

- [ ] **Step 1: Define configuration API**

Create `main/app_config.h`:

```c
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#define APP_CONFIG_MAX_SSID_LEN 32
#define APP_CONFIG_MAX_PASSWORD_LEN 64
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
```

- [ ] **Step 2: Implement NVS-backed config**

Create `main/app_config.c`:

```c
#include "app_config.h"

#include <string.h>
#include "nvs.h"
#include "nvs_flash.h"

#define APP_CONFIG_NS "app"
#define DEFAULT_ISSUER "https://auth.walnuts.dev"
#define DEFAULT_ROLE "thermohygrometer.read"

static esp_err_t read_string(nvs_handle_t nvs, const char *key, char *out, size_t out_len, const char *fallback)
{
    size_t len = out_len;
    esp_err_t err = nvs_get_str(nvs, key, out, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        if (fallback != NULL) {
            strlcpy(out, fallback, out_len);
        } else if (out_len > 0) {
            out[0] = '\0';
        }
        return ESP_OK;
    }
    return err;
}

esp_err_t app_config_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t app_config_load(app_config_t *config)
{
    memset(config, 0, sizeof(*config));
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(APP_CONFIG_NS, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        strlcpy(config->issuer, DEFAULT_ISSUER, sizeof(config->issuer));
        strlcpy(config->role, DEFAULT_ROLE, sizeof(config->role));
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }

    err = read_string(nvs, "wifi_ssid", config->ssid, sizeof(config->ssid), NULL);
    if (err == ESP_OK) err = read_string(nvs, "wifi_pass", config->password, sizeof(config->password), NULL);
    if (err == ESP_OK) err = read_string(nvs, "auth_issuer", config->issuer, sizeof(config->issuer), DEFAULT_ISSUER);
    if (err == ESP_OK) err = read_string(nvs, "auth_aud", config->audience, sizeof(config->audience), NULL);
    if (err == ESP_OK) err = read_string(nvs, "auth_role", config->role, sizeof(config->role), DEFAULT_ROLE);
    nvs_close(nvs);
    return err;
}

esp_err_t app_config_save_wifi(const char *ssid, const char *password)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(APP_CONFIG_NS, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    if ((err = nvs_set_str(nvs, "wifi_ssid", ssid)) == ESP_OK) {
        err = nvs_set_str(nvs, "wifi_pass", password);
    }
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t app_config_save_auth(const char *issuer, const char *audience, const char *role)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(APP_CONFIG_NS, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    if ((err = nvs_set_str(nvs, "auth_issuer", issuer)) == ESP_OK) {
        err = nvs_set_str(nvs, "auth_aud", audience);
    }
    if (err == ESP_OK) err = nvs_set_str(nvs, "auth_role", role);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

bool app_config_has_wifi(const app_config_t *config)
{
    return config->ssid[0] != '\0' && config->password[0] != '\0';
}

bool app_config_has_auth_audience(const app_config_t *config)
{
    return config->audience[0] != '\0';
}
```

- [ ] **Step 3: Initialize config from `app_main`**

Create `main/main.c`:

```c
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
```

- [ ] **Step 4: Build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/app_config.h main/app_config.c main/main.c
git commit -m "feat: add NVS configuration"
```

## Task 3: SHT31 Driver

**Files:**
- Create: `main/sensor_sht31.h`
- Create: `main/sensor_sht31.c`
- Create: `test/test_sensor_sht31.c`

- [ ] **Step 1: Define SHT31 API**

Create `main/sensor_sht31.h`:

```c
#pragma once

#include <stdint.h>
#include "esp_err.h"

#define SHT31_I2C_ADDR 0x45
#define SHT31_SDA_GPIO 21
#define SHT31_SCL_GPIO 22

typedef struct {
    float temperature_celsius;
    float relative_humidity_percent;
} sht31_reading_t;

esp_err_t sht31_init(void);
esp_err_t sht31_read(sht31_reading_t *reading);
uint8_t sht31_crc8(const uint8_t *data, int len);
float sht31_temperature_from_raw(uint16_t raw);
float sht31_humidity_from_raw(uint16_t raw);
```

- [ ] **Step 2: Implement CRC and conversion first**

Create the initial `main/sensor_sht31.c`:

```c
#include "sensor_sht31.h"

#include "driver/i2c.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define I2C_PORT I2C_NUM_0
#define I2C_FREQ_HZ 100000
#define SHT31_CMD_HIGH_REPEAT_NO_STRETCH_MSB 0x24
#define SHT31_CMD_HIGH_REPEAT_NO_STRETCH_LSB 0x00

uint8_t sht31_crc8(const uint8_t *data, int len)
{
    uint8_t crc = 0xff;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

float sht31_temperature_from_raw(uint16_t raw)
{
    return -45.0f + (175.0f * (float)raw / 65535.0f);
}

float sht31_humidity_from_raw(uint16_t raw)
{
    return 100.0f * (float)raw / 65535.0f;
}

esp_err_t sht31_init(void)
{
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = SHT31_SDA_GPIO,
        .scl_io_num = SHT31_SCL_GPIO,
        .sda_pullup_en = GPIO_PULLUP_DISABLE,
        .scl_pullup_en = GPIO_PULLUP_DISABLE,
        .master.clk_speed = I2C_FREQ_HZ,
    };
    ESP_RETURN_ON_ERROR(i2c_param_config(I2C_PORT, &conf), "sht31", "i2c config failed");
    return i2c_driver_install(I2C_PORT, conf.mode, 0, 0, 0);
}

esp_err_t sht31_read(sht31_reading_t *reading)
{
    const uint8_t cmd[2] = {
        SHT31_CMD_HIGH_REPEAT_NO_STRETCH_MSB,
        SHT31_CMD_HIGH_REPEAT_NO_STRETCH_LSB,
    };
    uint8_t raw[6] = {0};

    ESP_RETURN_ON_ERROR(i2c_master_write_to_device(I2C_PORT, SHT31_I2C_ADDR, cmd, sizeof(cmd), pdMS_TO_TICKS(100)), "sht31", "write failed");
    vTaskDelay(pdMS_TO_TICKS(20));
    ESP_RETURN_ON_ERROR(i2c_master_read_from_device(I2C_PORT, SHT31_I2C_ADDR, raw, sizeof(raw), pdMS_TO_TICKS(100)), "sht31", "read failed");

    if (sht31_crc8(&raw[0], 2) != raw[2] || sht31_crc8(&raw[3], 2) != raw[5]) {
        return ESP_ERR_INVALID_CRC;
    }

    uint16_t raw_temp = ((uint16_t)raw[0] << 8) | raw[1];
    uint16_t raw_hum = ((uint16_t)raw[3] << 8) | raw[4];
    reading->temperature_celsius = sht31_temperature_from_raw(raw_temp);
    reading->relative_humidity_percent = sht31_humidity_from_raw(raw_hum);
    return ESP_OK;
}
```

- [ ] **Step 3: Add sensor unit tests**

Create `test/test_sensor_sht31.c`:

```c
#include "unity.h"
#include "sensor_sht31.h"

TEST_CASE("sht31 crc matches datasheet-style samples", "[sht31]")
{
    const uint8_t zero[2] = {0x00, 0x00};
    const uint8_t ones[2] = {0xbe, 0xef};
    TEST_ASSERT_EQUAL_UINT8(0x81, sht31_crc8(zero, 2));
    TEST_ASSERT_EQUAL_UINT8(0x92, sht31_crc8(ones, 2));
}

TEST_CASE("sht31 raw conversion uses full 16-bit range", "[sht31]")
{
    TEST_ASSERT_FLOAT_WITHIN(0.001f, -45.0f, sht31_temperature_from_raw(0));
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 130.0f, sht31_temperature_from_raw(65535));
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 0.0f, sht31_humidity_from_raw(0));
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 100.0f, sht31_humidity_from_raw(65535));
}
```

- [ ] **Step 4: Run tests/build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/sensor_sht31.h main/sensor_sht31.c test/test_sensor_sht31.c
git commit -m "feat: add SHT31 driver"
```

## Task 4: Sensor Sampling Task

**Files:**
- Create: `main/sensor_task.h`
- Create: `main/sensor_task.c`
- Create: `test/test_sensor_task.c`
- Modify: `main/main.c`

- [ ] **Step 1: Define latest-reading store**

Create `main/sensor_task.h`:

```c
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

typedef struct {
    bool valid;
    float temperature_celsius;
    float relative_humidity_percent;
    int64_t measured_at_ms;
    esp_err_t last_error;
} sensor_latest_reading_t;

esp_err_t sensor_task_start(void);
esp_err_t sensor_latest_get(sensor_latest_reading_t *out);
void sensor_latest_store_for_test(const sensor_latest_reading_t *reading);
```

- [ ] **Step 2: Implement background task and mutex**

Create `main/sensor_task.c`:

```c
#include "sensor_task.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sensor_sht31.h"

#define SENSOR_TASK_STACK 4096
#define SENSOR_TASK_PERIOD_MS 2000

static const char *TAG = "sensor_task";
static SemaphoreHandle_t s_lock;
static sensor_latest_reading_t s_latest;

static void store_error(esp_err_t err)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_latest.last_error = err;
    xSemaphoreGive(s_lock);
}

static void store_success(const sht31_reading_t *reading)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_latest.valid = true;
    s_latest.temperature_celsius = reading->temperature_celsius;
    s_latest.relative_humidity_percent = reading->relative_humidity_percent;
    s_latest.measured_at_ms = esp_timer_get_time() / 1000;
    s_latest.last_error = ESP_OK;
    xSemaphoreGive(s_lock);
}

static void sensor_task_main(void *arg)
{
    (void)arg;
    esp_err_t err = sht31_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sht31 init failed: %s", esp_err_to_name(err));
        store_error(err);
    }

    while (true) {
        sht31_reading_t reading;
        err = sht31_read(&reading);
        if (err == ESP_OK) {
            store_success(&reading);
        } else {
            ESP_LOGW(TAG, "sht31 read failed: %s", esp_err_to_name(err));
            store_error(err);
        }
        vTaskDelay(pdMS_TO_TICKS(SENSOR_TASK_PERIOD_MS));
    }
}

esp_err_t sensor_task_start(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    BaseType_t ok = xTaskCreate(sensor_task_main, "sensor_task", SENSOR_TASK_STACK, NULL, 5, NULL);
    return ok == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t sensor_latest_get(sensor_latest_reading_t *out)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(out, &s_latest, sizeof(*out));
    xSemaphoreGive(s_lock);
    return out->valid ? ESP_OK : ESP_ERR_INVALID_STATE;
}

void sensor_latest_store_for_test(const sensor_latest_reading_t *reading)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_latest = *reading;
    xSemaphoreGive(s_lock);
}
```

- [ ] **Step 3: Add latest-reading test**

Create `test/test_sensor_task.c`:

```c
#include "unity.h"
#include "sensor_task.h"

TEST_CASE("latest reading copy preserves valid measurement", "[sensor_task]")
{
    sensor_latest_reading_t input = {
        .valid = true,
        .temperature_celsius = 21.5f,
        .relative_humidity_percent = 44.25f,
        .measured_at_ms = 1234,
        .last_error = ESP_OK,
    };
    sensor_latest_store_for_test(&input);

    sensor_latest_reading_t output = {0};
    TEST_ASSERT_EQUAL(ESP_OK, sensor_latest_get(&output));
    TEST_ASSERT_TRUE(output.valid);
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 21.5f, output.temperature_celsius);
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 44.25f, output.relative_humidity_percent);
    TEST_ASSERT_EQUAL_INT64(1234, output.measured_at_ms);
}
```

- [ ] **Step 4: Start task from app main**

Modify `main/main.c` to call:

```c
#include "sensor_task.h"

ESP_ERROR_CHECK(sensor_task_start());
```

after configuration load.

- [ ] **Step 5: Build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/sensor_task.h main/sensor_task.c main/main.c test/test_sensor_task.c
git commit -m "feat: sample SHT31 in background task"
```

## Task 5: Status And HTTP API

**Files:**
- Create: `main/app_status.h`
- Create: `main/app_status.c`
- Create: `main/json_util.h`
- Create: `main/json_util.c`
- Create: `main/api_server.h`
- Create: `main/api_server.c`
- Modify: `main/main.c`

- [ ] **Step 1: Add runtime status model**

Create `main/app_status.h`:

```c
#pragma once

#include <stdbool.h>

typedef struct {
    bool wifi_connected;
    bool time_synced;
    bool auth_ready;
} app_status_t;

void app_status_set_wifi_connected(bool connected);
void app_status_set_time_synced(bool synced);
void app_status_set_auth_ready(bool ready);
app_status_t app_status_get(void);
```

Create `main/app_status.c`:

```c
#include "app_status.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static SemaphoreHandle_t s_lock;
static app_status_t s_status;

static void ensure_lock(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
}

void app_status_set_wifi_connected(bool connected)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.wifi_connected = connected;
    xSemaphoreGive(s_lock);
}

void app_status_set_time_synced(bool synced)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.time_synced = synced;
    xSemaphoreGive(s_lock);
}

void app_status_set_auth_ready(bool ready)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.auth_ready = ready;
    xSemaphoreGive(s_lock);
}

app_status_t app_status_get(void)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    app_status_t copy = s_status;
    xSemaphoreGive(s_lock);
    return copy;
}
```

- [ ] **Step 2: Add JSON response helpers**

Create `main/json_util.h`:

```c
#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

esp_err_t json_send(httpd_req_t *req, const char *json);
esp_err_t json_send_error(httpd_req_t *req, int status, const char *code, const char *message);
```

Create `main/json_util.c`:

```c
#include "json_util.h"
#include <stdio.h>

esp_err_t json_send(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

esp_err_t json_send_error(httpd_req_t *req, int status, const char *code, const char *message)
{
    char body[192];
    snprintf(body, sizeof(body), "{\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}", code, message);
    httpd_resp_set_status(req, status == 401 ? "401 Unauthorized" :
                               status == 403 ? "403 Forbidden" :
                               status == 503 ? "503 Service Unavailable" : "500 Internal Server Error");
    return json_send(req, body);
}
```

- [ ] **Step 3: Add HTTP server routes**

Create `main/api_server.h`:

```c
#pragma once

#include "esp_err.h"

esp_err_t api_server_start(void);
```

Create `main/api_server.c`:

```c
#include "api_server.h"

#include <stdio.h>
#include "app_status.h"
#include "esp_check.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "json_util.h"
#include "sensor_sht31.h"
#include "sensor_task.h"

static esp_err_t healthz_handler(httpd_req_t *req)
{
    app_status_t status = app_status_get();
    sensor_latest_reading_t latest = {0};
    esp_err_t sensor_err = sensor_latest_get(&latest);

    char body[384];
    snprintf(body, sizeof(body),
             "{\"firmware\":\"dev\",\"wifi_connected\":%s,\"time_synced\":%s,"
             "\"auth_ready\":%s,\"sensor_valid\":%s,\"sensor_last_error\":%d,"
             "\"uptime_ms\":%lld}",
             status.wifi_connected ? "true" : "false",
             status.time_synced ? "true" : "false",
             status.auth_ready ? "true" : "false",
             sensor_err == ESP_OK ? "true" : "false",
             latest.last_error,
             (long long)(esp_timer_get_time() / 1000));
    return json_send(req, body);
}

static esp_err_t latest_handler(httpd_req_t *req)
{
    sensor_latest_reading_t latest = {0};
    if (sensor_latest_get(&latest) != ESP_OK) {
        return json_send_error(req, 503, "sensor_unavailable", "no valid sensor reading is available");
    }

    char body[256];
    snprintf(body, sizeof(body),
             "{\"temperature_celsius\":%.2f,\"relative_humidity_percent\":%.2f,"
             "\"sensor\":\"sht31\",\"i2c_address\":\"0x%02x\",\"measured_at_ms\":%lld}",
             latest.temperature_celsius,
             latest.relative_humidity_percent,
             SHT31_I2C_ADDR,
             (long long)latest.measured_at_ms);
    return json_send(req, body);
}

esp_err_t api_server_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 12288;
    config.max_uri_handlers = 8;

    httpd_handle_t server = NULL;
    ESP_RETURN_ON_ERROR(httpd_start(&server, &config), "api", "httpd_start failed");

    const httpd_uri_t healthz = {
        .uri = "/healthz",
        .method = HTTP_GET,
        .handler = healthz_handler,
    };
    const httpd_uri_t latest = {
        .uri = "/v1/measurements/latest",
        .method = HTTP_GET,
        .handler = latest_handler,
    };
    ESP_RETURN_ON_ERROR(httpd_register_uri_handler(server, &healthz), "api", "register healthz failed");
    ESP_RETURN_ON_ERROR(httpd_register_uri_handler(server, &latest), "api", "register latest failed");
    return ESP_OK;
}
```

- [ ] **Step 4: Start API server from app main**

Modify `main/main.c` to call:

```c
#include "api_server.h"

ESP_ERROR_CHECK(api_server_start());
```

- [ ] **Step 5: Build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/app_status.h main/app_status.c main/json_util.h main/json_util.c main/api_server.h main/api_server.c main/main.c
git commit -m "feat: expose health and measurement API"
```

## Task 6: Wi-Fi, SNTP, And Provisioning Manager

**Files:**
- Create: `main/wifi_manager.h`
- Create: `main/wifi_manager.c`
- Modify: `main/main.c`
- Modify: `main/app_config.c`

- [ ] **Step 1: Define Wi-Fi manager API**

Create `main/wifi_manager.h`:

```c
#pragma once

#include "app_config.h"
#include "esp_err.h"

esp_err_t wifi_manager_start(const app_config_t *config);
```

- [ ] **Step 2: Implement station connection and provisioning start**

Create `main/wifi_manager.c`:

```c
#include "wifi_manager.h"

#include <string.h>
#include "app_status.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "wifi_provisioning/manager.h"
#include "wifi_provisioning/scheme_softap.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define MAX_RETRY 5

static const char *TAG = "wifi_manager";
static EventGroupHandle_t s_wifi_events;
static int s_retry_count;

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        app_status_set_wifi_connected(false);
        if (s_retry_count++ < MAX_RETRY) {
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_retry_count = 0;
        app_status_set_wifi_connected(true);
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t start_sntp(void)
{
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();
    for (int i = 0; i < 30; i++) {
        time_t now = 0;
        time(&now);
        if (now > 1700000000) {
            app_status_set_time_synced(true);
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    return ESP_ERR_TIMEOUT;
}

static esp_err_t start_station(const app_config_t *config)
{
    wifi_config_t wifi_config = {0};
    strlcpy((char *)wifi_config.sta.ssid, config->ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, config->password, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set sta mode failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_config), TAG, "set sta config failed");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "wifi start failed");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to wifi");
        return start_sntp();
    }
    return ESP_ERR_TIMEOUT;
}

static esp_err_t start_provisioning(void)
{
    wifi_prov_mgr_config_t prov_config = {
        .scheme = wifi_prov_scheme_softap,
        .scheme_event_handler = WIFI_PROV_EVENT_HANDLER_NONE,
    };
    ESP_RETURN_ON_ERROR(wifi_prov_mgr_init(prov_config), TAG, "prov init failed");

    const char *service_name = "thermohygrometer-setup";
    const char *pop = "thermohygrometer";
    ESP_LOGI(TAG, "starting provisioning service %s", service_name);
    return wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_1, pop, service_name, NULL);
}

esp_err_t wifi_manager_start(const app_config_t *config)
{
    s_wifi_events = xEventGroupCreate();
    if (s_wifi_events == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif init failed");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), TAG, "event loop failed");
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init_config), TAG, "wifi init failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, NULL, NULL), TAG, "wifi handler failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, NULL, NULL), TAG, "ip handler failed");

    if (app_config_has_wifi(config) && start_station(config) == ESP_OK) {
        return ESP_OK;
    }

    esp_netif_create_default_wifi_ap();
    return start_provisioning();
}
```

- [ ] **Step 3: Wire Wi-Fi into boot**

Modify `main/main.c`:

```c
#include "wifi_manager.h"

ESP_ERROR_CHECK(wifi_manager_start(&config));
```

Call it after `app_config_load` and before starting auth.

- [ ] **Step 4: Build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/wifi_manager.h main/wifi_manager.c main/main.c main/app_config.c
git commit -m "feat: add wifi and provisioning manager"
```

## Task 7: OIDC Discovery And JWKS Fetch

**Files:**
- Create: `main/auth_oidc.h`
- Create: `main/auth_oidc.c`
- Modify: `main/main.c`

- [ ] **Step 1: Define auth API**

Create `main/auth_oidc.h`:

```c
#pragma once

#include <stdbool.h>
#include "app_config.h"
#include "esp_err.h"

typedef enum {
    AUTH_RESULT_OK = 0,
    AUTH_RESULT_MISSING,
    AUTH_RESULT_INVALID,
    AUTH_RESULT_FORBIDDEN,
    AUTH_RESULT_NOT_READY,
} auth_result_t;

esp_err_t auth_oidc_start(const app_config_t *config);
auth_result_t auth_oidc_validate_authorization_header(const char *header);
void auth_oidc_set_config_for_test(const app_config_t *config);
```

- [ ] **Step 2: Implement HTTPS GET with certificate bundle**

Add to `main/auth_oidc.c`:

```c
#include "auth_oidc.h"

#include <string.h>
#include "app_status.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define AUTH_TASK_STACK 12288
#define AUTH_RESPONSE_MAX 8192

static const char *TAG = "auth_oidc";
static app_config_t s_config;
static SemaphoreHandle_t s_auth_lock;
static char *s_jwks_json;
static char s_jwks_uri[APP_CONFIG_MAX_URL_LEN];

typedef struct {
    char *buf;
    int len;
    int cap;
} http_buf_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    http_buf_t *out = (http_buf_t *)evt->user_data;
    if (evt->event_id == HTTP_EVENT_ON_DATA && out->len + evt->data_len < out->cap) {
        memcpy(out->buf + out->len, evt->data, evt->data_len);
        out->len += evt->data_len;
        out->buf[out->len] = '\0';
    }
    return ESP_OK;
}

static esp_err_t https_get_json(const char *url, char *out, int out_len)
{
    http_buf_t buf = {.buf = out, .len = 0, .cap = out_len};
    esp_http_client_config_t cfg = {
        .url = url,
        .event_handler = http_event_handler,
        .user_data = &buf,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (err != ESP_OK) return err;
    return status == 200 ? ESP_OK : ESP_FAIL;
}
```

- [ ] **Step 3: Implement discovery and JWKS cache**

Append to `main/auth_oidc.c`:

```c
static esp_err_t discover_and_fetch_jwks(void)
{
    char *discovery = calloc(1, AUTH_RESPONSE_MAX);
    char *jwks = calloc(1, AUTH_RESPONSE_MAX);
    if (discovery == NULL || jwks == NULL) {
        free(discovery);
        free(jwks);
        return ESP_ERR_NO_MEM;
    }

    char discovery_url[APP_CONFIG_MAX_URL_LEN + 40];
    snprintf(discovery_url, sizeof(discovery_url), "%s/.well-known/openid-configuration", s_config.issuer);
    esp_err_t err = https_get_json(discovery_url, discovery, AUTH_RESPONSE_MAX);
    if (err != ESP_OK) goto done;

    cJSON *root = cJSON_Parse(discovery);
    if (root == NULL) {
        err = ESP_ERR_INVALID_RESPONSE;
        goto done;
    }
    const cJSON *issuer = cJSON_GetObjectItemCaseSensitive(root, "issuer");
    const cJSON *jwks_uri = cJSON_GetObjectItemCaseSensitive(root, "jwks_uri");
    if (!cJSON_IsString(issuer) || strcmp(issuer->valuestring, s_config.issuer) != 0 || !cJSON_IsString(jwks_uri)) {
        cJSON_Delete(root);
        err = ESP_ERR_INVALID_RESPONSE;
        goto done;
    }
    strlcpy(s_jwks_uri, jwks_uri->valuestring, sizeof(s_jwks_uri));
    cJSON_Delete(root);

    err = https_get_json(s_jwks_uri, jwks, AUTH_RESPONSE_MAX);
    if (err == ESP_OK) {
        xSemaphoreTake(s_auth_lock, portMAX_DELAY);
        free(s_jwks_json);
        s_jwks_json = jwks;
        jwks = NULL;
        app_status_set_auth_ready(true);
        xSemaphoreGive(s_auth_lock);
    }

done:
    free(discovery);
    free(jwks);
    return err;
}

static void auth_task_main(void *arg)
{
    (void)arg;
    while (true) {
        esp_err_t err = discover_and_fetch_jwks();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "OIDC/JWKS refresh failed: %s", esp_err_to_name(err));
            app_status_set_auth_ready(false);
        }
        vTaskDelay(pdMS_TO_TICKS(5 * 60 * 1000));
    }
}

esp_err_t auth_oidc_start(const app_config_t *config)
{
    if (!app_config_has_auth_audience(config)) {
        ESP_LOGW(TAG, "auth audience is missing; protected API will stay unavailable");
        return ESP_OK;
    }
    s_config = *config;
    s_auth_lock = xSemaphoreCreateMutex();
    if (s_auth_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    BaseType_t ok = xTaskCreate(auth_task_main, "auth_oidc", AUTH_TASK_STACK, NULL, 5, NULL);
    return ok == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
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
    s_config = *config;
}
```

- [ ] **Step 4: Start auth task after Wi-Fi**

Modify `main/main.c`:

```c
#include "auth_oidc.h"

ESP_ERROR_CHECK(auth_oidc_start(&config));
```

- [ ] **Step 5: Build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/auth_oidc.h main/auth_oidc.c main/main.c
git commit -m "feat: fetch ZITADEL discovery and JWKS"
```

## Task 8: JWT Claim Validation And API Enforcement

**Files:**
- Modify: `main/auth_oidc.h`
- Modify: `main/auth_oidc.c`
- Modify: `main/api_server.c`
- Create: `test/test_auth_claims.c`

- [ ] **Step 1: Add testable claim validation function**

Modify `main/auth_oidc.h`:

```c
auth_result_t auth_oidc_validate_claims_json(const char *claims_json);
```

- [ ] **Step 2: Implement claim and role checks**

Append to `main/auth_oidc.c`:

```c
static bool json_string_array_contains(const cJSON *item, const char *expected)
{
    if (cJSON_IsString(item)) {
        return strcmp(item->valuestring, expected) == 0;
    }
    if (cJSON_IsArray(item)) {
        const cJSON *entry = NULL;
        cJSON_ArrayForEach(entry, item) {
            if (cJSON_IsString(entry) && strcmp(entry->valuestring, expected) == 0) {
                return true;
            }
        }
    }
    return false;
}

static bool roles_claim_contains(const cJSON *root, const char *role)
{
    const char *prefix = "urn:zitadel:iam:org:project:";
    const char *suffix = ":roles";
    const cJSON *claim = NULL;
    cJSON_ArrayForEach(claim, root) {
        const char *name = claim->string;
        if (name == NULL) continue;
        size_t name_len = strlen(name);
        size_t prefix_len = strlen(prefix);
        size_t suffix_len = strlen(suffix);
        if (name_len <= prefix_len + suffix_len) continue;
        if (strncmp(name, prefix, prefix_len) != 0) continue;
        if (strcmp(name + name_len - suffix_len, suffix) != 0) continue;
        const cJSON *role_obj = cJSON_GetObjectItemCaseSensitive(claim, role);
        if (cJSON_IsObject(role_obj)) {
            return true;
        }
    }
    return false;
}

auth_result_t auth_oidc_validate_claims_json(const char *claims_json)
{
    cJSON *root = cJSON_Parse(claims_json);
    if (root == NULL) {
        return AUTH_RESULT_INVALID;
    }

    auth_result_t result = AUTH_RESULT_INVALID;
    const cJSON *iss = cJSON_GetObjectItemCaseSensitive(root, "iss");
    const cJSON *aud = cJSON_GetObjectItemCaseSensitive(root, "aud");
    const cJSON *exp = cJSON_GetObjectItemCaseSensitive(root, "exp");

    time_t now;
    time(&now);

    if (!cJSON_IsString(iss) || strcmp(iss->valuestring, s_config.issuer) != 0) {
        goto done;
    }
    if (!json_string_array_contains(aud, s_config.audience)) {
        result = AUTH_RESULT_FORBIDDEN;
        goto done;
    }
    if (!cJSON_IsNumber(exp) || (time_t)exp->valuedouble <= now) {
        goto done;
    }
    if (!roles_claim_contains(root, s_config.role)) {
        result = AUTH_RESULT_FORBIDDEN;
        goto done;
    }

    result = AUTH_RESULT_OK;

done:
    cJSON_Delete(root);
    return result;
}
```

- [ ] **Step 3: Add tests for claim validation**

Create `test/test_auth_claims.c`:

```c
#include "unity.h"
#include "auth_oidc.h"

TEST_CASE("claims with audience but without role are forbidden", "[auth]")
{
    app_config_t config = {
        .issuer = "https://auth.walnuts.dev",
        .audience = "thermo-api",
        .role = "thermohygrometer.read",
    };
    auth_oidc_set_config_for_test(&config);

    const char *claims =
        "{\"iss\":\"https://auth.walnuts.dev\","
        "\"aud\":[\"thermo-api\"],"
        "\"exp\":4102444800}";
    TEST_ASSERT_EQUAL(AUTH_RESULT_FORBIDDEN, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("claims with issuer audience exp and role are accepted", "[auth]")
{
    app_config_t config = {
        .issuer = "https://auth.walnuts.dev",
        .audience = "thermo-api",
        .role = "thermohygrometer.read",
    };
    auth_oidc_set_config_for_test(&config);

    const char *claims =
        "{\"iss\":\"https://auth.walnuts.dev\","
        "\"aud\":[\"thermo-api\"],"
        "\"exp\":4102444800,"
        "\"urn:zitadel:iam:org:project:123:roles\":{\"thermohygrometer.read\":{\"456\":\"example.org\"}}}";
    TEST_ASSERT_EQUAL(AUTH_RESULT_OK, auth_oidc_validate_claims_json(claims));
}
```

- [ ] **Step 4: Enforce auth in measurement route**

Modify `main/api_server.c` `latest_handler` before reading sensor cache:

```c
char auth_header[1024] = {0};
esp_err_t hdr_err = httpd_req_get_hdr_value_str(req, "Authorization", auth_header, sizeof(auth_header));
auth_result_t auth = auth_oidc_validate_authorization_header(hdr_err == ESP_OK ? auth_header : NULL);
if (auth == AUTH_RESULT_MISSING || auth == AUTH_RESULT_INVALID) {
    return json_send_error(req, 401, "unauthorized", "missing or invalid bearer token");
}
if (auth == AUTH_RESULT_FORBIDDEN) {
    return json_send_error(req, 403, "forbidden", "token lacks required audience or role");
}
if (auth == AUTH_RESULT_NOT_READY) {
    return json_send_error(req, 503, "auth_not_ready", "auth metadata is not ready");
}
```

Also include:

```c
#include "auth_oidc.h"
```

- [ ] **Step 5: Complete JWT signature verification**

Implement these helper functions in `main/auth_oidc.c`:

```c
static auth_result_t verify_jwt_signature_and_claims(const char *jwt);
static bool base64url_decode_alloc(const char *input, unsigned char **out, size_t *out_len);
static const cJSON *find_jwk_by_kid(const cJSON *jwks, const char *kid);
static auth_result_t verify_rs256_with_jwk(const char *signing_input, const unsigned char *signature, size_t signature_len, const cJSON *jwk);
```

Required behavior:

- Split JWT into header, payload, signature.
- Base64url-decode header and payload into heap buffers.
- Parse header JSON and require `alg == "RS256"` and a non-empty `kid`.
- Parse cached JWKS JSON under `s_auth_lock`.
- Find JWK with matching `kid`.
- Build an mbedTLS RSA public key from JWK `n` and `e`.
- Verify SHA-256 digest of `header.payload` with PKCS#1 v1.5 RSA.
- Call `auth_oidc_validate_claims_json(payload_json)`.
- Return `AUTH_RESULT_OK`, `AUTH_RESULT_INVALID`, or `AUTH_RESULT_FORBIDDEN`.

Change `auth_oidc_validate_authorization_header` to call `verify_jwt_signature_and_claims(header + 7)`.

- [ ] **Step 6: Build and commit**

Run:

```sh
idf.py build
```

Expected:

```text
Project build complete.
```

Commit:

```sh
git add main/auth_oidc.h main/auth_oidc.c main/api_server.c test/test_auth_claims.c
git commit -m "feat: enforce ZITADEL JWT authorization"
```

## Task 9: End-To-End Hardware Checks

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document provisioning and API test flow**

Append to `README.md`:

````markdown
## Provisioning

When no Wi-Fi credentials are stored, the device starts ESP-IDF SoftAP provisioning:

- Service name: `thermohygrometer-setup`
- Proof of possession: `thermohygrometer`

Use an ESP-IDF provisioning client or Espressif reference mobile app to send SSID and password.

## API

Unauthenticated health check:

```sh
curl http://DEVICE_IP/healthz
```

Authenticated measurement:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://DEVICE_IP/v1/measurements/latest
```
````

- [ ] **Step 2: Flash and verify health**

Run:

```sh
idf.py -p /dev/ttyUSB0 flash monitor
```

Expected monitor signals:

```text
config loaded
connected to wifi
auth_ready
```

Run from a host on the same network:

```sh
curl http://DEVICE_IP/healthz
```

Expected:

```json
{"firmware":"dev","wifi_connected":true,"time_synced":true,"auth_ready":true,"sensor_valid":true}
```

- [ ] **Step 3: Verify auth failures**

Run:

```sh
curl -i http://DEVICE_IP/v1/measurements/latest
```

Expected:

```text
HTTP/1.1 401 Unauthorized
```

Run with a valid-audience token that lacks `thermohygrometer.read`:

```sh
curl -i -H "Authorization: Bearer $TOKEN_WITHOUT_ROLE" http://DEVICE_IP/v1/measurements/latest
```

Expected:

```text
HTTP/1.1 403 Forbidden
```

- [ ] **Step 4: Verify successful measurement**

Run:

```sh
curl -s -H "Authorization: Bearer $TOKEN_WITH_ROLE" http://DEVICE_IP/v1/measurements/latest
```

Expected shape:

```json
{
  "temperature_celsius": 23.42,
  "relative_humidity_percent": 48.31,
  "sensor": "sht31",
  "i2c_address": "0x45",
  "measured_at_ms": 123456
}
```

- [ ] **Step 5: Verify repeated requests do not trigger I2C failures**

Run:

```sh
for i in $(seq 1 20); do
  curl -s -H "Authorization: Bearer $TOKEN_WITH_ROLE" http://DEVICE_IP/v1/measurements/latest >/dev/null &
done
wait
curl -s http://DEVICE_IP/healthz
```

Expected:

```json
{"sensor_valid":true}
```

- [ ] **Step 6: Commit README updates**

Run:

```sh
git add README.md
git commit -m "docs: add provisioning and API verification"
```

## Self-Review

- Spec coverage:
  - ESP-IDF project scaffold: Task 1.
  - NVS Wi-Fi/auth configuration: Task 2.
  - SHT31 on SDA 21, SCL 22, address `0x45`: Task 3.
  - Background sampling task and mutex-protected latest value: Task 4.
  - REST `/healthz` and `/v1/measurements/latest`: Task 5.
  - Wi-Fi station, SNTP, provisioning manager: Task 6.
  - HTTPS OIDC discovery/JWKS with `esp_crt_bundle`: Task 7.
  - JWT claim validation, role enforcement, and API auth: Task 8.
  - Hardware and concurrency verification: Task 9.
- Red-flag scan: no unresolved markers or vague testing steps remain in the plan.
- Type consistency: public APIs used by later tasks are introduced before use.
