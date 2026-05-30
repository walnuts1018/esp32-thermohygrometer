#include "sensor_task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sensor_sht31.h"

#define SENSOR_TASK_STACK_SIZE 4096
#define SENSOR_TASK_PRIORITY 5
#define SENSOR_POLL_INTERVAL_MS 2000

static const char *TAG = "sensor_task";

static SemaphoreHandle_t s_latest_mutex;
static TaskHandle_t s_sensor_task_handle;
static bool s_sensor_task_starting;
static sensor_latest_reading_t s_latest;
static portMUX_TYPE s_sensor_task_lock = portMUX_INITIALIZER_UNLOCKED;

static esp_err_t sensor_latest_mutex_ensure(void)
{
    taskENTER_CRITICAL(&s_sensor_task_lock);
    if (s_latest_mutex != NULL) {
        taskEXIT_CRITICAL(&s_sensor_task_lock);
        return ESP_OK;
    }
    taskEXIT_CRITICAL(&s_sensor_task_lock);

    SemaphoreHandle_t new_mutex = xSemaphoreCreateMutex();
    if (new_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    taskENTER_CRITICAL(&s_sensor_task_lock);
    if (s_latest_mutex == NULL) {
        s_latest_mutex = new_mutex;
        new_mutex = NULL;
    }
    taskEXIT_CRITICAL(&s_sensor_task_lock);

    if (new_mutex != NULL) {
        vSemaphoreDelete(new_mutex);
    }

    return ESP_OK;
}

static void sensor_latest_store_error(esp_err_t err)
{
    if (sensor_latest_mutex_ensure() != ESP_OK) {
        return;
    }

    if (xSemaphoreTake(s_latest_mutex, portMAX_DELAY) == pdTRUE) {
        s_latest.last_error = err;
        xSemaphoreGive(s_latest_mutex);
    }
}

void sensor_latest_store_for_test(const sensor_latest_reading_t *reading)
{
    if (sensor_latest_mutex_ensure() != ESP_OK) {
        return;
    }

    if (xSemaphoreTake(s_latest_mutex, portMAX_DELAY) == pdTRUE) {
        if (reading == NULL) {
            s_latest = (sensor_latest_reading_t){
                .valid = false,
                .last_error = ESP_ERR_INVALID_ARG,
            };
        } else {
            s_latest = *reading;
        }
        xSemaphoreGive(s_latest_mutex);
    }
}

esp_err_t sensor_latest_get(sensor_latest_reading_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = sensor_latest_mutex_ensure();
    if (err != ESP_OK) {
        return err;
    }

    if (xSemaphoreTake(s_latest_mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;
    }

    *out = s_latest;
    const bool valid = s_latest.valid;
    xSemaphoreGive(s_latest_mutex);

    return valid ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static void sensor_task_run(void *arg)
{
    (void)arg;

    esp_err_t err = sht31_init();
    if (err != ESP_OK) {
        sensor_latest_store_error(err);
        ESP_LOGW(TAG, "sht31 init failed: %s", esp_err_to_name(err));
    }

    while (true) {
        sht31_reading_t reading = {0};
        err = sht31_read(&reading);
        if (err == ESP_OK) {
            sensor_latest_reading_t latest = {
                .valid = true,
                .temperature_celsius = reading.temperature_celsius,
                .relative_humidity_percent = reading.relative_humidity_percent,
                .measured_at_ms = esp_timer_get_time() / 1000,
                .last_error = ESP_OK,
            };
            sensor_latest_store_for_test(&latest);
        } else {
            sensor_latest_store_error(err);
            ESP_LOGW(TAG, "sht31 read failed: %s", esp_err_to_name(err));
        }

        vTaskDelay(pdMS_TO_TICKS(SENSOR_POLL_INTERVAL_MS));
    }
}

esp_err_t sensor_task_start(void)
{
    esp_err_t err = sensor_latest_mutex_ensure();
    if (err != ESP_OK) {
        return err;
    }

    while (true) {
        taskENTER_CRITICAL(&s_sensor_task_lock);
        if (s_sensor_task_handle != NULL) {
            taskEXIT_CRITICAL(&s_sensor_task_lock);
            return ESP_OK;
        }

        if (!s_sensor_task_starting) {
            s_sensor_task_starting = true;
            taskEXIT_CRITICAL(&s_sensor_task_lock);
            break;
        }
        taskEXIT_CRITICAL(&s_sensor_task_lock);

        vTaskDelay(1);
    }

    TaskHandle_t task_handle = NULL;
    BaseType_t created = xTaskCreate(
        sensor_task_run,
        "sensor_task",
        SENSOR_TASK_STACK_SIZE,
        NULL,
        SENSOR_TASK_PRIORITY,
        &task_handle);

    taskENTER_CRITICAL(&s_sensor_task_lock);
    if (created != pdPASS) {
        s_sensor_task_starting = false;
        taskEXIT_CRITICAL(&s_sensor_task_lock);
        return ESP_ERR_NO_MEM;
    }

    s_sensor_task_handle = task_handle;
    s_sensor_task_starting = false;
    taskEXIT_CRITICAL(&s_sensor_task_lock);

    return ESP_OK;
}
