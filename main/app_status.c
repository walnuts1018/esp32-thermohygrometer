#include "app_status.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static SemaphoreHandle_t s_status_mutex;
static app_status_t s_status;
static portMUX_TYPE s_status_lock = portMUX_INITIALIZER_UNLOCKED;

static bool app_status_mutex_ensure(void)
{
    taskENTER_CRITICAL(&s_status_lock);
    if (s_status_mutex != NULL) {
        taskEXIT_CRITICAL(&s_status_lock);
        return true;
    }
    taskEXIT_CRITICAL(&s_status_lock);

    SemaphoreHandle_t new_mutex = xSemaphoreCreateMutex();
    if (new_mutex == NULL) {
        return false;
    }

    taskENTER_CRITICAL(&s_status_lock);
    if (s_status_mutex == NULL) {
        s_status_mutex = new_mutex;
        new_mutex = NULL;
    }
    taskEXIT_CRITICAL(&s_status_lock);

    if (new_mutex != NULL) {
        vSemaphoreDelete(new_mutex);
    }

    return true;
}

void app_status_set_wifi_connected(bool connected)
{
    if (!app_status_mutex_ensure()) {
        return;
    }

    if (xSemaphoreTake(s_status_mutex, portMAX_DELAY) == pdTRUE) {
        s_status.wifi_connected = connected;
        xSemaphoreGive(s_status_mutex);
    }
}

void app_status_set_time_synced(bool synced)
{
    if (!app_status_mutex_ensure()) {
        return;
    }

    if (xSemaphoreTake(s_status_mutex, portMAX_DELAY) == pdTRUE) {
        s_status.time_synced = synced;
        xSemaphoreGive(s_status_mutex);
    }
}

void app_status_set_auth_ready(bool ready)
{
    if (!app_status_mutex_ensure()) {
        return;
    }

    if (xSemaphoreTake(s_status_mutex, portMAX_DELAY) == pdTRUE) {
        s_status.auth_ready = ready;
        xSemaphoreGive(s_status_mutex);
    }
}

app_status_t app_status_get(void)
{
    app_status_t status = {0};

    if (!app_status_mutex_ensure()) {
        return status;
    }

    if (xSemaphoreTake(s_status_mutex, portMAX_DELAY) == pdTRUE) {
        status = s_status;
        xSemaphoreGive(s_status_mutex);
    }

    return status;
}
