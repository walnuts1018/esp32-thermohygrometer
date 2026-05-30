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
