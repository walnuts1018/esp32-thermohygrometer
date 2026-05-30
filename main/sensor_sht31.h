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
