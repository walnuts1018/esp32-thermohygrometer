#include "sensor_sht31.h"

#include "driver/gpio.h"
#include "driver/i2c.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define SHT31_I2C_PORT I2C_NUM_0
#define SHT31_I2C_FREQ_HZ 100000
#define SHT31_READ_TIMEOUT_MS 1000
#define SHT31_MEASUREMENT_DELAY_MS 20
#define SHT31_CRC_POLYNOMIAL 0x31
#define SHT31_CRC_INIT 0xff

esp_err_t sht31_init(void)
{
    const i2c_config_t config = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = SHT31_SDA_GPIO,
        .scl_io_num = SHT31_SCL_GPIO,
        .sda_pullup_en = GPIO_PULLUP_DISABLE,
        .scl_pullup_en = GPIO_PULLUP_DISABLE,
        .master.clk_speed = SHT31_I2C_FREQ_HZ,
    };

    esp_err_t err = i2c_param_config(SHT31_I2C_PORT, &config);
    if (err != ESP_OK) {
        return err;
    }

    err = i2c_driver_install(SHT31_I2C_PORT, I2C_MODE_MASTER, 0, 0, 0);
    if (err == ESP_ERR_INVALID_STATE) {
        return ESP_OK;
    }

    return err;
}

esp_err_t sht31_read(sht31_reading_t *reading)
{
    if (reading == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const uint8_t command[2] = {0x24, 0x00};
    esp_err_t err = i2c_master_write_to_device(
        SHT31_I2C_PORT,
        SHT31_I2C_ADDR,
        command,
        sizeof(command),
        pdMS_TO_TICKS(SHT31_READ_TIMEOUT_MS));
    if (err != ESP_OK) {
        return err;
    }

    vTaskDelay(pdMS_TO_TICKS(SHT31_MEASUREMENT_DELAY_MS));

    uint8_t data[6] = {0};
    err = i2c_master_read_from_device(
        SHT31_I2C_PORT,
        SHT31_I2C_ADDR,
        data,
        sizeof(data),
        pdMS_TO_TICKS(SHT31_READ_TIMEOUT_MS));
    if (err != ESP_OK) {
        return err;
    }

    if (sht31_crc8(data, 2) != data[2] || sht31_crc8(&data[3], 2) != data[5]) {
        return ESP_ERR_INVALID_CRC;
    }

    const uint16_t raw_temperature = ((uint16_t)data[0] << 8) | data[1];
    const uint16_t raw_humidity = ((uint16_t)data[3] << 8) | data[4];

    reading->temperature_celsius = sht31_temperature_from_raw(raw_temperature);
    reading->relative_humidity_percent = sht31_humidity_from_raw(raw_humidity);

    return ESP_OK;
}

uint8_t sht31_crc8(const uint8_t *data, int len)
{
    uint8_t crc = SHT31_CRC_INIT;

    if (data == NULL || len <= 0) {
        return crc;
    }

    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            if ((crc & 0x80) != 0) {
                crc = (uint8_t)((crc << 1) ^ SHT31_CRC_POLYNOMIAL);
            } else {
                crc <<= 1;
            }
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
