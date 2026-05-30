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

TEST_CASE("latest reading becomes unavailable after sensor read error", "[sensor_task]")
{
    sensor_latest_reading_t input = {
        .valid = true,
        .temperature_celsius = 21.5f,
        .relative_humidity_percent = 44.25f,
        .measured_at_ms = 1234,
        .last_error = ESP_OK,
    };
    sensor_latest_store_for_test(&input);

    sensor_latest_store_error_for_test(ESP_ERR_TIMEOUT);

    sensor_latest_reading_t output = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, sensor_latest_get(&output));
    TEST_ASSERT_FALSE(output.valid);
    TEST_ASSERT_EQUAL(ESP_ERR_TIMEOUT, output.last_error);
}
