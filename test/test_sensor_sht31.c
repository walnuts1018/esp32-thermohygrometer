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
