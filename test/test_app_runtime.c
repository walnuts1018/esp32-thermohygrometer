#include <string.h>

#include "app_runtime.h"
#include "unity.h"

TEST_CASE("api server is not started while wifi provisioning owns http server", "[app_runtime]")
{
    app_config_t config = {0};
    strlcpy(config.ssid, "ssid", sizeof(config.ssid));
    strlcpy(config.password, "password", sizeof(config.password));

    TEST_ASSERT_FALSE(app_runtime_should_start_api(&config, true));
}

TEST_CASE("api server is started after saved wifi configuration is active", "[app_runtime]")
{
    app_config_t config = {0};
    strlcpy(config.ssid, "ssid", sizeof(config.ssid));
    strlcpy(config.password, "password", sizeof(config.password));

    TEST_ASSERT_TRUE(app_runtime_should_start_api(&config, false));
}
