#include "app_runtime.h"

bool app_runtime_should_start_api(const app_config_t *config, bool wifi_provisioning)
{
    return app_config_has_wifi(config) && !wifi_provisioning;
}
