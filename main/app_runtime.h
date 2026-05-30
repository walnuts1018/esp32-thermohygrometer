#pragma once

#include <stdbool.h>

#include "app_config.h"

bool app_runtime_should_start_api(const app_config_t *config, bool wifi_provisioning);
