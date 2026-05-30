#pragma once

#include "app_config.h"
#include "esp_err.h"

esp_err_t wifi_manager_start(const app_config_t *config);
bool wifi_manager_is_provisioning(void);
