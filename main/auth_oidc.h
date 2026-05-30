#pragma once

#include <stdbool.h>

#include "app_config.h"
#include "esp_err.h"

typedef enum {
    AUTH_RESULT_OK = 0,
    AUTH_RESULT_MISSING,
    AUTH_RESULT_INVALID,
    AUTH_RESULT_FORBIDDEN,
    AUTH_RESULT_NOT_READY,
} auth_result_t;

esp_err_t auth_oidc_start(const app_config_t *config);
auth_result_t auth_oidc_validate_authorization_header(const char *header);
void auth_oidc_set_config_for_test(const app_config_t *config);
