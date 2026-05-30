#pragma once

#include <stdbool.h>
#include <stddef.h>

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
auth_result_t auth_oidc_validate_claims_json(const char *claims_json);
void auth_oidc_set_config_for_test(const app_config_t *config);
size_t auth_oidc_build_rsa_public_key_der_for_test(const unsigned char *n, size_t n_len,
                                                   const unsigned char *e, size_t e_len,
                                                   unsigned char *der_out, size_t der_out_len);
