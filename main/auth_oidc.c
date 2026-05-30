#include "auth_oidc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app_status.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

#define AUTH_TASK_STACK_SIZE 12288
#define AUTH_TASK_PRIORITY 5
#define AUTH_RESPONSE_MAX 8192
#define AUTH_REFRESH_INTERVAL_MS (5 * 60 * 1000)
#define AUTH_DISCOVERY_SUFFIX "/.well-known/openid-configuration"
#define AUTH_HTTPS_SCHEME "https://"
#define AUTH_CLOCK_SKEW_SECONDS 60

static const char *TAG = "auth_oidc";

static app_config_t s_config;
static SemaphoreHandle_t s_auth_mutex;
static TaskHandle_t s_auth_task_handle;
static bool s_auth_task_starting;
static char *s_jwks_json;
static char s_jwks_uri[APP_CONFIG_MAX_URL_LEN];
static portMUX_TYPE s_auth_lock = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    char *data;
    int len;
    int capacity;
    bool overflow;
} auth_http_buffer_t;

static esp_err_t auth_oidc_ensure_mutex(void)
{
    taskENTER_CRITICAL(&s_auth_lock);
    if (s_auth_mutex != NULL) {
        taskEXIT_CRITICAL(&s_auth_lock);
        return ESP_OK;
    }
    taskEXIT_CRITICAL(&s_auth_lock);

    SemaphoreHandle_t new_mutex = xSemaphoreCreateMutex();
    if (new_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    taskENTER_CRITICAL(&s_auth_lock);
    if (s_auth_mutex == NULL) {
        s_auth_mutex = new_mutex;
        new_mutex = NULL;
    }
    taskEXIT_CRITICAL(&s_auth_lock);

    if (new_mutex != NULL) {
        vSemaphoreDelete(new_mutex);
    }

    return ESP_OK;
}

static bool auth_url_is_https(const char *url)
{
    return url != NULL && strncmp(url, AUTH_HTTPS_SCHEME, strlen(AUTH_HTTPS_SCHEME)) == 0;
}

static bool auth_issuer_has_trailing_slash(const char *issuer)
{
    if (issuer == NULL || issuer[0] == '\0') {
        return false;
    }

    return issuer[strlen(issuer) - 1] == '/';
}

static esp_err_t auth_validate_issuer(const char *issuer)
{
    if (!auth_url_is_https(issuer) || auth_issuer_has_trailing_slash(issuer)) {
        return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
}

static void auth_oidc_copy_config_locked(const app_config_t *config)
{
    if (config == NULL) {
        return;
    }

    s_config = *config;
}

static esp_err_t auth_oidc_get_config_copy(app_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = auth_oidc_ensure_mutex();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    *config = s_config;
    xSemaphoreGive(s_auth_mutex);
    return ESP_OK;
}

static char *auth_strdup(const char *value)
{
    if (value == NULL) {
        return NULL;
    }

    size_t len = strlen(value);
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, value, len + 1);
    return copy;
}

static char *auth_strndup(const char *value, size_t len)
{
    if (value == NULL) {
        return NULL;
    }

    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, value, len);
    copy[len] = '\0';
    return copy;
}

static char *auth_oidc_copy_jwks_json_alloc(void)
{
    if (auth_oidc_ensure_mutex() != ESP_OK) {
        return NULL;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    char *copy = auth_strdup(s_jwks_json);
    xSemaphoreGive(s_auth_mutex);
    return copy;
}

static cJSON *auth_parse_json_strict(const char *json)
{
    if (json == NULL) {
        return NULL;
    }

    const char *parse_end = NULL;
    return cJSON_ParseWithOpts(json, &parse_end, true);
}

static cJSON *auth_parse_decoded_json_strict(const unsigned char *json, size_t json_len)
{
    if (json == NULL || json_len == 0 || memchr(json, '\0', json_len) != NULL) {
        return NULL;
    }

    return auth_parse_json_strict((const char *)json);
}

static bool json_string_array_contains(const cJSON *item, const char *expected)
{
    if (expected == NULL || expected[0] == '\0') {
        return false;
    }

    if (cJSON_IsString(item)) {
        return item->valuestring != NULL && strcmp(item->valuestring, expected) == 0;
    }

    if (!cJSON_IsArray(item)) {
        return false;
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, item)
    {
        if (cJSON_IsString(entry) && entry->valuestring != NULL &&
            strcmp(entry->valuestring, expected) == 0) {
            return true;
        }
    }

    return false;
}

static bool roles_claim_contains(const cJSON *root, const char *role)
{
    static const char roles_prefix[] = "urn:zitadel:iam:org:project:";
    static const char roles_suffix[] = ":roles";

    if (!cJSON_IsObject(root) || role == NULL || role[0] == '\0') {
        return false;
    }

    const cJSON *claim = NULL;
    cJSON_ArrayForEach(claim, root)
    {
        const char *claim_name = claim->string;
        if (claim_name == NULL || strncmp(claim_name, roles_prefix, strlen(roles_prefix)) != 0) {
            continue;
        }

        size_t claim_name_len = strlen(claim_name);
        size_t suffix_len = strlen(roles_suffix);
        if (claim_name_len <= suffix_len ||
            strcmp(claim_name + claim_name_len - suffix_len, roles_suffix) != 0) {
            continue;
        }

        if (!cJSON_IsObject(claim)) {
            continue;
        }

        if (cJSON_GetObjectItemCaseSensitive(claim, role) != NULL) {
            return true;
        }
    }

    return false;
}

static bool auth_numeric_time_in_future(const cJSON *item, time_t now, int skew_seconds)
{
    return cJSON_IsNumber(item) && item->valuedouble > (double)now + (double)skew_seconds;
}

auth_result_t auth_oidc_validate_claims_json(const char *claims_json)
{
    if (claims_json == NULL) {
        return AUTH_RESULT_INVALID;
    }

    app_config_t config;
    if (auth_oidc_get_config_copy(&config) != ESP_OK) {
        return AUTH_RESULT_INVALID;
    }

    cJSON *root = auth_parse_json_strict(claims_json);
    if (root == NULL || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return AUTH_RESULT_INVALID;
    }

    auth_result_t result = AUTH_RESULT_INVALID;
    time_t now = 0;
    time(&now);

    const cJSON *issuer = cJSON_GetObjectItemCaseSensitive(root, "iss");
    const cJSON *audience = cJSON_GetObjectItemCaseSensitive(root, "aud");
    const cJSON *expires = cJSON_GetObjectItemCaseSensitive(root, "exp");
    const cJSON *not_before = cJSON_GetObjectItemCaseSensitive(root, "nbf");
    const cJSON *issued_at = cJSON_GetObjectItemCaseSensitive(root, "iat");

    if (!cJSON_IsString(issuer) || issuer->valuestring == NULL ||
        strcmp(issuer->valuestring, config.issuer) != 0) {
        result = AUTH_RESULT_INVALID;
    } else if (!json_string_array_contains(audience, config.audience)) {
        result = AUTH_RESULT_FORBIDDEN;
    } else if (!cJSON_IsNumber(expires) || expires->valuedouble <= (double)now) {
        result = AUTH_RESULT_INVALID;
    } else if (not_before != NULL &&
               (!cJSON_IsNumber(not_before) ||
                auth_numeric_time_in_future(not_before, now, AUTH_CLOCK_SKEW_SECONDS))) {
        result = AUTH_RESULT_INVALID;
    } else if (issued_at != NULL &&
               (!cJSON_IsNumber(issued_at) ||
                auth_numeric_time_in_future(issued_at, now, AUTH_CLOCK_SKEW_SECONDS))) {
        result = AUTH_RESULT_INVALID;
    } else if (!roles_claim_contains(root, config.role)) {
        result = AUTH_RESULT_FORBIDDEN;
    } else {
        result = AUTH_RESULT_OK;
    }

    cJSON_Delete(root);
    return result;
}

static bool base64url_decode_alloc(const char *input, unsigned char **out, size_t *out_len)
{
    if (input == NULL || out == NULL || out_len == NULL) {
        return false;
    }

    *out = NULL;
    *out_len = 0;

    size_t input_len = strlen(input);
    if (input_len == 0 || input_len % 4 == 1) {
        return false;
    }

    size_t padded_len = input_len;
    size_t remainder = padded_len % 4;
    if (remainder != 0) {
        padded_len += 4 - remainder;
    }

    unsigned char *base64 = malloc(padded_len + 1);
    if (base64 == NULL) {
        return false;
    }

    for (size_t i = 0; i < input_len; ++i) {
        unsigned char ch = (unsigned char)input[i];
        if (isalnum(ch)) {
            base64[i] = ch;
        } else if (ch == '-') {
            base64[i] = '+';
        } else if (ch == '_') {
            base64[i] = '/';
        } else {
            free(base64);
            return false;
        }
    }
    for (size_t i = input_len; i < padded_len; ++i) {
        base64[i] = '=';
    }
    base64[padded_len] = '\0';

    size_t max_decoded_len = (padded_len / 4) * 3;
    unsigned char *decoded = calloc(1, max_decoded_len + 1);
    if (decoded == NULL) {
        free(base64);
        return false;
    }

    size_t decoded_len = 0;
    int ret = mbedtls_base64_decode(decoded, max_decoded_len, &decoded_len, base64, padded_len);
    free(base64);
    if (ret != 0) {
        free(decoded);
        return false;
    }

    *out = decoded;
    *out_len = decoded_len;
    return true;
}

static bool jwt_header_typ_is_allowed(const cJSON *typ)
{
    if (typ == NULL) {
        return true;
    }
    if (!cJSON_IsString(typ) || typ->valuestring == NULL) {
        return false;
    }

    return strcmp(typ->valuestring, "JWT") == 0 ||
           strcmp(typ->valuestring, "jwt") == 0 ||
           strcmp(typ->valuestring, "at+jwt") == 0 ||
           strcmp(typ->valuestring, "application/jwt") == 0 ||
           strcmp(typ->valuestring, "application/at+jwt") == 0;
}

static const cJSON *find_jwk_by_kid(const cJSON *jwks, const char *kid)
{
    if (!cJSON_IsObject(jwks) || kid == NULL || kid[0] == '\0') {
        return NULL;
    }

    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(jwks, "keys");
    if (!cJSON_IsArray(keys)) {
        return NULL;
    }

    const cJSON *jwk = NULL;
    cJSON_ArrayForEach(jwk, keys)
    {
        if (!cJSON_IsObject(jwk)) {
            continue;
        }

        const cJSON *jwk_kid = cJSON_GetObjectItemCaseSensitive(jwk, "kid");
        if (!cJSON_IsString(jwk_kid) || jwk_kid->valuestring == NULL ||
            strcmp(jwk_kid->valuestring, kid) != 0) {
            continue;
        }

        const cJSON *kty = cJSON_GetObjectItemCaseSensitive(jwk, "kty");
        if (kty != NULL &&
            (!cJSON_IsString(kty) || kty->valuestring == NULL || strcmp(kty->valuestring, "RSA") != 0)) {
            continue;
        }

        const cJSON *use = cJSON_GetObjectItemCaseSensitive(jwk, "use");
        if (use != NULL &&
            (!cJSON_IsString(use) || use->valuestring == NULL || strcmp(use->valuestring, "sig") != 0)) {
            continue;
        }

        return jwk;
    }

    return NULL;
}

static auth_result_t verify_rs256_with_jwk(const char *signing_input,
                                           const unsigned char *signature,
                                           size_t signature_len,
                                           const cJSON *jwk)
{
    if (signing_input == NULL || signature == NULL || signature_len == 0 || !cJSON_IsObject(jwk)) {
        return AUTH_RESULT_INVALID;
    }

    const cJSON *modulus = cJSON_GetObjectItemCaseSensitive(jwk, "n");
    const cJSON *exponent = cJSON_GetObjectItemCaseSensitive(jwk, "e");
    if (!cJSON_IsString(modulus) || modulus->valuestring == NULL ||
        !cJSON_IsString(exponent) || exponent->valuestring == NULL) {
        return AUTH_RESULT_INVALID;
    }

    unsigned char *n_bytes = NULL;
    unsigned char *e_bytes = NULL;
    size_t n_len = 0;
    size_t e_len = 0;
    if (!base64url_decode_alloc(modulus->valuestring, &n_bytes, &n_len) ||
        !base64url_decode_alloc(exponent->valuestring, &e_bytes, &e_len) ||
        n_len == 0 || e_len == 0) {
        free(n_bytes);
        free(e_bytes);
        return AUTH_RESULT_INVALID;
    }

    unsigned char digest[32];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL ||
        mbedtls_md(md_info, (const unsigned char *)signing_input, strlen(signing_input), digest) != 0) {
        free(n_bytes);
        free(e_bytes);
        return AUTH_RESULT_INVALID;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret == 0) {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
        ret = mbedtls_rsa_import_raw(rsa, n_bytes, n_len, NULL, 0, NULL, 0, NULL, 0, e_bytes, e_len);
        if (ret == 0) {
            ret = mbedtls_rsa_complete(rsa);
        }
        if (ret == 0) {
            ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                                    signature, signature_len);
        }
    }

    mbedtls_pk_free(&pk);
    free(n_bytes);
    free(e_bytes);

    return ret == 0 ? AUTH_RESULT_OK : AUTH_RESULT_INVALID;
}

static auth_result_t verify_jwt_signature_and_claims(const char *jwt)
{
    if (jwt == NULL) {
        return AUTH_RESULT_INVALID;
    }

    const char *dot1 = strchr(jwt, '.');
    if (dot1 == NULL || dot1 == jwt) {
        return AUTH_RESULT_INVALID;
    }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (dot2 == NULL || dot2 == dot1 + 1 || dot2[1] == '\0' || strchr(dot2 + 1, '.') != NULL) {
        return AUTH_RESULT_INVALID;
    }

    size_t header_segment_len = (size_t)(dot1 - jwt);
    size_t payload_segment_len = (size_t)(dot2 - dot1 - 1);
    size_t signing_input_len = (size_t)(dot2 - jwt);

    char *header_segment = auth_strndup(jwt, header_segment_len);
    char *payload_segment = auth_strndup(dot1 + 1, payload_segment_len);
    char *signature_segment = auth_strdup(dot2 + 1);
    char *signing_input = auth_strndup(jwt, signing_input_len);
    if (header_segment == NULL || payload_segment == NULL || signature_segment == NULL ||
        signing_input == NULL) {
        free(header_segment);
        free(payload_segment);
        free(signature_segment);
        free(signing_input);
        return AUTH_RESULT_INVALID;
    }

    unsigned char *header_json = NULL;
    unsigned char *payload_json = NULL;
    unsigned char *signature = NULL;
    size_t header_json_len = 0;
    size_t payload_json_len = 0;
    size_t signature_len = 0;
    cJSON *header_root = NULL;
    cJSON *jwks_root = NULL;
    char *jwks_json = NULL;
    auth_result_t result = AUTH_RESULT_INVALID;

    if (!base64url_decode_alloc(header_segment, &header_json, &header_json_len) ||
        !base64url_decode_alloc(payload_segment, &payload_json, &payload_json_len) ||
        !base64url_decode_alloc(signature_segment, &signature, &signature_len)) {
        goto cleanup;
    }
    if (header_json_len == 0 || payload_json_len == 0 || signature_len == 0) {
        goto cleanup;
    }

    header_root = auth_parse_decoded_json_strict(header_json, header_json_len);
    if (header_root == NULL || !cJSON_IsObject(header_root)) {
        goto cleanup;
    }

    const cJSON *alg = cJSON_GetObjectItemCaseSensitive(header_root, "alg");
    const cJSON *kid = cJSON_GetObjectItemCaseSensitive(header_root, "kid");
    const cJSON *typ = cJSON_GetObjectItemCaseSensitive(header_root, "typ");
    if (!cJSON_IsString(alg) || alg->valuestring == NULL || strcmp(alg->valuestring, "RS256") != 0 ||
        !cJSON_IsString(kid) || kid->valuestring == NULL || kid->valuestring[0] == '\0' ||
        !jwt_header_typ_is_allowed(typ)) {
        goto cleanup;
    }

    jwks_json = auth_oidc_copy_jwks_json_alloc();
    if (jwks_json == NULL) {
        goto cleanup;
    }

    jwks_root = auth_parse_json_strict(jwks_json);
    if (jwks_root == NULL) {
        goto cleanup;
    }

    const cJSON *jwk = find_jwk_by_kid(jwks_root, kid->valuestring);
    if (jwk == NULL) {
        goto cleanup;
    }

    result = verify_rs256_with_jwk(signing_input, signature, signature_len, jwk);
    if (result == AUTH_RESULT_OK) {
        result = auth_oidc_validate_claims_json((const char *)payload_json);
    }

cleanup:
    cJSON_Delete(jwks_root);
    cJSON_Delete(header_root);
    free(jwks_json);
    free(signature);
    free(payload_json);
    free(header_json);
    free(signature_segment);
    free(payload_segment);
    free(header_segment);
    free(signing_input);
    return result;
}

static esp_err_t auth_http_event_handler(esp_http_client_event_t *event)
{
    auth_http_buffer_t *buffer = (auth_http_buffer_t *)event->user_data;
    if (event->event_id != HTTP_EVENT_ON_DATA || buffer == NULL || event->data_len <= 0) {
        return ESP_OK;
    }

    if (event->data_len > buffer->capacity - buffer->len - 1) {
        buffer->overflow = true;
        if (buffer->capacity > 0) {
            buffer->data[buffer->capacity - 1] = '\0';
        }
        return ESP_ERR_NO_MEM;
    }

    memcpy(buffer->data + buffer->len, event->data, event->data_len);
    buffer->len += event->data_len;
    buffer->data[buffer->len] = '\0';
    return ESP_OK;
}

static esp_err_t auth_https_get_json(const char *url, char *out, int out_len)
{
    if (url == NULL || out == NULL || out_len <= 1) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!auth_url_is_https(url)) {
        return ESP_ERR_INVALID_ARG;
    }

    out[0] = '\0';
    auth_http_buffer_t buffer = {
        .data = out,
        .len = 0,
        .capacity = out_len,
        .overflow = false,
    };
    esp_http_client_config_t http_config = {
        .url = url,
        .event_handler = auth_http_event_handler,
        .user_data = &buffer,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (client == NULL) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        return err;
    }
    if (buffer.overflow) {
        return ESP_ERR_NO_MEM;
    }
    if (status_code != 200) {
        ESP_LOGW(TAG, "HTTPS GET failed url=%s status=%d", url, status_code);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t auth_build_discovery_url(const char *issuer, char *out, size_t out_size)
{
    if (issuer == NULL || out == NULL || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = auth_validate_issuer(issuer);
    if (err != ESP_OK) {
        return err;
    }

    int len = snprintf(out, out_size, "%s%s", issuer, AUTH_DISCOVERY_SUFFIX);
    if (len < 0 || len >= (int)out_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

static esp_err_t auth_parse_discovery(const char *discovery_json,
                                      const app_config_t *config,
                                      char *jwks_uri,
                                      size_t jwks_uri_size)
{
    if (discovery_json == NULL || config == NULL || jwks_uri == NULL || jwks_uri_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *root = cJSON_Parse(discovery_json);
    if (root == NULL) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    esp_err_t err = ESP_OK;
    const cJSON *issuer = cJSON_GetObjectItemCaseSensitive(root, "issuer");
    const cJSON *jwks = cJSON_GetObjectItemCaseSensitive(root, "jwks_uri");
    if (!cJSON_IsString(issuer) || strcmp(issuer->valuestring, config->issuer) != 0 ||
        !cJSON_IsString(jwks) || !auth_url_is_https(jwks->valuestring)) {
        err = ESP_ERR_INVALID_RESPONSE;
    } else if (strnlen(jwks->valuestring, jwks_uri_size) >= jwks_uri_size) {
        err = ESP_ERR_INVALID_SIZE;
    } else {
        strlcpy(jwks_uri, jwks->valuestring, jwks_uri_size);
    }

    cJSON_Delete(root);
    return err;
}

static esp_err_t auth_validate_jwks(const char *jwks_json)
{
    if (jwks_json == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *root = cJSON_Parse(jwks_json);
    if (root == NULL) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    esp_err_t err = ESP_OK;
    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(root, "keys");
    if (!cJSON_IsObject(root) || !cJSON_IsArray(keys) || cJSON_GetArraySize(keys) <= 0) {
        err = ESP_ERR_INVALID_RESPONSE;
    }

    cJSON_Delete(root);
    return err;
}

static esp_err_t auth_discover_and_fetch_jwks(void)
{
    app_config_t config;
    esp_err_t err = auth_oidc_get_config_copy(&config);
    if (err != ESP_OK) {
        return err;
    }

    char discovery_url[APP_CONFIG_MAX_URL_LEN + sizeof(AUTH_DISCOVERY_SUFFIX)];
    err = auth_build_discovery_url(config.issuer, discovery_url, sizeof(discovery_url));
    if (err != ESP_OK) {
        return err;
    }

    char *discovery_json = calloc(1, AUTH_RESPONSE_MAX);
    char *jwks_json = calloc(1, AUTH_RESPONSE_MAX);
    if (discovery_json == NULL || jwks_json == NULL) {
        free(discovery_json);
        free(jwks_json);
        return ESP_ERR_NO_MEM;
    }

    char jwks_uri[APP_CONFIG_MAX_URL_LEN] = {0};
    err = auth_https_get_json(discovery_url, discovery_json, AUTH_RESPONSE_MAX);
    if (err == ESP_OK) {
        err = auth_parse_discovery(discovery_json, &config, jwks_uri, sizeof(jwks_uri));
    }
    if (err == ESP_OK) {
        err = auth_https_get_json(jwks_uri, jwks_json, AUTH_RESPONSE_MAX);
    }
    if (err == ESP_OK) {
        err = auth_validate_jwks(jwks_json);
    }
    if (err == ESP_OK) {
        xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
        free(s_jwks_json);
        s_jwks_json = jwks_json;
        jwks_json = NULL;
        strlcpy(s_jwks_uri, jwks_uri, sizeof(s_jwks_uri));
        app_status_set_auth_ready(true);
        xSemaphoreGive(s_auth_mutex);
    }

    free(discovery_json);
    free(jwks_json);
    return err;
}

static void auth_oidc_task(void *arg)
{
    (void)arg;

    while (true) {
        esp_err_t err = auth_discover_and_fetch_jwks();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "OIDC discovery/JWKS refresh failed: %s", esp_err_to_name(err));
            app_status_set_auth_ready(false);
        }

        vTaskDelay(pdMS_TO_TICKS(AUTH_REFRESH_INTERVAL_MS));
    }
}

esp_err_t auth_oidc_start(const app_config_t *config)
{
    if (config == NULL || !app_config_has_auth_audience(config)) {
        ESP_LOGW(TAG, "auth audience is missing; protected API will stay unavailable");
        app_status_set_auth_ready(false);
        return ESP_OK;
    }
    esp_err_t err = auth_validate_issuer(config->issuer);
    if (err != ESP_OK) {
        app_status_set_auth_ready(false);
        return err;
    }

    err = auth_oidc_ensure_mutex();
    if (err != ESP_OK) {
        app_status_set_auth_ready(false);
        return err;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    auth_oidc_copy_config_locked(config);
    xSemaphoreGive(s_auth_mutex);

    app_status_set_auth_ready(false);

    while (true) {
        taskENTER_CRITICAL(&s_auth_lock);
        if (s_auth_task_handle != NULL) {
            taskEXIT_CRITICAL(&s_auth_lock);
            return ESP_OK;
        }

        if (!s_auth_task_starting) {
            s_auth_task_starting = true;
            taskEXIT_CRITICAL(&s_auth_lock);
            break;
        }
        taskEXIT_CRITICAL(&s_auth_lock);

        vTaskDelay(1);
    }

    TaskHandle_t task_handle = NULL;
    BaseType_t created = xTaskCreate(auth_oidc_task, "auth_oidc", AUTH_TASK_STACK_SIZE, NULL,
                                     AUTH_TASK_PRIORITY, &task_handle);
    taskENTER_CRITICAL(&s_auth_lock);
    if (created != pdPASS) {
        s_auth_task_starting = false;
        taskEXIT_CRITICAL(&s_auth_lock);
        return ESP_ERR_NO_MEM;
    }

    s_auth_task_handle = task_handle;
    s_auth_task_starting = false;
    taskEXIT_CRITICAL(&s_auth_lock);

    return ESP_OK;
}

auth_result_t auth_oidc_validate_authorization_header(const char *header)
{
    if (header == NULL || strncmp(header, "Bearer ", 7) != 0) {
        return AUTH_RESULT_MISSING;
    }
    if (!app_status_get().auth_ready) {
        return AUTH_RESULT_NOT_READY;
    }

    return verify_jwt_signature_and_claims(header + 7);
}

void auth_oidc_set_config_for_test(const app_config_t *config)
{
    if (config == NULL || auth_oidc_ensure_mutex() != ESP_OK) {
        return;
    }

    xSemaphoreTake(s_auth_mutex, portMAX_DELAY);
    auth_oidc_copy_config_locked(config);
    xSemaphoreGive(s_auth_mutex);
}
