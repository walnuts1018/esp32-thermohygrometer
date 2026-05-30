#include "auth_oidc.h"

#include <stdio.h>
#include <time.h>

#include "app_status.h"
#include "psa/crypto.h"
#include "unity.h"

static void set_test_auth_config(void)
{
    app_config_t config = {
        .issuer = "https://auth.walnuts.dev",
        .audience = "thermo-api",
        .role = "thermohygrometer.read",
    };
    auth_oidc_set_config_for_test(&config);
    app_status_set_time_synced(true);
}

static void build_claims(char *buffer,
                         size_t buffer_size,
                         const char *issuer,
                         const char *audience_json,
                         const char *roles_json)
{
    time_t now = time(NULL);
    int len = snprintf(buffer, buffer_size,
                       "{"
                       "\"iss\":\"%s\","
                       "\"aud\":%s,"
                       "\"exp\":%lld%s%s"
                       "}",
                       issuer,
                       audience_json,
                       (long long)(now + 3600),
                       roles_json == NULL ? "" : ",",
                       roles_json == NULL ? "" : roles_json);
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_LESS_THAN((int)buffer_size, len);
}

TEST_CASE("claims with valid issuer audience and exp but no role are forbidden", "[auth]")
{
    set_test_auth_config();

    char claims[512];
    build_claims(claims, sizeof(claims), "https://auth.walnuts.dev", "\"thermo-api\"", NULL);

    TEST_ASSERT_EQUAL(AUTH_RESULT_FORBIDDEN, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("claims with valid issuer audience exp and ZITADEL role are accepted", "[auth]")
{
    set_test_auth_config();

    char claims[768];
    build_claims(claims, sizeof(claims), "https://auth.walnuts.dev", "[\"account\",\"thermo-api\"]",
                 "\"urn:zitadel:iam:org:project:123456:roles\":{"
                 "\"thermohygrometer.read\":{}}");

    TEST_ASSERT_EQUAL(AUTH_RESULT_OK, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("claims with wrong issuer are invalid", "[auth]")
{
    set_test_auth_config();

    char claims[768];
    build_claims(claims, sizeof(claims), "https://evil.example", "\"thermo-api\"",
                 "\"urn:zitadel:iam:org:project:123456:roles\":{"
                 "\"thermohygrometer.read\":{}}");

    TEST_ASSERT_EQUAL(AUTH_RESULT_INVALID, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("claims with wrong audience are forbidden", "[auth]")
{
    set_test_auth_config();

    char claims[768];
    build_claims(claims, sizeof(claims), "https://auth.walnuts.dev", "\"other-api\"",
                 "\"urn:zitadel:iam:org:project:123456:roles\":{"
                 "\"thermohygrometer.read\":{}}");

    TEST_ASSERT_EQUAL(AUTH_RESULT_FORBIDDEN, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("claims with global ZITADEL role claim are accepted", "[auth]")
{
    set_test_auth_config();

    char claims[768];
    build_claims(claims, sizeof(claims), "https://auth.walnuts.dev", "[\"thermo-api\"]",
                 "\"urn:zitadel:iam:org:project:roles\":{"
                 "\"thermohygrometer.read\":{\"orgid123\":\"example.org\"}}");

    TEST_ASSERT_EQUAL(AUTH_RESULT_OK, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("expired token is invalid", "[auth]")
{
    set_test_auth_config();

    time_t past = time(NULL) - 3600;
    char claims[768];
    int len = snprintf(claims, sizeof(claims),
                       "{\"iss\":\"https://auth.walnuts.dev\","
                       "\"aud\":[\"thermo-api\"],"
                       "\"exp\":%lld,"
                       "\"urn:zitadel:iam:org:project:123456:roles\":"
                       "{\"thermohygrometer.read\":{}}}",
                       (long long)past);
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_LESS_THAN((int)sizeof(claims), len);

    TEST_ASSERT_EQUAL(AUTH_RESULT_INVALID, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("claims are not accepted before time is synchronized", "[auth]")
{
    set_test_auth_config();
    app_status_set_time_synced(false);

    char claims[768];
    build_claims(claims, sizeof(claims), "https://auth.walnuts.dev", "[\"thermo-api\"]",
                 "\"urn:zitadel:iam:org:project:123456:roles\":{"
                 "\"thermohygrometer.read\":{}}");

    TEST_ASSERT_EQUAL(AUTH_RESULT_NOT_READY, auth_oidc_validate_claims_json(claims));
}

TEST_CASE("JWK RSA public key material is encoded in PSA import format", "[auth]")
{
    const unsigned char n[] = {
        0xc7, 0x3f, 0x5c, 0x60, 0xbb, 0x88, 0x1f, 0x58,
        0x9a, 0x40, 0x75, 0x53, 0x7d, 0xb7, 0x9a, 0x5d,
        0xc3, 0xbb, 0x1a, 0xf6, 0x70, 0x32, 0x95, 0x5f,
        0x4f, 0x30, 0xcb, 0x72, 0x9e, 0x87, 0x6c, 0x4d,
        0x95, 0x52, 0xf2, 0x7c, 0xfa, 0x23, 0x60, 0x3d,
        0x28, 0xe5, 0xa4, 0x03, 0x8f, 0x83, 0x23, 0x10,
        0x4c, 0x79, 0xb8, 0xba, 0x83, 0x05, 0x88, 0xc9,
        0x2e, 0x2a, 0x38, 0x54, 0xdf, 0x66, 0x51, 0x93,
        0xd2, 0x21, 0x19, 0xc2, 0x2f, 0xa4, 0xe0, 0xd2,
        0xe6, 0xd4, 0x4a, 0xe2, 0xe3, 0x75, 0x70, 0x7e,
        0x0e, 0xd5, 0x13, 0xd1, 0x15, 0xbb, 0x2d, 0x29,
        0x0b, 0x3f, 0x63, 0xd3, 0x7b, 0xf4, 0x11, 0xdd,
        0x34, 0xf3, 0x0e, 0x6e, 0xba, 0xc3, 0xa1, 0x38,
        0x97, 0x91, 0xa0, 0x8b, 0x5b, 0xa5, 0x0e, 0xf6,
        0x7a, 0x72, 0x2a, 0x5d, 0x78, 0xeb, 0x36, 0x61,
        0x09, 0xaf, 0xd0, 0x44, 0x3f, 0x06, 0xf3, 0xf1,
    };
    const unsigned char e[] = {0x01, 0x00, 0x01};
    unsigned char der[160];
    size_t der_len = auth_oidc_build_rsa_public_key_der_for_test(n, sizeof(n), e, sizeof(e),
                                                                 der, sizeof(der));
    TEST_ASSERT_GREATER_THAN(0, der_len);

    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_import_key(&attrs, der, der_len, &key_id));
    TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_destroy_key(key_id));
}
