#include "auth_oidc.h"

#include <stdio.h>
#include <time.h>

#include "app_status.h"
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
