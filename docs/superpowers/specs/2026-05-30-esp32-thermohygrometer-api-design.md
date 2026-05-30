# ESP32 Thermohygrometer API Design

## Goal

Build ESP32 firmware that reads an Akizuki AE-SHT3x/SHT31-DIS temperature and humidity sensor over I2C and exposes the latest measurement through an authenticated HTTP API.

The firmware should be practical on ESP32 hardware. REST/JSON is selected instead of gRPC because the service only exposes small sensor readings and ESP32 support for HTTP/2/gRPC is heavier than the use case justifies.

## Hardware

- MCU: ESP32.
- Sensor: Akizuki AE-SHT3x module using Sensirion SHT31-DIS.
- I2C pins:
  - SDA: GPIO21.
  - SCL: GPIO22.
- Sensor address:
  - ADR open, so the I2C address is `0x45`.
- The sensor module already includes 10 kOhm pull-ups on SDA and SCL, so firmware should not require extra pull-ups.

## Platform

Use ESP-IDF.

Reasons:

- Native Wi-Fi, TLS, HTTP server, HTTP client, NVS, and I2C support.
- Better fit for JWT/JWKS verification than Arduino-style stacks.
- More predictable memory and task control for an always-on network service.

## Configuration Storage

Use ESP-IDF NVS instead of EEPROM. ESP32 Arduino exposes EEPROM-like APIs, but in ESP-IDF NVS is the normal persistent key/value store and better matches this firmware.

Configuration keys:

- `wifi.ssid`: Wi-Fi SSID.
- `wifi.password`: Wi-Fi password.
- `auth.issuer`: OIDC issuer. Default: `https://auth.walnuts.dev`.
- `auth.audience`: required JWT audience. No hard-coded default unless the project ID is known at build time.
- `auth.role`: required project role. Default: `thermohygrometer.read`.
- `auth.jwks_uri`: discovered from OIDC metadata and cached after successful discovery.

Minimum dynamic requirement:

- Wi-Fi SSID and password must be configurable at runtime and persisted in NVS.

Preferred dynamic behavior:

- Auth settings can also be changed at runtime and persisted in NVS, but the firmware may ship with `auth.issuer=https://auth.walnuts.dev` as a default.

## Provisioning Flow

On boot:

1. Initialize NVS.
2. Read Wi-Fi configuration.
3. If SSID/password are present, connect as a Wi-Fi station.
4. If Wi-Fi configuration is missing or connection fails repeatedly, start provisioning mode.

Provisioning mode:

- Start a temporary Wi-Fi access point, for example `thermohygrometer-setup`.
- Run a local HTTP server.
- Expose:
  - `GET /setup`: returns current configuration status without secrets.
  - `POST /setup/wifi`: accepts `ssid` and `password`, stores them in NVS, and restarts station connection.
  - `POST /setup/auth`: optional endpoint for `issuer`, `audience`, and `role`.
- Setup endpoints are only available in provisioning mode.
- After successful Wi-Fi connection, stop provisioning endpoints.

For initial implementation, a JSON API is sufficient. A browser UI is not required.

## Sensor Reading

Use SHT31 single-shot measurement with high repeatability and clock stretching disabled:

- Command: `0x24 0x00`.
- Wait for the measurement to complete.
- Read 6 bytes:
  - temperature MSB.
  - temperature LSB.
  - temperature CRC.
  - humidity MSB.
  - humidity LSB.
  - humidity CRC.

Validate both CRC bytes using the SHT3x CRC-8 algorithm before returning data.

Conversion:

- `temperature_celsius = -45 + 175 * raw_temperature / 65535`
- `relative_humidity_percent = 100 * raw_humidity / 65535`

Sensor errors should produce a structured HTTP error and be reflected in `/healthz`.

## API

### `GET /healthz`

Authentication: none.

Purpose:

- Allow local liveness checks without requiring a token.

Response fields:

- firmware version.
- Wi-Fi state.
- sensor state.
- auth discovery/JWKS cache state.
- uptime.

### `GET /v1/measurements/latest`

Authentication: required.

Authorization: caller must pass JWT validation and required role/scope checks.

Behavior:

- Trigger a fresh SHT31 measurement per request.
- Return JSON:

```json
{
  "temperature_celsius": 23.42,
  "relative_humidity_percent": 48.31,
  "sensor": "sht31",
  "i2c_address": "0x45",
  "measured_at_ms": 123456
}
```

Errors:

- `401 Unauthorized`: missing or invalid bearer token.
- `403 Forbidden`: valid token but missing required audience or role.
- `503 Service Unavailable`: sensor unavailable, Wi-Fi/auth initialization incomplete, or no valid JWKS cache.

## ZITADEL Authentication And Authorization

The firmware acts as an OAuth2 resource server.

OIDC metadata:

- Fetch `https://auth.walnuts.dev/.well-known/openid-configuration` on boot unless `auth.issuer` is changed.
- Require the returned `issuer` to match configured `auth.issuer`.
- Read `jwks_uri`, expected to be `https://auth.walnuts.dev/oauth/v2/keys`.

JWKS:

- Fetch JWKS at boot after Wi-Fi is connected.
- Cache keys in memory.
- Store the last successful `jwks_uri` in NVS.
- Refresh periodically based on cache headers when available, or at a conservative interval.
- If a JWT uses an unknown `kid`, try one on-demand JWKS refresh before rejecting.

JWT validation:

- Require `Authorization: Bearer <token>`.
- Parse the JWT header and claims.
- Require `typ` to be compatible with JWT if present.
- Require `alg` to be in the supported allowlist. Initial implementation should support `RS256`; add ES/EdDSA only if the configured ZITADEL instance uses them and the embedded crypto library supports them safely.
- Select the JWK by `kid`.
- Verify the JWS signature.
- Validate claims:
  - `iss` equals configured issuer.
  - `exp` is in the future.
  - `nbf`, if present, is not in the future beyond allowed clock skew.
  - `iat`, if present, is not unreasonably in the future.
  - `aud` contains configured `auth.audience`.
  - Token is not accepted solely because `aud` matches.

Authorization:

- Prefer a ZITADEL project role for access, because ZITADEL documents that audience alone is not sufficient authorization.
- Required default role: `thermohygrometer.read`.
- Check the project-specific ZITADEL role claim:
  - `urn:zitadel:iam:org:project:{projectId}:roles`
- The client obtaining tokens should request:
  - `urn:zitadel:iam:org:project:id:{projectId}:aud`
  - a role-claim scope such as `urn:zitadel:iam:org:projects:roles` or configure the project to assert roles.

If custom scopes are preferred later, the same authorization layer can check a configured scope instead of, or in addition to, the project role.

## Time Handling

JWT validation requires reasonably correct time.

On boot:

1. Connect Wi-Fi.
2. Sync time using SNTP.
3. Fetch OIDC metadata and JWKS.
4. Start protected API readiness.

Before time sync completes:

- `/healthz` remains available.
- Protected endpoints return `503 Service Unavailable`.

## Task Structure

Suggested modules:

- `main`: boot orchestration and task setup.
- `config`: NVS-backed configuration.
- `wifi`: station connection and provisioning AP mode.
- `sensor_sht31`: I2C driver, CRC, conversion.
- `auth_oidc`: discovery, JWKS cache, JWT validation.
- `api_server`: HTTP routes and JSON responses.

## Testing Strategy

Host-side unit tests:

- SHT31 CRC validation.
- Raw sensor conversion formulas.
- JWT claim validation logic with fixed test claims.
- ZITADEL role-claim extraction.
- NVS config serialization logic where practical.

Target/hardware tests:

- I2C scan or sensor read confirms address `0x45`.
- `/healthz` works without auth.
- `/v1/measurements/latest` rejects missing token.
- Valid token with correct audience and role succeeds.
- Valid token with audience but missing role fails with `403`.

## Open Inputs

These values are still needed for a complete deployment:

- ZITADEL project ID or concrete API audience.
- Whether only role-based authorization is desired, or whether a custom scope should also be required.
- Final provisioning AP SSID/password policy.

The firmware can be implemented before those values are known by using NVS-backed auth settings and refusing protected requests until `auth.audience` is configured.
