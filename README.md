# esp32-thermohygrometer

ESP-IDF firmware for an ESP32-connected SHT31 thermohygrometer.

## Prerequisites

開発環境は Dev Container として定義されています。ローカルに ESP-IDF をインストールすることなくビルドや開発を行うことができます。

ホスト環境（またはAIエージェントの実行環境）には、[Dev Container CLI](https://code.visualstudio.com/docs/devcontainers/devcontainer-cli) がインストールされている必要があります。

## Build

Dev Container を使用してビルドを行う例です。

```sh
# コンテナの起動（初回はイメージのビルド/プルが行われます）
devcontainer up --workspace-folder .

# コンテナ内でのビルド実行（ESP-IDFのパスを読み込ませるためbash経由で実行します）
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build set-target esp32"
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build build"
```

## Flash

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build -p /dev/ttyUSB0 flash monitor"
```

## Tests

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && cd test && idf.py -B /tmp/esp32-thermohygrometer-test-build set-target esp32"
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && cd test && idf.py -B /tmp/esp32-thermohygrometer-test-build build"
```

## Provisioning

When no Wi-Fi credentials are stored, the device starts ESP-IDF SoftAP provisioning:

- Service name: `thermohygrometer-setup`
- Proof of possession: `thermohygrometer`

Use an ESP-IDF provisioning client or Espressif reference mobile app to send SSID and password.

## API

Unauthenticated health check:

```sh
curl http://DEVICE_IP/healthz
```

Authenticated measurement:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://DEVICE_IP/v1/measurements/latest
```

Auth failure checks:

```sh
curl -i http://DEVICE_IP/v1/measurements/latest
curl -i -H "Authorization: Bearer $TOKEN_WITHOUT_ROLE" \
  http://DEVICE_IP/v1/measurements/latest
```

The first request should return `401 Unauthorized`; the second should return
`403 Forbidden` when the token has the required audience but does not include
the `thermohygrometer.read` role.

Successful measurement check:

```sh
curl -s -H "Authorization: Bearer $TOKEN_WITH_ROLE" \
  http://DEVICE_IP/v1/measurements/latest
```

Expected response shape:

```json
{
  "temperature_celsius": 23.42,
  "relative_humidity_percent": 48.31,
  "sensor": "sht31",
  "i2c_address": "0x45",
  "measured_at_ms": 123456
}
```

Repeated request check:

```sh
for i in $(seq 1 20); do
  curl -s -H "Authorization: Bearer $TOKEN_WITH_ROLE" \
    http://DEVICE_IP/v1/measurements/latest >/dev/null &
done
wait
curl -s http://DEVICE_IP/healthz
```

`/healthz` should continue to report `"sensor_valid":true` after the repeated
measurement requests.
