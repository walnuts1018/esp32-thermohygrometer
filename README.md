# esp32-thermohygrometer

ESP32 と SHT31 温湿度センサーを使い、最新の温度・湿度を HTTP API で取得するための ESP-IDF ファームウェアです。

Wi-Fi 設定は ESP-IDF の SoftAP provisioning で投入します。測定値 API は ZITADEL の JWT で保護され、`/healthz` はトークンなしで確認できます。

## できること

- SHT31 から温度と湿度を定期的に読み取る
- `GET /healthz` でデバイス状態を確認する
- `GET /v1/measurements/latest` で最新の測定値を JSON で取得する
- ZITADEL のアクセストークンで測定値 API を保護する
- Dev Container だけでビルド、テスト、書き込みを行う

## 必要なもの

### ハードウェア

- ESP32 開発ボード
- SHT31-DIS 搭載の温湿度センサーモジュール
  - 秋月電子 AE-SHT3x など
- USB ケーブル
- センサー配線用のジャンパーワイヤー

### ソフトウェア

- Docker
- Dev Container CLI
- ESP-IDF provisioning に対応したクライアント
  - スマートフォンアプリ、または ESP-IDF の provisioning 用ツールを使います

ローカル環境へ ESP-IDF を直接インストールする必要はありません。ビルドや書き込みは Dev Container 内で実行します。

## 配線

| ESP32 | SHT31 |
| --- | --- |
| 3V3 | VCC |
| GND | GND |
| GPIO21 | SDA |
| GPIO22 | SCL |

このファームウェアは SHT31 の I2C アドレスを `0x45` として扱います。AE-SHT3x モジュールの ADR がオープンの状態を想定しています。

## セットアップ

### 1. リポジトリを取得する

```sh
git clone https://github.com/walnuts1018/esp32-thermohygrometer.git
cd esp32-thermohygrometer
```

### 2. Dev Container を起動する

```sh
devcontainer up --workspace-folder .
```

初回はコンテナイメージの取得と準備に時間がかかります。

### 3. ファームウェアをビルドする

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build set-target esp32"
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build build"
```

`Project build complete.` が表示されれば成功です。

### 4. ESP32 に書き込む

ESP32 を USB で接続し、コンテナ内から見えるシリアルデバイスを確認します。

```sh
devcontainer exec --workspace-folder . bash -c "ls -l /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true"
```

通常は `/dev/ttyUSB0` または `/dev/ttyACM0` です。環境に合わせて `-p` の値を変更してください。

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build -p /dev/ttyUSB0 flash monitor"
```

書き込み後、ログが流れ始めます。終了するときは `Ctrl+]` を押します。

## Wi-Fi 設定

初回起動時、または保存済み Wi-Fi に接続できない場合、ESP32 は SoftAP provisioning モードで起動します。

- サービス名: `thermohygrometer-setup`
- Proof of Possession: `thermohygrometer`

ESP-IDF provisioning 対応クライアントから上記の値を指定し、接続したい Wi-Fi の SSID とパスワードを送信してください。成功すると ESP32 は STA モードで Wi-Fi に接続します。

provisioning が成功すると、ファームウェアは Wi-Fi 情報と認証設定を NVS に保存して再起動します。再起動後、保存済み Wi-Fi へ自動接続します。

デバイスの IP アドレスは、再起動後のシリアルモニターのログ、またはルーターの DHCP クライアント一覧で確認します。

## 認証設定

測定値 API を使うには、ZITADEL のアクセストークンに次の条件が必要です。

- issuer: `https://auth.walnuts.dev`
- audience: デバイスに保存した API audience
- role: `thermohygrometer.read`

`issuer` と `role` には上記のデフォルト値があります。`audience` は環境ごとに異なるため、未設定のままだと保護 API は `503 auth_not_ready` を返します。

Wi-Fi 情報を送信する前に、provisioning の `custom-data` endpoint へ次の JSON を送ってください。

```json
{
  "audience": "thermo-api",
  "issuer": "https://auth.walnuts.dev",
  "role": "thermohygrometer.read"
}
```

`issuer` と `role` は省略できます。`audience` は必須です。custom-data は ESP-IDF provisioning の Wi-Fi credentials 送信より前に送る必要があります。

## API の使い方

以降の例では、ESP32 の IP アドレスを `DEVICE_IP`、ZITADEL から取得したアクセストークンを `ACCESS_TOKEN` とします。

### ヘルスチェック

`/healthz` は認証なしで確認できます。

```sh
curl http://DEVICE_IP/healthz
```

レスポンス例:

```json
{
  "firmware": "dev",
  "wifi_connected": true,
  "time_synced": true,
  "auth_ready": true,
  "sensor_valid": true,
  "sensor_last_error": "ESP_OK",
  "uptime_ms": 123456
}
```

`auth_ready` が `false` の場合は、ZITADEL の discovery/JWKS 取得、時刻同期、または audience 設定を確認してください。

### 最新の測定値を取得する

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://DEVICE_IP/v1/measurements/latest
```

レスポンス例:

```json
{
  "temperature_celsius": 23.42,
  "relative_humidity_percent": 48.31,
  "sensor": "sht31",
  "i2c_address": "0x45",
  "measured_at_ms": 123456
}
```

### 認証エラーを確認する

トークンを付けない場合は `401 Unauthorized` になります。

```sh
curl -i http://DEVICE_IP/v1/measurements/latest
```

audience は正しいが `thermohygrometer.read` ロールがない場合は `403 Forbidden` になります。

```sh
curl -i -H "Authorization: Bearer $TOKEN_WITHOUT_ROLE" \
  http://DEVICE_IP/v1/measurements/latest
```

### 連続リクエストを確認する

```sh
for i in $(seq 1 20); do
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    http://DEVICE_IP/v1/measurements/latest >/dev/null &
done
wait
curl -s http://DEVICE_IP/healthz
```

連続アクセス後も `/healthz` の `"sensor_valid":true` が維持されていれば、HTTP リクエストによってセンサー読み取りが詰まっていないことを確認できます。

## テスト

ユニットテスト用プロジェクトも Dev Container 内でビルドできます。

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && cd test && idf.py -B /tmp/esp32-thermohygrometer-test-build set-target esp32"
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && cd test && idf.py -B /tmp/esp32-thermohygrometer-test-build build"
```

## よくあるトラブル

### シリアルデバイスが見えない

コンテナから `/dev/ttyUSB0` や `/dev/ttyACM0` が見えない場合は、USB ケーブル、OS 側の USB シリアルドライバー、Dev Container へのデバイス公開設定を確認してください。

### Wi-Fi provisioning が始まらない

保存済み Wi-Fi 情報がある場合、ESP32 はまず STA 接続を試します。接続に失敗すると provisioning に戻ります。設定を完全に消したい場合は、NVS を消去してから再書き込みしてください。

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build -p /dev/ttyUSB0 erase-flash flash monitor"
```

### `/v1/measurements/latest` が `503` を返す

次のどれかが未完了の可能性があります。

- SHT31 からまだ有効な測定値を取得できていない
- Wi-Fi 接続または SNTP 時刻同期が終わっていない
- ZITADEL の OIDC discovery または JWKS 取得が終わっていない
- `auth_aud` が NVS に保存されていない

まず `/healthz` の `wifi_connected`、`time_synced`、`auth_ready`、`sensor_valid` を確認してください。
