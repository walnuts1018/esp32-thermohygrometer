# esp32-thermohygrometer

ESP32 と SHT31 温湿度センサーを使い、最新の温度・湿度を HTTP API で取得するための ESP-IDF ファームウェアです。

Wi-Fi 設定は ESP-IDF の SoftAP provisioning で投入します。測定値 API は ZITADEL の JWT で保護され、`/healthz` はトークンなしで確認できます。

## できること

- SHT31 から温度と湿度を定期的に読み取る
- `GET /healthz` でデバイス状態を確認する
- `GET /v1/measurements/latest` で最新の測定値を JSON で取得する
- ZITADEL のアクセストークンで測定値 API を保護する
- Dev Container でビルドとテストを行い、ホスト側から ESP32 に書き込む

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
- Python 3
- esptool
  - ESP32 への書き込みとシリアル確認に使います
- ESP-IDF provisioning に対応したクライアント
  - この README では Dev Container 内の `esp_prov.py` を使います

ローカル環境へ ESP-IDF を直接インストールする必要はありません。ビルドとテストは Dev Container 内で実行します。
USB シリアルデバイスは Dev Container から見えない場合があるため、ESP32 への書き込みとシリアル確認はホスト側で行います。

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
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B build set-target esp32"
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B build build"
```

`Project build complete.` が表示されれば成功です。書き込みに使う `build/flash_args` と各 `.bin` ファイルもこの時点で作成されます。

### 4. ESP32 に書き込む

ESP32 を USB で接続し、ホスト側から見えるシリアルデバイスを確認します。

macOS の例:

```sh
find /dev -maxdepth 1 \
  \( -name 'cu.usbserial*' -o -name 'cu.SLAB_USBtoUART*' -o -name 'cu.wchusbserial*' \) \
  -print
```

Linux の例:

```sh
find /dev -maxdepth 1 \( -name 'ttyUSB*' -o -name 'ttyACM*' \) -print
```

見つかったデバイスを `ESPPORT` に指定し、ホスト側から書き込みます。

macOS の例:

```sh
ESPPORT=/dev/cu.usbserial-0001
cd build
esptool --chip esp32 -p "$ESPPORT" -b 460800 write-flash @flash_args
cd ..
```

Linux の例:

```sh
ESPPORT=/dev/ttyUSB0
cd build
esptool --chip esp32 -p "$ESPPORT" -b 460800 write-flash @flash_args
cd ..
```

書き込み後にログを見る場合は、ホスト側でシリアルモニターを起動します。

```sh
screen "$ESPPORT" 115200
```

終了するときは `Ctrl+A` を押してから `K` を押します。

## Wi-Fi 設定

初回起動時、または保存済み Wi-Fi に接続できない場合、ESP32 は SoftAP provisioning モードで起動します。

- サービス名: `thermohygrometer-setup`
- Proof of Possession: `thermohygrometer`

ESP-IDF provisioning 対応クライアントから上記の値を指定し、接続したい Wi-Fi の SSID とパスワードを送信してください。成功すると ESP32 は STA モードで Wi-Fi に接続します。

provisioning が成功すると、ファームウェアは Wi-Fi 情報と認証設定を NVS に保存して再起動します。再起動後、保存済み Wi-Fi へ自動接続します。

デバイスの IP アドレスは、再起動後のシリアルモニターのログ、またはルーターの DHCP クライアント一覧で確認します。

### コマンドで provisioning する

まず通常のインターネット接続がある状態で、Dev Container 内の provisioning tool が動くことを確認します。Dev Container の初回作成時に必要な Python パッケージは入りますが、既存の Dev Container を使っている場合は次のコマンドを一度だけ実行してください。

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && python -m pip install protobuf cryptography"
```

`esp_prov.py --help` が表示できれば準備完了です。

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && python managed_components/espressif__network_provisioning/tool/esp_prov/esp_prov.py --help"
```

次に、PC の Wi-Fi 接続先を `thermohygrometer-setup` に切り替えます。接続後、ESP32 は通常 `192.168.4.1` で provisioning API を待ち受けます。

別のターミナルで Dev Container 内に入り、`esp_prov.py` を実行します。`YOUR_WIFI_SSID` と `YOUR_WIFI_PASSWORD` は、ESP32 を接続したい Wi-Fi の値に置き換えてください。

```sh
devcontainer exec --workspace-folder . bash
```

Dev Container 内で次を実行します。

```sh
. /opt/esp/idf/export.sh

python managed_components/espressif__network_provisioning/tool/esp_prov/esp_prov.py \
  --transport softap \
  --service_name 192.168.4.1:80 \
  --sec_ver 1 \
  --pop thermohygrometer \
  --custom_data '{"audience":"thermo-api","issuer":"https://auth.walnuts.dev","role":"thermohygrometer.read"}' \
  --ssid 'YOUR_WIFI_SSID' \
  --passphrase 'YOUR_WIFI_PASSWORD'
```

成功すると、シリアルモニターに provisioning 完了と再起動のログが表示されます。再起動後に次のログが出れば Wi-Fi 情報と認証設定の保存は完了です。

```text
config loaded: wifi=set auth_audience=set
```

その後、PC の Wi-Fi 接続先を元のネットワークへ戻し、ESP32 の IP アドレスに対して `/healthz` を確認します。

```sh
curl http://DEVICE_IP/healthz
```

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

### ホスト側でシリアルデバイスが見えない

Dev Container ではなく、ホスト側でシリアルデバイスを確認してください。macOS では `/dev/cu.usbserial*` や `/dev/cu.SLAB_USBtoUART*`、Linux では `/dev/ttyUSB*` や `/dev/ttyACM*` として見えることが多いです。

ホスト側にも表示されない場合は、USB ケーブル、ESP32 ボードの USB シリアルドライバー、OS のデバイスアクセス権限を確認してください。
macOS ではボードによって `/dev/cu.wchusbserial*` として見えることもあります。

### Wi-Fi provisioning が始まらない

保存済み Wi-Fi 情報がある場合、ESP32 はまず STA 接続を試します。接続に失敗すると provisioning に戻ります。設定を完全に消したい場合は、NVS を消去してから再書き込みしてください。

```sh
ESPPORT=/dev/cu.usbserial-0001
esptool --chip esp32 -p "$ESPPORT" erase-flash
cd build
esptool --chip esp32 -p "$ESPPORT" -b 460800 write-flash @flash_args
cd ..
```

### `/v1/measurements/latest` が `503` を返す

次のどれかが未完了の可能性があります。

- SHT31 からまだ有効な測定値を取得できていない
- Wi-Fi 接続または SNTP 時刻同期が終わっていない
- ZITADEL の OIDC discovery または JWKS 取得が終わっていない
- `auth_aud` が NVS に保存されていない

まず `/healthz` の `wifi_connected`、`time_synced`、`auth_ready`、`sensor_valid` を確認してください。
