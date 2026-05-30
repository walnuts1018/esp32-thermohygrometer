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
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py set-target esp32"
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py build"
```

## Flash

```sh
idf.py -p /dev/ttyUSB0 flash monitor
```

## Tests

```sh
cd test
idf.py set-target esp32
idf.py build
```
