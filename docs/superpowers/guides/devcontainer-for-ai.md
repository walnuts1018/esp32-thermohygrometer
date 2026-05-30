# AI Agent DevContainer Guide

このガイドは、AIエージェント（Antigravity等）が `esp32-thermohygrometer` リポジトリで開発およびテストを行うための手順とルールを定義しています。

## 基本ルール

このプロジェクトでは、ESP-IDF等のツールチェーンへの依存を避けるため、**VS Code Dev Container** を開発環境の標準として採用しています。
AIエージェントは、ホストマシン（実行環境）に直接ツールをインストールしたり、直接ビルドコマンドを実行したり**してはいけません**。代わりに、`@devcontainers/cli` を用いて、Dev Container内で全てのコマンドを実行してください。

### 前提条件
- 実行環境には `@devcontainers/cli` (`devcontainer` コマンド) がインストールされていること。

## ワークフロー

### 1. 環境の立ち上げ
開発やビルドを始める前に、まず以下のコマンドを実行してコンテナを起動（またはビルド）します。
すでに起動している場合でも安全に実行できます。

```sh
devcontainer up --workspace-folder .
```

### 2. コマンドの実行
コンテナが起動したら、`devcontainer exec` を用いてコマンドを実行します。
コンテナイメージ (`espressif/idf:latest`) に含まれる ESP-IDF 環境変数を正しく読み込ませるため、コマンドは必ず `bash -c ". /opt/esp/idf/export.sh && ..."` の形式でラップしてください。

#### ビルドの例
```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py build"
```

#### テストビルドの例
```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && cd test && idf.py build"
```
※ ディレクトリ移動が必要な場合は、上記のように `bash -c` を用いてください。

### 3. 注意事項
- **対話型プロンプトの回避:** コマンドは常に非対話的に実行されるようにフラグを調整してください（AIエージェント向けの基本事項）。
- **ファイルの編集:** ソースコードなどのファイルの編集はホスト側のファイルシステム（マウントされたプロジェクトディレクトリ）に対して直接行います。コンテナ内にコピーする必要はありません。
- **Git 操作:** バージョン管理（Git）もホスト環境で実行してください。コンテナ内でGitを実行する必要はありません。
