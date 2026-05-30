---
name: devcontainer
description: Use when building, testing, flashing, or running ESP-IDF commands in this repository so commands run inside the VS Code Dev Container.
---

# Dev Container

Use the repository Dev Container for ESP-IDF build, test, flash, and monitor commands. Do not install ESP-IDF tools on the host or run `idf.py` directly on the host.

## Workflow

Start or reuse the container:

```sh
devcontainer up --workspace-folder .
```

Run ESP-IDF commands through `devcontainer exec`, always loading the ESP-IDF environment first:

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build build"
```

Test project build:

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && cd test && idf.py -B /tmp/esp32-thermohygrometer-test-build build"
```

Flash/monitor, when a device is available to the container:

```sh
devcontainer exec --workspace-folder . bash -c ". /opt/esp/idf/export.sh && idf.py -B /tmp/esp32-thermohygrometer-build -p /dev/ttyUSB0 flash monitor"
```

## Rules

- Edit files on the host workspace; the project directory is mounted into the container.
- Run Git commands on the host, not inside the container.
- Keep commands non-interactive where possible.
- Prefer explicit `/tmp/...` build directories so host-path CMake caches in `build/` do not break container builds.
- If `devcontainer` is missing or device access is unavailable, report that blocker instead of falling back to host ESP-IDF commands.
