# esp32-thermohygrometer

ESP-IDF firmware for an ESP32-connected SHT31 thermohygrometer.

## Build

```sh
idf.py set-target esp32
idf.py build
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
