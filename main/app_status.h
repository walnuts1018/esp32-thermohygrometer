#pragma once

#include <stdbool.h>

typedef struct {
    bool wifi_connected;
    bool time_synced;
    bool auth_ready;
} app_status_t;

void app_status_set_wifi_connected(bool connected);
void app_status_set_time_synced(bool synced);
void app_status_set_auth_ready(bool ready);
app_status_t app_status_get(void);
