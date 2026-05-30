#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

esp_err_t json_send(httpd_req_t *req, const char *json);
esp_err_t json_send_error(httpd_req_t *req, int status, const char *code, const char *message);
