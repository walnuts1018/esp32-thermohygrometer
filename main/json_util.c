#include "json_util.h"

#include <stdio.h>

esp_err_t json_send(httpd_req_t *req, const char *json)
{
    esp_err_t err = httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        return err;
    }

    return httpd_resp_sendstr(req, json);
}

esp_err_t json_send_error(httpd_req_t *req, int status, const char *code, const char *message)
{
    const char *status_text = "500 Internal Server Error";

    switch (status) {
    case 401:
        status_text = "401 Unauthorized";
        break;
    case 403:
        status_text = "403 Forbidden";
        break;
    case 503:
        status_text = "503 Service Unavailable";
        break;
    default:
        break;
    }

    char body[192];
    int len = snprintf(body, sizeof(body),
                       "{\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}",
                       code, message);
    if (len < 0 || len >= (int)sizeof(body)) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = httpd_resp_set_status(req, status_text);
    if (err != ESP_OK) {
        return err;
    }

    return json_send(req, body);
}
