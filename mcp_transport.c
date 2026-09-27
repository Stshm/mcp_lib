#include "mcp_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mcp_transport_send_response(json_object *id, json_object *result) {
    json_object *response = json_object_new_object();
    json_object_object_add(response, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(response, "id", id ? json_object_get(id) : json_object_new_null());
    json_object_object_add(response, "result", result ? result : json_object_new_null());
    fputs(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN), stdout);
    fputc('\n', stdout);
    fflush(stdout);
    json_object_put(response);
}

void mcp_transport_send_error(json_object *id, int code, const char *message) {
    json_object *response = json_object_new_object();
    json_object *error = json_object_new_object();
    json_object_object_add(response, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(response, "id", id ? json_object_get(id) : json_object_new_null());
    json_object_object_add(error, "code", json_object_new_int(code));
    json_object_object_add(error, "message", json_object_new_string(message ? message : "JSON-RPC error"));
    json_object_object_add(response, "error", error);
    fputs(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN), stdout);
    fputc('\n', stdout);
    fflush(stdout);
    json_object_put(response);
}

int mcp_transport_run(mcp_request_handler handler, void *userdata) {
    if (!handler) return -1;
    char *line = NULL;
    size_t capacity = 0;
    for (;;) {
        size_t length = 0;
        int character;
        while ((character = fgetc(stdin)) != EOF) {
            if (length + 1 >= capacity) {
                size_t next = capacity ? capacity * 2 : 4096;
                if (next <= capacity) { free(line); return -1; }
                char *grown = realloc(line, next);
                if (!grown) { free(line); return -1; }
                line = grown;
                capacity = next;
            }
            line[length++] = (char)character;
            if (character == '\n') break;
        }
        if (character == EOF && length == 0) break;
        line[length] = '\0';
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        struct json_tokener *tok = json_tokener_new();
        json_object *request = json_tokener_parse_ex(tok, line, strlen(line));
        enum json_tokener_error error = json_tokener_get_error(tok);
        json_tokener_free(tok);
        if (error != json_tokener_success || !request ||
            !json_object_is_type(request, json_type_object)) {
            if (request) json_object_put(request);
            mcp_transport_send_error(NULL, -32600, "Invalid Request");
            continue;
        }
        handler(request, userdata);
        json_object_put(request);
    }
    free(line);
    return ferror(stdin) ? -1 : 0;
}
