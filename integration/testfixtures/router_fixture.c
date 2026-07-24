#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define CLIPROXY_EXPORT __declspec(dllexport)
#else
#define CLIPROXY_EXPORT __attribute__((visibility("default")))
#endif

#define ABI_VERSION 1

typedef struct {
    void *ptr;
    size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void *, const char *, const uint8_t *, size_t, cliproxy_buffer *);
typedef void (*cliproxy_host_free_fn)(void *, size_t);

typedef struct {
    uint32_t abi_version;
    void *host_ctx;
    cliproxy_host_call_fn call;
    cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(const char *, const uint8_t *, size_t, cliproxy_buffer *);
typedef void (*cliproxy_plugin_free_fn)(void *, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
    uint32_t abi_version;
    cliproxy_plugin_call_fn call;
    cliproxy_plugin_free_fn free_buffer;
    cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

typedef enum {
    FIXTURE_READY = 0,
    FIXTURE_ROUTE_ERROR,
    FIXTURE_INVALID_TARGET,
    FIXTURE_EMPTY_IDENTIFIER,
    FIXTURE_NO_FORMATS,
    FIXTURE_ROUTER_ONLY,
    FIXTURE_OAUTH_SCOPE,
    FIXTURE_UNHANDLED,
    FIXTURE_REGISTER_ERROR
} fixture_mode;

static atomic_int active_mode = FIXTURE_READY;

static const char *READY_REGISTRATION =
    "{\"ok\":true,\"result\":{\"schema_version\":1,"
    "\"metadata\":{\"Name\":\"CPA Router Fixture\",\"Version\":\"0.0.1\","
    "\"Author\":\"Cyber Abuse Guard Test Suite\","
    "\"GitHubRepository\":\"https://github.com/yujianwudi/cyber-abuse-guard-next\"},"
    "\"capabilities\":{\"model_router\":true,\"executor\":true,"
    "\"executor_model_scope\":\"static\","
    "\"executor_input_formats\":[\"openai\"],"
    "\"executor_output_formats\":[\"openai\"]}}}";

static const char *NO_FORMATS_REGISTRATION =
    "{\"ok\":true,\"result\":{\"schema_version\":1,"
    "\"metadata\":{\"Name\":\"CPA Router Fixture\",\"Version\":\"0.0.1\","
    "\"Author\":\"Cyber Abuse Guard Test Suite\","
    "\"GitHubRepository\":\"https://github.com/yujianwudi/cyber-abuse-guard-next\"},"
    "\"capabilities\":{\"model_router\":true,\"executor\":true,"
    "\"executor_model_scope\":\"static\","
    "\"executor_input_formats\":[],\"executor_output_formats\":[]}}}";

static const char *ROUTER_ONLY_REGISTRATION =
    "{\"ok\":true,\"result\":{\"schema_version\":1,"
    "\"metadata\":{\"Name\":\"CPA Router Fixture\",\"Version\":\"0.0.1\","
    "\"Author\":\"Cyber Abuse Guard Test Suite\","
    "\"GitHubRepository\":\"https://github.com/yujianwudi/cyber-abuse-guard-next\"},"
    "\"capabilities\":{\"model_router\":true,\"executor\":false}}}";

static const char *OAUTH_SCOPE_REGISTRATION =
    "{\"ok\":true,\"result\":{\"schema_version\":1,"
    "\"metadata\":{\"Name\":\"CPA Router Fixture\",\"Version\":\"0.0.1\","
    "\"Author\":\"Cyber Abuse Guard Test Suite\","
    "\"GitHubRepository\":\"https://github.com/yujianwudi/cyber-abuse-guard-next\"},"
    "\"capabilities\":{\"model_router\":true,\"executor\":true,"
    "\"executor_model_scope\":\"oauth\","
    "\"executor_input_formats\":[\"openai\"],"
    "\"executor_output_formats\":[\"openai\"]}}}";

static const char *REGISTER_ERROR =
    "{\"ok\":false,\"error\":{\"code\":\"fixture_register_error\","
    "\"message\":\"router fixture registration failed\"}}";

static const char *ROUTE_READY =
    "{\"ok\":true,\"result\":{\"Handled\":true,\"TargetKind\":\"self\","
    "\"Target\":\"\",\"Reason\":\"fixture handled request\"}}";

static const char *ROUTE_UNHANDLED =
    "{\"ok\":true,\"result\":{\"Handled\":false,\"Reason\":\"fixture declined request\"}}";

static const char *ROUTE_ERROR =
    "{\"ok\":false,\"error\":{\"code\":\"fixture_route_error\","
    "\"message\":\"router fixture route error\"}}";

static const char *ROUTE_INVALID_TARGET =
    "{\"ok\":true,\"result\":{\"Handled\":true,\"TargetKind\":\"invalid\","
    "\"Target\":\"fixture-invalid-target\",\"Reason\":\"fixture invalid target\"}}";

static const char *IDENTIFIER_READY =
    "{\"ok\":true,\"result\":{\"identifier\":\"fixture-provider\"}}";
static const char *IDENTIFIER_EMPTY =
    "{\"ok\":true,\"result\":{\"identifier\":\"\"}}";

static const char *EXECUTE_RESPONSE =
    "{\"ok\":true,\"result\":{\"Payload\":"
    "\"eyJpZCI6ImZpeHR1cmUiLCJvYmplY3QiOiJjaGF0LmNvbXBsZXRpb24iLCJjcmVhdGVkIjoxLCJtb2RlbCI6ImludGVncmF0aW9uLW1vZGVsIiwiY2hvaWNlcyI6W3siaW5kZXgiOjAsIm1lc3NhZ2UiOnsicm9sZSI6ImFzc2lzdGFudCIsImNvbnRlbnQiOiJmaXh0dXJlLXJvdXRlci1oYW5kbGVkIn0sImZpbmlzaF9yZWFzb24iOiJzdG9wIn1dLCJ1c2FnZSI6eyJwcm9tcHRfdG9rZW5zIjowLCJjb21wbGV0aW9uX3Rva2VucyI6MCwidG90YWxfdG9rZW5zIjowfX0=\","
    "\"Headers\":{\"content-type\":[\"application/json\"]}}}";

static const char *STREAM_RESPONSE =
    "{\"ok\":true,\"result\":{\"headers\":{\"content-type\":[\"text/event-stream\"]},"
    "\"chunks\":[{\"Payload\":\"ZGF0YToge1wiZml4dHVyZVwiOnRydWV9XG5cbg==\"}]}}";

static const char *COUNT_TOKENS_RESPONSE =
    "{\"ok\":true,\"result\":{\"Payload\":\"eyJ0b3RhbF90b2tlbnMiOjB9\","
    "\"Headers\":{\"content-type\":[\"application/json\"]}}}";

static const char *HTTP_REQUEST_RESPONSE =
    "{\"ok\":false,\"error\":{\"code\":\"method_not_allowed\","
    "\"message\":\"router fixture HTTP bridge is disabled\",\"http_status\":405}}";

static const char *OK_EMPTY = "{\"ok\":true,\"result\":{}}";
static const char *UNKNOWN_METHOD =
    "{\"ok\":false,\"error\":{\"code\":\"unknown_method\",\"message\":\"unknown method\"}}";

static fixture_mode read_mode(void) {
    const char *value = getenv("CPA_ROUTER_FIXTURE_MODE");
    if (value == NULL || strcmp(value, "ready") == 0) {
        return FIXTURE_READY;
    }
    if (strcmp(value, "route_error") == 0) {
        return FIXTURE_ROUTE_ERROR;
    }
    if (strcmp(value, "invalid_target") == 0) {
        return FIXTURE_INVALID_TARGET;
    }
    if (strcmp(value, "empty_identifier") == 0) {
        return FIXTURE_EMPTY_IDENTIFIER;
    }
    if (strcmp(value, "no_formats") == 0) {
        return FIXTURE_NO_FORMATS;
    }
    if (strcmp(value, "router_only") == 0) {
        return FIXTURE_ROUTER_ONLY;
    }
    if (strcmp(value, "oauth_scope") == 0) {
        return FIXTURE_OAUTH_SCOPE;
    }
    if (strcmp(value, "unhandled") == 0) {
        return FIXTURE_UNHANDLED;
    }
    if (strcmp(value, "register_error") == 0) {
        return FIXTURE_REGISTER_ERROR;
    }
    return FIXTURE_REGISTER_ERROR;
}

static int write_response(const char *payload, cliproxy_buffer *response) {
    size_t length;
    void *copy;
    if (response == NULL || payload == NULL) {
        return 1;
    }
    response->ptr = NULL;
    response->len = 0;
    length = strlen(payload);
    if (length == 0) {
        return 0;
    }
    copy = malloc(length);
    if (copy == NULL) {
        return 1;
    }
    memcpy(copy, payload, length);
    response->ptr = copy;
    response->len = length;
    return 0;
}

static const char *registration_response(fixture_mode mode) {
    switch (mode) {
        case FIXTURE_NO_FORMATS:
            return NO_FORMATS_REGISTRATION;
        case FIXTURE_ROUTER_ONLY:
            return ROUTER_ONLY_REGISTRATION;
        case FIXTURE_OAUTH_SCOPE:
            return OAUTH_SCOPE_REGISTRATION;
        case FIXTURE_REGISTER_ERROR:
            return REGISTER_ERROR;
        default:
            return READY_REGISTRATION;
    }
}

static const char *route_response(fixture_mode mode) {
    switch (mode) {
        case FIXTURE_ROUTE_ERROR:
            return ROUTE_ERROR;
        case FIXTURE_INVALID_TARGET:
            return ROUTE_INVALID_TARGET;
        case FIXTURE_UNHANDLED:
            return ROUTE_UNHANDLED;
        default:
            return ROUTE_READY;
    }
}

static int plugin_call(const char *method, const uint8_t *request, size_t request_len, cliproxy_buffer *response) {
    fixture_mode mode;
    (void)request;
    (void)request_len;
    if (method == NULL) {
        return write_response(UNKNOWN_METHOD, response);
    }
    if (strcmp(method, "plugin.register") == 0 || strcmp(method, "plugin.reconfigure") == 0) {
        mode = read_mode();
        atomic_store_explicit(&active_mode, mode, memory_order_release);
        return write_response(registration_response(mode), response);
    }
    mode = (fixture_mode)atomic_load_explicit(&active_mode, memory_order_acquire);
    if (strcmp(method, "model.route") == 0) {
        return write_response(route_response(mode), response);
    }
    if (strcmp(method, "executor.identifier") == 0) {
        return write_response(mode == FIXTURE_EMPTY_IDENTIFIER ? IDENTIFIER_EMPTY : IDENTIFIER_READY, response);
    }
    if (strcmp(method, "executor.execute") == 0) {
        return write_response(EXECUTE_RESPONSE, response);
    }
    if (strcmp(method, "executor.execute_stream") == 0) {
        return write_response(STREAM_RESPONSE, response);
    }
    if (strcmp(method, "executor.count_tokens") == 0) {
        return write_response(COUNT_TOKENS_RESPONSE, response);
    }
    if (strcmp(method, "executor.http_request") == 0) {
        return write_response(HTTP_REQUEST_RESPONSE, response);
    }
    if (strcmp(method, "plugin.shutdown") == 0) {
        return write_response(OK_EMPTY, response);
    }
    return write_response(UNKNOWN_METHOD, response);
}

static void plugin_free(void *pointer, size_t length) {
    (void)length;
    free(pointer);
}

static void plugin_shutdown(void) {
    atomic_store_explicit(&active_mode, FIXTURE_READY, memory_order_release);
}

CLIPROXY_EXPORT int cliproxy_plugin_init(const cliproxy_host_api *host, cliproxy_plugin_api *output) {
    if (output == NULL || (host != NULL && host->abi_version != ABI_VERSION)) {
        return 1;
    }
    output->abi_version = ABI_VERSION;
    output->call = plugin_call;
    output->free_buffer = plugin_free;
    output->shutdown = plugin_shutdown;
    return 0;
}
