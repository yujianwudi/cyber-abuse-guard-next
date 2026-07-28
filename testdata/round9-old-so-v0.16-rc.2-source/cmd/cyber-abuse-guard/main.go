package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static size_t cliproxy_bounded_strlen(const char* value, size_t maximum) {
	if (value == NULL) {
		return 0;
	}
	for (size_t index = 0; index < maximum; index++) {
		if (value[index] == '\0') {
			return index;
		}
	}
	return maximum;
}

// Keep a private value copy: the host-owned struct passed to init is not
// required to outlive the call. Go serializes every access to this state and
// waits for in-flight host callbacks before clearing it during shutdown.
static cliproxy_host_api stored_host_api;
static int stored_host_api_present;

static void cliproxy_store_host_api(const cliproxy_host_api* host) {
	if (host == NULL) {
		stored_host_api = (cliproxy_host_api){0};
		stored_host_api_present = 0;
		return;
	}
	stored_host_api = *host;
	stored_host_api_present = 1;
}

static void cliproxy_clear_host_api(void) {
	stored_host_api = (cliproxy_host_api){0};
	stored_host_api_present = 0;
}

static int cliproxy_call_host(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (!stored_host_api_present || stored_host_api.call == NULL) {
		return 1;
	}
	return stored_host_api.call(stored_host_api.host_ctx, method, request, request_len, response);
}

static void cliproxy_free_host_buffer(void* ptr, size_t len) {
	if (stored_host_api_present && stored_host_api.free_buffer != NULL && ptr != NULL) {
		stored_host_api.free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"sync"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	guardplugin "github.com/yujianwudi/cyber-abuse-guard/internal/plugin"
)

const (
	abiVersion            = pluginabi.ABIVersion
	maxNativeMethodBytes  = 256
	maxNativeRequestBytes = 8 << 20
)

var (
	activePlugin = guardplugin.New()

	// hostAPIMu is the native host-callback lifetime barrier. Readers keep it
	// for the complete host call and response-buffer free. Init and shutdown
	// take the write lock, so clearing the copied C API also waits for a logger
	// that was captured by Plugin.log immediately before SetLogger(nil).
	hostAPIMu sync.RWMutex
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, output *C.cliproxy_plugin_api) C.int {
	if output == nil {
		return 1
	}
	if host != nil && uint32(host.abi_version) != abiVersion {
		return 1
	}
	hostAPIMu.Lock()
	C.cliproxy_store_host_api(host)
	if host == nil {
		activePlugin.SetLogger(nil)
	} else {
		activePlugin.SetLogger(hostLogger)
	}
	hostAPIMu.Unlock()
	output.abi_version = C.uint32_t(abiVersion)
	output.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	output.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	output.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (returnCode C.int) {
	methodString := ""
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			raw, code := activePlugin.RecoverNativeCallbackPanic(methodString)
			if !writeNativeResponse(response, raw) {
				returnCode = 1
				return
			}
			returnCode = C.int(code)
		}
	}()
	if response == nil {
		return 1
	}
	if method == nil {
		raw, _ := handlePluginCall("", nil)
		if !writeNativeResponse(response, raw) {
			return 1
		}
		return 0
	}
	methodLen := int(C.cliproxy_bounded_strlen(method, C.size_t(maxNativeMethodBytes)))
	if methodLen >= maxNativeMethodBytes {
		raw := []byte(`{"ok":false,"error":{"code":"invalid_method","message":"method exceeds the size limit"}}`)
		if !writeNativeResponse(response, raw) {
			return 1
		}
		return 0
	}
	methodString = C.GoStringN(method, C.int(methodLen))
	if uint64(requestLen) > maxNativeRequestBytes {
		// Do not C.GoBytes an unbounded request. Model-route oversize handling is
		// mode-aware because returning an RPC error would make CPA continue to the
		// provider path; enforcing modes instead self-route to a local refusal.
		raw, code := handleOversizedPluginCall(methodString)
		if !writeNativeResponse(response, raw) {
			return 1
		}
		return C.int(code)
	}
	if requestLen > 0 && request == nil {
		raw := []byte(`{"ok":false,"error":{"code":"invalid_request","message":"request pointer is required"}}`)
		if !writeNativeResponse(response, raw) {
			return 1
		}
		return 0
	}

	var requestBytes []byte
	if requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, code := handlePluginCall(methodString, requestBytes)
	if !writeNativeResponse(response, raw) {
		return 1
	}
	return C.int(code)
}

//export cliproxyPluginFree
func cliproxyPluginFree(pointer unsafe.Pointer, length C.size_t) {
	if pointer != nil {
		C.free(pointer)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	// Stop new logger captures first. A goroutine that already copied the
	// logger may still be entering hostLogger, so the write lock below is the
	// in-flight barrier before the host API is cleared and may be released by
	// CPA. Policy shutdown happens only after that external callback path is
	// fully detached.
	activePlugin.SetLogger(nil)
	clearHostAPIAndWait()
	activePlugin.Shutdown()
}

func clearHostAPIAndWait() {
	hostAPIMu.Lock()
	defer hostAPIMu.Unlock()
	C.cliproxy_clear_host_api()
}

func handlePluginCall(method string, request []byte) ([]byte, int) {
	return activePlugin.Call(method, request)
}

func handleOversizedPluginCall(method string) ([]byte, int) {
	return activePlugin.CallOversized(method)
}

func hostLogger(level, message string, fields map[string]any) {
	payload, err := json.Marshal(struct {
		Level   string         `json:"level"`
		Message string         `json:"message"`
		Fields  map[string]any `json:"fields,omitempty"`
	}{Level: level, Message: message, Fields: fields})
	if err != nil {
		return
	}
	withHostAPICallback(func() {
		method := C.CString(pluginabi.MethodHostLog)
		defer C.free(unsafe.Pointer(method))
		var request *C.uint8_t
		if len(payload) != 0 {
			request = (*C.uint8_t)(C.CBytes(payload))
			if request == nil {
				return
			}
			defer C.free(unsafe.Pointer(request))
		}
		var response C.cliproxy_buffer
		if C.cliproxy_call_host(method, request, C.size_t(len(payload)), &response) == 0 && response.ptr != nil {
			C.cliproxy_free_host_buffer(response.ptr, response.len)
		}
	})
}

func withHostAPICallback(callback func()) {
	hostAPIMu.RLock()
	defer hostAPIMu.RUnlock()
	callback()
}

func writeNativeResponse(response *C.cliproxy_buffer, raw []byte) bool {
	if response == nil {
		return false
	}
	if len(raw) == 0 {
		return true
	}
	pointer := C.CBytes(raw)
	if pointer == nil {
		return false
	}
	response.ptr = pointer
	response.len = C.size_t(len(raw))
	return true
}
