// C interface of the wireDetour Go core (core/bridge). Strings returned by
// wdGetStatus / wdTestDomain are heap-allocated and must be released with free().
#ifndef WIREDETOUR_H
#define WIREDETOUR_H

#include <stdint.h>

typedef void (*wd_log_fn)(void *context, int32_t level, const char *message);

// Installs the complete set of dynamic routes (JSON array of CIDR strings).
// Must block until the OS has applied them; returns 0 on success.
typedef int32_t (*wd_route_fn)(void *context, const char *routes_json);

extern void wdSetLogger(void *context, wd_log_fn fn);

// Starts WireGuard + the engine on the given utun file descriptor.
// Returns a handle > 0, or a negative error code.
extern int32_t wdTurnOn(const char *uapi_config, const char *engine_json, int32_t tun_fd,
                        void *route_context, wd_route_fn route_fn);
extern void wdTurnOff(int32_t handle);
extern char *wdGetStatus(int32_t handle);
extern char *wdTestDomain(int32_t handle, const char *domain);
extern void wdBumpSockets(int32_t handle);
extern const char *wdVersion(void);

#endif
