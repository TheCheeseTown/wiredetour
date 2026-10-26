// Command bridge is built with -buildmode=c-archive and exposes the Go core
// to the Swift packet tunnel through the functions in include/wiredetour.h.
package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef void (*wd_log_fn)(void *context, int32_t level, const char *message);
typedef int32_t (*wd_route_fn)(void *context, const char *routes_json);

static void callLog(wd_log_fn fn, void *ctx, int32_t level, const char *msg) { fn(ctx, level, msg); }
static int32_t callRoute(wd_route_fn fn, void *ctx, const char *json) { return fn(ctx, json); }
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"wiredetour/core/engine"
)

const version = "0.1.0"

var (
	logMu  sync.Mutex
	logFn  C.wd_log_fn
	logCtx unsafe.Pointer

	handlesMu sync.Mutex
	handles   = map[int32]*tunnel{}
	nextID    int32
)

type tunnel struct {
	dev *device.Device
	eng *engine.Engine
}

func logf(level int32, format string, args ...any) {
	logMu.Lock()
	fn, ctx := logFn, logCtx
	logMu.Unlock()
	if fn == nil {
		return
	}
	msg := C.CString(fmt.Sprintf(format, args...))
	C.callLog(fn, ctx, C.int32_t(level), msg)
	C.free(unsafe.Pointer(msg))
}

//export wdSetLogger
func wdSetLogger(ctx unsafe.Pointer, fn C.wd_log_fn) {
	logMu.Lock()
	logFn, logCtx = fn, ctx
	logMu.Unlock()
}

//export wdTurnOn
func wdTurnOn(uapi *C.char, engineJSON *C.char, tunFd C.int32_t, routeCtx unsafe.Pointer, routeFn C.wd_route_fn) C.int32_t {
	var cfg engine.Config
	if err := json.Unmarshal([]byte(C.GoString(engineJSON)), &cfg); err != nil {
		logf(1, "invalid engine config: %v", err)
		return -1
	}

	dupFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logf(1, "dup tun fd: %v", err)
		return -2
	}
	if err := unix.SetNonblock(dupFd, true); err != nil {
		unix.Close(dupFd)
		logf(1, "set nonblock: %v", err)
		return -2
	}
	tunDev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupFd), "/dev/tun"), 0)
	if err != nil {
		unix.Close(dupFd)
		logf(1, "create tun: %v", err)
		return -3
	}

	apply := func(set []netip.Prefix) error {
		strs := make([]string, len(set))
		for i, p := range set {
			strs[i] = p.String()
		}
		js, _ := json.Marshal(strs)
		cjs := C.CString(string(js))
		defer C.free(unsafe.Pointer(cjs))
		if rc := C.callRoute(routeFn, routeCtx, cjs); rc != 0 {
			return fmt.Errorf("route update failed (%d)", int32(rc))
		}
		return nil
	}
	eng := engine.New(cfg, apply, func(f string, a ...any) { logf(0, "engine: "+f, a...) })

	logger := &device.Logger{
		Verbosef: func(f string, a ...any) { logf(0, f, a...) },
		Errorf:   func(f string, a ...any) { logf(1, f, a...) },
	}
	dev := device.NewDevice(eng.Wrap(tunDev), conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(C.GoString(uapi)); err != nil {
		logf(1, "configure device: %v", err)
		dev.Close()
		return -4
	}
	if err := dev.Up(); err != nil {
		logf(1, "device up: %v", err)
		dev.Close()
		return -5
	}

	handlesMu.Lock()
	defer handlesMu.Unlock()
	for {
		nextID++
		if nextID <= 0 {
			nextID = 1
		}
		if _, used := handles[nextID]; !used {
			break
		}
	}
	handles[nextID] = &tunnel{dev: dev, eng: eng}
	logf(0, "tunnel %d up (core %s)", nextID, version)
	return C.int32_t(nextID)
}

func lookup(h C.int32_t) *tunnel {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	return handles[int32(h)]
}

//export wdTurnOff
func wdTurnOff(h C.int32_t) {
	handlesMu.Lock()
	t := handles[int32(h)]
	delete(handles, int32(h))
	handlesMu.Unlock()
	if t != nil {
		t.dev.Close() // closes the wrapped tun, which closes the engine
		t.eng.Close()
	}
}

type wgStats struct {
	LastHandshakeSecAgo *int   `json:"lastHandshakeSecAgo"`
	RxBytes             uint64 `json:"rxBytes"`
	TxBytes             uint64 `json:"txBytes"`
}

func readWGStats(dev *device.Device) wgStats {
	var s wgStats
	text, err := dev.IpcGet()
	if err != nil {
		return s
	}
	var latest int64
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "rx_bytes":
			s.RxBytes += n
		case "tx_bytes":
			s.TxBytes += n
		case "last_handshake_time_sec":
			if n <= math.MaxInt64 && int64(n) > latest {
				latest = int64(n)
			}
		}
	}
	if latest > 0 {
		ago := int(time.Since(time.Unix(latest, 0)).Seconds())
		s.LastHandshakeSecAgo = &ago
	}
	return s
}

//export wdGetStatus
func wdGetStatus(h C.int32_t) *C.char {
	t := lookup(h)
	if t == nil {
		return nil
	}
	js, _ := json.Marshal(struct {
		WireGuard wgStats       `json:"wireguard"`
		Engine    engine.Status `json:"engine"`
	}{readWGStats(t.dev), t.eng.Status()})
	return C.CString(string(js))
}

//export wdTestDomain
func wdTestDomain(h C.int32_t, domain *C.char) *C.char {
	t := lookup(h)
	if t == nil {
		return nil
	}
	js, _ := json.Marshal(t.eng.TestDomain(C.GoString(domain)))
	return C.CString(string(js))
}

//export wdBumpSockets
func wdBumpSockets(h C.int32_t) {
	t := lookup(h)
	if t == nil {
		return
	}
	go func() {
		// Rebind after a network change; retry briefly while the new path settles.
		for i := 0; i < 10; i++ {
			if err := t.dev.BindUpdate(); err == nil {
				t.dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			time.Sleep(time.Second / 2)
		}
		logf(1, "unable to rebind sockets after network change")
	}()
}

var versionCString = C.CString(version)

//export wdVersion
func wdVersion() *C.char { return versionCString }

func main() {}
