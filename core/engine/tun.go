package engine

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// interceptTUN wraps the OS tun device. wireguard-go reads outbound packets
// from it and writes inbound packets to it; the engine taps both directions
// and can inject packets of its own (upstream DNS queries).
type interceptTUN struct {
	inner tun.Device
	e     *Engine

	out     chan outPkt // OS packets, already filtered, waiting for wireguard
	readErr chan error
	pool    sync.Pool

	writeMu sync.Mutex
}

var _ tun.Device = (*interceptTUN)(nil)

// tunHeadroom is the offset reads and engine writes use; the darwin tun
// device needs 4 bytes in front of each packet for its address-family header.
const tunHeadroom = 16

type outPkt struct {
	buf *[]byte
	n   int
}

// Wrap returns a tun.Device for wireguard-go that routes traffic through the
// engine. The engine owns the reader goroutine of inner from this point.
func (e *Engine) Wrap(inner tun.Device) tun.Device {
	t := &interceptTUN{
		inner:   inner,
		e:       e,
		out:     make(chan outPkt, 256),
		readErr: make(chan error, 1),
	}
	t.pool.New = func() any {
		b := make([]byte, 65535)
		return &b
	}
	e.setOSWriter(t.writeToOS)
	go t.readLoop()
	return t
}

func (e *Engine) setOSWriter(w func([]byte)) { e.writer.Store(&w) }

func (e *Engine) osWriter() func([]byte) {
	if w := e.writer.Load(); w != nil {
		return *w
	}
	return nil
}

func (t *interceptTUN) readLoop() {
	batch := t.inner.BatchSize()
	bufs := make([][]byte, batch)
	held := make([]*[]byte, batch)
	sizes := make([]int, batch)
	for {
		for i := range bufs {
			if held[i] == nil {
				held[i] = t.pool.Get().(*[]byte)
			}
			bufs[i] = *held[i]
		}
		n, err := t.inner.Read(bufs, sizes, tunHeadroom)
		for i := 0; i < n; i++ {
			pkt := bufs[i][tunHeadroom : tunHeadroom+sizes[i]]
			if t.e.handleOutbound(pkt) {
				continue
			}
			p := outPkt{held[i], sizes[i]}
			held[i] = nil
			select {
			case t.out <- p:
			case <-t.e.closed:
				return
			}
		}
		if err != nil {
			select {
			case t.readErr <- err:
			default:
			}
			return
		}
	}
}

func (t *interceptTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	put := func(pkt []byte) {
		sizes[n] = copy(bufs[n][offset:], pkt)
		n++
	}
	// Block for the first packet, from either source.
	select {
	case p := <-t.out:
		put((*p.buf)[tunHeadroom : tunHeadroom+p.n])
		t.pool.Put(p.buf)
	case pkt := <-t.e.inject:
		put(pkt)
	case err := <-t.readErr:
		return 0, err
	case <-t.e.closed:
		return 0, os.ErrClosed
	}
	// Then drain whatever else is ready without blocking.
	for n < len(bufs) {
		select {
		case p := <-t.out:
			put((*p.buf)[tunHeadroom : tunHeadroom+p.n])
			t.pool.Put(p.buf)
		case pkt := <-t.e.inject:
			put(pkt)
		default:
			return n, nil
		}
	}
	return n, nil
}

func (t *interceptTUN) Write(bufs [][]byte, offset int) (int, error) {
	keep := bufs[:0:0]
	for _, b := range bufs {
		if t.e.handleInbound(b[offset:]) {
			continue
		}
		keep = append(keep, b)
	}
	if len(keep) > 0 {
		t.writeMu.Lock()
		_, err := t.inner.Write(keep, offset)
		t.writeMu.Unlock()
		if err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// writeToOS writes a packet produced by the engine (a DNS answer) to the OS.
func (t *interceptTUN) writeToOS(pkt []byte) {
	buf := make([]byte, tunHeadroom+len(pkt))
	copy(buf[tunHeadroom:], pkt)
	t.writeMu.Lock()
	_, err := t.inner.Write([][]byte{buf}, tunHeadroom)
	t.writeMu.Unlock()
	if err != nil {
		t.e.logf("write DNS answer: %v", err)
	}
}

func (t *interceptTUN) File() *os.File           { return t.inner.File() }
func (t *interceptTUN) MTU() (int, error)        { return t.inner.MTU() }
func (t *interceptTUN) Name() (string, error)    { return t.inner.Name() }
func (t *interceptTUN) Events() <-chan tun.Event { return t.inner.Events() }
func (t *interceptTUN) BatchSize() int           { return t.inner.BatchSize() }

func (t *interceptTUN) Close() error {
	t.e.Close()
	return t.inner.Close()
}
