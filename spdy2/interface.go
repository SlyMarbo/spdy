package spdy2

import (
	"time"

	"github.com/SlyMarbo/spdy/spdy2/frames"
)

// Close ends the connection, cleaning up relevant resources.
// Close can be called multiple times safely.
func (conn *Conn) Close() (err error) {
	conn.shutdownOnce.Do(conn.shutdown)
	return nil
}

func (conn *Conn) shutdown() {
	if conn.closed() {
		return
	}

	// Try to inform the other endpoint that the connection is closing.
	conn.sendingLock.Lock()
	isSending := conn.sending != nil
	conn.sendingLock.Unlock()
	if !conn.goawaySent && !isSending {
		goaway := new(frames.GOAWAY)
		if conn.server != nil {
			goaway.LastGoodStreamID = conn.lastRequestStreamID
		} else {
			goaway.LastGoodStreamID = conn.lastPushStreamID
		}
		select {
		case conn.output[0] <- goaway:
			conn.goawaySent = true
		case <-time.After(100 * time.Millisecond):
			debug.Println("Failed to send closing GOAWAY.")
		}
	}

	// Give any pending frames 200ms to send.
	conn.sendingLock.Lock()
	if conn.sending == nil {
		conn.sending = make(chan struct{})
		conn.sendingLock.Unlock()
		select {
		case <-conn.sending:
		case <-time.After(200 * time.Millisecond):
		}
		conn.sendingLock.Lock()
	}
	conn.sending = nil
	conn.sendingLock.Unlock()

	select {
	case _, ok := <-conn.stop:
		if ok {
			close(conn.stop)
		}
	default:
		close(conn.stop)
	}

	conn.connLock.Lock()
	if conn.conn != nil {
		conn.conn.Close()
		conn.conn = nil
	}
	conn.connLock.Unlock()

	for _, stream := range conn.streams {
		if err := stream.Close(); err != nil {
			debug.Println(err)
		}
	}
	conn.streams = nil

	if conn.compressor != nil {
		conn.compressor.Close()
		conn.compressor = nil
	}
	conn.decompressor = nil

	conn.pushedResources = nil

	for _, stream := range conn.output {
		select {
		case _, ok := <-stream:
			if ok {
				close(stream)
			}
		default:
			close(stream)
		}
	}
}

func (c *Conn) SetReadTimeout(d time.Duration) {
	c.timeoutLock.Lock()
	c.readTimeout = d
	c.timeoutLock.Unlock()
}

func (c *Conn) SetWriteTimeout(d time.Duration) {
	c.timeoutLock.Lock()
	c.writeTimeout = d
	c.timeoutLock.Unlock()
}

func (c *Conn) refreshReadTimeout() {
	c.timeoutLock.Lock()
	if d := c.readTimeout; d != 0 && c.conn != nil {
		c.conn.SetReadDeadline(time.Now().Add(d))
	}
	c.timeoutLock.Unlock()
}

func (c *Conn) refreshWriteTimeout() {
	c.timeoutLock.Lock()
	if d := c.writeTimeout; d != 0 && c.conn != nil {
		c.conn.SetWriteDeadline(time.Now().Add(d))
	}
	c.timeoutLock.Unlock()
}
