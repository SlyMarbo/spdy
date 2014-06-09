package spdy3

import (
	"time"
)

func (c *Conn) CloseNotify() <-chan bool {
	return c.stop
}

// InitialWindowSize gives the most recently-received value for
// the INITIAL_WINDOW_SIZE setting.
func (c *Conn) InitialWindowSize() (uint32, error) {
	c.initialWindowSizeLock.Lock()
	i := c.initialWindowSize
	c.initialWindowSizeLock.Unlock()
	return i, nil
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
