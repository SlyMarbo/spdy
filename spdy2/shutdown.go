package spdy2

import (
	"time"

	"github.com/SlyMarbo/spdy/spdy2/frames"
)

// Close ends the connection, cleaning up relevant resources.
// Close can be called multiple times safely.
func (c *Conn) Close() (err error) {
	c.shutdownOnce.Do(c.shutdown)
	return nil
}

// closed indicates whether the connection has
// been closed.
func (c *Conn) closed() bool {
	select {
	case _ = <-c.stop:
		return true
	default:
		return false
	}
}

func (c *Conn) shutdown() {
	if c.closed() {
		return
	}

	// Try to inform the other endpoint that the connection is closing.
	c.sendingLock.Lock()
	isSending := c.sending != nil
	c.sendingLock.Unlock()
	c.goawayLock.Lock()
	sent := c.goawaySent
	c.goawayReceived = true
	c.goawayLock.Unlock()
	if !sent && !isSending {
		goaway := new(frames.GOAWAY)
		if c.server != nil {
			c.lastRequestStreamIDLock.Lock()
			goaway.LastGoodStreamID = c.lastRequestStreamID
			c.lastRequestStreamIDLock.Unlock()
		} else {
			c.lastPushStreamIDLock.Lock()
			goaway.LastGoodStreamID = c.lastPushStreamID
			c.lastPushStreamIDLock.Unlock()
		}
		select {
		case c.output[0] <- goaway:
			c.goawayLock.Lock()
			c.goawaySent = true
			c.goawayLock.Unlock()
		case <-time.After(100 * time.Millisecond):
			debug.Println("Failed to send closing GOAWAY.")
		}
	}

	// Give any pending frames 200ms to send.
	c.sendingLock.Lock()
	if c.sending == nil {
		c.sending = make(chan struct{})
		c.sendingLock.Unlock()
		select {
		case <-c.sending:
		case <-time.After(200 * time.Millisecond):
		}
		c.sendingLock.Lock()
	}
	c.sending = nil
	c.sendingLock.Unlock()

	select {
	case _, ok := <-c.stop:
		if ok {
			close(c.stop)
		}
	default:
		close(c.stop)
	}

	c.connLock.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connLock.Unlock()

	c.streamsLock.Lock()
	for _, stream := range c.streams {
		if err := stream.Close(); err != nil {
			debug.Println(err)
		}
	}
	c.streams = nil
	c.streamsLock.Unlock()

	if c.compressor != nil {
		c.compressor.Close()
		c.compressor = nil
	}
	c.decompressor = nil

	c.pushedResources = nil

	for _, stream := range c.output {
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
