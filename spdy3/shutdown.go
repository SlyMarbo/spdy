package spdy3

import (
	"time"

	"github.com/SlyMarbo/spdy/spdy3/frames"
)

// Close ends the connection, cleaning up relevant resources.
// Close can be called multiple times safely.
func (c *Conn) Close() (err error) {
	c.shutdownOnce.Do(c.shutdown)
	return nil
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

	// Ensure any pending frames are sent.
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

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.streamsLock.Lock()
	for _, stream := range c.streams {
		stream.Close()
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
