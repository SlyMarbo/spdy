// Copyright 2014 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Response is used in handling responses; storing
// the data as it's received, and producing an
// http.Response once complete.
//
// Response may be given a Receiver to enable live
// handling of the response data. This is provided
// by setting spdy.Transport.Receiver.
type Response struct {
	StatusCode int

	headerM sync.Mutex
	Header  http.Header

	dataM sync.Mutex
	Data  *bytes.Buffer

	Request  *http.Request
	Receiver Receiver
}

func (r *Response) ReceiveData(req *http.Request, data []byte, finished bool) {
	r.dataM.Lock()
	r.Data.Write(data)
	r.dataM.Unlock()
	if r.Receiver != nil {
		r.Receiver.ReceiveData(req, data, finished)
	}
}

func (r *Response) ReceiveHeader(req *http.Request, header http.Header) {
	r.headerM.Lock()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	UpdateHeader(r.Header, header)
	if status := r.Header.Get(":status"); status != "" {
		status = strings.TrimSpace(status)
		if i := strings.Index(status, " "); i >= 0 {
			status = status[:i]
		}
		s, err := strconv.Atoi(status)
		if err == nil {
			r.StatusCode = s
		}
	}
	if r.Receiver != nil {
		r.Receiver.ReceiveHeader(req, header)
	}
	r.headerM.Unlock()
}

func (r *Response) ReceiveRequest(req *http.Request) bool {
	if r.Receiver != nil {
		return r.Receiver.ReceiveRequest(req)
	}
	return false
}

func (r *Response) Response() *http.Response {
	if r.Data == nil {
		r.Data = new(bytes.Buffer)
	}
	out := new(http.Response)

	r.headerM.Lock()
	out.Status = fmt.Sprintf("%d %s", r.StatusCode, http.StatusText(r.StatusCode))
	out.StatusCode = r.StatusCode
	out.Header = r.Header
	r.headerM.Unlock()

	out.Proto = "HTTP/1.1"
	out.ProtoMajor = 1
	out.ProtoMinor = 1

	r.dataM.Lock()
	out.Body = &ReadCloser{r.Data}
	out.ContentLength = int64(r.Data.Len())
	r.dataM.Unlock()

	out.TransferEncoding = nil
	out.Close = true
	out.Trailer = make(http.Header)
	out.Request = r.Request
	return out
}
