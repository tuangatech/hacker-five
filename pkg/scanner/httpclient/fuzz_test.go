package httpclient

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
)

// FuzzResponseParsing exercises response parsing with malformed/edge-case
// inputs. The scanner parses untrusted target responses, which is its own
// attack surface, not just the target's.
func FuzzResponseParsing(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("not an http response"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\nshort"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzzz\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)
	})
}
