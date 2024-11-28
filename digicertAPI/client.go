// Copyright (c) HashiCorp, Inc.

package digicertapi

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	ApiKey     string
	ApiKeyName string
	client     *http.Client
}

type rateLimitedTransport struct {
	delegate http.RoundTripper
	throttle time.Time
	sync.Mutex
}

const (
	headerAccept        = "Accept"
	headerAuthorization = "Authorization"
	headerContent       = "Content-Type"
	headerDeviceKey     = "X-DC-DEVKEY"
	mediaTypeJSON       = "application/json"
	rateLimit           = 1 * time.Second
)

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.Lock()
	defer t.Unlock()

	if t.throttle.After(time.Now()) {
		delta := time.Until(t.throttle)
		time.Sleep(delta)
	}

	t.throttle = time.Now().Add(rateLimit)
	return t.delegate.RoundTrip(req)
}

func NewClient(apiKey string) (*Client, error) {

	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &Client{
		ApiKey: apiKey,
		client: &http.Client{
			Timeout: time.Second * 30,
			Transport: &rateLimitedTransport{
				delegate: netTransport,
				throttle: time.Now().Add(-(rateLimit)),
			},
		},
	}, nil
}

func (c *Client) httpResponse(httpMethod string, url string, payload []byte) (resp []byte, err error) {
	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer(payload))

	if err != nil {
		return nil, err
	}

	httpResponse, err := c.execute(req)
	if err != nil {
		return nil, err
	}

	defer httpResponse.Body.Close()

	if httpResponse.StatusCode == 403 {
		return nil, fmt.Errorf("403 Forbidden When calling Digicert's API.")
	}

	return io.ReadAll(httpResponse.Body)
}

func (c *Client) execute(req *http.Request) (resp *http.Response, err error) {
	req.Header.Add(headerContent, mediaTypeJSON)
	req.Header.Add(headerDeviceKey, c.ApiKey)

	resp, err = c.client.Do(req)
	return
}
