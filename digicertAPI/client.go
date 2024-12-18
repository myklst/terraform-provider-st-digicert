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

	"github.com/cenkalti/backoff/v4"
	"github.com/myklst/terraform-provider-st-digicert/digicert/backoff_retry"
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
	MAX_ELAPSED_TIME    = 10 * time.Minute
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
	var req *http.Request
	httpRequest := func() error {
		req, err = http.NewRequest(httpMethod, url, bytes.NewBuffer(payload))
		if err != nil {
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(httpRequest, MAX_ELAPSED_TIME); err != nil {
		return nil, fmt.Errorf("digicert http request failure: %v", err)
	}

	httpResponse, err := c.execute(req)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()

	return io.ReadAll(httpResponse.Body)
}

func (c *Client) execute(req *http.Request) (resp *http.Response, err error) {
	req.Header.Add(headerContent, mediaTypeJSON)
	req.Header.Add(headerDeviceKey, c.ApiKey)

	var httpResp *http.Response
	httpResponse := func() error {
		resp, err = c.client.Do(req)
		if err != nil {
			if httpResp.StatusCode == 403 {
				return backoff.Permanent(fmt.Errorf("403 Forbidden When calling Digicert's API"))
			}
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(httpResponse, MAX_ELAPSED_TIME); err != nil {
		return nil, fmt.Errorf("digicert http response failure: %v", err)
	}

	return resp, nil
}
