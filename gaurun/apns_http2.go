package gaurun

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/RobotsAndPencils/buford/payload"
	"github.com/RobotsAndPencils/buford/payload/badge"
	"github.com/RobotsAndPencils/buford/push"

	"golang.org/x/net/http2"
)

func NewTransportHttp2(cert tls.Certificate) (*http.Transport, error) {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	config.BuildNameToCertificate()

	transport := &http.Transport{
		TLSClientConfig:     config,
		MaxIdleConnsPerHost: ConfGaurun.Ios.KeepAliveConns,
		Dial: (&net.Dialer{
			Timeout:   time.Duration(ConfGaurun.Ios.Timeout) * time.Second,
			KeepAlive: time.Duration(keepAliveInterval(ConfGaurun.Ios.KeepAliveTimeout)) * time.Second,
		}).Dial,
		IdleConnTimeout: time.Duration(ConfGaurun.Ios.KeepAliveTimeout) * time.Second,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}

	return transport, nil
}

func NewApnsClientHttp2(certPath, keyPath string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	transport, err := NewTransportHttp2(cert)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(ConfGaurun.Ios.Timeout) * time.Second,
	}, nil
}

func NewApnsServiceHttp2(client *http.Client) *push.Service {
	var host string
	if ConfGaurun.Ios.Sandbox {
		host = push.Development
	} else {
		host = push.Production
	}
	return &push.Service{
		Client: client,
		Host:   host,
	}
}

func NewApnsPayloadHttp2(req *RequestGaurunNotification) map[string]interface{} {
	b := badge.Preserve
	if req.Badge != nil {
		b = badge.New(uint(*req.Badge))
	}
	p := payload.APS{
		Alert:            payload.Alert{Title: req.Title, Body: req.Message, Subtitle: req.Subtitle},
		Badge:            b,
		Category:         req.Category,
		Sound:            req.Sound,
		ContentAvailable: req.ContentAvailable,
		MutableContent:   req.MutableContent,
	}

	pm := p.Map()

	if len(req.Extend) > 0 {
		for _, extend := range req.Extend {
			pm[extend.Key] = extend.Value
		}
	}

	return pm
}

func NewApnsHeadersHttp2(req *RequestGaurunNotification) *push.Headers {
	headers := &push.Headers{
		Topic: ConfGaurun.Ios.Topic,
	}

	if req.Expiry > 0 {
		headers.Expiration = time.Now().Add(time.Duration(int64(req.Expiry)) * time.Second).UTC()
	}

	return headers
}

func ApnsPushHttp2(token string, service *push.Service, headers *push.Headers, payload map[string]interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = service.Push(token, headers, b)
	return err
}
