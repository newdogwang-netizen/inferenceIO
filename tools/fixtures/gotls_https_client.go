// Command gotls_https_client is a deterministic, certificate-validating
// fixture used to qualify the eCapture GoTLS bridge against pinned Go releases.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const maxResponseBytes = 1 << 20
const maxRequests = 8

func main() {
	caPath := flag.String("ca", "", "PEM certificate authority file")
	url := flag.String("url", "", "HTTPS fixture URL")
	marker := flag.String("marker", "", "ASCII request marker")
	bodyBytes := flag.Int("body-bytes", 0, "exact body bytes per request (default marker length)")
	requests := flag.Int("requests", 1, "number of concurrent HTTPS requests")
	delay := flag.Duration("delay", 0, "bounded delay before requests")
	flag.Parse()
	if *caPath == "" || *url == "" || *marker == "" || flag.NArg() != 0 {
		fail("--ca, --url, and --marker are required; positional arguments are forbidden")
	}
	if *bodyBytes == 0 {
		*bodyBytes = len(*marker)
	}
	if *bodyBytes < len(*marker) || *bodyBytes > maxResponseBytes {
		fail("--body-bytes must contain the marker and be at most %d", maxResponseBytes)
	}
	if *requests < 1 || *requests > maxRequests {
		fail("--requests must be in 1..%d", maxRequests)
	}
	if *delay < 0 || *delay > 30*time.Second {
		fail("--delay must be in 0..30s")
	}

	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		fail("read CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fail("CA file contains no usable certificate")
	}

	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	if *delay > 0 {
		time.Sleep(*delay)
	}

	errors := make(chan error, *requests)
	var wait sync.WaitGroup
	for index := 0; index < *requests; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			tag := *marker
			if *requests > 1 {
				tag = fmt.Sprintf("%s-%02d", *marker, index)
			}
			body := repeatedBody(tag, *bodyBytes)
			errors <- requestOnce(client, *url, tag, body)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			fail("HTTPS request: %v", err)
		}
	}
	fmt.Printf(
		"verified %d requests and %d response bytes over certificate-validating TLS\n",
		*requests,
		*requests**bodyBytes,
	)
}

func repeatedBody(marker string, size int) []byte {
	body := make([]byte, size)
	for index := range body {
		body[index] = marker[index%len(marker)]
	}
	return body
}

func requestOnce(client *http.Client, url, marker string, requestBody []byte) error {
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Iorec-GoTLS-Marker", marker)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", response.Status)
	}
	if !bytes.Equal(body, requestBody) {
		return fmt.Errorf("response body does not exactly match request body")
	}
	return nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gotls fixture: "+format+"\n", args...)
	os.Exit(1)
}
