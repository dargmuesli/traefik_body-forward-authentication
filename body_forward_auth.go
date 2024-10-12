package body_forward_auth

import (
    "bytes"
    "context"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/traefik/traefik/v2/pkg/log"
)

// Config holds configuration for the plugin
type Config struct {
    AuthUrl string
    Timeout time.Duration // Timeout for client requests
}

// CreateConfig populates the Config object
func CreateConfig() *Config {
    return &Config{
        AuthUrl: "http://127.0.0.1",   // Default authentication URL
        Timeout: 5 * time.Second,      // Default timeout for HTTP client requests
    }
}

type BodyForwardAuth struct {
    next    http.Handler
    authUrl string
    timeout time.Duration
    name    string
}

// New instantiates and returns the plugin's main handler
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    logger := log.FromContext(ctx)

    if len(config.AuthUrl) == 0 {
        return nil, fmt.Errorf("AuthUrl cannot be empty")
    }

    logger.Debugf("Initializing BodyForwardAuth plugin with AuthUrl: %s", config.AuthUrl)

    return &BodyForwardAuth{
        next:    next,
        authUrl: config.AuthUrl,
        timeout: config.Timeout,
        name:    name,
    }, nil
}

// ServeHTTP processes the incoming request, forwards it to the auth server, and passes the request to the next handler.
func (bfa *BodyForwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    logger := log.FromContext(req.Context())
    logger.Debugf("ServeHTTP called, forwarding request to auth URL: %s", bfa.authUrl)

    body, err := io.ReadAll(req.Body)
    if err != nil {
        logger.Error("Failed to read request body: ", err)
        http.Error(rw, "failed to read request body", http.StatusInternalServerError)
        return
    }
    defer req.Body.Close()

    // Create proxy request
    proxyRequest, err := http.NewRequest(req.Method, bfa.authUrl, bytes.NewReader(body))
    if err != nil {
        logger.Error("Failed to create proxy request: ", err)
        http.Error(rw, "failed to create proxy request", http.StatusBadGateway)
        return
    }

    // Copy headers from original request to proxy request
    proxyRequest.Header = req.Header

    client := &http.Client{
        Timeout: bfa.timeout, // Set timeout for client request
    }

    response, err := client.Do(proxyRequest)
    if err != nil {
        logger.Error("Request to auth server failed: ", err)
        http.Error(rw, "auth server request failed", http.StatusInternalServerError)
        return
    }
    defer response.Body.Close()

    logger.Debugf("Received response from auth server with status: %d", response.StatusCode)

    // If authentication is successful, pass request to the next handler
    if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
        req.Body = io.NopCloser(bytes.NewReader(body)) // Reset request body for the next handler
        bfa.next.ServeHTTP(rw, req)
    } else {
        logger.Error("Authentication failed with status: ", response.StatusCode)
        http.Error(rw, "auth failed", response.StatusCode)
    }
}
