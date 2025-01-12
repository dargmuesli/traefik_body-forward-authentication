package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/v2/forward"
	"github.com/vulcand/oxy/v2/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http/httpguts"
)

const typeNameForward = "ForwardAuth"

const (
	xForwardedURI    = "X-Forwarded-Uri"
	xForwardedMethod = "X-Forwarded-Method"
)

// hopHeaders Hop-by-hop headers to be removed in the authentication request.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// Proxy-Authorization header is forwarded to the authentication server (see https://tools.ietf.org/html/rfc7235#section-4.4).
var hopHeaders = []string{
	forward.Connection,
	forward.KeepAlive,
	forward.Te, // canonicalized version of "TE"
	forward.Trailers,
	forward.TransferEncoding,
	forward.Upgrade,
}

const ForwardAuthDefaultMaxBodySize int64 = -1

type ClientTLS struct {
	CA                 string `description:"TLS CA" json:"ca,omitempty" toml:"ca,omitempty" yaml:"ca,omitempty"`
	Cert               string `description:"TLS cert" json:"cert,omitempty" toml:"cert,omitempty" yaml:"cert,omitempty"`
	Key                string `description:"TLS key" json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty" loggable:"false"`
	InsecureSkipVerify bool   `description:"TLS insecure skip verify" json:"insecureSkipVerify,omitempty" toml:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty" export:"true"`
	// Deprecated: TLS client authentication is a server side option (see https://github.com/golang/go/blob/740a490f71d026bb7d2d13cb8fa2d6d6e0572b70/src/crypto/tls/common.go#L634).
	CAOptional *bool `description:"TLS CA.Optional" json:"caOptional,omitempty" toml:"caOptional,omitempty" yaml:"caOptional,omitempty" export:"true"`
}

type Config struct {
	// Address defines the authentication server address.
	Address string `json:"address,omitempty" toml:"address,omitempty" yaml:"address,omitempty"`
	// TLS defines the configuration used to secure the connection to the authentication server.
	TLS *ClientTLS `json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty" export:"true"`
	// TrustForwardHeader defines whether to trust (ie: forward) all X-Forwarded-* headers.
	TrustForwardHeader bool `json:"trustForwardHeader,omitempty" toml:"trustForwardHeader,omitempty" yaml:"trustForwardHeader,omitempty" export:"true"`
	// AuthResponseHeaders defines the list of headers to copy from the authentication server response and set on forwarded request, replacing any existing conflicting headers.
	AuthResponseHeaders []string `json:"authResponseHeaders,omitempty" toml:"authResponseHeaders,omitempty" yaml:"authResponseHeaders,omitempty" export:"true"`
	// AuthResponseHeadersRegex defines the regex to match headers to copy from the authentication server response and set on forwarded request, after stripping all headers that match the regex.
	// More info: https://doc.traefik.io/traefik/v3.3/middlewares/http/forwardauth/#authresponseheadersregex
	AuthResponseHeadersRegex string `json:"authResponseHeadersRegex,omitempty" toml:"authResponseHeadersRegex,omitempty" yaml:"authResponseHeadersRegex,omitempty" export:"true"`
	// AuthRequestHeaders defines the list of the headers to copy from the request to the authentication server.
	// If not set or empty then all request headers are passed.
	AuthRequestHeaders []string `json:"authRequestHeaders,omitempty" toml:"authRequestHeaders,omitempty" yaml:"authRequestHeaders,omitempty" export:"true"`
	// AddAuthCookiesToResponse defines the list of cookies to copy from the authentication server response to the response.
	AddAuthCookiesToResponse []string `json:"addAuthCookiesToResponse,omitempty" toml:"addAuthCookiesToResponse,omitempty" yaml:"addAuthCookiesToResponse,omitempty" export:"true"`
	// HeaderField defines a header field to store the authenticated user.
	// More info: https://doc.traefik.io/traefik/v3.0/middlewares/http/forwardauth/#headerfield
	HeaderField string `json:"headerField,omitempty" toml:"headerField,omitempty" yaml:"headerField,omitempty" export:"true"`
	// ForwardBody defines whether to send the request body to the authentication server.
	ForwardBody bool `json:"forwardBody,omitempty" toml:"forwardBody,omitempty" yaml:"forwardBody,omitempty" export:"true"`
	// MaxBodySize defines the maximum body size in bytes allowed to be forwarded to the authentication server.
	MaxBodySize *int64 `json:"maxBodySize,omitempty" toml:"maxBodySize,omitempty" yaml:"maxBodySize,omitempty" export:"true"`
	// PreserveLocationHeader defines whether to forward the Location header to the client as is or prefix it with the domain name of the authentication server.
	PreserveLocationHeader bool `json:"preserveLocationHeader,omitempty" toml:"preserveLocationHeader,omitempty" yaml:"preserveLocationHeader,omitempty" export:"true"`
}

func (c *ClientTLS) CreateTLSConfig(ctx context.Context) (*tls.Config, error) {
	if c == nil {
		//log.Ctx(ctx).Warn().Msg("clientTLS is nil")
		logrus.Warn("clientTLS is nil")
		return nil, nil
	}

	// Not initialized, to rely on system bundle.
	var caPool *x509.CertPool

	if c.CA != "" {
		var ca []byte
		if _, errCA := os.Stat(c.CA); errCA == nil {
			var err error
			ca, err = os.ReadFile(c.CA)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA. %w", err)
			}
		} else {
			ca = []byte(c.CA)
		}

		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(ca) {
			return nil, errors.New("failed to parse CA")
		}
	}

	hasCert := len(c.Cert) > 0
	hasKey := len(c.Key) > 0

	if hasCert != hasKey {
		return nil, errors.New("both TLS cert and key must be defined")
	}

	if !hasCert || !hasKey {
		return &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: c.InsecureSkipVerify,
		}, nil
	}

	cert, err := loadKeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}, nil
}

func loadKeyPair(cert, key string) (tls.Certificate, error) {
	keyPair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err == nil {
		return keyPair, nil
	}

	_, err = os.Stat(cert)
	if err != nil {
		return tls.Certificate{}, errors.New("cert file does not exist")
	}

	_, err = os.Stat(key)
	if err != nil {
		return tls.Certificate{}, errors.New("key file does not exist")
	}

	keyPair, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}

func SetStatusErrorf(ctx context.Context, format string, args ...interface{}) {
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetStatus(codes.Error, fmt.Sprintf(format, args...))
	}
}

type Tracer struct {
	trace.Tracer

	safeQueryParams         []string
	capturedRequestHeaders  []string
	capturedResponseHeaders []string
}

func TracerFromContext(ctx context.Context) *Tracer {
	// Prevent picking trace.noopSpan tracer.
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return nil
	}

	span := trace.SpanFromContext(ctx)
	if span != nil && span.TracerProvider() != nil {
		tracer := span.TracerProvider().Tracer("github.com/traefik/traefik")
		if tracer, ok := tracer.(*Tracer); ok {
			return tracer
		}

		return nil
	}

	return nil
}

func InjectContextIntoCarrier(req *http.Request) {
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(req.Context(), propagation.HeaderCarrier(req.Header))
}

func (t *Tracer) CaptureClientRequest(span trace.Span, r *http.Request) {
	if t == nil || span == nil || r == nil {
		return
	}

	// Common attributes https://github.com/open-telemetry/semantic-conventions/blob/v1.26.0/docs/http/http-spans.md#common-attributes
	span.SetAttributes(semconv.HTTPRequestMethodKey.String(r.Method))
	span.SetAttributes(semconv.NetworkProtocolVersion(proto(r.Proto)))

	// Client attributes https://github.com/open-telemetry/semantic-conventions/blob/v1.26.0/docs/http/http-spans.md#http-client
	sURL := t.safeURL(r.URL)
	span.SetAttributes(semconv.URLFull(sURL.String()))
	span.SetAttributes(semconv.URLScheme(sURL.Scheme))
	span.SetAttributes(semconv.UserAgentOriginal(r.UserAgent()))

	host, port, err := net.SplitHostPort(sURL.Host)
	if err != nil {
		span.SetAttributes(semconv.NetworkPeerAddress(host))
		span.SetAttributes(semconv.ServerAddress(sURL.Host))
		switch sURL.Scheme {
		case "http":
			span.SetAttributes(semconv.NetworkPeerPort(80))
			span.SetAttributes(semconv.ServerPort(80))
		case "https":
			span.SetAttributes(semconv.NetworkPeerPort(443))
			span.SetAttributes(semconv.ServerPort(443))
		}
	} else {
		span.SetAttributes(semconv.NetworkPeerAddress(host))
		intPort, _ := strconv.Atoi(port)
		span.SetAttributes(semconv.NetworkPeerPort(intPort))
		span.SetAttributes(semconv.ServerAddress(host))
		span.SetAttributes(semconv.ServerPort(intPort))
	}

	for _, header := range t.capturedRequestHeaders {
		// User-agent is already part of the semantic convention as a recommended attribute.
		if strings.EqualFold(header, "User-Agent") {
			continue
		}

		if value := r.Header[header]; value != nil {
			span.SetAttributes(attribute.StringSlice(fmt.Sprintf("http.request.header.%s", strings.ToLower(header)), value))
		}
	}
}

func (t *Tracer) safeURL(originalURL *url.URL) *url.URL {
	if originalURL == nil {
		return nil
	}

	redactedURL := *originalURL

	// Redact password if exists.
	if redactedURL.User != nil {
		redactedURL.User = url.UserPassword("REDACTED", "REDACTED")
	}

	// Redact query parameters.
	query := redactedURL.Query()
	for k := range query {
		if slices.Contains(t.safeQueryParams, k) {
			continue
		}

		query.Set(k, "REDACTED")
	}
	redactedURL.RawQuery = query.Encode()

	return &redactedURL
}

func proto(proto string) string {
	switch proto {
	case "HTTP/1.0":
		return "1.0"
	case "HTTP/1.1":
		return "1.1"
	case "HTTP/2":
		return "2"
	case "HTTP/3":
		return "3"
	default:
		return proto
	}
}

func GetLogData(req *http.Request) *LogData {
	if ld, ok := req.Context().Value(DataTableKey).(*LogData); ok {
		return ld
	}
	return nil
}

const (
	// DataTableKey is the key within the request context used to store the Log Data Table.
	DataTableKey key = "LogDataTable"
)

type key string

type LogData struct {
	Core               CoreLogData
	Request            request
	OriginResponse     http.Header
	DownstreamResponse downstreamResponse
}

type CoreLogData map[string]interface{}

type downstreamResponse struct {
	headers http.Header
	status  int
	size    int64
}

type request struct {
	headers http.Header
	// Request body size
	size int64
}

func (t *Tracer) CaptureResponse(span trace.Span, responseHeaders http.Header, code int, spanKind trace.SpanKind) {
	if t == nil || span == nil {
		return
	}

	var status codes.Code
	var desc string
	switch spanKind {
	case trace.SpanKindServer:
		status, desc = serverStatus(code)
	case trace.SpanKindClient:
		status, desc = clientStatus(code)
	default:
		status, desc = defaultStatus(code)
	}
	span.SetStatus(status, desc)
	if code > 0 {
		span.SetAttributes(semconv.HTTPResponseStatusCode(code))
	}

	for _, header := range t.capturedResponseHeaders {
		if value := responseHeaders[header]; value != nil {
			span.SetAttributes(attribute.StringSlice(fmt.Sprintf("http.response.header.%s", strings.ToLower(header)), value))
		}
	}
}

func serverStatus(code int) (codes.Code, string) {
	if code < 100 || code >= 600 {
		return codes.Error, fmt.Sprintf("Invalid HTTP status code %d", code)
	}
	if code >= 500 {
		return codes.Error, ""
	}
	return codes.Unset, ""
}

func clientStatus(code int) (codes.Code, string) {
	if code < 100 || code >= 600 {
		return codes.Error, fmt.Sprintf("Invalid HTTP status code %d", code)
	}
	if code >= 400 {
		return codes.Error, ""
	}
	return codes.Unset, ""
}

func defaultStatus(code int) (codes.Code, string) {
	if code < 100 || code >= 600 {
		return codes.Error, fmt.Sprintf("Invalid HTTP status code %d", code)
	}
	if code >= 500 {
		return codes.Error, ""
	}
	return codes.Unset, ""
}

func RemoveConnectionHeaders(req *http.Request) {
	var reqUpType string
	if httpguts.HeaderValuesContainsToken(req.Header[connectionHeader], upgradeHeader) {
		reqUpType = req.Header.Get(upgradeHeader)
	}

	for _, f := range req.Header[connectionHeader] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				req.Header.Del(sf)
			}
		}
	}

	if reqUpType != "" {
		req.Header.Set(connectionHeader, upgradeHeader)
		req.Header.Set(upgradeHeader, reqUpType)
	} else {
		req.Header.Del(connectionHeader)
	}
}

const (
	connectionHeader = "Connection"
	upgradeHeader    = "Upgrade"
)

const (
	ClientUsername = "ClientUsername"
)

func NewResponseModifier(w http.ResponseWriter, r *http.Request, modifier func(*http.Response) error) http.ResponseWriter {
	return &ResponseModifier{
		req:      r,
		rw:       w,
		modifier: modifier,
		code:     http.StatusOK,
	}
}

type ResponseModifier struct {
	req *http.Request
	rw  http.ResponseWriter

	headersSent bool // whether headers have already been sent
	code        int  // status code, must default to 200

	modifier    func(*http.Response) error // can be nil
	modified    bool                       // whether modifier has already been called for the current request
	modifierErr error                      // returned by modifier call
}

func (r *ResponseModifier) WriteHeader(code int) {
	if r.headersSent {
		return
	}

	// Handling informational headers.
	if code >= 100 && code <= 199 {
		r.rw.WriteHeader(code)
		return
	}

	defer func() {
		r.code = code
		r.headersSent = true
	}()

	if r.modifier == nil || r.modified {
		r.rw.WriteHeader(code)
		return
	}

	resp := http.Response{
		Header:  r.rw.Header(),
		Request: r.req,
	}

	if err := r.modifier(&resp); err != nil {
		r.modifierErr = err
		// we are propagating when we are called in Write, but we're logging anyway,
		// because we could be called from another place which does not take care of
		// checking w.modifierErr.
		//log.Error().Err(err).Msg("Error when applying response modifier")
		logrus.WithError(err).Error("Error when applying response modifier")

		r.rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	r.modified = true
	r.rw.WriteHeader(code)
}

func (r *ResponseModifier) Header() http.Header {
	return r.rw.Header()
}

func (r *ResponseModifier) Write(b []byte) (int, error) {
	r.WriteHeader(r.code)
	if r.modifierErr != nil {
		return 0, r.modifierErr
	}

	return r.rw.Write(b)
}

type forwardAuth struct {
	address                  string
	authResponseHeaders      []string
	authResponseHeadersRegex *regexp.Regexp
	next                     http.Handler
	name                     string
	client                   http.Client
	trustForwardHeader       bool
	authRequestHeaders       []string
	addAuthCookiesToResponse map[string]struct{}
	headerField              string
	forwardBody              bool
	maxBodySize              int64
	preserveLocationHeader   bool
}

func CreateConfig() *Config {
	return &Config{
		Address: "http://127.0.0.1:3000",
	}
}

// NewForward creates a forward auth middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	//logger := middlewares.GetLogger(ctx, name, typeNameForward)
	logger := logrus.WithFields(logrus.Fields{
		"middleware": name,
		"type":       typeNameForward,
	})
	logger.Debug("Creating middleware")
	//logger.Debug().Msg("Creating middleware")

	addAuthCookiesToResponse := make(map[string]struct{})
	for _, cookieName := range config.AddAuthCookiesToResponse {
		addAuthCookiesToResponse[cookieName] = struct{}{}
	}

	fa := &forwardAuth{
		address:                  config.Address,
		authResponseHeaders:      config.AuthResponseHeaders,
		next:                     next,
		name:                     name,
		trustForwardHeader:       config.TrustForwardHeader,
		authRequestHeaders:       config.AuthRequestHeaders,
		addAuthCookiesToResponse: addAuthCookiesToResponse,
		headerField:              config.HeaderField,
		forwardBody:              config.ForwardBody,
		maxBodySize:              ForwardAuthDefaultMaxBodySize,
		preserveLocationHeader:   config.PreserveLocationHeader,
	}

	if config.MaxBodySize != nil {
		fa.maxBodySize = *config.MaxBodySize
	}

	// Ensure our request client does not follow redirects
	fa.client = http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	if config.TLS != nil {
		if config.TLS.CAOptional != nil {
			//logger.Warn().Msg("CAOptional option is deprecated, TLS client authentication is a server side option, please remove any usage of this option.")
			logger.Warn("CAOptional option is deprecated, TLS client authentication is a server side option, please remove any usage of this option.")
		}

		clientTLS := &ClientTLS{
			CA:                 config.TLS.CA,
			Cert:               config.TLS.Cert,
			Key:                config.TLS.Key,
			InsecureSkipVerify: config.TLS.InsecureSkipVerify,
		}

		tlsConfig, err := clientTLS.CreateTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to create client TLS configuration: %w", err)
		}

		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		fa.client.Transport = tr
	}

	if config.AuthResponseHeadersRegex != "" {
		re, err := regexp.Compile(config.AuthResponseHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regular expression %s: %w", config.AuthResponseHeadersRegex, err)
		}
		fa.authResponseHeadersRegex = re
	}

	return fa, nil
}

func (fa *forwardAuth) GetTracingInformation() (string, string, trace.SpanKind) {
	return fa.name, typeNameForward, trace.SpanKindInternal
}

func (fa *forwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	//logger := middlewares.GetLogger(req.Context(), fa.name, typeNameForward)
	logger := logrus.WithFields(logrus.Fields{
		"type": typeNameForward,
	})

	forwardReq, err := http.NewRequestWithContext(req.Context(), http.MethodGet, fa.address, nil)
	if err != nil {
		//logger.Debug().Err(err).Msgf("Error calling %s", fa.address)
		logger.WithError(err).Debugf("Error calling %s", fa.address)
		SetStatusErrorf(req.Context(), "Error calling %s. Cause %s", fa.address, err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if fa.forwardBody {
		bodyBytes, err := fa.readBodyBytes(req)
		if errors.Is(err, errBodyTooLarge) {
			//logger.Debug().Msgf("Request body is too large, maxBodySize: %d", fa.maxBodySize)
			logger.Debugf("Request body is too large, maxBodySize: %d", fa.maxBodySize)

			SetStatusErrorf(req.Context(), "Request body is too large, maxBodySize: %d", fa.maxBodySize)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			//logger.Debug().Err(err).Msg("Error while reading body")
			logger.WithError(err).Debug("Error while reading body")

			SetStatusErrorf(req.Context(), "Error while reading Body: %s", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		// bodyBytes is nil when the request has no body.
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			forwardReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	writeHeader(req, forwardReq, fa.trustForwardHeader, fa.authRequestHeaders)

	var forwardSpan trace.Span
	var tracer *Tracer
	if tracer = TracerFromContext(req.Context()); tracer != nil {
		var tracingCtx context.Context
		tracingCtx, forwardSpan = tracer.Start(req.Context(), "AuthRequest", trace.WithSpanKind(trace.SpanKindClient))
		defer forwardSpan.End()

		forwardReq = forwardReq.WithContext(tracingCtx)

		InjectContextIntoCarrier(forwardReq)
		tracer.CaptureClientRequest(forwardSpan, forwardReq)
	}

	forwardResponse, forwardErr := fa.client.Do(forwardReq)
	if forwardErr != nil {
		//logger.Debug().Err(forwardErr).Msgf("Error calling %s", fa.address)
		logger.WithError(forwardErr).Debugf("Error calling %s", fa.address)
		SetStatusErrorf(req.Context(), "Error calling %s. Cause: %s", fa.address, forwardErr)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer forwardResponse.Body.Close()

	body, readError := io.ReadAll(forwardResponse.Body)
	if readError != nil {
		//logger.Debug().Err(readError).Msgf("Error reading body %s", fa.address)
		logger.WithError(readError).Debugf("Error reading body %s", fa.address)
		SetStatusErrorf(req.Context(), "Error reading body %s. Cause: %s", fa.address, readError)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Ending the forward request span as soon as the response is handled.
	// If any errors happen earlier, this span will be close by the defer instruction.
	if forwardSpan != nil {
		forwardSpan.End()
	}

	if fa.headerField != "" {
		if elems := forwardResponse.Header[http.CanonicalHeaderKey(fa.headerField)]; len(elems) > 0 {
			logData := GetLogData(req)
			if logData != nil {
				logData.Core[ClientUsername] = elems[0]
			}
		}
	}

	// Pass the forward response's body and selected headers if it
	// didn't return a response within the range of [200, 300).
	if forwardResponse.StatusCode < http.StatusOK || forwardResponse.StatusCode >= http.StatusMultipleChoices {
		//logger.Debug().Msgf("Remote error %s. StatusCode: %d", fa.address, forwardResponse.StatusCode)
		logger.Debugf("Remote error %s. StatusCode: %d", fa.address, forwardResponse.StatusCode)

		utils.CopyHeaders(rw.Header(), forwardResponse.Header)
		utils.RemoveHeaders(rw.Header(), hopHeaders...)

		redirectURL, err := fa.redirectURL(forwardResponse)
		if err != nil {
			if !errors.Is(err, http.ErrNoLocation) {
				//logger.Debug().Err(err).Msgf("Error reading response location header %s", fa.address)
				logger.WithError(err).Debugf("Error reading response location header %s", fa.address)
				SetStatusErrorf(req.Context(), "Error reading response location header %s. Cause: %s", fa.address, err)

				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else if redirectURL.String() != "" {
			// Set the location in our response if one was sent back.
			rw.Header().Set("Location", redirectURL.String())
		}

		tracer.CaptureResponse(forwardSpan, forwardResponse.Header, forwardResponse.StatusCode, trace.SpanKindClient)
		rw.WriteHeader(forwardResponse.StatusCode)

		if _, err = rw.Write(body); err != nil {
			//logger.Error().Err(err).Send()
			logger.WithError(err).Error("An error occurred")
		}
		return
	}

	for _, headerName := range fa.authResponseHeaders {
		headerKey := http.CanonicalHeaderKey(headerName)
		req.Header.Del(headerKey)
		if len(forwardResponse.Header[headerKey]) > 0 {
			req.Header[headerKey] = append([]string(nil), forwardResponse.Header[headerKey]...)
		}
	}

	if fa.authResponseHeadersRegex != nil {
		for headerKey := range req.Header {
			if fa.authResponseHeadersRegex.MatchString(headerKey) {
				req.Header.Del(headerKey)
			}
		}

		for headerKey, headerValues := range forwardResponse.Header {
			if fa.authResponseHeadersRegex.MatchString(headerKey) {
				req.Header[headerKey] = append([]string(nil), headerValues...)
			}
		}
	}

	tracer.CaptureResponse(forwardSpan, forwardResponse.Header, forwardResponse.StatusCode, trace.SpanKindClient)

	req.RequestURI = req.URL.RequestURI()

	authCookies := forwardResponse.Cookies()
	if len(authCookies) == 0 {
		fa.next.ServeHTTP(rw, req)
		return
	}

	fa.next.ServeHTTP(NewResponseModifier(rw, req, fa.buildModifier(authCookies)), req)
}

func (fa *forwardAuth) redirectURL(forwardResponse *http.Response) (*url.URL, error) {
	if !fa.preserveLocationHeader {
		return forwardResponse.Location()
	}

	// Preserve the Location header if it exists.
	if lv := forwardResponse.Header.Get("Location"); lv != "" {
		return url.Parse(lv)
	}
	return nil, http.ErrNoLocation
}

func (fa *forwardAuth) buildModifier(authCookies []*http.Cookie) func(res *http.Response) error {
	return func(res *http.Response) error {
		cookies := res.Cookies()
		res.Header.Del("Set-Cookie")

		for _, cookie := range cookies {
			if _, found := fa.addAuthCookiesToResponse[cookie.Name]; !found {
				res.Header.Add("Set-Cookie", cookie.String())
			}
		}

		for _, cookie := range authCookies {
			if _, found := fa.addAuthCookiesToResponse[cookie.Name]; found {
				res.Header.Add("Set-Cookie", cookie.String())
			}
		}

		return nil
	}
}

var errBodyTooLarge = errors.New("request body too large")

func (fa *forwardAuth) readBodyBytes(req *http.Request) ([]byte, error) {
	if fa.maxBodySize < 0 {
		return io.ReadAll(req.Body)
	}

	body := make([]byte, fa.maxBodySize+1)
	n, err := io.ReadFull(req.Body, body)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("reading body bytes: %w", err)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return body[:n], nil
	}
	return nil, errBodyTooLarge
}

func writeHeader(req, forwardReq *http.Request, trustForwardHeader bool, allowedHeaders []string) {
	utils.CopyHeaders(forwardReq.Header, req.Header)

	RemoveConnectionHeaders(forwardReq)
	utils.RemoveHeaders(forwardReq.Header, hopHeaders...)

	forwardReq.Header = filterForwardRequestHeaders(forwardReq.Header, allowedHeaders)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if trustForwardHeader {
			if prior, ok := req.Header[forward.XForwardedFor]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
		}
		forwardReq.Header.Set(forward.XForwardedFor, clientIP)
	}

	xMethod := req.Header.Get(xForwardedMethod)
	switch {
	case xMethod != "" && trustForwardHeader:
		forwardReq.Header.Set(xForwardedMethod, xMethod)
	case req.Method != "":
		forwardReq.Header.Set(xForwardedMethod, req.Method)
	default:
		forwardReq.Header.Del(xForwardedMethod)
	}

	xfp := req.Header.Get(forward.XForwardedProto)
	switch {
	case xfp != "" && trustForwardHeader:
		forwardReq.Header.Set(forward.XForwardedProto, xfp)
	case req.TLS != nil:
		forwardReq.Header.Set(forward.XForwardedProto, "https")
	default:
		forwardReq.Header.Set(forward.XForwardedProto, "http")
	}

	if xfp := req.Header.Get(forward.XForwardedPort); xfp != "" && trustForwardHeader {
		forwardReq.Header.Set(forward.XForwardedPort, xfp)
	}

	xfh := req.Header.Get(forward.XForwardedHost)
	switch {
	case xfh != "" && trustForwardHeader:
		forwardReq.Header.Set(forward.XForwardedHost, xfh)
	case req.Host != "":
		forwardReq.Header.Set(forward.XForwardedHost, req.Host)
	default:
		forwardReq.Header.Del(forward.XForwardedHost)
	}

	xfURI := req.Header.Get(xForwardedURI)
	switch {
	case xfURI != "" && trustForwardHeader:
		forwardReq.Header.Set(xForwardedURI, xfURI)
	case req.URL.RequestURI() != "":
		forwardReq.Header.Set(xForwardedURI, req.URL.RequestURI())
	default:
		forwardReq.Header.Del(xForwardedURI)
	}
}

func filterForwardRequestHeaders(forwardRequestHeaders http.Header, allowedHeaders []string) http.Header {
	if len(allowedHeaders) == 0 {
		return forwardRequestHeaders
	}

	filteredHeaders := http.Header{}
	for _, headerName := range allowedHeaders {
		values := forwardRequestHeaders.Values(headerName)
		if len(values) > 0 {
			filteredHeaders[http.CanonicalHeaderKey(headerName)] = append([]string(nil), values...)
		}
	}

	return filteredHeaders
}
