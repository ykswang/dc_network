package dc_network

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DCHttpTrace: Step-by-step timing information for an http request
type DCHttpTrace struct {
	TotalSart             time.Time        // Request start time
	TotalEnd              time.Time        // Request completion time
	TotalDuration         time.Duration    // Total time spent on one request.
	DNSStart              time.Time        // Start lookup DNS. If the request is sent through the proxy, maybe value is zero
	DNSDone               time.Time        // Finished lookup DNS. If the request is sent through the proxy, maybe value is zero
	DNSDuration           time.Duration    // If the request is sent through the proxy, maybe value is zero
	ConnectStart          time.Time        // TCP connect start
	ConnectDone           time.Time        // TCP connected or failed
	ConnectDuration       time.Duration    // Time spent on TCP connecting
	TLSHandshakeStart     time.Time        // Start TLS handshake
	TLSHandshakeDone      time.Time        // Finished TLS handshake (Success or Failed)
	TLSHandshakeDuration  time.Duration    // Time spent on TLS handshake
	RequestSended         time.Time        // Finished tp send request (headers + body)
	ResponseReturned      time.Time        // Got the first bytes of response
	ServerDuration        time.Duration    // The time taken by the server to process this request (including the time when the Response is returned on the road)
}

// DCHttpResponse: Http response from DCHttpClient
type DCHttpResponse struct {
	Raw         *http.Response             // *http.Response
	Header      map[string]string          // Cache *http.Response.Header to map[string]string
	TraceInfo   *DCHttpTrace               // Step-by-step timing information for an http request
	body        []byte                     // To support multiple reads, cache the contents of the body
	bodyErr     error                      // Body IO Error cache
}

// GetRawResponse return golang native response
func (v *DCHttpResponse) GetRawResponse() *http.Response {
	return v.Raw
}


// Load the contents of the body into the cache first
// To support multiple reads, cache the contents of the body
func (v *DCHttpResponse) cacheBodyToMemory() {
	if !v.Raw.Close {
		v.body, v.bodyErr = ioutil.ReadAll(v.Raw.Body)
		_ = v.Raw.Body.Close()
	}
}

// ToString convert body([]bytes) to string
func (v *DCHttpResponse) ToString() (body string, err error) {
	v.cacheBodyToMemory()
	if v.bodyErr != nil {
		return "", v.bodyErr
	}
	return string(v.body), nil
}

// ToBytes returned body([]bytes)
func (v *DCHttpResponse) ToBytes() (body []byte, err error) {
	v.cacheBodyToMemory()
	return body, nil
}

// Get the http status code
func (v *DCHttpResponse) GetStatusCode() (statusCode int) {
	return v.Raw.StatusCode
}

// Get http protocol information, such as "HTTP/1.0"
func (v *DCHttpResponse) GetProto() (proto string) {
	return v.Raw.Proto
}

// Returns the header information
// @param key: header key
// @return value: the value of header key
func (v *DCHttpResponse) GetHeader(key string) (value string) {
	value, ok := v.Header[key]
	if !ok {
		value = ""
	}
	return
}

// Determine whether the specified header information is included
// @param key: header key
// @return ok: true means 'included'
func (v *DCHttpResponse) HasHeader(key string) (ok bool) {
	_, ok = v.Header[key]
	return
}

// Get all header information
// @return headers: all header information
func (v *DCHttpResponse) GetHeaders() (headers map[string]string) {
	return v.Header
}

// Get the step-by-step time-consuming information for this HTTP request
//
//  @premise：
//  	DCHttpClient.SetTrace(true)
//  @return
//  	traceInfo: the time-consuming information result
func (v *DCHttpResponse) GetTraceInfo() (traceInfo *DCHttpTrace) {
	return v.TraceInfo
}

// When getting a Response, if the body information has never been read,
// then the input stream of the body is open and needs to be closed once.
func (v *DCHttpResponse) Close() {
	if !v.Raw.Close && v.Raw.Body != nil {
		v.Raw.Body.Close()
	}
}

// Http Client
type DCHttpClient struct {
	Dialer    *net.Dialer     // *net.Dialer
	Core      *http.Client    // based http client
	Transport *http.Transport // client properties
	Trace     bool            // enable trace time spent
}

// With dual-stack support, if the server is also a dual-stack address, the client will first perform
// a Fallback connection test on the IPv6 address according to the content defined in RFC 6555,
// and determine whether it needs to be downgraded to the IPv4 request according to the delay of the FallbackDelay.
//  @Params
//     delay: if set to 0, the system will be set as 300ms, if set to negative, it means disable IPv6
func (v *DCHttpClient) SetFallbackDelay(delay time.Duration) {
	v.Dialer.FallbackDelay = delay
}

// Timeout of the connection established?
//  @Params
//     timeout: The default is 30s, 0 means unrestricted. Unrestricted does not mean that there is
//              really no limit, but is limited by the operating system itself. Under normal circumstances,
//              this limit may be around 3 minutes or even shorter.
func (v *DCHttpClient) SetConnectTimeout(timeout time.Duration) {
	v.Dialer.Timeout = timeout
}

// Keep-alive keepalive parameters at the TCP level
//  @Params
//     timout：The default is 30s. If it is 0, it will be the default value of the operating system.
//             If it is negative, the keep-alive will be disabled.
//
// This parameter corresponds to net.Dailer.KeepAlive, the document explains the mode, here is a
// supplementary explanation In fact, this value is the tcp_keepalive_intvl and tcp_keepalive_time
// values ​​at the tcp level. The linux man description is as follows
//
//  tcp_keepalive_intvl (integer; default: 75; since Linux 2.4)
//      The number of seconds between TCP keep-alive probes.
//
//  tcp_keepalive_probes (integer; default: 9; since Linux 2.2)
//     The  maximum number of TCP keep-alive probes to send before giving up and killing the connection
//     if no response is obtained from the other end.
//
//  tcp_keepalive_time (integer; default: 7200; since Linux 2.2)
//     The number of seconds a connection needs to be idle before TCP begins sending out keep-alive probes.
//     Keep-alives are  only sent  when  the SO_KEEPALIVE socket option is enabled.  The default value is
//     7200 seconds (2 hours).  An idle connection is terminated after approximately an additional 11 minutes
//     (9 probes an interval of  75  seconds  apart)  when  keep-alive is enabled.
//
// To use the keepalive mechanism, first turn on the SO_KEEPALIVE setting; then the system will initiate the probe
// after the connection idle 'keepalive_time' time. When consecutive 'keepalive_probes' probes fail, the system closes
// the connection. 'keepalive_intvl' is the interval between two probes
//
// Refer to the implementation of the go source
//
//  setKeepAlive():
//  syscall.SetsockoptInt(fd.sysfd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(keepalive))
//  ...
//  setKeepAlivePeriod():
//  syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_TCP, sysTCP_KEEPINTVL, secs)
//  syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_TCP, syscall.TCP_KEEPALIVE, secs)
//
// Golang sets the 'tcp_keepalive_intvl' value and the 'tcp_keepalive_time' value with Dail.KeepAlive.
// Linux is calculated according to the 9 Probes timeout to close the connection.
// The lifetime of the connection is the normal request period (continuous idle time < Dail.KeepAlive )
// + 'Dail.KeepAlive' + 9 * 'Dail.KeepAlive' time will be closed. Some people will be confused that http.Transport
// already has control over the idle. Why is this needed? Because this is the parameter exposed by the Net library
// of golang, and the http library is a separate library, which can be understood as http.Transport has closed the
// connection in advance according to idleTimeout before the net timeout is closed.
func (v *DCHttpClient) SetTCPKeepAlive(timeout time.Duration) {
	v.Dialer.KeepAlive = timeout
}

// Set the idle timeout of the keep-alive http layer.
//  @Params
//     timeout: The default is 90s, 0 means no limit (TCPKeepAlive by default)
func (v *DCHttpClient) SetKeepAliveIdleTimeout(timeout time.Duration) {
	v.Transport.IdleConnTimeout = timeout
}

// Timed from the start of the request to send, to the response's head of the service return, timeout setting
//  @Params
//     timeout: The default is 30s, 0 means no limit
func (v *DCHttpClient) SetResponseHeaderTimeout(timeout time.Duration) {
	v.Transport.ResponseHeaderTimeout = timeout
}

// For requests with "Expect: 100-continue" header information,
// wait for the server to grant a timeout for the body to send
//  @Params
//     timeout: The default is 1s, 0 means no waiting, immediately send the requested body
func (v *DCHttpClient) SetExpectContinueTimeout(timeout time.Duration) {
	v.Transport.ExpectContinueTimeout = timeout
}

// Whether to use http keep-alive to reuse connections, including http2
//  @Params
//     enable: True means enabled, false means off, default is true
func (v *DCHttpClient) SetKeepAlive(enable bool) {
	v.Transport.DisableKeepAlives = !enable
}

// Set the upper limit of the idle connection of the total connection pool under keep-alive
//  @Params
//     size: The size of the connection pool, 0 means no limit, the default is 0
func (v *DCHttpClient) SetMaxIdleConns(size int) {
	v.Transport.MaxIdleConns = size
}

// Set the upper limit of the idle connection of the connection pool under keep-alive
// (each domain name is counted separately), MaxIdleConns has a higher priority than MaxIdleConnsPerHost,
// that is, IdleConnsPerHost is less than the sum of Hosts <= MaxIdleConns
//  @Params
//     size: The size of the connection pool, 0 means use tcp.DefaultMaxIdleConnsPerHost, the default is 0
func (v *DCHttpClient) SetMaxIdleConnsPerHost(size int) {
	v.Transport.MaxIdleConnsPerHost = size
}

// Set the upper limit of all connections for the connection pool under keep-alive
// (each domain name is counted separately), MaxConnsPerHost > MaxIdleConnsPerHost
//  @Params
//     size: The size of the connection pool, 0 means no restrictions on use, the default is 0
func (v *DCHttpClient) SetMaxConnsPerHost(size int) {
	v.Transport.MaxConnsPerHost = size
}

// Whether to disable compression when requested
// Compression means bringing the "Accept-Encoding: gzip" header to the request.
//  @Params
//     enable: True means enabled, false means disabled, default is true
func (v *DCHttpClient) SetCompression(enable bool) {
	v.Transport.DisableCompression = !enable
}

// Is it necessary to verify the validity of the certificate for TLS?
//  @Params
//     enable: True means check, false means no check, default is true
func (v *DCHttpClient) SetTLSVerify(enable bool) {
	v.Transport.TLSClientConfig.InsecureSkipVerify = !enable
}

// Set the minimum protocol version number of TLS
//  @Params
//     version: 0 means >= TLS 1.0, other values ​​can read tls library, for example tls.VersionTLS12, default 0
func (v *DCHttpClient) SetTLSMinVersion(version uint16) {
	v.Transport.TLSClientConfig.MinVersion = version
}

// Set the maximum protocol version number of TLS
//  @Params
//     version: 0 means <= TLS 1.3, other values ​​can read tls library, for example tls.VersionTLS12, default 0
func (v *DCHttpClient) SetTLSMaxVersion(version uint16) {
	v.Transport.TLSClientConfig.MinVersion = version
}

// Set the handshake timeout period for TLS
//  @Params
//     timeout: the default is 10s, 0 means no limit
func (v *DCHttpClient) SetTLSHandshakeTimeout(timeout time.Duration) {
	v.Transport.TLSHandshakeTimeout = timeout
}

// Whether you need to perform performance statistics on http requests, such as dns time-consuming, etc.
//  @Params
//     enable: true means traceMode on
func (v *DCHttpClient) SetTrace(enable bool) {
	v.Trace = enable
}

// Send a get request
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) Get(url string, headers map[string]string) (response *DCHttpResponse, err error) {
	return v.DoWithoutContent(http.MethodGet, url, headers)
}

// Post a string (Content-Type: text/plain)
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//     text: the string that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) PostString(
	url string, headers map[string]string, text string) (response *DCHttpResponse, err error) {
	return v.DoString(http.MethodPost,url, headers, text)
}

// Send bytes (without Content-Type)
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//     data: bytes that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) PostBytes(
	url string, headers map[string]string, data []byte) (response *DCHttpResponse, err error) {
	return v.DoBytes(http.MethodPost,url, headers, data)
}

// Send a json object (Content-Type: application/json)
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//     jsonObject: json object that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) PostJSON(
	url string, headers map[string]string, jsonObject interface{}) (response *DCHttpResponse, err error) {
	return v.DoJSON(http.MethodPost,url, headers, jsonObject)
}

// Post a form (Content-Type: application/x-www-form-urlencoded)
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//     form: form that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) PostForm(
	url string, headers map[string]string, form map[string]string) (response *DCHttpResponse, err error) {
	return v.DoForm(http.MethodPost,url, headers, form)
}

// Post a multipartform (Content-Type: multipart/form-data) make sure your server
// is compatible with your request method.
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//     form: form that needs to be sent
//     fileParam: parameter name of the file.
//     filePath: filePath need to be uploaded
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) PostMultipartForm(
	url string, headers map[string]string, form map[string]string,
	fileParam string, filePath string) (response *DCHttpResponse, err error) {
	return v.DoMultipartForm(http.MethodPost,url, headers, form, fileParam, filePath)
}

// Send a PUT request
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) Put(
	url string, headers map[string]string) (response *DCHttpResponse, err error) {
	return v.DoWithoutContent(http.MethodPut, url, headers)
}

// Send a DELETE request
//  @Params
//     url: http address
//     headers: add extra headers or which need to be replaced
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) Delete(
	url string, headers map[string]string) (response *DCHttpResponse, err error) {
	return v.DoWithoutContent(http.MethodDelete, url, headers)
}

// Send a request without any body
//  @Params
//     method: http method, such as 'http.MethodPost'.
//     url: http address
//     headers: add extra headers or which need to be replaced
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) DoWithoutContent(
	method string, url string, headers map[string]string) (response *DCHttpResponse, err error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	return v.do(req, headers)
}

// Send a string (Content-Type: text/plain)
// In principle, only Post can attach the body parameter, please make sure your server
// is compatible with your request method.
//  @Params
//     method: http method, such as 'http.MethodPost'.
//     url: http address
//     headers: add extra headers or which need to be replaced
//     text: the string that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) DoString(
	method string, url string, headers map[string]string, text string) (response *DCHttpResponse, err error) {
	req, err := http.NewRequest(method, url, strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	return v.do(req, headers)
}

// Send bytes (without Content-Type)
// In principle, only Post can attach the body parameter, please make sure your server
// is compatible with your request method.
//  @Params
//     method: http method, such as 'http.MethodPost'.
//     url: http address
//     headers: add extra headers or which need to be replaced
//     data: bytes that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) DoBytes(
	method string, url string, headers map[string]string, data []byte) (response *DCHttpResponse, err error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return v.do(req, headers)
}

// Send json (Content-Type: application/json)
// In principle, only Post can attach the body parameter, please make sure your server
// is compatible with your request method.
//  @Params
//     method: http method, such as 'http.MethodPost'.
//     url: http address
//     headers: add extra headers or which need to be replaced
//     jsonObject: json object that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) DoJSON(
	method string, url string, headers map[string]string, jsonObject interface{}) (response *DCHttpResponse, err error) {

	jsonStringBytes, err := json.Marshal(jsonObject)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(jsonStringBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return v.do(req, headers)
}

// Send form (Content-Type: application/x-www-form-urlencoded)
// In principle, only Post can attach the body parameter, please make sure your server
// is compatible with your request method.
//  @Params
//     method: http method, such as 'http.MethodPost'.
//     url: http address
//     headers: add extra headers or which need to be replaced
//     form: form that needs to be sent
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) DoForm(
	method string, url string, headers map[string]string, form map[string]string) (response *DCHttpResponse, err error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	if req.Form == nil {
		req.Form = make(map[string][]string)
	}
	for k,v := range form {
		req.Form.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return v.do(req, headers)
}

// Send multipartform (Content-Type: multipart/form-data)
// In principle, only Post can attach the body parameter, please make sure your server
// is compatible with your request method.
//  @Params
//     method: http method, such as 'http.MethodPost'.
//     url: http address
//     headers: add extra headers or which need to be replaced
//     form: form that needs to be sent
//     fileParam: parameter name of the file.
//     filePath: filePath need to be uploaded
//  @Return
//     response: http response (*DCHttpResponse)
//     err: error info
func (v *DCHttpClient) DoMultipartForm(
	method string, url string, headers map[string]string, form map[string]string,
	fileParam string, filePath string) (response *DCHttpResponse, err error) {

	// 读取文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(fileParam, filepath.Base(filePath))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, err
	}

	for key, val := range form {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return v.do(req, headers)
}

// enable trace mode
func (v *DCHttpClient) enableTraceRequest(req *http.Request, trace *DCHttpTrace) *http.Request {
	context := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			trace.TotalSart = time.Now()
			trace.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			trace.DNSDone = time.Now()
			trace.DNSDuration = trace.DNSDone.Sub(trace.DNSStart)
		},
		ConnectStart: func(network, addr string) {
			trace.ConnectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			trace.ConnectDone = time.Now()
			trace.ConnectDuration = trace.ConnectDone.Sub(trace.ConnectStart)
		},
		TLSHandshakeStart: func() {
			trace.TLSHandshakeStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			trace.TLSHandshakeDone = time.Now()
			trace.TLSHandshakeDuration = trace.TLSHandshakeDone.Sub(trace.TLSHandshakeStart)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			trace.RequestSended = time.Now()
		},
		GotFirstResponseByte: func() {
			trace.ResponseReturned = time.Now()
			trace.ServerDuration = trace.ResponseReturned.Sub(trace.RequestSended)
		},
	})
	return req.WithContext(context)
}

// Do request with build-in http client
func (v *DCHttpClient) do(req *http.Request, headers map[string]string) (response *DCHttpResponse, err error) {

	response = &DCHttpResponse{}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if v.Trace {
		response.TraceInfo = &DCHttpTrace{}
		req = v.enableTraceRequest(req, response.TraceInfo)
		response.TraceInfo.TotalSart = time.Now()
	}

	defer func() {
		if !req.Close && req.Body != nil{
			req.Body.Close()
		}
	}()

	resp, err := v.Core.Do(req)
	if v.Trace {
		response.TraceInfo.TotalEnd = time.Now()
		response.TraceInfo.TotalDuration = response.TraceInfo.TotalEnd.Sub(response.TraceInfo.TotalSart)
	}
	if err != nil {
		return nil, err
	}
	response.Raw = resp
	response.Header = make(map[string]string)
	for k, _ := range resp.Header {
		response.Header[k] = resp.Header.Get(k)
	}
	return
}

// NewHttpClient help user to create a httpclient
//  @return
//     client: DCHttpClient instance
func NewHttpClient() (client *DCHttpClient) {

	// Although the http library has a built-in DefaultTransport, it is a pointer object.
	// Modifying this object will affect the every new httpClient properties.
	// So copying the source code of golang has opened up a Transport object only for the http client created now.
	// The source code is based on golang 1.12.9, slightly modified
	// Modification:
	// -- Increase ResponseHeaderTimeout judgment, no timeout by default, easy to encounter black hole request
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment, // Starting with 1.11, golang supports reading
		                                                  // the system's HTTP_PROXY and HTTPS_PROXY variables.
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		TLSClientConfig:       &tls.Config{},
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	dcClient := &DCHttpClient{
		Dialer:    dialer,
		Transport: tr,
		Core:      &http.Client{Transport: tr},
	}
	return dcClient
}
