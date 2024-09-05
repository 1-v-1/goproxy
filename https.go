package goproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/imroc/req/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type ConnectActionLiteral int

const (
	ConnectAccept = iota
	ConnectReject
	ConnectMitm
	ConnectHijack
	ConnectHTTPMitm
	ConnectProxyAuthHijack
)

var (
	OkConnect       = &ConnectAction{Action: ConnectAccept, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	MitmConnect     = &ConnectAction{Action: ConnectMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	HTTPMitmConnect = &ConnectAction{Action: ConnectHTTPMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	RejectConnect   = &ConnectAction{Action: ConnectReject, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	httpsRegexp     = regexp.MustCompile(`^https:\/\/`)
)

// ConnectAction enables the caller to override the standard connect flow.
// When Action is ConnectHijack, it is up to the implementer to send the
// HTTP 200, or any other valid http response back to the client from within the
// Hijack func
type ConnectAction struct {
	Action    ConnectActionLiteral
	Hijack    func(req *http.Request, client net.Conn, ctx *ProxyCtx)
	TLSConfig func(host string, ctx *ProxyCtx) (*tls.Config, error)
}

func stripPort(s string) string {
	var ix int
	if strings.Contains(s, "[") && strings.Contains(s, "]") {
		//ipv6 : for example : [2606:4700:4700::1111]:443

		//strip '[' and ']'
		s = strings.ReplaceAll(s, "[", "")
		s = strings.ReplaceAll(s, "]", "")

		ix = strings.LastIndexAny(s, ":")
		if ix == -1 {
			return s
		}
	} else {
		//ipv4
		ix = strings.IndexRune(s, ':')
		if ix == -1 {
			return s
		}

	}
	return s[:ix]
}

func (proxy *ProxyHttpServer) dial(network, addr string) (c net.Conn, err error) {
	//if proxy.Tr.Dial != nil {
	//	return proxy.Tr.Dial(network, addr)
	//}
	if proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(context.Background(), network, addr)
	}
	return net.Dial(network, addr)
}

func (proxy *ProxyHttpServer) connectDial(ctx *ProxyCtx, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDialWithReq == nil && proxy.ConnectDial == nil {
		return proxy.dial(network, addr)
	}

	if proxy.ConnectDialWithReq != nil {
		return proxy.ConnectDialWithReq(ctx.Req, network, addr)
	}

	return proxy.ConnectDial(network, addr)
}

type halfClosable interface {
	net.Conn
	CloseWrite() error
	CloseRead() error
}

var _ halfClosable = (*net.TCPConn)(nil)

func (proxy *ProxyHttpServer) handleHttps(w http.ResponseWriter, r *http.Request) {
	ctx := &ProxyCtx{Req: r, Session: atomic.AddInt64(&proxy.sess, 1), Proxy: proxy, certStore: proxy.CertStore}

	hij, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	proxyClient, _, e := hij.Hijack()
	if e != nil {
		panic("Cannot hijack connection " + e.Error())
	}

	ctx.Logf("Running %d CONNECT handlers", len(proxy.httpsHandlers))
	todo, host := OkConnect, r.URL.Host
	for i, h := range proxy.httpsHandlers {
		newtodo, newhost := h.HandleConnect(host, ctx)

		// If found a result, break the loop immediately
		if newtodo != nil {
			todo, host = newtodo, newhost
			ctx.Logf("on %dth handler: %v %s", i, todo, host)
			break
		}
	}
	switch todo.Action {
	case ConnectAccept:
		if !hasPort.MatchString(host) {
			host += ":80"
		}
		targetSiteCon, err := proxy.connectDial(ctx, "tcp", host)
		if err != nil {
			ctx.Warnf("Error dialing to %s: %s", host, err.Error())
			httpError(proxyClient, ctx, err)
			return
		}
		ctx.Logf("Accepting CONNECT to %s", host)
		proxyClient.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

		targetTCP, targetOK := targetSiteCon.(halfClosable)
		proxyClientTCP, clientOK := proxyClient.(halfClosable)
		if targetOK && clientOK {
			go copyAndClose(ctx, targetTCP, proxyClientTCP)
			go copyAndClose(ctx, proxyClientTCP, targetTCP)
		} else {
			go func() {
				var wg sync.WaitGroup
				wg.Add(2)
				go copyOrWarn(ctx, targetSiteCon, proxyClient, &wg)
				go copyOrWarn(ctx, proxyClient, targetSiteCon, &wg)
				wg.Wait()
				proxyClient.Close()
				targetSiteCon.Close()

			}()
		}

	case ConnectHijack:
		todo.Hijack(r, proxyClient, ctx)
	case ConnectHTTPMitm:
		proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		ctx.Logf("Assuming CONNECT is plain HTTP tunneling, mitm proxying it")
		targetSiteCon, err := proxy.connectDial(ctx, "tcp", host)
		if err != nil {
			ctx.Warnf("Error dialing to %s: %s", host, err.Error())
			return
		}
		for {
			client := bufio.NewReader(proxyClient)
			remote := bufio.NewReader(targetSiteCon)

			var clientCopy bytes.Buffer
			tee := io.TeeReader(client, &clientCopy)
			req, err := http.ReadRequest(bufio.NewReader(tee))
			ctx.RawRequest, _ = io.ReadAll(&clientCopy)

			lines := strings.Split(strings.Split(string(ctx.RawRequest), "\r\n\r\n")[0], "\r\n")
			keys := make([]string, 0, len(lines))
			for _, line := range lines[1:] {
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					keys = append(keys, parts[0])
				}
			}
			ctx.HeaderOrder = keys

			if err != nil && err != io.EOF {
				ctx.Warnf("cannot read request of MITM HTTP client: %+#v", err)
			}
			if err != nil {
				return
			}
			req, resp := proxy.filterRequest(req, ctx)
			if resp == nil {
				if err := req.Write(targetSiteCon); err != nil {
					httpError(proxyClient, ctx, err)
					return
				}
				resp, err = http.ReadResponse(remote, req)
				if err != nil {
					httpError(proxyClient, ctx, err)
					return
				}
				defer resp.Body.Close()
			}
			resp = proxy.filterResponse(resp, ctx)
			if err := resp.Write(proxyClient); err != nil {
				httpError(proxyClient, ctx, err)
				return
			}
		}
	case ConnectMitm:
		proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		ctx.Logf("Assuming CONNECT is TLS, mitm proxying it")
		// this goes in a separate goroutine, so that the net/http server won't think we're
		// still handling the request even after hijacking the connection. Those HTTP CONNECT
		// request can take forever, and the server will be stuck when "closed".
		// TODO: Allow Server.Close() mechanism to shut down this connection as nicely as possible
		tlsConfig := defaultTLSConfig
		if todo.TLSConfig != nil {
			var err error
			tlsConfig, err = todo.TLSConfig(host, ctx)
			if err != nil {
				httpError(proxyClient, ctx, err)
				return
			}
		}
		go func() {
			//TODO: cache connections to the remote website
			rawClientTls := tls.Server(proxyClient, tlsConfig)
			defer rawClientTls.Close()
			if err := rawClientTls.Handshake(); err != nil {
				ctx.Warnf("Cannot handshake client %v %v", r.Host, err)
				return
			}

			//判断是否协商了http2
			if rawClientTls.ConnectionState().NegotiatedProtocol == "h2" {
				ctx.Logf("Client is using HTTP2")

				//pr, pw := io.Pipe()
				//tee := io.TeeReader(rawClientTls, pw)
				//go func() {
				//	b := make([]byte, len(http2.ClientPreface))
				//	if _, err := io.ReadFull(pr, b); err != nil {
				//		log.Println("read preface err", err)
				//	}
				//
				//	framer := http2.NewFramer(nil, pr)
				//	for {
				//		frame, err := framer.ReadFrame()
				//		if err == io.EOF {
				//			log.Println("EOF")
				//			return
				//		}
				//		if err != nil {
				//			log.Println("read frame err", err)
				//		}
				//		switch f := frame.(type) {
				//		case *http2.HeadersFrame:
				//			//log.Println("headers", f.HeaderBlockFragment())
				//			hpackDecoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
				//			headerFields, err := hpackDecoder.DecodeFull(f.HeaderBlockFragment())
				//			if err != nil {
				//				log.Fatalf("Failed to decode header block: %v", err)
				//			}
				//			for _, v := range headerFields {
				//				log.Println(v)
				//			}
				//
				//		case *http2.DataFrame:
				//			fmt.Printf("Data frame received: %s\n", string(f.Data()))
				//		default:
				//			log.Println("frame", frame)
				//
				//		}
				//	}
				//}()

				pr, pw := io.Pipe()
				go func() {
					b := make([]byte, len(http2.ClientPreface))
					if _, err := io.ReadFull(rawClientTls, b); err != nil {
						log.Println("read preface err", err)
					}
					pw.Write(b)

					framer := http2.NewFramer(nil, rawClientTls)
					framer2 := http2.NewFramer(pw, nil)
					for {
						frame, err := framer.ReadFrame()
						if err == io.EOF {
							log.Println("EOF")
							pw.Close()
							return
						}
						if err != nil {
							//log.Println("read frame err", err)  每一次请求结束都会到这来，或许有更好的转发方式
							pw.Close()
							return
						}
						header := frame.Header()
						hDec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
						hEnc := hpack.NewEncoder(pw)
						hBuf := bytes.NewBuffer(nil)

						switch f := frame.(type) {
						case *http2.DataFrame:
							framer2.WriteData(header.StreamID, false, f.Data())
						case *http2.HeadersFrame:
							headerFields, err := hDec.DecodeFull(f.HeaderBlockFragment())
							if err != nil {
								log.Printf("Failed to decode header block: %v\n", err)
								pw.Close()
							}

							hBuf.Reset()
							headerOderKey := ""
							pseudoHeaderOderKey := ""
							for k, v := range headerFields {
								if k < 4 {
									pseudoHeaderOderKey += v.Name + ","
								} else {
									headerOderKey += v.Name + ","
								}
								hEnc.WriteField(hpack.HeaderField{Name: v.Name, Value: v.Value})
							}
							//先省略了ctx.rawHeader、order的写入 后面使用时要注意
							hEnc.WriteField(hpack.HeaderField{Name: req.HeaderOderKey, Value: headerOderKey})
							hEnc.WriteField(hpack.HeaderField{Name: req.PseudoHeaderOderKey, Value: pseudoHeaderOderKey})
							framer2.WriteHeaders(http2.HeadersFrameParam{
								StreamID: header.StreamID,
								//BlockFragment: f.HeaderBlockFragment(),
								BlockFragment: hBuf.Bytes(),
								EndStream:     f.StreamEnded(),
								EndHeaders:    f.HeadersEnded(),
								PadLength:     0,
								Priority:      f.Priority,
							})
						case *http2.PriorityFrame:
							framer2.WritePriority(header.StreamID, f.PriorityParam)
						case *http2.RSTStreamFrame:
							framer2.WriteRSTStream(header.StreamID, f.ErrCode)
						case *http2.SettingsFrame:
							//这样会报错connection error: PROTOCOL_ERROR
							//settings := make([]http2.Setting, f.NumSettings())
							//for i := 0; i < f.NumSettings(); i++ {
							//	settings[i] = f.Setting(i)
							//}
							//err := framer2.WriteSettings(settings...)

							var buf []byte
							for i := 0; i < f.NumSettings(); i++ {
								setting := f.Setting(i)
								buf = append(buf, byte(setting.ID>>8), byte(setting.ID), byte(setting.Val>>24), byte(setting.Val>>16), byte(setting.Val>>8), byte(setting.Val))
							}
							framer2.WriteRawFrame(header.Type, header.Flags, header.StreamID, buf)

						case *http2.PushPromiseFrame:
							framer2.WriteRawFrame(header.Type, header.Flags, header.StreamID, f.HeaderBlockFragment())
						case *http2.PingFrame:
							framer2.WritePing(f.IsAck(), f.Data)
						case *http2.GoAwayFrame:
							framer2.WriteGoAway(f.LastStreamID, f.ErrCode, f.DebugData())
						case *http2.WindowUpdateFrame:
							framer2.WriteWindowUpdate(header.StreamID, f.Increment)
						case *http2.ContinuationFrame:
							framer2.WriteContinuation(header.StreamID, f.HeadersEnded(), f.HeaderBlockFragment())
						case *http2.UnknownFrame:
							framer2.WriteRawFrame(header.Type, header.Flags, header.StreamID, f.Payload())
						default:
							log.Println("未知帧")
						}
					}
				}()
				//可以在上面直接拿到res了 只是要自己处理stream
				conn := &teeConn{
					Conn:   rawClientTls,
					reader: pr,
				}
				h2Server := &http2.Server{}
				h2Server.ServeConn(conn, &http2.ServeConnOpts{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if isWebSocketRequest(req) {
							ctx.Logf("Request looks like websocket upgrade.")
							proxy.serveWebsocketTLS(ctx, w, req, tlsConfig, rawClientTls)
							return
						}

						rawRequest, err := httputil.DumpRequest(req, false)
						if err != nil {
							ctx.Warnf("Cannot dump request: %v", err)
							return
						}
						ctx.RawRequest = rawRequest
						lines := strings.Split(strings.Split(string(ctx.RawRequest), "\r\n\r\n")[0], "\r\n")
						keys := make([]string, 0, len(lines))
						for _, line := range lines[1:] {
							parts := strings.Split(line, ":")
							if len(parts) > 0 {
								keys = append(keys, parts[0])
							}
						}
						ctx.HeaderOrder = keys

						if !httpsRegexp.MatchString(req.URL.String()) {
							req.URL, _ = url.Parse("https://" + r.Host + req.URL.String())
						}
						ctx.Req = req
						req, resp := proxy.filterRequest(req, ctx)
						removeProxyHeaders(ctx, req)
						resp, err = func() (*http.Response, error) {
							defer req.Body.Close()
							return ctx.RoundTrip(req)
							//return http.DefaultTransport.RoundTrip(req)
						}()
						if err != nil {
							http.Error(w, "", http.StatusInternalServerError)
							ctx.Warnf("Cannot read HTTP2 response from mitm'd server %v", err)
							return
						}
						resp = proxy.filterResponse(resp, ctx)
						defer resp.Body.Close()

						// Copy response headers
						for k, v := range resp.Header {
							w.Header()[k] = v
						}

						w.WriteHeader(resp.StatusCode)
						io.Copy(w, resp.Body)
						return
					}),
				})
			}
			clientTlsReader := bufio.NewReader(rawClientTls)
			for !isEof(clientTlsReader) {

				var clientTlsReaderCopy bytes.Buffer
				tee := io.TeeReader(clientTlsReader, &clientTlsReaderCopy)
				req, err := http.ReadRequest(bufio.NewReader(tee))

				var ctx = &ProxyCtx{Req: req, Session: atomic.AddInt64(&proxy.sess, 1), Proxy: proxy, UserData: ctx.UserData}
				ctx.RawRequest, _ = io.ReadAll(&clientTlsReaderCopy)

				//lines := strings.Split(strings.Trim(string(ctx.RawRequest), "\r\n"), "\r\n")
				lines := strings.Split(strings.Split(string(ctx.RawRequest), "\r\n\r\n")[0], "\r\n")
				keys := make([]string, 0, len(lines))
				for _, line := range lines[1:] {
					parts := strings.Split(line, ":")
					if len(parts) > 0 {
						keys = append(keys, parts[0])
					}
				}
				ctx.HeaderOrder = keys

				if err != nil && err != io.EOF {
					return
				}
				if err != nil {
					ctx.Warnf("Cannot read TLS request from mitm'd client %v %v", r.Host, err)
					return
				}
				req.RemoteAddr = r.RemoteAddr // since we're converting the request, need to carry over the original connecting IP as well
				ctx.Logf("req %v", r.Host)

				if !httpsRegexp.MatchString(req.URL.String()) {
					req.URL, err = url.Parse("https://" + r.Host + req.URL.String())
				}

				// Bug fix which goproxy fails to provide request
				// information URL in the context when does HTTPS MITM
				ctx.Req = req

				req, resp := proxy.filterRequest(req, ctx)
				if resp == nil {
					if req.Method == "PRI" {
						// Handle HTTP/2 connections.

						// NOTE: As of 1.22, golang's http module will not recognize or
						// parse the HTTP Body for PRI requests. This leaves the body of
						// the http2.ClientPreface ("SM\r\n\r\n") on the wire which we need
						// to clear before setting up the connection.
						_, err := clientTlsReader.Discard(6)
						if err != nil {
							ctx.Warnf("Failed to process HTTP2 client preface: %v", err)
							return
						}
						if !proxy.AllowHTTP2 {
							ctx.Warnf("HTTP2 connection failed: disallowed")
							return
						}
						tr := H2Transport{clientTlsReader, rawClientTls, tlsConfig.Clone(), host}
						if _, err := tr.RoundTrip(req); err != nil {
							ctx.Warnf("HTTP2 connection failed: %v", err)
						} else {
							ctx.Logf("Exiting on EOF")
						}
						return
					}
					if isWebSocketRequest(req) {
						ctx.Logf("Request looks like websocket upgrade.")
						proxy.serveWebsocketTLS(ctx, w, req, tlsConfig, rawClientTls)
						return
					}
					if err != nil {
						if req.URL != nil {
							ctx.Warnf("Illegal URL %s", "https://"+r.Host+req.URL.Path)
						} else {
							ctx.Warnf("Illegal URL %s", "https://"+r.Host)
						}
						return
					}
					removeProxyHeaders(ctx, req)
					resp, err = func() (*http.Response, error) {
						// explicitly discard request body to avoid data races in certain RoundTripper implementations
						// see https://github.com/golang/go/issues/61596#issuecomment-1652345131
						defer req.Body.Close()
						return ctx.RoundTrip(req)
					}()
					if err != nil {
						ctx.Warnf("Cannot read TLS response from mitm'd server %v", err)
						return
					}
					ctx.Logf("resp %v", resp.Status)
				}
				resp = proxy.filterResponse(resp, ctx)
				defer resp.Body.Close()

				text := resp.Status
				protoMajor, protoMinor := strconv.Itoa(resp.ProtoMajor), strconv.Itoa(resp.ProtoMinor)
				statusCode := strconv.Itoa(resp.StatusCode) + " "
				if strings.HasPrefix(text, statusCode) {
					text = text[len(statusCode):]
				}
				// always use 1.1 to support chunked encoding
				//if _, err := io.WriteString(rawClientTls, "HTTP/1.1"+" "+statusCode+text+"\r\n"); err != nil {
				if _, err := io.WriteString(rawClientTls, "HTTP/"+protoMajor+"."+protoMinor+" "+statusCode+text+"\r\n"); err != nil {
					ctx.Warnf("Cannot write TLS response HTTP status from mitm'd client: %v", err)
					return
				}

				if resp.Request.Method == "HEAD" {
					// don't change Content-Length for HEAD request
				} else {
					// Since we don't know the length of resp, return chunked encoded response
					// TODO: use a more reasonable scheme
					resp.Header.Del("Content-Length")
					resp.Header.Set("Transfer-Encoding", "chunked")
				}
				// Force connection close otherwise chrome will keep CONNECT tunnel open forever
				resp.Header.Set("Connection", "close")
				if err := resp.Header.Write(rawClientTls); err != nil {
					ctx.Warnf("Cannot write TLS response header from mitm'd client: %v", err)
					return
				}
				if _, err = io.WriteString(rawClientTls, "\r\n"); err != nil {
					ctx.Warnf("Cannot write TLS response header end from mitm'd client: %v", err)
					return
				}

				if resp.Request.Method == "HEAD" {
					// Don't write out a response body for HEAD request
				} else {
					chunked := newChunkedWriter(rawClientTls)
					if _, err := io.Copy(chunked, resp.Body); err != nil {
						ctx.Warnf("Cannot write TLS response body from mitm'd client: %v", err)
						return
					}
					if err := chunked.Close(); err != nil {
						ctx.Warnf("Cannot write TLS chunked EOF from mitm'd client: %v", err)
						return
					}
					if _, err = io.WriteString(rawClientTls, "\r\n"); err != nil {
						ctx.Warnf("Cannot write TLS response chunked trailer from mitm'd client: %v", err)
						return
					}
				}
			}
			ctx.Logf("Exiting on EOF")
		}()
	case ConnectProxyAuthHijack:
		proxyClient.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n"))
		todo.Hijack(r, proxyClient, ctx)
	case ConnectReject:
		if ctx.Resp != nil {
			if err := ctx.Resp.Write(proxyClient); err != nil {
				ctx.Warnf("Cannot write response that reject http CONNECT: %v", err)
			}
		}
		proxyClient.Close()
	}
}

func httpError(w io.WriteCloser, ctx *ProxyCtx, err error) {
	errStr := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(err.Error()), err.Error())
	if _, err := io.WriteString(w, errStr); err != nil {
		ctx.Warnf("Error responding to client: %s", err)
	}
	if err := w.Close(); err != nil {
		ctx.Warnf("Error closing client connection: %s", err)
	}
}

func copyOrWarn(ctx *ProxyCtx, dst io.Writer, src io.Reader, wg *sync.WaitGroup) {
	if _, err := io.Copy(dst, src); err != nil {
		ctx.Warnf("Error copying to client: %s", err)
	}
	wg.Done()
}

func copyAndClose(ctx *ProxyCtx, dst, src halfClosable) {
	if _, err := io.Copy(dst, src); err != nil {
		ctx.Warnf("Error copying to client: %s", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func dialerFromEnv(proxy *ProxyHttpServer) func(network, addr string) (net.Conn, error) {
	https_proxy := os.Getenv("HTTPS_PROXY")
	if https_proxy == "" {
		https_proxy = os.Getenv("https_proxy")
	}
	if https_proxy == "" {
		return nil
	}
	return proxy.NewConnectDialToProxy(https_proxy)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxy(https_proxy string) func(network, addr string) (net.Conn, error) {
	return proxy.NewConnectDialToProxyWithHandler(https_proxy, nil)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxyWithHandler(https_proxy string, connectReqHandler func(req *http.Request)) func(network, addr string) (net.Conn, error) {
	u, err := url.Parse(https_proxy)
	if err != nil {
		return nil
	}
	if u.Scheme == "" || u.Scheme == "http" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":80"
		}
		return func(network, addr string) (net.Conn, error) {
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			c, err := proxy.dial(network, u.Host)
			if err != nil {
				return nil, err
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				resp, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
				c.Close()
				return nil, errors.New("proxy refused connection" + string(resp))
			}
			return c, nil
		}
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":443"
		}
		return func(network, addr string) (net.Conn, error) {
			c, err := proxy.dial(network, u.Host)
			if err != nil {
				return nil, err
			}
			c = tls.Client(c, proxy.Tr.TLSClientConfig)
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 500))
				if err != nil {
					return nil, err
				}
				c.Close()
				return nil, errors.New("proxy refused connection" + string(body))
			}
			return c, nil
		}
	}
	return nil
}

func TLSConfigFromCA(ca *tls.Certificate) func(host string, ctx *ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *ProxyCtx) (*tls.Config, error) {
		var err error
		var cert *tls.Certificate

		hostname := stripPort(host)
		config := defaultTLSConfig.Clone()
		ctx.Logf("signing for %s", stripPort(host))

		genCert := func() (*tls.Certificate, error) {
			return signHost(*ca, []string{hostname})
		}
		if ctx.certStore != nil {
			cert, err = ctx.certStore.Fetch(hostname, genCert)
		} else {
			cert, err = genCert()
		}

		if err != nil {
			ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}

		config.Certificates = append(config.Certificates, *cert)
		config.NextProtos = []string{"h2", "http/1.1"}
		return config, nil
	}
}

type teeConn struct {
	net.Conn
	reader io.Reader
}

func (t *teeConn) Read(b []byte) (int, error) {
	return t.reader.Read(b)
}
