package cmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/net/gtcp"
	"github.com/gogf/gf/v2/util/guid"
)

func TestIsHTTPSRedirectExemptURI(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// ACME HTTP-01 验证必须保留明文
		{"/.well-known/acme-challenge", true},
		{"/.well-known/acme-challenge/", true},
		{"/.well-known/acme-challenge/token123", true},
		// 其余路径一律跳转
		{"/", false},
		{"/overview", false},
		{"/roundcube/", false},
		{"/api/batch_mail/api/send", false},
		// 形近路径不得被豁免
		{"/.well-known/acme-challenger", false},
		{"/.well-known/openid-configuration", false},
		{"/admin/.well-known/acme-challenge", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isHTTPSRedirectExemptURI(tt.path); got != tt.want {
			t.Errorf("isHTTPSRedirectExemptURI(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestForceHTTPSEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{"未配置时默认开启", "", true},
		{"0 关闭", "0", false},
		{"false 关闭", "false", false},
		{"off 关闭", "off", false},
		{"no 关闭", "no", false},
		{"大小写不敏感", "FALSE", false},
		{"带空白仍能识别", "  off  ", false},
		{"1 开启", "1", true},
		{"true 开启", "true", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(forceHTTPSEnvKey, tt.env)

			if got := forceHTTPSEnabled(); got != tt.want {
				t.Errorf("forceHTTPSEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHTTPSRedirectStatus 锁定方法语义：POST 等带请求体的方法必须用 308，
// 用 301 会被客户端改写成 GET，HTTP 调用发信 API 时请求体就丢了。
func TestHTTPSRedirectStatus(t *testing.T) {
	tests := []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusMovedPermanently},
		{http.MethodHead, http.StatusMovedPermanently},
		{"get", http.StatusMovedPermanently},
		{"", http.StatusMovedPermanently},
		{http.MethodPost, http.StatusPermanentRedirect},
		{http.MethodPut, http.StatusPermanentRedirect},
		{http.MethodDelete, http.StatusPermanentRedirect},
	}

	for _, tt := range tests {
		if got := httpsRedirectStatus(tt.method); got != tt.want {
			t.Errorf("httpsRedirectStatus(%q) = %d, want %d", tt.method, got, tt.want)
		}
	}
}

func TestHTTPSRedirectTarget(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		requestURI string
		httpsPort  int
		want       string
	}{
		{"标准 443 不带端口", "mail.example.com", "/overview", 443, "https://mail.example.com/overview"},
		{"Host 带 80 端口要换掉", "mail.example.com:80", "/overview", 443, "https://mail.example.com/overview"},
		{"非标准端口要写进目标", "mail.example.com", "/overview", 8443, "https://mail.example.com:8443/overview"},
		{"保留查询串", "mail.example.com", "/roundcube/?_task=mail", 443, "https://mail.example.com/roundcube/?_task=mail"},
		{"空路径归一为根", "mail.example.com", "", 443, "https://mail.example.com/"},
		{"IPv6 字面量加方括号", "[::1]:80", "/", 443, "https://[::1]/"},
		{"IPv6 字面量带非标端口", "[::1]:80", "/", 8443, "https://[::1]:8443/"},
		{"Host 缺失时不跳转", "", "/overview", 443, ""},
		{"Host 全是空白时不跳转", "   ", "/overview", 443, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpsRedirectTarget(tt.host, tt.requestURI, tt.httpsPort); got != tt.want {
				t.Errorf("httpsRedirectTarget(%q, %q, %d) = %q, want %q",
					tt.host, tt.requestURI, tt.httpsPort, got, tt.want)
			}
		})
	}
}

// TestRequestIsSecure 覆盖反向代理场景：认不出 X-Forwarded-Proto 就会把
// 反代后面的部署打进无限重定向。
func TestRequestIsSecure(t *testing.T) {
	newRequest := func(tlsOn bool, headers map[string]string) *ghttp.Request {
		req, err := http.NewRequest(http.MethodGet, "http://mail.example.com/overview", nil)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}

		if tlsOn {
			req.TLS = &tls.ConnectionState{}
		}

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		return &ghttp.Request{Request: req}
	}

	tests := []struct {
		name    string
		tlsOn   bool
		headers map[string]string
		want    bool
	}{
		{"直连 TLS", true, nil, true},
		{"明文直连", false, nil, false},
		{"反代声明 https", false, map[string]string{"X-Forwarded-Proto": "https"}, true},
		{"反代声明 http", false, map[string]string{"X-Forwarded-Proto": "http"}, false},
		{"大小写不敏感", false, map[string]string{"X-Forwarded-Proto": "HTTPS"}, true},
		{"多级代理取最前一跳", false, map[string]string{"X-Forwarded-Proto": "https, http"}, true},
		{"多级代理首跳是明文", false, map[string]string{"X-Forwarded-Proto": "http, https"}, false},
		{"兼容 X-Forwarded-Protocol", false, map[string]string{"X-Forwarded-Protocol": "https"}, true},
		{"兼容 X-Forwarded-Ssl", false, map[string]string{"X-Forwarded-Ssl": "on"}, true},
		{"X-Forwarded-Ssl 为 off", false, map[string]string{"X-Forwarded-Ssl": "off"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestIsSecure(newRequest(tt.tlsOn, tt.headers)); got != tt.want {
				t.Errorf("requestIsSecure() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEnforceHTTPSOverHTTP 是端到端验证：明文请求应拿到跳转，
// ACME 验证路径和关闭开关后的请求应照常被后端处理。
func TestEnforceHTTPSOverHTTP(t *testing.T) {
	port, err := gtcp.GetFreePort()
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}

	s := g.Server(guid.S())
	s.SetPort(port)
	s.SetDumpRouterMap(false)
	s.SetLogStdout(false)

	// 与 cmd.go 中的 hook 绑定保持一致
	s.BindHookHandlerByMap("/*", map[ghttp.HookName]ghttp.HandlerFunc{
		ghttp.HookBeforeServe: func(r *ghttp.Request) {
			if enforceHTTPS(r, "", 443) {
				r.ExitAll()
			}
		},
	})
	s.BindHandler("/*any", func(r *ghttp.Request) { r.Response.Write("served") })

	s.Start()
	defer s.Shutdown()
	time.Sleep(300 * time.Millisecond)

	// 不跟随跳转，否则拿不到 3xx 响应本身
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	request := func(t *testing.T, method, path string, headers map[string]string) *http.Response {
		t.Helper()

		req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", path, err)
		}

		t.Cleanup(func() { resp.Body.Close() })

		return resp
	}

	// 尾斜杠必须原样保留：GoFrame 会在 hook 之前规范化 r.URL，
	// 用规范化后的路径拼跳转会把访客甩到另一个地址上。
	t.Run("明文 GET 跳转到 HTTPS", func(t *testing.T) {
		t.Setenv(forceHTTPSEnvKey, "")

		resp := request(t, http.MethodGet, "/roundcube/", nil)

		if resp.StatusCode != http.StatusMovedPermanently {
			t.Errorf("状态码 = %d, want %d", resp.StatusCode, http.StatusMovedPermanently)
		}

		if got, want := resp.Header.Get("Location"), "https://127.0.0.1/roundcube/"; got != want {
			t.Errorf("Location = %q, want %q", got, want)
		}
	})

	t.Run("查询串原样带到 HTTPS", func(t *testing.T) {
		t.Setenv(forceHTTPSEnvKey, "")

		resp := request(t, http.MethodGet, "/roundcube/?_task=mail&_action=show", nil)

		if got, want := resp.Header.Get("Location"), "https://127.0.0.1/roundcube/?_task=mail&_action=show"; got != want {
			t.Errorf("Location = %q, want %q", got, want)
		}
	})

	t.Run("明文 POST 用 308 保留方法", func(t *testing.T) {
		t.Setenv(forceHTTPSEnvKey, "")

		resp := request(t, http.MethodPost, "/api/batch_mail/api/send", nil)

		if resp.StatusCode != http.StatusPermanentRedirect {
			t.Errorf("状态码 = %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
		}
	})

	t.Run("ACME 验证路径保留明文", func(t *testing.T) {
		t.Setenv(forceHTTPSEnvKey, "")

		resp := request(t, http.MethodGet, "/.well-known/acme-challenge/token123", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("状态码 = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("反代已终止 TLS 时不跳转", func(t *testing.T) {
		t.Setenv(forceHTTPSEnvKey, "")

		resp := request(t, http.MethodGet, "/overview", map[string]string{"X-Forwarded-Proto": "https"})

		if resp.StatusCode != http.StatusOK {
			t.Errorf("状态码 = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("关闭开关后退回明文服务", func(t *testing.T) {
		t.Setenv(forceHTTPSEnvKey, "0")

		resp := request(t, http.MethodGet, "/overview", nil)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("状态码 = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}
