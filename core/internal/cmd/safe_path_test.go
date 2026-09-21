package cmd

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/net/gtcp"
	"github.com/gogf/gf/v2/util/guid"
)

func TestIsSafePathExemptURI(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Roundcube：普通邮箱用户的 Webmail 入口
		{"/roundcube", true},
		{"/roundcube/", true},
		{"/roundcube/index.php", true},
		{"/roundcube/skins/elastic/styles.css", true},
		// ACME HTTP-01 验证
		{"/.well-known/acme-challenge", true},
		{"/.well-known/acme-challenge/", true},
		{"/.well-known/acme-challenge/token123", true},
		// 邮件跟踪链接
		{"/pmta", true},
		{"/pmta/aGVsbG8", true},
		// 管理后台路径必须继续受保护
		{"/", false},
		{"/overview", false},
		{"/api/overview/get", false},
		{"/rspamd/", false},
		// 形近路径不得被放行
		{"/roundcube-admin", false},
		{"/roundcubeadmin/x", false},
		{"/pmtax", false},
		{"/.well-known/acme-challenger", false},
		{"/.well-known/openid-configuration", false},
		// 前缀必须出现在路径开头
		{"/admin/roundcube", false},
	}

	for _, tt := range tests {
		if got := isSafePathExemptURI(tt.path); got != tt.want {
			t.Errorf("isSafePathExemptURI(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestTrimWebBasePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		basePath string
		want     string
	}{
		{"未配置前缀时原样返回", "/roundcube", "", "/roundcube"},
		{"未配置前缀时根路径不变", "/", "", "/"},
		{"命中前缀本身归一为根", "/billionmail", "/billionmail", "/"},
		{"前缀带尾斜杠归一为根", "/billionmail/", "/billionmail", "/"},
		{"剥掉前缀保留子路径", "/billionmail/roundcube", "/billionmail", "/roundcube"},
		{"剥掉前缀保留深层子路径", "/billionmail/api/overview/get", "/billionmail", "/api/overview/get"},
		{"未命中前缀时不改动", "/roundcube", "/billionmail", "/roundcube"},
		{"形近前缀不得被剥掉", "/billionmailx/roundcube", "/billionmail", "/billionmailx/roundcube"},
	}

	for _, tt := range tests {
		if got := trimWebBasePath(tt.path, tt.basePath); got != tt.want {
			t.Errorf("%s: trimWebBasePath(%q, %q) = %q, want %q", tt.name, tt.path, tt.basePath, got, tt.want)
		}
	}
}

// TestTrimWebBasePathMatchesSafePathExemption 覆盖反向代理前缀 + SafePath 同时启用的组合：
// hook 早于 stripWebBasePathMiddleware 执行，必须先归一化路径，豁免判断才会生效。
func TestTrimWebBasePathMatchesSafePathExemption(t *testing.T) {
	const basePath = "/billionmail"

	for _, path := range []string{
		"/billionmail/roundcube",
		"/billionmail/roundcube/index.php",
		"/billionmail/.well-known/acme-challenge/token123",
		"/billionmail/pmta/aGVsbG8",
	} {
		if !isSafePathExemptURI(trimWebBasePath(path, basePath)) {
			t.Errorf("带前缀的公共路由 %q 未被豁免", path)
		}
	}

	if isSafePathExemptURI(trimWebBasePath("/billionmail/overview", basePath)) {
		t.Error("带前缀的管理后台路径不应被豁免")
	}
}

// TestPublicRoutesAreNotSwallowedByFallback 固定住路由层的前提：
// isSafePathExemptURI 只有在这些路径确实能命中各自的 handler、
// 而不是掉进 "/*any" 静态兜底时才有意义。GoFrame 的 "*any" 可匹配空串，
// 因此不带尾斜杠的 /roundcube、/pmta 同样由专属 handler 处理。
func TestPublicRoutesAreNotSwallowedByFallback(t *testing.T) {
	port, err := gtcp.GetFreePort()
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}

	s := g.Server(guid.S())
	s.SetPort(port)
	s.SetDumpRouterMap(false)
	s.SetLogStdout(false)

	// 与 cmd.go 中的路由绑定保持一致
	s.BindHandler("/roundcube/*any", func(r *ghttp.Request) { r.Response.Write("roundcube") })
	s.BindHandler("/.well-known/acme-challenge/*any", func(r *ghttp.Request) { r.Response.Write("acme") })
	s.BindHandler("/pmta/*any", func(r *ghttp.Request) { r.Response.Write("pmta") })
	s.BindHandler("/*any", func(r *ghttp.Request) { r.Response.Write("fallback") })

	s.Start()
	defer s.Shutdown()
	time.Sleep(300 * time.Millisecond)

	tests := []struct {
		path string
		want string
	}{
		{"/roundcube", "roundcube"},
		{"/roundcube/", "roundcube"},
		{"/roundcube/index.php", "roundcube"},
		{"/.well-known/acme-challenge/token123", "acme"},
		{"/pmta", "pmta"},
		{"/pmta/aGVsbG8", "pmta"},
		{"/overview", "fallback"},
	}

	for _, tt := range tests {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, tt.path))
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", tt.path, err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(body) != tt.want {
			t.Errorf("%s 命中 %q，期望 %q", tt.path, string(body), tt.want)
		}
	}
}
