package cmd

import (
	"billionmail-core/internal/service/public"
	"context"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/util/gconv"
)

// forceHTTPSEnvKey 控制“明文 HTTP 请求一律跳转到 HTTPS”，默认开启。
// 上游同时监听 80 和 443，但两个端口都直接提供服务，控制台登录页和 Webmail
// 登录页都能用明文打开，密码会以明文过网。关掉它就退回上游行为。
const forceHTTPSEnvKey = "FORCE_HTTPS"

// forceHTTPSEnabled 读取开关。未配置时返回 true——邮件系统的登录入口不应允许明文访问。
func forceHTTPSEnabled() bool {
	for _, v := range []string{os.Getenv(forceHTTPSEnvKey), public.MustGetDockerEnv(forceHTTPSEnvKey, "")} {
		v = strings.ToLower(strings.TrimSpace(v))

		if v == "" {
			continue
		}

		_, falsy := falsyEnvValues[v]

		return !falsy
	}

	return true
}

// httpsRedirectExemptPrefixes 列出必须保留明文 HTTP 的路由前缀。
//
//   - /.well-known/acme-challenge  证书签发/续期的 HTTP-01 验证。验证方虽然会跟随
//     重定向，但首次签发时本机还没有可用证书，把它推去 HTTPS 只会平白增加失败面。
var httpsRedirectExemptPrefixes = []string{
	"/.well-known/acme-challenge",
}

// isHTTPSRedirectExemptURI 判断 path 是否属于上述必须保留明文的路由。
// 匹配规则与 isSafePathExemptURI 一致：完全相等或以 "/" 为边界。
func isHTTPSRedirectExemptURI(path string) bool {
	for _, prefix := range httpsRedirectExemptPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}

	return false
}

// requestIsSecure 判断请求到达时是否已经过加密。
func requestIsSecure(r *ghttp.Request) bool {
	if r.TLS != nil {
		return true
	}

	// TLS 由前置反向代理终止时 core 收到的是明文，必须认这些头，
	// 否则反代后面的部署会陷入无限重定向。
	// 头可被客户端伪造，但伪造的后果只是自己继续用明文，不影响其他访客。
	proto := r.Header.Get("X-Forwarded-Proto")

	if proto == "" {
		proto = r.Header.Get("X-Forwarded-Protocol")
	}

	// 多级代理会累加成 "https, http"，最靠近客户端的一跳在最前面。
	if idx := strings.Index(proto, ","); idx >= 0 {
		proto = proto[:idx]
	}

	if strings.EqualFold(strings.TrimSpace(proto), "https") {
		return true
	}

	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Ssl")), "on")
}

// httpsRedirectStatus 选择跳转状态码。
// GET/HEAD 用 301 让浏览器记住；其余方法用 308，保留请求方法与请求体，
// 避免 HTTP 调用发信 API 时被降级成 GET 而丢掉 body。
func httpsRedirectStatus(method string) int {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", http.MethodGet, http.MethodHead:
		return http.StatusMovedPermanently
	default:
		return http.StatusPermanentRedirect
	}
}

// httpsRedirectTarget 拼出跳转目标绝对地址；返回空串表示信息不足、不应跳转。
func httpsRedirectTarget(host, requestURI string, httpsPort int) string {
	host = strings.TrimSpace(host)

	if host == "" {
		return ""
	}

	// Host 头常带着 HTTP 端口（mail.example.com:80），要换成 HTTPS 端口。
	hostname := host

	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	if hostname == "" {
		return ""
	}

	if httpsPort > 0 && httpsPort != 443 {
		hostname = net.JoinHostPort(hostname, strconv.Itoa(httpsPort))
	} else if strings.Contains(hostname, ":") {
		// 裸 IPv6 字面量在 URL 里必须加方括号
		hostname = "[" + hostname + "]"
	}

	if requestURI == "" {
		requestURI = "/"
	}

	return "https://" + hostname + requestURI
}

// requestURIOf 取请求行里的原始 URI。
// GoFrame 在 hook 之前会规范化 r.URL（实测会把 /roundcube/ 的尾斜杠抹掉），
// 拿它重建跳转目标等于改写了访客本来要访问的地址，还会多绕一次目录补斜杠的跳转。
func requestURIOf(r *ghttp.Request) string {
	// 代理形式（http://host/path）和 OPTIONS * 不以 / 开头，这两种回退到解析后的 URL
	if strings.HasPrefix(r.RequestURI, "/") {
		return r.RequestURI
	}

	return r.URL.RequestURI()
}

// resolvedHTTPSPort 返回服务实际监听的 HTTPS 端口，取值顺序与 cmd.go 里
// SetHTTPSPort 保持一致：配置文件打底，docker 环境变量覆盖。
func resolvedHTTPSPort(ctx context.Context) int {
	port := g.Cfg().MustGet(ctx, "server.httpsPort", 443).Int()

	if v, err := public.DockerEnv("HTTPS_PORT"); err == nil && v != "" {
		if p := gconv.Int(v); p > 0 {
			port = p
		}
	}

	return port
}

// enforceHTTPS 在明文请求上写好跳转响应，返回 true 表示请求已被接管，调用方应停止后续处理。
func enforceHTTPS(r *ghttp.Request, basePath string, httpsPort int) bool {
	if !forceHTTPSEnabled() || requestIsSecure(r) {
		return false
	}

	// hook 早于 stripWebBasePathMiddleware 执行，先剥掉反向代理前缀再比较路径
	if isHTTPSRedirectExemptURI(trimWebBasePath(r.URL.Path, basePath)) {
		return false
	}

	target := httpsRedirectTarget(r.Host, requestURIOf(r), httpsPort)

	if target == "" {
		return false
	}

	r.Response.Header().Set("Location", target)
	r.Response.WriteHeader(httpsRedirectStatus(r.Method))

	return true
}
