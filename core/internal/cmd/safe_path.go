package cmd

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"os"
	"strings"
)

// safePathExemptPrefixes 列出不应被管理员 SafePath 拦截的公共路由前缀：
//
//   - /roundcube                   普通邮箱用户的 Webmail 登录入口
//   - /.well-known/acme-challenge  证书签发/续期的 HTTP-01 验证路径
//   - /pmta                        外发邮件中内嵌的打开/点击跟踪链接
//
// 这三类请求的发起方（普通收件人、Let's Encrypt 验证服务器、邮件客户端）都不可能
// 先访问管理员安全入口，一旦要求 safe_path_pass 会话标记就会直接变成 404。
// 参见 https://github.com/aaPanel/BillionMail/issues/364（同源问题还有 #338、#360、#361）。
var safePathExemptPrefixes = []string{
	"/roundcube",
	"/.well-known/acme-challenge",
	"/pmta",
}

// isSafePathExemptURI 判断 path 是否属于上述公共路由。
// 匹配要求完全相等或以 "/" 为边界，因此 "/roundcube-admin" 这类形近路径仍受 SafePath 保护。
func isSafePathExemptURI(path string) bool {
	for _, prefix := range safePathExemptPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}

	return false
}

// trimWebBasePath 把入站请求路径还原成路由实际使用的逻辑路径。
// 服务器 hook 早于 stripWebBasePathMiddleware 执行，不做这一步的话 hook 里看到的
// 仍然带着反向代理前缀，任何路径比较都匹配不上。
func trimWebBasePath(path, basePath string) string {
	if basePath == "" {
		return path
	}

	if path == basePath {
		return "/"
	}

	if strings.HasPrefix(path, basePath+"/") {
		if trimmed := strings.TrimPrefix(path, basePath); trimmed != "" {
			return trimmed
		}

		return "/"
	}

	return path
}

// rootToWebmailEnvKey 控制“未通过 SafePath 的访客访问根路径时跳转到 Webmail”，默认开启。
// 关掉它就退回上游行为：根路径直接回 404。
const rootToWebmailEnvKey = "ROOT_REDIRECT_TO_WEBMAIL"

// falsyEnvValues 是 rootToWebmailEnvKey 被视为“关闭”的取值，其余非空值一律算开启。
var falsyEnvValues = map[string]struct{}{
	"0":     {},
	"off":   {},
	"false": {},
	"no":    {},
}

// rootRedirectsToWebmail 读取开关。未配置时返回 true——这是本 fork 的预期默认行为：
// 站点根路径属于普通邮箱用户，管理后台只在安全入口背后。
func rootRedirectsToWebmail() bool {
	for _, v := range []string{os.Getenv(rootToWebmailEnvKey), public.MustGetDockerEnv(rootToWebmailEnvKey, "")} {
		v = strings.ToLower(strings.TrimSpace(v))

		if v == "" {
			continue
		}

		_, falsy := falsyEnvValues[v]

		return !falsy
	}

	return true
}

// webmailSockPath 返回 PHP-FPM 套接字路径，抽成变量是为了在测试中替换。
var webmailSockPath = func() string {
	return public.AbsPath(consts.PHP_FPM_SOCK_PATH)
}

// webmailAvailable 检查 PHP-FPM 套接字是否就绪。
// roundcube 被关停时不能把访客甩进 502，此时保持上游的 404 行为，
// 管理员仍可通过 SafePath 入口进控制台。
func webmailAvailable() bool {
	_, err := os.Stat(webmailSockPath())

	return err == nil
}

// consoleEntryURIs 是控制台 SPA 的入口路径。
//
// 这两个路径会被 GoFrame 的静态文件服务直接映射到 public/dist/index.html，
// 在 hook 的 IsFileRequest 分支里被当普通静态文件放行——SafePath 对它们等于没配。
// 必须显式列出来，在静态放行之前接管。
var consoleEntryURIs = map[string]struct{}{
	"/":           {},
	"/index.html": {},
}

// isConsoleEntryURI 判断 path 是否为控制台入口。
func isConsoleEntryURI(path string) bool {
	_, ok := consoleEntryURIs[path]

	return ok
}

// webmailRedirectTarget 返回控制台入口应跳转到的 Webmail 地址；
// 返回空串表示不跳转，调用方应按 404 处理。
//
// 只接管控制台入口：其余后台路径（/overview、/domains 等）继续回 404，
// 不向未授权访客暴露控制台路由的存在。
func webmailRedirectTarget(reqPath, basePath string) string {
	if !isConsoleEntryURI(reqPath) {
		return ""
	}

	if !rootRedirectsToWebmail() || !webmailAvailable() {
		return ""
	}

	return webBaseRoot(basePath) + "roundcube/"
}
