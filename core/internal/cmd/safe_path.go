package cmd

import "strings"

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
