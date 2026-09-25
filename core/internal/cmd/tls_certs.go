package cmd

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"crypto/tls"
	"os"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"
)

// certFiles 是一对证书与私钥文件的路径。
type certFiles struct {
	crt string
	key string
}

// certFingerprint 用两个文件的修改时间和大小判断证书是否被换过。
type certFingerprint struct {
	crtMod, keyMod   time.Time
	crtSize, keySize int64
}

func fingerprintOf(files certFiles) (fp certFingerprint, err error) {
	crt, err := os.Stat(files.crt)
	if err != nil {
		return fp, err
	}

	key, err := os.Stat(files.key)
	if err != nil {
		return fp, err
	}

	return certFingerprint{
		crtMod:  crt.ModTime(),
		keyMod:  key.ModTime(),
		crtSize: crt.Size(),
		keySize: key.Size(),
	}, nil
}

// loadedCert 记录一对证书文件最近一次加载的结果。
type loadedCert struct {
	cert  *tls.Certificate // 最近一次成功加载的证书，从未成功过时为 nil
	tried certFingerprint  // 最近一次尝试加载时文件的指纹，同一指纹不重复解析
}

// reloadingCertStore 按需加载 HTTPS 证书，证书文件被替换后，下一次握手就换上新证书。
//
// 上游每次申请、续期、上传证书后都会重启 core 容器让新证书生效，代价是：
//   - 重启那几秒控制台和 Webmail 都不可用，紧接着的操作会因连接中断而失败
//     （前端还不会关掉 loading，界面一直转圈）；
//   - 自动续期是在一个循环里逐个域名处理的，第一个续期成功就触发重启，
//     循环被拦腰截断，排在后面的域名这一轮续不到。
//
// 由它接管证书之后，写完证书文件即可生效，不再需要重启。
type reloadingCertStore struct {
	mu      sync.RWMutex
	loaded  map[certFiles]*loadedCert
	domains map[string]certFiles // SNI → 该域名的证书文件，只缓存查到过的域名

	// fallback 是控制台证书（cert.pem / key.pem），SNI 查不到域名证书时使用
	fallback certFiles

	// resolve 查询 SNI 对应的域名证书文件，生产环境查数据库，测试里可替换
	resolve func(serverName string) (certFiles, bool)
}

func newReloadingCertStore(fallback certFiles, resolve func(serverName string) (certFiles, bool)) *reloadingCertStore {
	return &reloadingCertStore{
		loaded:   make(map[certFiles]*loadedCert),
		domains:  make(map[string]certFiles),
		fallback: fallback,
		resolve:  resolve,
	}
}

// consoleCertFiles 返回控制台证书的路径。
func consoleCertFiles() certFiles {
	return certFiles{
		crt: public.AbsPath(consts.SSL_PATH, "cert.pem"),
		key: public.AbsPath(consts.SSL_PATH, "key.pem"),
	}
}

// resolveDomainCertFiles 判断 SNI 是否属于已添加的域名，并且证书文件已就位。
// 查询条件与上游原先的内联实现保持一致。
func resolveDomainCertFiles(serverName string) (certFiles, bool) {
	hostname := public.FormatMX(serverName)

	if exists, _ := g.DB().Model("domain").Where("a_record", hostname).Exist(); !exists {
		return certFiles{}, false
	}

	files := certFiles{
		crt: public.AbsPath(consts.SSL_PATH, hostname, "fullchain.pem"),
		key: public.AbsPath(consts.SSL_PATH, hostname, "privkey.pem"),
	}

	if !public.FileExists(files.crt) || !public.FileExists(files.key) {
		return certFiles{}, false
	}

	return files, true
}

// load 返回 files 对应的证书，文件自上次加载后有变化就重新读取。
// 读取失败时沿用上一张能用的证书：证书和私钥是先后两次写入的，
// 中间那一瞬间两者并不匹配，这时退回默认证书反而会让访客看到证书告警。
func (s *reloadingCertStore) load(files certFiles) *tls.Certificate {
	fp, statErr := fingerprintOf(files)

	s.mu.RLock()
	entry := s.loaded[files]
	s.mu.RUnlock()

	if entry != nil && (statErr != nil || entry.tried == fp) {
		return entry.cert
	}

	if statErr != nil {
		return nil
	}

	var last *tls.Certificate

	if entry != nil {
		last = entry.cert
	}

	next := &loadedCert{cert: last, tried: fp}
	crt, err := tls.LoadX509KeyPair(files.crt, files.key)

	if err == nil {
		next.cert = &crt
	} else {
		g.Log().Warningf(context.Background(), "Failed to load TLS certificate %s, keeping the last usable one: %v", files.crt, err)
	}

	s.mu.Lock()
	s.loaded[files] = next
	s.mu.Unlock()

	return next.cert
}

// domainFiles 返回 SNI 对应的域名证书文件。
// 只缓存查到的域名，查不到的每次重查，这样新域名申请完证书后无需重启就能用上。
func (s *reloadingCertStore) domainFiles(serverName string) (certFiles, bool) {
	if serverName == "" {
		return certFiles{}, false
	}

	s.mu.RLock()
	files, ok := s.domains[serverName]
	s.mu.RUnlock()

	if ok {
		return files, true
	}

	if files, ok = s.resolve(serverName); !ok {
		return certFiles{}, false
	}

	s.mu.Lock()
	s.domains[serverName] = files
	s.mu.Unlock()

	return files, true
}

// GetCertificate 实现 tls.Config.GetCertificate。
func (s *reloadingCertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if files, ok := s.domainFiles(hello.ServerName); ok {
		if crt := s.load(files); crt != nil {
			return crt, nil
		}
	}

	// 返回 nil 时 Go 会退回 Certificates[0]，即 GoFrame 启动时读入的控制台证书
	return s.load(s.fallback), nil
}

// tlsConfig 返回交给 GoFrame 的 TLS 配置。
func (s *reloadingCertStore) tlsConfig() *tls.Config {
	cfg := &tls.Config{GetCertificate: s.GetCertificate}

	// GoFrame 启动时会把 cert.pem 读进 cfg.Certificates。不带 SNI 的握手
	// （直接用 IP 访问）Go 会直接用那一份，不经过 GetCertificate，证书换了也看不到。
	// 这类握手改用去掉 Certificates 的副本，让它也走热加载。
	// 控制台证书一次都没读成功时维持原配置，至少还有启动时那一份可用。
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != "" || s.load(s.fallback) == nil {
			return nil, nil
		}

		c := cfg.Clone()
		c.Certificates = nil
		c.GetConfigForClient = nil

		return c, nil
	}

	return cfg
}
