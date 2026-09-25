package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/net/gtcp"
	"github.com/gogf/gf/v2/util/guid"
)

// newCertFiles 在临时目录里准备一对证书文件路径。
func newCertFiles(t *testing.T, name string) certFiles {
	t.Helper()

	dir := filepath.Join(t.TempDir(), name)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建证书目录失败: %v", err)
	}

	return certFiles{crt: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
}

// generateCertPair 生成一张以 commonName 为主体的自签证书，返回 PEM 编码的证书和私钥。
func generateCertPair(t *testing.T, commonName string) (crtPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// mtimeTick 让每次写入的文件修改时间严格递增，避免测试跑得太快、
// 两次写入落在同一时间戳上而误判为文件没变。
var mtimeTick = time.Now()

func writeFileAdvancingMtime(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}

	mtimeTick = mtimeTick.Add(time.Second)

	if err := os.Chtimes(path, mtimeTick, mtimeTick); err != nil {
		t.Fatalf("设置 %s 修改时间失败: %v", path, err)
	}
}

// writeCertPair 把一张新签的证书写进 files，模拟申请/续期/上传证书。
func writeCertPair(t *testing.T, files certFiles, commonName string) {
	t.Helper()

	crtPEM, keyPEM := generateCertPair(t, commonName)
	writeFileAdvancingMtime(t, files.crt, crtPEM)
	writeFileAdvancingMtime(t, files.key, keyPEM)
}

func commonNameOf(t *testing.T, crt *tls.Certificate) string {
	t.Helper()

	if crt == nil {
		return ""
	}

	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}

	return leaf.Subject.CommonName
}

func noDomainCerts(string) (certFiles, bool) { return certFiles{}, false }

// presentedCN 模拟一次握手，返回服务端会出示的证书主体。
func presentedCN(t *testing.T, store *reloadingCertStore, serverName string) string {
	t.Helper()

	crt, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: serverName})
	if err != nil {
		t.Fatalf("GetCertificate(%q) 出错: %v", serverName, err)
	}

	return commonNameOf(t, crt)
}

func TestReloadingCertStoreReloadsChangedFiles(t *testing.T) {
	files := newCertFiles(t, "console")
	writeCertPair(t, files, "old.example.com")

	store := newReloadingCertStore(files, noDomainCerts)

	if got := commonNameOf(t, store.load(files)); got != "old.example.com" {
		t.Fatalf("首次加载 = %q, want %q", got, "old.example.com")
	}

	writeCertPair(t, files, "new.example.com")

	if got := commonNameOf(t, store.load(files)); got != "new.example.com" {
		t.Errorf("证书文件替换后 = %q, want %q", got, "new.example.com")
	}
}

// TestReloadingCertStoreKeepsLastGoodCert 覆盖写证书的中间状态：
// 证书和私钥分两次写入，其间两者不匹配；这时必须继续用旧证书，
// 退回默认证书会让访客看到证书告警。
func TestReloadingCertStoreKeepsLastGoodCert(t *testing.T) {
	files := newCertFiles(t, "mail.example.com")
	writeCertPair(t, files, "old.example.com")

	store := newReloadingCertStore(newCertFiles(t, "console"), noDomainCerts)
	store.load(files)

	t.Run("证书已换私钥未换", func(t *testing.T) {
		crtPEM, _ := generateCertPair(t, "half-written.example.com")
		writeFileAdvancingMtime(t, files.crt, crtPEM)

		if got := commonNameOf(t, store.load(files)); got != "old.example.com" {
			t.Errorf("证书与私钥不匹配时 = %q, want 沿用 %q", got, "old.example.com")
		}
	})

	t.Run("私钥写完后换上新证书", func(t *testing.T) {
		writeCertPair(t, files, "new.example.com")

		if got := commonNameOf(t, store.load(files)); got != "new.example.com" {
			t.Errorf("写入完成后 = %q, want %q", got, "new.example.com")
		}
	})

	t.Run("文件被删时沿用内存里的证书", func(t *testing.T) {
		if err := os.Remove(files.key); err != nil {
			t.Fatalf("删除私钥失败: %v", err)
		}

		if got := commonNameOf(t, store.load(files)); got != "new.example.com" {
			t.Errorf("私钥被删后 = %q, want 沿用 %q", got, "new.example.com")
		}
	})
}

func TestReloadingCertStoreNeverLoaded(t *testing.T) {
	files := newCertFiles(t, "broken")
	crtPEM, _ := generateCertPair(t, "a.example.com")
	_, keyPEM := generateCertPair(t, "b.example.com")
	writeFileAdvancingMtime(t, files.crt, crtPEM)
	writeFileAdvancingMtime(t, files.key, keyPEM)

	store := newReloadingCertStore(files, noDomainCerts)

	if crt := store.load(files); crt != nil {
		t.Errorf("从未加载成功的坏证书应返回 nil，实际拿到 %q", commonNameOf(t, crt))
	}

	if crt := store.load(newCertFiles(t, "absent")); crt != nil {
		t.Error("不存在的证书文件应返回 nil")
	}
}

func TestReloadingCertStoreGetCertificate(t *testing.T) {
	console := newCertFiles(t, "console")
	writeCertPair(t, console, "console.example.com")

	domain := newCertFiles(t, "mail.example.com")
	writeCertPair(t, domain, "mail.example.com")

	lookups := map[string]int{}
	store := newReloadingCertStore(console, func(serverName string) (certFiles, bool) {
		lookups[serverName]++

		if serverName == "mail.example.com" {
			return domain, true
		}

		return certFiles{}, false
	})

	tests := []struct {
		name       string
		serverName string
		want       string
	}{
		{"已添加域名用域名证书", "mail.example.com", "mail.example.com"},
		{"未知域名用控制台证书", "unknown.example.com", "console.example.com"},
		{"无 SNI 用控制台证书", "", "console.example.com"},
	}

	for _, tt := range tests {
		if got := presentedCN(t, store, tt.serverName); got != tt.want {
			t.Errorf("%s: 拿到 %q, want %q", tt.name, got, tt.want)
		}
	}

	presentedCN(t, store, "mail.example.com")
	presentedCN(t, store, "unknown.example.com")

	// 查到的域名要缓存，否则每次握手都查两次库
	if n := lookups["mail.example.com"]; n != 1 {
		t.Errorf("已知域名查询了 %d 次，want 1", n)
	}

	// 查不到的不能缓存，否则新域名申请完证书后要重启才能生效
	if n := lookups["unknown.example.com"]; n != 2 {
		t.Errorf("未知域名查询了 %d 次，want 2", n)
	}

	if n := lookups[""]; n != 0 {
		t.Errorf("无 SNI 时不应查询域名，实际查询 %d 次", n)
	}

	t.Run("域名证书坏了退回控制台证书", func(t *testing.T) {
		broken := newCertFiles(t, "broken.example.com")
		crtPEM, _ := generateCertPair(t, "broken.example.com")
		_, keyPEM := generateCertPair(t, "other.example.com")
		writeFileAdvancingMtime(t, broken.crt, crtPEM)
		writeFileAdvancingMtime(t, broken.key, keyPEM)

		store := newReloadingCertStore(console, func(string) (certFiles, bool) { return broken, true })

		if got := presentedCN(t, store, "broken.example.com"); got != "console.example.com" {
			t.Errorf("拿到 %q, want %q", got, "console.example.com")
		}
	})
}

// TestReloadingCertStoreOverGoFrame 在真实的 GoFrame HTTPS 服务上验证：
// 换证书后不重启，带 SNI 和不带 SNI（直接用 IP 访问）的新连接都拿到新证书。
// 不带 SNI 的握手 Go 默认直接用 GoFrame 启动时读入的 Certificates，
// 这条用例专门锁住 GetConfigForClient 那段绕行。
func TestReloadingCertStoreOverGoFrame(t *testing.T) {
	console := newCertFiles(t, "console")
	writeCertPair(t, console, "console-old.example.com")

	domain := newCertFiles(t, "mail.example.com")
	writeCertPair(t, domain, "mail-old.example.com")

	store := newReloadingCertStore(console, func(serverName string) (certFiles, bool) {
		return domain, serverName == "mail.example.com"
	})

	httpPort, err := gtcp.GetFreePort()
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}

	httpsPort, err := gtcp.GetFreePort()
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}

	s := g.Server(guid.S())
	s.SetPort(httpPort)
	s.SetDumpRouterMap(false)
	s.SetLogStdout(false)
	s.BindHandler("/*any", func(r *ghttp.Request) { r.Response.Write("ok") })

	// 与 cmd.go 中的调用保持一致
	s.EnableHTTPS(store.fallback.crt, store.fallback.key, store.tlsConfig())
	s.SetHTTPSPort(httpsPort)

	s.Start()
	defer s.Shutdown()
	time.Sleep(300 * time.Millisecond)

	addr := fmt.Sprintf("127.0.0.1:%d", httpsPort)

	peerCN := func(t *testing.T, serverName string) string {
		t.Helper()

		// 连接 IP 且不设 ServerName 时，Go 客户端不会发送 SNI。
		// 测试要看的是服务端出示了哪张证书（无 SNI 时名字本就对不上），所以跳过校验。
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
		if err != nil {
			t.Fatalf("TLS 握手失败 (SNI=%q): %v", serverName, err)
		}
		defer conn.Close()

		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}

	if got := peerCN(t, "mail.example.com"); got != "mail-old.example.com" {
		t.Fatalf("换证书前 SNI 握手 = %q, want %q", got, "mail-old.example.com")
	}

	if got := peerCN(t, ""); got != "console-old.example.com" {
		t.Fatalf("换证书前无 SNI 握手 = %q, want %q", got, "console-old.example.com")
	}

	writeCertPair(t, domain, "mail-new.example.com")
	writeCertPair(t, console, "console-new.example.com")

	if got := peerCN(t, "mail.example.com"); got != "mail-new.example.com" {
		t.Errorf("换证书后 SNI 握手 = %q, want %q", got, "mail-new.example.com")
	}

	if got := peerCN(t, ""); got != "console-new.example.com" {
		t.Errorf("换证书后无 SNI 握手 = %q, want %q", got, "console-new.example.com")
	}

	if got := peerCN(t, "unknown.example.com"); got != "console-new.example.com" {
		t.Errorf("换证书后未知域名握手 = %q, want %q", got, "console-new.example.com")
	}
}
