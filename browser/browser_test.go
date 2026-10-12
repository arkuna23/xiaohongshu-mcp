package browser

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaskProxyCredentials 校验代理日志脱敏：绝不能把用户名/密码打进日志。
func TestMaskProxyCredentials(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "空字符串", input: "", want: ""},
		{name: "无认证信息原样返回", input: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "用户名+密码都脱敏", input: "http://user:pass@host:8080", want: "http://***:***@host:8080"},
		{name: "仅用户名脱敏", input: "http://user@host:8080", want: "http://***@host:8080"},
		{name: "socks5带认证", input: "socks5://alice:secret@127.0.0.1:1080", want: "socks5://***:***@127.0.0.1:1080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, maskProxyCredentials(tt.input))
		})
	}
}

// TestOptions 校验 Option 正确写入 browserConfig（New+Option 的接线）。
func TestOptions(t *testing.T) {
	cfg := &browserConfig{}
	WithFingerprintSeed(98759)(cfg)
	WithProxy("http://127.0.0.1:8080")(cfg)

	assert.Equal(t, 98759, cfg.fingerprintSeed)
	assert.Equal(t, "http://127.0.0.1:8080", cfg.proxy)
}

// TestOptions_Defaults 未传 Option 时各字段为零值（回退随机 seed / 不设代理）。
func TestOptions_Defaults(t *testing.T) {
	cfg := &browserConfig{}
	assert.Equal(t, 0, cfg.fingerprintSeed)
	assert.Equal(t, "", cfg.proxy)
}

func TestBrowserLoadsPagesThroughAuthenticatedProxy(t *testing.T) {
	_, binName, supported := platformAsset()
	cacheDir, err := browserCacheDir()
	require.NoError(t, err)
	if !supported || findBinary(cacheDir, binName) == "" {
		t.Skip("需要已缓存的内置浏览器")
	}
	t.Setenv("COOKIES_PATH", filepath.Join(t.TempDir(), "cookies.json"))
	const username, password = "proxy-user", "p@ss:word"
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != authorization {
			w.Header().Set("Proxy-Authenticate", `Basic realm="browser-test"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Path)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	proxyURL.User = url.UserPassword(username, password)
	b := NewBrowser(true, WithProxy(proxyURL.String()))
	defer b.Close()
	for _, path := range []string{"/first", "/second"} {
		page := b.NewPage().Timeout(10 * time.Second)
		require.NoError(t, page.Navigate("http://proxy-test.invalid:18080"+path))
		require.NoError(t, page.WaitLoad())
		text, err := page.MustElement("body").Text()
		require.NoError(t, err)
		assert.Equal(t, path, text)
		require.NoError(t, page.Close())
	}
}
