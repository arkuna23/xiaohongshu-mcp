package browser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/sirupsen/logrus"
	"github.com/xpzouying/headless_browser"
	"github.com/xpzouying/xiaohongshu-mcp/cookies"
)

type browserConfig struct {
	// fingerprintSeed 固定指纹 seed；>0 时钉死，同账号每次同一套指纹。0 = 每次随机。
	fingerprintSeed int
	// proxy 代理地址；非空时启用。
	proxy string
}

type Option func(*browserConfig)

// WithProxy 设置代理（http/https/socks5）。空字符串视为不启用。
func WithProxy(proxy string) Option {
	return func(c *browserConfig) {
		c.proxy = proxy
	}
}

// WithFingerprintSeed 设置 seed，seed<=0 视为未设，回退每次随机。
func WithFingerprintSeed(seed int) Option {
	return func(c *browserConfig) {
		c.fingerprintSeed = seed
	}
}

// maskProxyCredentials masks username and password in proxy URL for safe logging.
func maskProxyCredentials(proxyURL string) string {
	u, err := url.Parse(proxyURL)
	if err != nil || u.User == nil {
		return proxyURL
	}
	cred := "***"
	if _, hasPassword := u.User.Password(); hasPassword {
		cred = "***:***"
	}
	// 直接在原串替换 userinfo，避免 url.String() 把 * 编码成 %2A（日志变乱码）。
	return strings.Replace(proxyURL, u.User.String()+"@", cred+"@", 1)
}

func NewBrowser(headless bool, options ...Option) *headless_browser.Browser {
	cfg := &browserConfig{}
	for _, opt := range options {
		opt(cfg)
	}

	// 只用内置浏览器，没有别的来源。二进制必须显式传给 go-rod，
	// 否则 rod 会自行下载一个默认 Chromium：它不是内置浏览器，也不认识下面
	// 这些 flag（未知 flag 被静默忽略，日志照样打印 "fingerprint enabled"），
	// 属于无声降级。宁可不启动，也不启动一个不对的浏览器。
	binPath, err := EnsureBrowser()
	if err != nil {
		panic(fmt.Sprintf("内置浏览器不可用，拒绝启动: %v", err))
	}

	opts := []headless_browser.Option{
		headless_browser.WithHeadless(headless),
		// 用内置浏览器的默认配置，不强制 UA。
		headless_browser.WithFingerprint(""), // 空 = 按运行 OS 自动：Linux→windows，mac→macos
		headless_browser.WithStealthJS(false),
		headless_browser.WithLanguage("zh-CN"), // 面向小红书
		// 品牌报 Chrome。
		// 注：hardware-concurrency 不设，交给 seed 派生。
		headless_browser.WithExtraFlags(map[string]string{"fingerprint-brand": "Chrome"}),
	}
	opts = append(opts, headless_browser.WithChromeBinPath(binPath))

	// Chromium 只接收代理地址，认证信息通过 CDP 提供。
	var proxyUser *url.Userinfo
	if cfg.proxy != "" {
		proxyURL, err := url.Parse(cfg.proxy)
		if err != nil || proxyURL.Host == "" {
			panic("代理地址无效，请检查 XHS_PROXY")
		}
		if proxyURL.User != nil && proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
			panic("带认证的代理仅支持 HTTP/HTTPS")
		}
		proxyUser = proxyURL.User
		proxyURL.User = nil
		opts = append(opts, headless_browser.WithProxy(proxyURL.String()))
		logrus.Infof("Using proxy: %s", maskProxyCredentials(cfg.proxy))
	}

	// 固定指纹 seed（由调用方经 Option 传入，env 读取放在入口层）。
	if cfg.fingerprintSeed > 0 {
		opts = append(opts, headless_browser.WithFingerprintSeed(cfg.fingerprintSeed))
		logrus.Infof("fingerprint seed pinned: %d", cfg.fingerprintSeed)
	}

	// 加载 cookies
	cookiePath := cookies.GetCookiesFilePath()
	cookieLoader := cookies.NewLoadCookie(cookiePath)

	if data, err := cookieLoader.LoadCookies(); err == nil {
		opts = append(opts, headless_browser.WithCookies(string(data)))
		logrus.Debugf("loaded cookies from filesuccessfully")
	} else {
		logrus.Warnf("failed to load cookies: %v", err)
	}

	b := headless_browser.New(opts...)
	if proxyUser != nil {
		page := b.NewPage()
		rawBrowser := page.Browser()
		page.MustClose()
		if err := enableProxyAuth(rawBrowser, proxyUser); err != nil {
			b.Close()
			panic(fmt.Sprintf("启用代理认证失败: %v", err))
		}
	}
	return b
}

func enableProxyAuth(b *rod.Browser, user *url.Userinfo) error {
	password, _ := user.Password()
	attempted := make(map[proto.FetchRequestID]bool)
	wait := b.EachEvent(
		func(e *proto.FetchRequestPaused) {
			if err := (proto.FetchContinueRequest{RequestID: e.RequestID}).Call(b); err != nil {
				logrus.Warnf("继续代理请求失败: %v", err)
			}
		},
		func(e *proto.FetchAuthRequired) {
			response := &proto.FetchAuthChallengeResponse{
				Response: proto.FetchAuthChallengeResponseResponseDefault,
			}
			if e.AuthChallenge.Source == proto.FetchAuthChallengeSourceProxy {
				response.Response = proto.FetchAuthChallengeResponseResponseCancelAuth
				if !attempted[e.RequestID] {
					attempted[e.RequestID] = true
					response.Response = proto.FetchAuthChallengeResponseResponseProvideCredentials
					response.Username = user.Username()
					response.Password = password
				}
			}
			if err := (proto.FetchContinueWithAuth{
				RequestID: e.RequestID, AuthChallengeResponse: response,
			}).Call(b); err != nil {
				logrus.Warnf("响应代理认证失败: %v", err)
			}
		},
	)
	go wait()
	return (proto.FetchEnable{HandleAuthRequests: true}).Call(b)
}
