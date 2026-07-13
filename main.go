package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

/*
Env you should set on Render (or locally):
- UPSTREAM_BASE=https://app.noest-dz.com
- API_BEARER=... (optional; enables bearer gate)
- NOEST_EMAIL=...
- NOEST_PASSWORD=...
- DEFAULT_TRACKING=98K-19D-11050075
- DEFAULT_TYPE=1
- DEFAULT_WILAYA=16
- DEFAULT_COMMUNE=Alger Centre
- DEFAULT_ADRESSE=ALGER
- DEFAULT_CLIENT=CLIENT
- DEFAULT_REMARQUE=GIFT
- DEFAULT_PRODUCT=GIFT
- DEFAULT_MONTANT=1300.00
- DEFAULT_STOP_DESK=1
- DEFAULT_NOT_EXPIDIE=1
- DEFAULT_POIDS=2.00
- DEFAULT_ALT_PHONE=0660452100 (optional)

Optional path overrides (if upstream changes):
- LOGIN_PATH=/login
- LOGIN_PAGE_PATH=/login
- HOME_PATH=/home
- ORDER_UPDATE_PATH=/update/orders/info
- SCORING_TRIGGER_PATH=/get/scoring
*/

type Config struct {
	UpstreamBase       string
	APIBearer          string
	AllowedOrigin      string
	Port               string

	NoestEmail         string
	NoestPassword      string

	DefaultTracking    string
	DefaultType        string
	DefaultWilaya      string
	DefaultCommune     string
	DefaultAdresse     string
	DefaultClient      string
	DefaultRemarque    string
	DefaultProduct     string
	DefaultMontant     string
	DefaultStopDesk    string
	DefaultNotExpidie  string
	DefaultPoids       string
	DefaultAltPhone    string

	LoginPath          string
	LoginPagePath      string
	HomePath           string
	OrderUpdatePath    string
	ScoringTriggerPath string
}

func getenv(k, def string) string { v := os.Getenv(k); if v == "" { return def }; return v }

func getConfig() Config {
	return Config{
		UpstreamBase:       getenv("UPSTREAM_BASE", "https://app.noest-dz.com"),
		APIBearer:          os.Getenv("API_BEARER"),
		AllowedOrigin:      getenv("ALLOWED_ORIGIN", "*"),
		Port:               getenv("PORT", "8080"),

		NoestEmail:         os.Getenv("NOEST_EMAIL"),
		NoestPassword:      os.Getenv("NOEST_PASSWORD"),

		DefaultTracking:    os.Getenv("DEFAULT_TRACKING"),
		DefaultType:        getenv("DEFAULT_TYPE", "1"),
		DefaultWilaya:      getenv("DEFAULT_WILAYA", "16"),
		DefaultCommune:     getenv("DEFAULT_COMMUNE", "Alger Centre"),
		DefaultAdresse:     getenv("DEFAULT_ADRESSE", "ALGER"),
		DefaultClient:      getenv("DEFAULT_CLIENT", "CLIENT"),
		DefaultRemarque:    getenv("DEFAULT_REMARQUE", "GIFT"),
		DefaultProduct:     getenv("DEFAULT_PRODUCT", "GIFT"),
		DefaultMontant:     getenv("DEFAULT_MONTANT", "1300.00"),
		DefaultStopDesk:    getenv("DEFAULT_STOP_DESK", "1"),
		DefaultNotExpidie:  getenv("DEFAULT_NOT_EXPIDIE", "1"),
		DefaultPoids:       getenv("DEFAULT_POIDS", "2.00"),
		DefaultAltPhone:    os.Getenv("DEFAULT_ALT_PHONE"),

		LoginPath:          getenv("LOGIN_PATH", "/login"),
		LoginPagePath:      getenv("LOGIN_PAGE_PATH", "/login"),
		HomePath:           getenv("HOME_PATH", "/home"),
		OrderUpdatePath:    getenv("ORDER_UPDATE_PATH", "/update/orders/info"),
		ScoringTriggerPath: getenv("SCORING_TRIGGER_PATH", "/get/scoring"),
	}
}

func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: jar,
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil { return r.RemoteAddr }
	return host
}

func rateLimit(r rate.Limiter) gin.HandlerFunc {
	tokens := make(map[string]*rate.Limiter)
	mu := make(chan struct{}, 1)
	getLimiter := func(ip string) *rate.Limiter {
		mu <- struct{}{}
		lim, ok := tokens[ip]
		if !ok { copy := r; lim = rate.NewLimiter(copy.Limit(), copy.Burst()); tokens[ip] = lim }
		<-mu
		return lim
	}
	return func(c *gin.Context) {
		if !getLimiter(clientIP(c.Request)).Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

// --------- Parsers & helpers for tokens ----------

// <input type="hidden" name="_token" value="...">
var loginTokenRe = regexp.MustCompile(`(?is)<input[^>]*name=['"]?_token['"]?[^>]*value=['"]([^'"]+)['"]`)

// <meta name="csrf-token" content="...">
var metaCSRFRe = regexp.MustCompile(`(?is)<meta[^>]+name=['"]csrf-token['"][^>]*content=['"]([^'"]+)['"][^>]*>`)

func extractLoginToken(html []byte) (string, bool) {
	m := loginTokenRe.FindSubmatch(html)
	if len(m) < 2 { return "", false }
	return string(m[1]), true
}
func extractMetaCSRF(html []byte) (string, bool) {
	m := metaCSRFRe.FindSubmatch(html)
	if len(m) < 2 { return "", false }
	return string(m[1]), true
}
func cookieVal(j http.CookieJar, u *url.URL, name string) (string, bool) {
	for _, ck := range j.Cookies(u) {
		if ck.Name == name && ck.Value != "" { return ck.Value, true }
	}
	return "", false
}

// --------- Session (cookies + CSRF meta) ----------

type session struct {
	client     *http.Client
	csrfHeader string
	expiresAt  time.Time
}

var cached *session

// ensureSession returns (*session, loginOK, homeOK, error)
func ensureSession(cfg Config) (*session, bool, bool, error) {
	if cached != nil && time.Now().Before(cached.expiresAt.Add(-5*time.Minute)) {
		return cached, true, true, nil
	}
	if cfg.NoestEmail == "" || cfg.NoestPassword == "" {
		return nil, false, false, errors.New("NOEST_EMAIL/NOEST_PASSWORD not set")
	}

	cl := newHTTPClient()
	base := strings.TrimRight(cfg.UpstreamBase, "/")
	ua   := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit(537.36) Chrome/118.0.0.0 Safari/537.36"

	// 1) GET /login
	loginPageURL := base + cfg.LoginPagePath
	req0, _ := http.NewRequest(http.MethodGet, loginPageURL, nil)
	req0.Header.Set("User-Agent", ua)
	req0.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req0.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	resp0, err := cl.Do(req0)
	if err != nil { return nil, false, false, err }
	page, _ := io.ReadAll(resp0.Body)
	resp0.Body.Close()

	hidden, ok := extractLoginToken(page)
	if !ok {
		u0, _ := url.Parse(loginPageURL)
		if raw, ok2 := cookieVal(cl.Jar, u0, "XSRF-TOKEN"); ok2 {
			if dec, err := url.QueryUnescape(raw); err == nil && dec != "" {
				hidden, ok = dec, true
			}
		}
	}
	if !ok {
		return nil, false, false, errors.New("login _token not found in login page")
	}

	// 2) POST /login
	loginURL := base + cfg.LoginPath
	form := url.Values{
		"email":    {cfg.NoestEmail},
		"password": {cfg.NoestPassword},
		"_token":   {hidden},
	}
	req1, _ := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	req1.Header.Set("User-Agent", ua)
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("Accept", "*/*")
	req1.Header.Set("Origin", base)
	req1.Header.Set("Referer", loginPageURL)
	req1.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	resp1, err := cl.Do(req1)
	if err != nil { return nil, false, false, err }
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	loginOK := true

	// 3) GET /home and read meta CSRF
	homeURL := base + cfg.HomePath
	req2, _ := http.NewRequest(http.MethodGet, homeURL, nil)
	req2.Header.Set("User-Agent", ua)
	req2.Header.Set("Accept", "*/*")
	req2.Header.Set("Referer", base)
	req2.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	resp2, err := cl.Do(req2)
	if err != nil { return nil, loginOK, false, err }
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	csrf, ok := extractMetaCSRF(body)
	if !ok { return nil, loginOK, false, errors.New("csrf meta not found in /home") }
	homeOK := true

	cached = &session{client: cl, csrfHeader: csrf, expiresAt: time.Now().Add(110 * time.Minute)}
	return cached, loginOK, homeOK, nil
}

// --------- Upstream actions ----------

// PUT /update/orders/info
func updateOrderPhone(cfg Config, sess *session, formVals url.Values) error {
	u := strings.TrimRight(cfg.UpstreamBase, "/") + cfg.OrderUpdatePath
	req, _ := http.NewRequest(http.MethodPut, u, strings.NewReader(formVals.Encode()))
	// IMPORTANT: mimic browsery AJAX headers like your working example
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit(537.36) Chrome/139.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-Csrf-Token", sess.csrfHeader)
	req.Header.Set("X-CSRF-TOKEN", sess.csrfHeader)
	req.Header.Set("Origin", strings.TrimRight(cfg.UpstreamBase, "/"))
	req.Header.Set("Referer", strings.TrimRight(cfg.UpstreamBase, "/")+cfg.HomePath) // helps some CSRF middlewares
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")

	resp, err := sess.client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return errors.New("order update failed: " + resp.Status + " - " + string(b))
	}
	// Typically {"update":"success"}
	type upd struct{ Update string `json:"update"` }
	var ok upd
	if err := json.Unmarshal(bytes.TrimSpace(b), &ok); err == nil && ok.Update != "" && !strings.EqualFold(ok.Update, "success") {
		return errors.New("order update unexpected response: " + string(b))
	}
	return nil
}

// POST /get/scoring
func triggerScoring(cfg Config, sess *session, phone string) (map[string]any, error) {
	u := strings.TrimRight(cfg.UpstreamBase, "/") + cfg.ScoringTriggerPath
	form := url.Values{"phones[]": {phone}}
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit(537.36) Chrome/139.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-Csrf-Token", sess.csrfHeader)
	req.Header.Set("X-CSRF-TOKEN", sess.csrfHeader)
	req.Header.Set("Origin", strings.TrimRight(cfg.UpstreamBase, "/"))
	req.Header.Set("Referer", strings.TrimRight(cfg.UpstreamBase, "/")+cfg.HomePath)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")

	resp, err := sess.client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, errors.New("scoring failed: " + resp.Status + " - " + string(b))
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(b), &m); err != nil {
		return nil, errors.New("scoring response not JSON: " + err.Error())
	}
	return m, nil
}

// --------- Main server ----------

var phoneRe = regexp.MustCompile(`^[0-9+]{6,20}$`)

func main() {
	cfg := getConfig()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", cfg.AllowedOrigin)
		c.Writer.Header().Set("Vary", "Origin")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == http.MethodOptions { c.AbortWithStatus(http.StatusNoContent); return }
		c.Next()
	})

	// Bearer gate (robust; supports header or ?bearer=)
	r.Use(func(c *gin.Context) {
		if cfg.APIBearer == "" { return }
		token := ""
		if h := c.GetHeader("Authorization"); h != "" {
			parts := strings.SplitN(h, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				token = strings.TrimSpace(parts[1])
			}
		}
		if token == "" {
			token = strings.TrimSpace(c.Query("bearer")) // convenient for quick tests
		}
		want := strings.TrimSpace(cfg.APIBearer)
		if token != want {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
	})

	// Rate limit
	r.Use(rateLimit(*rate.NewLimiter(5, 20)))

	// Health
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	// Scoring orchestrator
	r.GET("/scoring", func(c *gin.Context) {
		type Steps struct {
			Login       bool `json:"login"`
			HomeCSRF    bool `json:"home_csrf"`
			OrderUpdate bool `json:"order_update"`
			Scoring     bool `json:"scoring"`
		}
		steps := Steps{}

		phone := strings.TrimSpace(c.Query("phone"))
		if phone == "" || !phoneRe.MatchString(phone) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing phone", "steps": steps})
			return
		}
		alt := strings.TrimSpace(c.Query("alt"))
		if alt == "" { alt = strings.TrimSpace(cfg.DefaultAltPhone) }

		tracking := strings.TrimSpace(c.Query("tracking"))
		if tracking == "" { tracking = strings.TrimSpace(cfg.DefaultTracking) }
		if tracking == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tracking missing (set DEFAULT_TRACKING or pass ?tracking=)", "steps": steps})
			return
		}

		// (1)+(2) session bootstrap: login + home csrf
		sess, loginOK, homeOK, err := ensureSession(cfg)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "step": "session", "steps": steps})
			return
		}
		steps.Login, steps.HomeCSRF = loginOK, homeOK

		// (3) update order with the exact fields you provided
		form := url.Values{
			"tracking":    {tracking},
			"type":        {cfg.DefaultType},
			"wilaya":      {cfg.DefaultWilaya},
			"commune":     {cfg.DefaultCommune},
			"adresse":     {cfg.DefaultAdresse},
			"client":      {cfg.DefaultClient},
			"tel":         {phone},
			"tel2":        {alt},
			"remarque":    {cfg.DefaultRemarque},
			"product":     {cfg.DefaultProduct},
			"montant":     {cfg.DefaultMontant},
			"stop_desk":   {cfg.DefaultStopDesk},
			"not_expidie": {cfg.DefaultNotExpidie},
			"poids":       {cfg.DefaultPoids},
		}
		if err := updateOrderPhone(cfg, sess, form); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "step": "order_update", "steps": steps})
			return
		}
		steps.OrderUpdate = true

		// (4) scoring
		raw, err := triggerScoring(cfg, sess, phone)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "step": "scoring", "steps": steps})
			return
		}
		steps.Scoring = true

		// Normalize to your target shape
		out := gin.H{
			"result": gin.H{
				phone: gin.H{
					"score":     0,
					"Delivered": "0",
					"Failed":    "0",
				},
			},
			"steps": steps,
		}

		if r0, ok := raw["result"].(map[string]any); ok {
			if v, ok := r0[phone]; ok {
				if m, ok := v.(map[string]any); ok {
					if _, ok := m["score"]; ok {
						out["result"].(gin.H)[phone] = gin.H{
							"type":"legacy",
							"score":coerceInt(m["score"]),
							"Delivered":coerceString(m["Delivered"]),
							"Failed":coerceString(m["Failed"]),
						}
					} else {
						badge:=strings.ToLower(coerceString(m["badge"]))
						prob:="Inconnue"
						switch badge {case "low": prob="Probabilité de livraison Haute"; case "high": prob="Probabilité de livraison Faible"}
						out["result"].(gin.H)[phone]=gin.H{"type":"badge","badge":badge,"probability":prob}
					}
				}
			}
		}
		if c.Query("debug") == "1" {
			out["raw"] = raw
		}
		c.JSON(http.StatusOK, out)
	})

	log.Printf("listening on :%s (upstream=%s)", cfg.Port, cfg.UpstreamBase)
	if err := r.Run(":" + cfg.Port); err != nil { log.Fatal(err) }
}

// ---- helpers for coercion ----
func coerceInt(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case int:
		return t
	case float64:
		return int(t)
	case json.Number:
		i, _ := t.Int64(); return int(i)
	case string:
		i, _ := strconv.Atoi(t); return i
	default:
		return 0
	}
}
func coerceString(v any) string {
	switch t := v.(type) {
	case nil:
		return "0"
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	default:
		return "0"
	}
}
