package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/oschwald/geoip2-golang"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

const frontendVersion = "v0.4.15"
const localVersionInt = 40151 // 版本整数值，用于对比
const ReleaseNotes = "" // 更新日志

var db *sql.DB
var wafInstances = make(map[string]*WAFInstance)
var proxyInstances = make(map[string]*ProxyInstance)
var portForwardInstances = make(map[string]*PortForwardInstance)
var certificates = make(map[string]*Certificate)
var certificateLogs = make(map[string][]string)
var certificateLogMutex sync.Mutex

func addCertLog(certID, message string) {
	certificateLogMutex.Lock()
	defer certificateLogMutex.Unlock()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s", timestamp, message)
	certificateLogs[certID] = append(certificateLogs[certID], logEntry)
}

func getCertLogs(certID string) []string {
	certificateLogMutex.Lock()
	defer certificateLogMutex.Unlock()
	logs := certificateLogs[certID]
	return logs
}

func clearCertLogs(certID string) {
	certificateLogMutex.Lock()
	defer certificateLogMutex.Unlock()
	delete(certificateLogs, certID)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type WSClient struct {
	conn   *websocket.Conn
	send   chan []byte
	userID string
}

type WSHub struct {
	clients    map[*WSClient]bool
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
	mu         sync.RWMutex
}

var wsHub = &WSHub{
	clients:    make(map[*WSClient]bool),
	broadcast:  make(chan []byte),
	register:   make(chan *WSClient),
	unregister: make(chan *WSClient),
}

func (h *WSHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("WebSocket客户端连接，用户: %s，当前连接数: %d", client.userID, len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("WebSocket客户端断开，用户: %s，当前连接数: %d", client.userID, len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	session, err := r.Cookie("session")
	if err != nil || session.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var userID string
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", session.Value).Scan(&userID)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}

	client := &WSClient{
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID,
	}

	wsHub.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *WSClient) readPump() {
	defer func() {
		wsHub.unregister <- c
		c.conn.Close()
	}()

	for {
		_, messageData, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket读取错误: %v", err)
			}
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(messageData, &msg); err != nil {
			log.Printf("WebSocket消息解析失败: %v", err)
			continue
		}

		c.handleMessage(msg)
	}
}

func (c *WSClient) writePump() {
	defer c.conn.Close()

	for {
		message, ok := <-c.send
		if !ok {
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}

		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			return
		}
	}
}

func (c *WSClient) handleMessage(msg WSMessage) {
	switch msg.Type {
	case "stats":
		c.handleStatsRequest()
	case "logs":
		c.handleLogsRequest(msg.Data)
	case "ping":
		c.send <- []byte(`{"type":"pong"}`)
	}
}

func (c *WSClient) handleStatsRequest() {
	startTime := time.Now()
	statsMutex.RLock()
	stats := currentStats
	statsMutex.RUnlock()

	attackIPs := 0
	countryStats := make(map[string]int)
	provinceStats := make(map[string]int)
	accessCountryStats := make(map[string]int)
	accessProvinceStats := make(map[string]int)
	detectedCountryStats := make(map[string]int)
	detectedProvinceStats := make(map[string]int)
	blockedCountryStats := make(map[string]int)
	blockedProvinceStats := make(map[string]int)

	rows, err := db.Query("SELECT ip, country, province, action FROM attack_logs LIMIT 500")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip, country, province, action string
			rows.Scan(&ip, &country, &province, &action)

			if country != "" {
				accessCountryStats[country]++
			}
			if country == "中国" && province != "" {
				accessProvinceStats[province]++
			}

			if action != "normal" {
				attackIPs++
				countryStats[country]++
				if country == "中国" && province != "" {
					provinceStats[province]++
				}
			}

			if action == "detected" {
				if country != "" {
					detectedCountryStats[country]++
				}
				if country == "中国" && province != "" {
					detectedProvinceStats[province]++
				}
			}

			if action == "blocked" {
				if country != "" {
					blockedCountryStats[country]++
				}
				if country == "中国" && province != "" {
					blockedProvinceStats[province]++
				}
			}
		}
	}

	ipAccessRows, err := db.Query("SELECT ip, country, province, mode, action, result FROM ip_access_logs WHERE result != 'pass' LIMIT 500")
	if err == nil {
		defer ipAccessRows.Close()
		for ipAccessRows.Next() {
			var ip, country, province, mode, action, result string
			ipAccessRows.Scan(&ip, &country, &province, &mode, &action, &result)

			if country != "" {
				accessCountryStats[country]++
			}
			if country == "中国" && province != "" {
				accessProvinceStats[province]++
			}

			attackIPs++
			countryStats[country]++
			if country == "中国" && province != "" {
				provinceStats[province]++
			}

			if result == "observe" {
				if country != "" {
					detectedCountryStats[country]++
				}
				if country == "中国" && province != "" {
					detectedProvinceStats[province]++
				}
			}

			if result == "block" {
				if country != "" {
					blockedCountryStats[country]++
				}
				if country == "中国" && province != "" {
					blockedProvinceStats[province]++
				}
			}
		}
	}

	uniqueIPs := make(map[string]bool)
	rows, err = db.Query("SELECT DISTINCT ip FROM attack_logs LIMIT 500")
	if err == nil {
		for rows.Next() {
			var ip string
			rows.Scan(&ip)
			uniqueIPs[ip] = true
		}
		rows.Close()
	}

	ipAccessRows, err = db.Query("SELECT DISTINCT ip FROM ip_access_logs WHERE result != 'pass' LIMIT 500")
	if err == nil {
		defer ipAccessRows.Close()
		for ipAccessRows.Next() {
			var ip string
			ipAccessRows.Scan(&ip)
			uniqueIPs[ip] = true
		}
	}

	stats.UniqueIP = len(uniqueIPs)
	stats.AttackIP = attackIPs
	stats.GeoDistribution = countryStats
	stats.ProvinceDistribution = provinceStats
	stats.AccessGeoDistribution = accessCountryStats
	stats.AccessProvinceDistribution = accessProvinceStats
	stats.DetectedGeoDistribution = detectedCountryStats
	stats.DetectedProvinceDistribution = detectedProvinceStats
	stats.BlockedGeoDistribution = blockedCountryStats
	stats.BlockedProvinceDistribution = blockedProvinceStats

	if stats.QPS > 0 {
		stats.AvgResponseTime = 1000 / int64(stats.QPS)
	} else {
		stats.AvgResponseTime = 0
	}

	statsMutex.RLock()
	history := map[string]interface{}{
		"qpsHistory":     qpsHistory,
		"attackHistory":  attackHistory,
		"trafficHistory": trafficHistory,
		"trafficStats":   trafficStats,
	}
	statsMutex.RUnlock()

	currentHour := time.Now().UTC().Hour()

	trendCacheMutex.RLock()
	needRefresh := currentHour != lastTrendUpdateHour || len(cachedTodayTrend) == 0
	trendCacheMutex.RUnlock()

	if needRefresh {
		refreshTrendCache()
	}

	trendCacheMutex.RLock()
	todayTrend := cachedTodayTrend
	yesterdayTrend := cachedYesterdayTrend
	trendCacheMutex.RUnlock()

	date := time.Now().Format("2006-01-02")
	compareDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	trendData := map[string]interface{}{
		"date":          date,
		"compareDate":   compareDate,
		"compareType":   "prev-day",
		"todayTrend":    todayTrend,
		"compareTrend":  yesterdayTrend,
	}

	platformStats := make(map[string]int)
	browserStats := make(map[string]int)

	platformRows, err := db.Query(`
		SELECT platform, browser, COUNT(*) as cnt
		FROM attack_logs
		WHERE platform IS NOT NULL AND platform != 'Unknown'
		AND browser IS NOT NULL AND browser != 'Unknown'
		GROUP BY platform, browser
		ORDER BY cnt DESC
		LIMIT 500
	`)
	if err == nil {
		defer platformRows.Close()
		for platformRows.Next() {
			var platform, browser string
			var cnt int
			platformRows.Scan(&platform, &browser, &cnt)
			platformStats[platform] += cnt
			browserStats[browser] += cnt
		}
	}

	type TopStatsItem struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	platformList := make([]TopStatsItem, 0)
	for name, count := range platformStats {
		platformList = append(platformList, TopStatsItem{Name: name, Count: count})
	}
	sort.Slice(platformList, func(i, j int) bool {
		return platformList[i].Count > platformList[j].Count
	})
	if len(platformList) > 5 {
		platformList = platformList[:5]
	}

	browserList := make([]TopStatsItem, 0)
	for name, count := range browserStats {
		browserList = append(browserList, TopStatsItem{Name: name, Count: count})
	}
	sort.Slice(browserList, func(i, j int) bool {
		return browserList[i].Count > browserList[j].Count
	})
	if len(browserList) > 5 {
		browserList = browserList[:5]
	}

	clientStatsData := map[string]interface{}{
		"platformStats": platformList,
		"browserStats":  browserList,
	}
	latestAttackLogs := func() []map[string]interface{} {
		rows, err := db.Query("SELECT id, action, url, attack_type, ip, time, country, province FROM attack_logs WHERE action != 'normal' ORDER BY time DESC LIMIT 50")
		if err != nil {
			return []map[string]interface{}{}
		}
		defer rows.Close()
		logs := make([]map[string]interface{}, 0)
		for rows.Next() {
			var id int64
			var action, url, attackType, ip, timeStr, country, province string
			rows.Scan(&id, &action, &url, &attackType, &ip, &timeStr, &country, &province)
			logs = append(logs, map[string]interface{}{
				"id":         id,
				"action":     action,
				"url":        url,
				"attackType": attackType,
				"ip":         ip,
				"time":       timeStr,
				"country":    country,
				"province":   province,
			})
		}
		return logs
	}

	latestIPBlockLogs := func() []map[string]interface{} {
		rows, err := db.Query("SELECT id, ip, country, province, result, created_at FROM ip_access_logs WHERE result != 'pass' ORDER BY created_at DESC LIMIT 50")
		if err != nil {
			return []map[string]interface{}{}
		}
		defer rows.Close()
		logs := make([]map[string]interface{}, 0)
		for rows.Next() {
			var id int64
			var ip, country, province, result string
			var createdAt int64
			rows.Scan(&id, &ip, &country, &province, &result, &createdAt)
			logs = append(logs, map[string]interface{}{
				"id":         id,
				"ip":         ip,
				"country":    country,
				"province":   province,
				"result":     result,
				"createdAt":  createdAt,
			})
		}
		return logs
	}

	response := WSMessage{
		Type: "stats",
		Data: map[string]interface{}{
			"stats":           stats,
			"history":         history,
			"clientStats":     clientStatsData,
			"trendData":       trendData,
			"latestAttackLogs":  latestAttackLogs(),
			"latestIPBlockLogs": latestIPBlockLogs(),
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		return
	}
	log.Printf("[handleStatsRequest] 处理时间: %v", time.Since(startTime))
	c.send <- data
}

func (c *WSClient) handleLogsRequest(data interface{}) {
	filter := "attack"
	pageSize := 50

	if dataMap, ok := data.(map[string]interface{}); ok {
		if f, ok := dataMap["filter"].(string); ok {
			filter = f
		}
		if ps, ok := dataMap["pageSize"].(float64); ok {
			pageSize = int(ps)
		}
	}

	var dataQuery string
	if filter == "normal" {
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'normal' ORDER BY time DESC LIMIT ?"
	} else if filter == "detected" {
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'detected' ORDER BY time DESC LIMIT ?"
	} else if filter == "blocked" {
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'blocked' ORDER BY time DESC LIMIT ?"
	} else {
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action != 'normal' ORDER BY time DESC LIMIT ?"
	}

	rows, err := db.Query(dataQuery, pageSize)
	if err != nil {
		log.Printf("WebSocket查询日志失败: %v", err)
		return
	}
	defer rows.Close()

	logs := make([]AttackLog, 0)
	for rows.Next() {
		var entry AttackLog
		var attackType sql.NullString
		var proxyID sql.NullString
		var country sql.NullString
		var province sql.NullString
		var city sql.NullString
		var latitude sql.NullFloat64
		var longitude sql.NullFloat64
		var filterType sql.NullString

		err := rows.Scan(&entry.ID, &entry.Action, &entry.URL, &attackType, &entry.IP, &entry.Time, &entry.Rules, &entry.Method, &proxyID, &entry.StatusCode, &country, &province, &city, &latitude, &longitude, &filterType)
		if err != nil {
			continue
		}

		if attackType.Valid {
			entry.AttackType = attackType.String
		}
		if proxyID.Valid {
			entry.ProxyID = proxyID.String
		}
		if country.Valid {
			entry.Country = country.String
		}
		if province.Valid {
			entry.Province = province.String
		}
		if city.Valid {
			entry.City = city.String
		}
		if latitude.Valid {
			entry.Latitude = latitude.Float64
		}
		if longitude.Valid {
			entry.Longitude = longitude.Float64
		}
		if filterType.Valid {
			entry.FilterType = filterType.String
		}

		logs = append(logs, entry)
	}

	response := WSMessage{
		Type: "logs",
		Data: map[string]interface{}{
			"logs":   logs,
			"filter": filter,
		},
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return
	}
	c.send <- responseData
}

var wafMutex sync.RWMutex
var proxyMutex sync.RWMutex
var portForwardMutex sync.RWMutex
var certificateMutex sync.RWMutex
var certStopChannels sync.Map
var attackLogs []AttackLog
var logsMutex sync.Mutex
var geoipReader *geoip2.Reader

type IPSettingsCache struct {
	Mode       string
	ActionMode string
}

type IPCache struct {
	whitelist     map[string]bool
	blacklist     map[string]bool
	whitelistCount int
	blacklistCount int
	settings      IPSettingsCache
	lastUpdate    time.Time
}

var ipCache = &IPCache{
	whitelist: make(map[string]bool),
	blacklist: make(map[string]bool),
}

var ipCacheMutex sync.RWMutex
var ipCacheDuration = 30 * time.Second

func refreshIPCache() {
	ipCacheMutex.Lock()
	defer ipCacheMutex.Unlock()

	var mode, actionMode string
	err := db.QueryRow("SELECT mode, action_mode FROM ip_settings ORDER BY id DESC LIMIT 1").Scan(&mode, &actionMode)
	if err != nil {
		mode = "normal"
		actionMode = "block"
	}

	whitelist := make(map[string]bool)
	rows, err := db.Query("SELECT ip FROM ip_whitelist")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var whitelistIP string
			rows.Scan(&whitelistIP)
			whitelist[whitelistIP] = true
		}
	}

	blacklist := make(map[string]bool)
	rows, err = db.Query("SELECT ip FROM ip_blacklist")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var blacklistIP string
			rows.Scan(&blacklistIP)
			blacklist[blacklistIP] = true
		}
	}

	var whitelistCount, blacklistCount int
	db.QueryRow("SELECT COUNT(*) FROM ip_whitelist").Scan(&whitelistCount)
	db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&blacklistCount)

	ipCache.whitelist = whitelist
	ipCache.blacklist = blacklist
	ipCache.whitelistCount = whitelistCount
	ipCache.blacklistCount = blacklistCount
	ipCache.settings = IPSettingsCache{Mode: mode, ActionMode: actionMode}
	ipCache.lastUpdate = time.Now()
}

func getIPSettings() (mode, actionMode string, whitelistCount, blacklistCount int, whitelist map[string]bool) {
	ipCacheMutex.RLock()
	if time.Since(ipCache.lastUpdate) > ipCacheDuration {
		ipCacheMutex.RUnlock()
		refreshIPCache()
		ipCacheMutex.RLock()
	}
	mode = ipCache.settings.Mode
	actionMode = ipCache.settings.ActionMode
	whitelistCount = ipCache.whitelistCount
	blacklistCount = ipCache.blacklistCount
	whitelist = ipCache.whitelist
	ipCacheMutex.RUnlock()
	return
}

func isIPInWhitelistCached(cleanIP string) bool {
	ipCacheMutex.RLock()
	defer ipCacheMutex.RUnlock()
	for ip := range ipCache.whitelist {
		if isIPInCIDR(cleanIP, ip) {
			return true
		}
	}
	return false
}

func isIPInBlacklistCached(cleanIP string) bool {
	ipCacheMutex.RLock()
	defer ipCacheMutex.RUnlock()
	for ip := range ipCache.blacklist {
		if isIPInCIDR(cleanIP, ip) {
			return true
		}
	}
	return false
}

var ruleMessageCN = map[string]string{
	"Inbound Anomaly Score Exceeded":                          "入站异常评分超标",
	"Outbound Anomaly Score Exceeded":                         "出站异常评分超标",
	"SQL Injection Attack":                                     "SQL注入攻击",
	"Cross Site Scripting (XSS) Attack":                       "跨站脚本(XSS)攻击",
	"Path Traversal Attack (/../) or (/.../)":                 "路径遍历攻击",
	"Remote Code Execution (RCE) Attack":                      "远程代码执行攻击",
	"PHP Injection Attack":                                     "PHP注入攻击",
	"OS Command Injection Attack":                              "操作系统命令注入攻击",
	"HTTP Response Splitting Attack":                           "HTTP响应拆分攻击",
	"Session Fixation Attack":                                  "会话固定攻击",
	"HTTPoxy Attack":                                           "HTTPoxy攻击",
	"Java Code Injection Attack":                               "Java代码注入攻击",
	"OGNL Injection Attack":                                    "OGNL注入攻击",
	"SSRF Attack":                                              "服务端请求伪造攻击",
	"XML External Entity (XXE) Attack":                         "XML外部实体攻击",
	"Remote File Inclusion (RFI) Attack":                       "远程文件包含攻击",
	"Local File Inclusion (LFI) Attack":                        "本地文件包含攻击",
	"Shellshock Attack":                                        "Shellshock攻击",
	"Heartbleed Attack":                                        "心脏出血攻击",
	"ETSCAN Attack":                                            "ETSCAN攻击",
	"TORNODE Attack":                                           "TOR节点攻击",
	"PROXY Attack":                                             "代理攻击",
	"SPAM Attack":                                              "垃圾邮件攻击",
	"TOR Attack":                                               "TOR攻击",
	"SPIDER Attack":                                            "爬虫攻击",
	"BOT Attack":                                               "机器人攻击",
	"SCANNER Attack":                                           "扫描器攻击",
	"BRUTE Force Attack":                                       "暴力破解攻击",
	"DOS Attack":                                               "拒绝服务攻击",
	"DDOS Attack":                                              "分布式拒绝服务攻击",
	"Restricted File Access Attempt":                           "受限文件访问尝试",
}

func translateMessage(msg string) string {
	if cn, ok := ruleMessageCN[msg]; ok {
		return cn
	}
	
	result := msg
	for en, cn := range ruleMessageCN {
		if strings.Contains(result, en) {
			result = strings.Replace(result, en, cn, 1)
		}
	}
	
	result = strings.Replace(result, "Total Score", "总评分", 1)
	result = strings.Replace(result, "Inbound Anomaly Score", "入站异常评分", 1)
	result = strings.Replace(result, "Outbound Anomaly Score", "出站异常评分", 1)
	
	return result
}

func translateAndDeduplicateRules(rulesStr string) string {
	if rulesStr == "" || rulesStr == "无" {
		return rulesStr
	}
	
	type RuleEntry struct {
		ID      int    `json:"id"`
		Message string `json:"message"`
	}
	
	var rules []RuleEntry
	err := json.Unmarshal([]byte("["+rulesStr+"]"), &rules)
	if err != nil {
		return rulesStr
	}
	
	seenMessages := make(map[string]bool)
	var translatedRules []string
	
	for _, rule := range rules {
		translatedMsg := translateMessage(rule.Message)
		if !seenMessages[translatedMsg] {
			seenMessages[translatedMsg] = true
			escapedMsg := strings.ReplaceAll(translatedMsg, `"`, `\"`)
			translatedRules = append(translatedRules, fmt.Sprintf(`{"id": %d, "message": "%s"}`, rule.ID, escapedMsg))
		}
	}
	
	return strings.Join(translatedRules, ",")
}

func getUTCTime() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func getUTCTimestamp() int64 {
	return time.Now().UTC().Unix()
}

func refreshTrendCache() {
	trendCacheMutex.Lock()
	defer trendCacheMutex.Unlock()

	currentHour := time.Now().UTC().Hour()
	lastTrendUpdateHour = currentHour

	queryHourlyTrend := func(queryDate string) []HourlyTrend {
		year, month, day := time.Now().UTC().Date()
		if queryDate != time.Now().Format("2006-01-02") {
			t, _ := time.Parse("2006-01-02", queryDate)
			year, month, day = t.UTC().Date()
		}
		startOfDay := time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Unix()
		endOfDay := time.Date(year, month, day, 23, 59, 59, 0, time.UTC).Unix()

		rows, err := db.Query(`
			SELECT
				CAST((created_at - ?) / 3600 AS INTEGER) as hour,
				COALESCE(COUNT(DISTINCT CASE WHEN result != 'pass' THEN ip END), 0) as abnormal_ip_count,
				COALESCE(SUM(CASE WHEN result = 'block' THEN 1 ELSE 0 END), 0) as block_count,
				COALESCE(SUM(CASE WHEN result = 'observe' THEN 1 ELSE 0 END), 0) as observe_count
			FROM ip_access_logs
			WHERE created_at >= ? AND created_at <= ?
			GROUP BY hour
			ORDER BY hour
		`, startOfDay, startOfDay, endOfDay)

		if err != nil {
			log.Printf("查询趋势数据失败: %v", err)
			return make([]HourlyTrend, 0)
		}
		defer rows.Close()

		hourlyMap := make(map[int]HourlyTrend)
		for rows.Next() {
			var trend HourlyTrend
			rows.Scan(&trend.Hour, &trend.AbnormalIPCount, &trend.BlockCount, &trend.ObserveCount)
			hourlyMap[trend.Hour] = trend
		}

		result := make([]HourlyTrend, 24)
		for i := 0; i < 24; i++ {
			if t, ok := hourlyMap[i]; ok {
				result[i] = t
			} else {
				result[i] = HourlyTrend{Hour: i, AbnormalIPCount: 0, BlockCount: 0, ObserveCount: 0}
			}
		}
		return result
	}

	date := time.Now().Format("2006-01-02")
	compareDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	cachedTodayTrend = queryHourlyTrend(date)
	cachedYesterdayTrend = queryHourlyTrend(compareDate)
}

const currentDBVersion = "1.6"

func getCurrentDBVersion() string {
	var version string
	err := db.QueryRow("SELECT version FROM db_version WHERE id = 1").Scan(&version)
	if err != nil {
		return "1.0"
	}
	return version
}

func setDBVersion(version string) error {
	// 先尝试更新 id 为 1 的记录
	result, err := db.Exec("UPDATE db_version SET version = ?, updated_at = ? WHERE id = 1", version, getUTCTimestamp())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	// 如果没有更新任何记录（说明不存在 id 为 1 的记录），则插入新记录
	if rowsAffected == 0 {
		_, err := db.Exec("INSERT INTO db_version (id, version, updated_at) VALUES (1, ?, ?)", version, getUTCTimestamp())
		return err
	}

	return nil
}

var upgradeProgress struct {
	mutex     sync.Mutex
	stage     string
	current   int
	total     int
	stepName  string
	completed bool
	error     string
}

func initUpgradeProgress() {
	upgradeProgress = struct {
		mutex     sync.Mutex
		stage     string
		current   int
		total     int
		stepName  string
		completed bool
		error     string
	}{}
}

func updateUpgradeProgress(stage string, current, total int, stepName string) {
	upgradeProgress.mutex.Lock()
	defer upgradeProgress.mutex.Unlock()
	upgradeProgress.stage = stage
	upgradeProgress.current = current
	upgradeProgress.total = total
	upgradeProgress.stepName = stepName
}

func setUpgradeCompleted() {
	upgradeProgress.mutex.Lock()
	defer upgradeProgress.mutex.Unlock()
	upgradeProgress.completed = true
}

func setUpgradeError(err string) {
	upgradeProgress.mutex.Lock()
	defer upgradeProgress.mutex.Unlock()
	upgradeProgress.error = err
}

func getUpgradeProgress() (stage string, current, total int, stepName string, completed bool, err string) {
	upgradeProgress.mutex.Lock()
	defer upgradeProgress.mutex.Unlock()
	return upgradeProgress.stage, upgradeProgress.current, upgradeProgress.total, upgradeProgress.stepName, upgradeProgress.completed, upgradeProgress.error
}

func backupDatabase() (string, error) {
	dbPath := "./data/waf.db"
	backupDir := "./data/backup"
	
	err := os.MkdirAll(backupDir, 0755)
	if err != nil {
		return "", fmt.Errorf("创建备份目录失败: %v", err)
	}
	
	_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err != nil {
		log.Printf("WAL检查点操作失败: %v", err)
	} else {
		log.Println("WAL文件已合并到主数据库")
	}
	
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s/waf_backup_%s.db", backupDir, timestamp)
	
	sourceFile, err := os.Open(dbPath)
	if err != nil {
		return "", fmt.Errorf("打开源数据库文件失败: %v", err)
	}
	defer sourceFile.Close()
	
	destFile, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("创建备份文件失败: %v", err)
	}
	defer destFile.Close()
	
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("复制数据库文件失败: %v", err)
	}
	
	return backupPath, nil
}

func convertTimeStringToTimestamp(timeStr string) int64 {
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	}

	for _, format := range formats {
		t, err := time.Parse(format, timeStr)
		if err == nil {
			return t.Unix()
		}
	}

	log.Printf("无法解析时间字符串: %s，使用当前时间", timeStr)
	return getUTCTimestamp()
}

func upgradeTo11() error {
	log.Println("升级到版本 1.1...")
	updateUpgradeProgress("backingup", 0, 2, "备份数据库...")

	backupPath, err := backupDatabase()
	if err != nil {
		log.Printf("数据库备份失败: %v", err)
		return fmt.Errorf("数据库备份失败: %v", err)
	}
	log.Printf("数据库备份成功: %s", backupPath)

	updateUpgradeProgress("upgrading", 0, 2, "转换时间字段...")

	tables := []struct {
		name        string
		idCol       string
		timeCol     string
		displayName string
		idType      string
	}{
		{"waf_instances", "id", "created_at", "WAF实例", "text"},
		{"proxy_instances", "id", "created_at", "代理实例", "text"},
		{"port_forward_instances", "id", "created_at", "端口转发", "text"},
		{"attack_logs", "id", "time", "攻击日志", "text"},
		{"statistics", "id", "updated_at", "统计数据", "int"},
		{"ip_whitelist", "id", "created_at", "IP白名单", "int"},
		{"ip_blacklist", "id", "created_at", "IP黑名单", "int"},
		{"ip_settings", "id", "updated_at", "IP设置", "int"},
		{"system_settings", "key", "updated_at", "系统设置", "text"},
		{"ip_access_logs", "id", "created_at", "IP访问日志", "int"},
		{"webhook_settings", "id", "updated_at", "Webhook设置", "int"},
	}

	batchSize := 1000
	for _, table := range tables {
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s", table.name)
		db.QueryRow(query).Scan(&count)
		if count == 0 {
			continue
		}

		processed := 0
		for processed < count {
			batchEnd := processed + batchSize
			if batchEnd > count {
				batchEnd = count
			}

			var rows *sql.Rows
			if table.idType == "int" {
				query := fmt.Sprintf("SELECT id, %s FROM %s LIMIT ? OFFSET ?", table.timeCol, table.name)
				rows, _ = db.Query(query, batchSize, processed)
			} else {
				query := fmt.Sprintf("SELECT %s, %s FROM %s LIMIT ? OFFSET ?", table.idCol, table.timeCol, table.name)
				rows, _ = db.Query(query, batchSize, processed)
			}

			updates := make([]struct {
				id        interface{}
				timestamp int64
			}, 0)

			for rows.Next() {
				var id interface{}
				var timeStr string
				if table.idType == "int" {
					var intId int
					rows.Scan(&intId, &timeStr)
					id = intId
				} else {
					var textId string
					rows.Scan(&textId, &timeStr)
					id = textId
				}
				timestamp := convertTimeStringToTimestamp(timeStr)
				updates = append(updates, struct {
					id        interface{}
					timestamp int64
				}{id, timestamp})
			}
			rows.Close()

			tx, _ := db.Begin()
			stmt, _ := tx.Prepare(fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?", table.name, table.timeCol, table.idCol))
			for _, u := range updates {
				stmt.Exec(u.timestamp, u.id)
			}
			stmt.Close()
			tx.Commit()

			processed = batchEnd
		}
		log.Printf("升级 %s 表完成", table.displayName)
	}

	_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err != nil {
		log.Printf("清理WAL文件失败: %v", err)
	}

	updateUpgradeProgress("finalizing", 2, 2, "更新数据库版本...")
	err = setDBVersion("1.1")
	if err != nil {
		return fmt.Errorf("更新数据库版本失败: %w", err)
	}

	log.Println("升级到 1.1 完成")
	return nil
}

func upgradeTo12() error {
	log.Println("升级到版本 1.2...")
	updateUpgradeProgress("upgrading", 0, 2, "添加 platform 字段...")

	_, err := db.Exec("ALTER TABLE attack_logs ADD COLUMN platform TEXT DEFAULT 'Unknown'")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加platform字段失败: %v", err)
		return err
	}
	log.Println("platform字段已添加/已存在")

	updateUpgradeProgress("upgrading", 1, 2, "添加 browser 字段...")

	_, err = db.Exec("ALTER TABLE attack_logs ADD COLUMN browser TEXT DEFAULT 'Unknown'")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加browser字段失败: %v", err)
		return err
	}
	log.Println("browser字段已添加/已存在")

	updateUpgradeProgress("finalizing", 2, 2, "更新数据库版本...")
	err = setDBVersion("1.2")
	if err != nil {
		return fmt.Errorf("更新数据库版本失败: %w", err)
	}

	log.Println("升级到 1.2 完成")
	return nil
}

func upgradeTo13() error {
	log.Println("升级到版本 1.3...")
	updateUpgradeProgress("upgrading", 0, 4, "添加 tls_enabled 字段到 proxy_instances...")

	_, err := db.Exec("ALTER TABLE proxy_instances ADD COLUMN tls_enabled INTEGER DEFAULT 0")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 tls_enabled 字段失败: %v", err)
		return err
	}
	log.Println("tls_enabled 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 1, 4, "添加 tls_cert_file 字段到 proxy_instances...")

	_, err = db.Exec("ALTER TABLE proxy_instances ADD COLUMN tls_cert_file TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 tls_cert_file 字段失败: %v", err)
		return err
	}
	log.Println("tls_cert_file 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 2, 4, "添加 tls_key_file 字段到 proxy_instances...")

	_, err = db.Exec("ALTER TABLE proxy_instances ADD COLUMN tls_key_file TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 tls_key_file 字段失败: %v", err)
		return err
	}
	log.Println("tls_key_file 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 3, 4, "添加 ACME 字段到 certificates...")

	acmeFields := []struct {
		field string
		sql   string
	}{
		{"acme_kid", "ALTER TABLE certificates ADD COLUMN acme_kid TEXT"},
		{"acme_hmac_key", "ALTER TABLE certificates ADD COLUMN acme_hmac_key TEXT"},
		{"acme_server_url", "ALTER TABLE certificates ADD COLUMN acme_server_url TEXT"},
		{"acme_email", "ALTER TABLE certificates ADD COLUMN acme_email TEXT"},
	}

	for _, f := range acmeFields {
		_, err = db.Exec(f.sql)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("添加 %s 字段失败: %v", f.field, err)
			return err
		}
		log.Printf("%s 字段已添加/已存在", f.field)
	}

	updateUpgradeProgress("finalizing", 4, 4, "更新数据库版本...")
	err = setDBVersion("1.3")
	if err != nil {
		return fmt.Errorf("更新数据库版本失败: %w", err)
	}

	log.Println("升级到 1.3 完成")
	return nil
}

func upgradeTo14() error {
	log.Println("升级到版本 1.4...")
	updateUpgradeProgress("upgrading", 0, 8, "创建域名规则表 proxy_domain_rules...")

	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS proxy_domain_rules (
		id TEXT PRIMARY KEY,
		proxy_id TEXT NOT NULL,
		domain TEXT NOT NULL,
		backend TEXT NOT NULL,
		is_default INTEGER DEFAULT 0,
		rule_type TEXT DEFAULT 'proxy',
		redirect_url TEXT,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (proxy_id) REFERENCES proxy_instances(id) ON DELETE CASCADE
	)`)
	if err != nil {
		log.Printf("创建 proxy_domain_rules 表失败: %v", err)
		return err
	}
	log.Println("proxy_domain_rules 表已创建")

	updateUpgradeProgress("upgrading", 1, 8, "添加 fallback_backend 字段到 proxy_instances...")
	_, err = db.Exec("ALTER TABLE proxy_instances ADD COLUMN fallback_backend TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 fallback_backend 字段失败: %v", err)
		return err
	}
	log.Println("fallback_backend 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 2, 8, "检查是否需要迁移代理实例...")
	rows, err := db.Query("SELECT name, listen_port, backend, waf_id, created_at, tls_enabled, tls_cert_file, tls_key_file FROM proxy_instances")
	if err != nil {
		log.Printf("查询代理实例失败: %v", err)
		return err
	}
	defer rows.Close()

	type oldProxyInstance struct {
		Name        string
		ListenPort  int
		Backend     string
		WafID       string
		CreatedAt   int64
		TLSEnabled  int
		TLSCertFile string
		TLSKeyFile  string
	}

	var oldInstances []oldProxyInstance
	for rows.Next() {
		var o oldProxyInstance
		err := rows.Scan(&o.Name, &o.ListenPort, &o.Backend, &o.WafID, &o.CreatedAt, &o.TLSEnabled, &o.TLSCertFile, &o.TLSKeyFile)
		if err != nil {
			log.Printf("扫描代理实例失败: %v", err)
			continue
		}
		oldInstances = append(oldInstances, o)
	}

	if len(oldInstances) == 0 {
		log.Println("没有需要迁移的代理实例")
	} else {
		updateUpgradeProgress("upgrading", 3, 8, fmt.Sprintf("迁移 %d 个代理实例到新结构...", len(oldInstances)))
		log.Printf("开始迁移 %d 个代理实例...", len(oldInstances))

		updateUpgradeProgress("upgrading", 3, 8, "删除旧实例...")
		_, err = db.Exec("DELETE FROM proxy_instances")
		if err != nil {
			log.Printf("删除旧代理实例失败: %v", err)
			return err
		}

		updateUpgradeProgress("upgrading", 3, 8, fmt.Sprintf("创建 %d 个新实例...", len(oldInstances)))
		for i, o := range oldInstances {
			newID := fmt.Sprintf("proxy-%d", time.Now().UnixNano()+int64(i))
			now := time.Now().Unix()

			_, err := db.Exec(`INSERT INTO proxy_instances (id, name, listen_port, backend, fallback_backend, waf_id, created_at, tls_enabled, tls_cert_file, tls_key_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				newID, o.Name, o.ListenPort, o.Backend, o.Backend, o.WafID, now, o.TLSEnabled, o.TLSCertFile, o.TLSKeyFile)
			if err != nil {
				log.Printf("迁移代理实例 %s 失败: %v", o.Name, err)
				continue
			}
			log.Printf("代理实例 %s 已迁移，新ID: %s", o.Name, newID)

			ruleID := fmt.Sprintf("rule-%d", time.Now().UnixNano()+int64(i)+1000)
			_, err = db.Exec(`INSERT INTO proxy_domain_rules (id, proxy_id, domain, backend, is_default, rule_type, redirect_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				ruleID, newID, "", o.Backend, 1, "proxy", "", now)
			if err != nil {
				log.Printf("为代理实例 %s 创建默认规则失败: %v", o.Name, err)
			} else {
				log.Printf("为代理实例 %s 创建默认规则成功", o.Name)
			}
		}
		log.Println("代理实例迁移完成")
	}

	updateUpgradeProgress("upgrading", 4, 8, "添加 rule_type 字段到域名规则...")
	_, err = db.Exec("ALTER TABLE proxy_domain_rules ADD COLUMN rule_type TEXT DEFAULT 'proxy'")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 rule_type 字段失败: %v", err)
		return err
	}
	log.Println("rule_type 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 5, 8, "添加 redirect_url 字段到域名规则...")
	_, err = db.Exec("ALTER TABLE proxy_domain_rules ADD COLUMN redirect_url TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 redirect_url 字段失败: %v", err)
		return err
	}
	log.Println("redirect_url 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 6, 8, "清理无用字段...")
	_, _ = db.Exec("DELETE FROM proxy_instances WHERE name = '' OR name IS NULL")
	log.Println("无用字段已清理")

	updateUpgradeProgress("finalizing", 7, 8, "更新数据库版本...")
	err = setDBVersion("1.4")
	if err != nil {
		return fmt.Errorf("更新数据库版本失败: %w", err)
	}

	log.Println("升级到 1.4 完成")
	return nil
}

func upgradeTo15() error {
	log.Println("升级到版本 1.5...")
	updateUpgradeProgress("upgrading", 0, 4, "添加 force_https 字段...")

	_, err := db.Exec("ALTER TABLE proxy_instances ADD COLUMN force_https INTEGER DEFAULT 0")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 force_https 字段失败: %v", err)
		return err
	}
	log.Println("force_https 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 1, 4, "添加 http_listen_port 字段...")
	_, err = db.Exec("ALTER TABLE proxy_instances ADD COLUMN http_listen_port INTEGER DEFAULT 0")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 http_listen_port 字段失败: %v", err)
		return err
	}
	log.Println("http_listen_port 字段已添加/已存在")

	updateUpgradeProgress("upgrading", 2, 4, "添加 fallback_backend 字段（如果不存在）...")
	_, err = db.Exec("ALTER TABLE proxy_instances ADD COLUMN fallback_backend TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		log.Printf("添加 fallback_backend 字段失败: %v", err)
	}

	updateUpgradeProgress("upgrading", 3, 4, "清理旧的 db_version 记录...")
	_, err = db.Exec("DELETE FROM db_version WHERE id != 1")
	if err != nil {
		log.Printf("清理旧的 db_version 记录失败: %v", err)
	}
	log.Println("旧的 db_version 记录已清理")

	updateUpgradeProgress("finalizing", 4, 4, "更新数据库版本...")
	err = setDBVersion("1.5")
	if err != nil {
		return fmt.Errorf("更新数据库版本失败: %w", err)
	}

	log.Println("升级到 1.5 完成")
	return nil
}

func upgradeTo16() error {
	log.Println("升级到版本 1.6...")

	updateUpgradeProgress("migrating", 1, 1, "添加 github_mirror 设置...")
	_, err := db.Exec("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('github_mirror', '', ?)", getUTCTimestamp())
	if err != nil {
		log.Printf("添加 github_mirror 设置失败: %v", err)
	}

	updateUpgradeProgress("finalizing", 1, 1, "更新数据库版本...")
	err = setDBVersion("1.6")
	if err != nil {
		return fmt.Errorf("更新数据库版本失败: %w", err)
	}

	log.Println("升级到 1.6 完成")
	return nil
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type WAFInstance struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	Rules           []string `json:"rules"`
	WAF             coraza.WAF
	CreatedAt       string   `json:"createdAt"`
	BoundProxyCount  int      `json:"boundProxyCount"`
}

type ProxyInstance struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ListenPort       int    `json:"listenPort"`
	Backend          string `json:"backend"`
	FallbackBackend  string `json:"fallbackBackend"`
	WAFID            string `json:"wafId"`
	WAFName          string `json:"wafName,omitempty"`
	Proxy            *httputil.ReverseProxy `json:"-"`
	Server           *http.Server `json:"-"`
	TLSEnabled       bool     `json:"tlsEnabled"`
	TLSCertFile      string   `json:"tlsCertFile"`
	TLSKeyFile       string   `json:"tlsKeyFile"`
	ForceHTTPS       bool     `json:"forceHttps"`
	HTTPListenPort   int      `json:"httpListenPort"`
	HTTPServer       *http.Server `json:"-"`
	DomainRules      []*DomainRule `json:"domainRules"`
	CreatedAt        string `json:"createdAt"`
}

type DomainRule struct {
	ID          string `json:"id"`
	ProxyID     string `json:"proxyId"`
	Domain      string `json:"domain"`
	Backend     string `json:"backend"`
	IsDefault   bool   `json:"isDefault"`
	RuleType    string `json:"ruleType"`
	RedirectURL string `json:"redirectUrl"`
	CreatedAt   string `json:"createdAt"`
}

type Certificate struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Domains         string `json:"domains"`
	Provider        string `json:"provider"`
	CertFile        string `json:"certFile"`
	KeyFile         string `json:"keyFile"`
	CaFile          string `json:"caFile"`
	ExpiresAt       int64  `json:"expiresAt"`
	AutoRenew       bool   `json:"autoRenew"`
	Status          string `json:"status"`
	CreatedAt       string `json:"createdAt"`
	CloudflareAPIToken string `json:"cloudflareApiToken"`
	CloudflareEmail     string `json:"cloudflareEmail"`
	AcmeKid         string `json:"acmeKid"`
	AcmeHmacKey     string `json:"acmeHmacKey"`
	AcmeServerURL   string `json:"acmeServerUrl"`
	AcmeEmail       string `json:"acmeEmail"`
}

type PortForwardInstance struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	ListenPort    int    `json:"listenPort"`
	TargetAddress string `json:"targetAddress"`
	TargetPort    int    `json:"targetPort"`
	IPMode        string `json:"ipMode"`
	ActionMode    string `json:"actionMode"`
	Status        string `json:"status"`
	CreatedAt     string `json:"createdAt"`
	Listener      interface{} `json:"-"`
	StopFunc      func()   `json:"-"`
}

type AttackLog struct {
	ID         string  `json:"id"`
	Action     string  `json:"action"`
	URL        string  `json:"url"`
	AttackType string  `json:"attackType"`
	IP         string  `json:"ip"`
	Time       string  `json:"time"`
	Rules      string  `json:"rules"`
	Method     string  `json:"method"`
	ProxyID    string  `json:"proxyId"`
	StatusCode  int     `json:"statusCode"`
	Country    string  `json:"country"`
	Province   string  `json:"province"`
	City       string  `json:"city"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	FilterType string  `json:"filterType"`
	Platform   string  `json:"platform"`
	Browser    string  `json:"browser"`
}

type RuleInfo struct {
	Code        string `json:"code"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Statistics struct {
	RequestCount    int64             `json:"requestCount"`
	PV             int64             `json:"pv"`
	UV             int64             `json:"uv"`
	UniqueIP        int               `json:"uniqueIP"`
	BlockedCount    int64             `json:"blockedCount"`
	AttackIP        int               `json:"attackIP"`
	QPS             int               `json:"qps"`
	AvgResponseTime int64             `json:"avgResponseTime"`
	PVPeak          int64             `json:"pvPeak"`
	BlockPeak       int64             `json:"blockPeak"`
	GeoDistribution  map[string]int    `json:"geoDistribution"`
	ProvinceDistribution map[string]int `json:"provinceDistribution"`
	AccessGeoDistribution map[string]int `json:"accessGeoDistribution"`
	AccessProvinceDistribution map[string]int `json:"accessProvinceDistribution"`
	DetectedGeoDistribution map[string]int `json:"detectedGeoDistribution"`
	DetectedProvinceDistribution map[string]int `json:"detectedProvinceDistribution"`
	BlockedGeoDistribution map[string]int `json:"blockedGeoDistribution"`
	BlockedProvinceDistribution map[string]int `json:"blockedProvinceDistribution"`
	FourXxError     int64             `json:"fourXxError"`
	FourXxErrorRate float64           `json:"fourXxErrorRate"`
	FiveXxError     int64             `json:"fiveXxError"`
	FiveXxErrorRate float64           `json:"fiveXxErrorRate"`
	FourXxBlocked    int64             `json:"fourXxBlocked"`
	FourXxBlockRate  float64           `json:"fourXxBlockRate"`
	InboundRate     int64             `json:"inboundRate"`
	OutboundRate    int64             `json:"outboundRate"`
}

type TrafficStats struct {
	InboundBytes  int64 `json:"inboundBytes"`
	OutboundBytes int64 `json:"outboundBytes"`
	InboundRate  int64 `json:"inboundRate"`
	OutboundRate int64 `json:"outboundRate"`
}

type QPSHistory struct {
	Time string `json:"time"`
	QPS  int    `json:"qps"`
}

type AttackHistory struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
}

type TrafficHistory struct {
	Time     string `json:"time"`
	Inbound  int64 `json:"inbound"`
	Outbound int64 `json:"outbound"`
}

var statsMutex sync.RWMutex
var currentStats Statistics
var trafficStats TrafficStats
var qpsHistory []QPSHistory
var attackHistory []AttackHistory
var trafficHistory []TrafficHistory
var lastRequestCount int64
var lastBlockedCount int64
var lastUpdateTime time.Time

type HourlyTrend struct {
	Hour            int `json:"hour"`
	AbnormalIPCount int `json:"abnormal_ip_count"`
	BlockCount      int `json:"block_count"`
	ObserveCount    int `json:"observe_count"`
}

var (
	trendCacheMutex     sync.RWMutex
	cachedTodayTrend    []HourlyTrend
	cachedYesterdayTrend []HourlyTrend
	lastTrendUpdateHour int
)
var lastInboundBytes int64
var lastOutboundBytes int64
var visitorMap = make(map[string]time.Time)

var ruleNameMap = map[string]string{
	"900": "排除规则配置",
	"901": "初始化配置",
	"905": "通用异常",
	"911": "HTTP方法强制",
	"913": "扫描器检测",
	"920": "协议强制执行",
	"921": "协议攻击",
	"922": "Multipart攻击",
	"930": "本地文件包含攻击",
	"931": "远程文件包含攻击",
	"932": "远程代码执行攻击",
	"933": "PHP应用攻击",
	"934": "通用应用攻击",
	"941": "跨站脚本攻击",
	"942": "SQL注入攻击",
	"943": "会话固定攻击",
	"944": "Java应用攻击",
	"949": "阻断评估",
	"950": "数据泄露",
	"951": "SQL数据泄露",
	"952": "Java数据泄露",
	"953": "PHP数据泄露",
	"954": "IIS数据泄露",
	"955": "Web Shell",
	"956": "Ruby数据泄露",
	"959": "阻断评估",
	"980": "关联分析",
	"999": "排除规则配置",
}

var adminPort = 15501

var rirImportProgress struct {
	Status    string
	Processed int
	Total     int
	Found     int
	Message   string
}

func closeDB() error {
	if db != nil {
		_, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		if err != nil {
			log.Printf("关闭前checkpoint失败: %v", err)
		}
		err = db.Close()
		if err != nil {
			return err
		}
		db = nil
	}
	return nil
}

func initDB() error {
	var err error

	err = os.MkdirAll("./data", 0755)
	if err != nil {
		return fmt.Errorf("创建data目录失败: %w", err)
	}

	db, err = sql.Open("sqlite", "./data/waf.db")
	if err != nil {
		return err
	}

	err = db.Ping()
	if err != nil {
		return err
	}

	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		log.Printf("启用WAL模式失败: %v", err)
	}

	_, err = db.Exec("PRAGMA busy_timeout=5000")
	if err != nil {
		log.Printf("设置busy_timeout失败: %v", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS waf_instances (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		mode TEXT NOT NULL,
		rules TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS proxy_instances (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		listen_port INTEGER NOT NULL,
		backend TEXT NOT NULL,
		fallback_backend TEXT,
		waf_id TEXT,
		tls_enabled INTEGER DEFAULT 0,
		tls_cert_file TEXT,
		tls_key_file TEXT,
		force_https INTEGER DEFAULT 0,
		http_listen_port INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (waf_id) REFERENCES waf_instances(id)
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		domains TEXT NOT NULL,
		provider TEXT NOT NULL,
		cert_file TEXT,
		key_file TEXT,
		ca_file TEXT,
		expires_at INTEGER,
		auto_renew INTEGER DEFAULT 0,
		status TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		cloudflare_api_token TEXT,
		cloudflare_email TEXT,
		acme_kid TEXT,
		acme_hmac_key TEXT,
		acme_server_url TEXT,
		acme_email TEXT
	);

	CREATE TABLE IF NOT EXISTS port_forward_instances (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		protocol TEXT NOT NULL,
		listen_port INTEGER NOT NULL,
		target_address TEXT NOT NULL,
		target_port INTEGER NOT NULL,
		ip_mode TEXT NOT NULL,
		action_mode TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS attack_logs (
		id TEXT PRIMARY KEY,
		action TEXT NOT NULL,
		url TEXT NOT NULL,
		attack_type TEXT,
		ip TEXT NOT NULL,
		time INTEGER NOT NULL,
		rules TEXT,
		method TEXT NOT NULL,
		proxy_id TEXT,
		status_code INTEGER,
		country TEXT,
		province TEXT,
		city TEXT,
		latitude REAL,
		longitude REAL,
		filter_type TEXT,
		platform TEXT DEFAULT 'Unknown',
		browser TEXT DEFAULT 'Unknown'
	);

	CREATE INDEX IF NOT EXISTS idx_attack_logs_time ON attack_logs(time DESC);
	CREATE INDEX IF NOT EXISTS idx_attack_logs_action ON attack_logs(action);
	CREATE INDEX IF NOT EXISTS idx_attack_logs_platform_browser ON attack_logs(platform, browser);

	CREATE TABLE IF NOT EXISTS statistics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_count INTEGER DEFAULT 0,
		pv INTEGER DEFAULT 0,
		uv INTEGER DEFAULT 0,
		unique_ip INTEGER DEFAULT 0,
		blocked_count INTEGER DEFAULT 0,
		attack_ip INTEGER DEFAULT 0,
		pv_peak INTEGER DEFAULT 0,
		block_peak INTEGER DEFAULT 0,
		four_xx_error INTEGER DEFAULT 0,
		four_xx_error_rate REAL DEFAULT 0,
		five_xx_error INTEGER DEFAULT 0,
		five_xx_error_rate REAL DEFAULT 0,
		four_xx_block_rate REAL DEFAULT 0,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS ip_whitelist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		description TEXT,
		source TEXT DEFAULT 'custom',
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS ip_blacklist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		description TEXT,
		source TEXT DEFAULT 'custom',
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS ip_settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT NOT NULL DEFAULT 'normal',
		action_mode TEXT NOT NULL DEFAULT 'block',
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS system_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS ip_access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		mode TEXT NOT NULL,
		action TEXT NOT NULL,
		result TEXT NOT NULL,
		url TEXT,
		country TEXT,
		province TEXT,
		city TEXT,
		latitude REAL,
		longitude REAL,
		forward_type TEXT,
		instance_name TEXT,
		forward_info TEXT,
		created_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_ip_access_logs_created_at ON ip_access_logs(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_ip_access_logs_result ON ip_access_logs(result);
	CREATE INDEX IF NOT EXISTS idx_ip_access_logs_created_at_date ON ip_access_logs(created_at);

	CREATE TABLE IF NOT EXISTS webhook_settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		enabled INTEGER NOT NULL DEFAULT 0,
		url TEXT NOT NULL,
		secret TEXT NOT NULL,
		events TEXT NOT NULL,
		timeout INTEGER NOT NULL DEFAULT 5,
		msg_type TEXT NOT NULL DEFAULT 'markdown',
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS db_version (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);
	`

	_, err = db.Exec(schema)
	if err != nil {
		return err
	}

	// 数据库迁移：为ip_settings表添加action_mode字段
	_, err = db.Exec("ALTER TABLE ip_settings ADD COLUMN action_mode TEXT NOT NULL DEFAULT 'block'")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加action_mode字段失败: %v", err)
	}
	
	// 数据库迁移：为ip_access_logs表添加url字段
	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN url TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加url字段到ip_access_logs失败: %v", err)
	}

	// 数据库迁移：为ip_access_logs表添加地理位置字段
	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN country TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加country字段到ip_access_logs失败: %v", err)
	}

	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN province TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加province字段到ip_access_logs失败: %v", err)
	}

	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN city TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加city字段到ip_access_logs失败: %v", err)
	}

	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN latitude REAL")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加latitude字段到ip_access_logs失败: %v", err)
	}

	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN longitude REAL")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加longitude字段到ip_access_logs失败: %v", err)
	}

	// 数据库迁移：为ip_access_logs表添加转发类型字段
	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN forward_type TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加forward_type字段到ip_access_logs失败: %v", err)
	}

	// 数据库迁移：为ip_access_logs表添加实例名称字段
	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN instance_name TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加instance_name字段到ip_access_logs失败: %v", err)
	}

	// 数据库迁移：为ip_access_logs表添加转发信息字段
	_, err = db.Exec("ALTER TABLE ip_access_logs ADD COLUMN forward_info TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加forward_info字段到ip_access_logs失败: %v", err)
	}

	// 数据库迁移：为attack_logs表添加filter_type字段
	_, err = db.Exec("ALTER TABLE attack_logs ADD COLUMN filter_type TEXT")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加filter_type字段到attack_logs失败: %v", err)
	}

	// 数据库迁移：为webhook_settings表添加msg_type字段
	_, err = db.Exec("ALTER TABLE webhook_settings ADD COLUMN msg_type TEXT NOT NULL DEFAULT 'markdown'")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加msg_type字段到webhook_settings失败: %v", err)
	}

	// 检查统计记录表是否为空
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM statistics").Scan(&count)
	if err != nil {
		log.Printf("查询统计记录数量失败: %v", err)
	} else if count == 0 {
		// 如果表为空，插入一条新记录
		_, err = db.Exec("INSERT INTO statistics (request_count, pv, uv, unique_ip, blocked_count, attack_ip, pv_peak, block_peak, four_xx_error, four_xx_error_rate, five_xx_error, five_xx_error_rate, four_xx_block_rate, updated_at) VALUES (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?)", getUTCTime())
		if err != nil {
			log.Printf("插入统计记录失败: %v", err)
		}
	}

	// 检查并添加source字段到ip_whitelist表
	err = db.QueryRow("PRAGMA table_info(ip_whitelist)").Scan(new(interface{}), new(interface{}), new(interface{}), new(interface{}), new(interface{}), new(interface{}))
	if err != nil {
		log.Printf("检查ip_whitelist表结构失败: %v", err)
	} else {
		var hasSourceColumn bool
		rows, _ := db.Query("PRAGMA table_info(ip_whitelist)")
		for rows.Next() {
			var cid interface{}
			var name string
			var type_ interface{}
			var notnull interface{}
			var dflt_value interface{}
			var pk interface{}
			rows.Scan(&cid, &name, &type_, &notnull, &dflt_value, &pk)
			if name == "source" {
				hasSourceColumn = true
				break
			}
		}
		rows.Close()
		
		if !hasSourceColumn {
			_, err = db.Exec("ALTER TABLE ip_whitelist ADD COLUMN source TEXT DEFAULT 'custom'")
			if err != nil {
				log.Printf("添加source字段到ip_whitelist失败: %v", err)
			} else {
				log.Println("已添加source字段到ip_whitelist表")
			}
		}
	}

	// 检查并添加source字段到ip_blacklist表
	err = db.QueryRow("PRAGMA table_info(ip_blacklist)").Scan(new(interface{}), new(interface{}), new(interface{}), new(interface{}), new(interface{}), new(interface{}))
	if err != nil {
		log.Printf("检查ip_blacklist表结构失败: %v", err)
	} else {
		var hasSourceColumn bool
		rows, _ := db.Query("PRAGMA table_info(ip_blacklist)")
		for rows.Next() {
			var cid interface{}
			var name string
			var type_ interface{}
			var notnull interface{}
			var dflt_value interface{}
			var pk interface{}
			rows.Scan(&cid, &name, &type_, &notnull, &dflt_value, &pk)
			if name == "source" {
				hasSourceColumn = true
				break
			}
		}
		rows.Close()
		
		if !hasSourceColumn {
			_, err = db.Exec("ALTER TABLE ip_blacklist ADD COLUMN source TEXT DEFAULT 'custom'")
			if err != nil {
				log.Printf("添加source字段到ip_blacklist失败: %v", err)
			} else {
				log.Println("已添加source字段到ip_blacklist表")
			}
		}
	}

	// Load statistics from database
	var stat Statistics
	err = db.QueryRow("SELECT request_count, pv, uv, unique_ip, blocked_count, attack_ip, pv_peak, block_peak, four_xx_error, four_xx_error_rate, five_xx_error, five_xx_error_rate, four_xx_block_rate FROM statistics ORDER BY id DESC LIMIT 1").Scan(
		&stat.RequestCount, &stat.PV, &stat.UV, &stat.UniqueIP, &stat.BlockedCount, &stat.AttackIP, 
		&stat.PVPeak, &stat.BlockPeak, &stat.FourXxError, &stat.FourXxErrorRate, 
		&stat.FiveXxError, &stat.FiveXxErrorRate, &stat.FourXxBlockRate,
	)
	if err != nil {
		log.Printf("加载统计数据失败: %v", err)
		// Use default values if loading fails
		stat = Statistics{}
	}
	
	currentStats = stat

	// 初始化默认webhook配置
	var webhookCount int
	err = db.QueryRow("SELECT COUNT(*) FROM webhook_settings").Scan(&webhookCount)
	if err == nil && webhookCount == 0 {
		_, err = db.Exec("INSERT INTO webhook_settings (enabled, url, secret, events, timeout, msg_type, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			0, "", "", "attack,ip_blocked", 5, "markdown", getUTCTimestamp())
		if err != nil {
			log.Printf("创建默认webhook配置失败: %v", err)
		}
	}

	return nil
}

func createDefaultUser() error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", "admin", "admin")
		if err != nil {
			return err
		}
		log.Println("创建默认用户: admin/admin")
	}

	return nil
}

func initGeoIP() error {
	dbPath := "static/geoip/GeoLite2-City.mmdb"
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		log.Printf("GeoIP数据库加载失败: %v", err)
		return err
	}
	geoipReader = reader
	log.Println("GeoIP数据库加载成功")
	return nil
}

func getGeoLocation(ipStr string) (country, province, city string, latitude, longitude float64) {
	if geoipReader == nil || ipStr == "" {
		return "", "", "", 0, 0
	}

	cleanIP := strings.Trim(ipStr, "[]")
	ip := net.ParseIP(cleanIP)
	if ip == nil {
		return "", "", "", 0, 0
	}

	record, err := geoipReader.City(ip)
	if err != nil {
		return "", "", "", 0, 0
	}

	country = ""
	province = ""
	city = ""

	if record.Country.Names != nil {
		if name, ok := record.Country.Names["zh-CN"]; ok {
			country = name
		} else if name, ok := record.Country.Names["en"]; ok {
			country = name
		} else {
			country = record.Country.IsoCode
		}
	}

	if len(record.Subdivisions) > 0 {
		if record.Subdivisions[0].Names != nil {
			if name, ok := record.Subdivisions[0].Names["zh-CN"]; ok {
				province = name
			} else if name, ok := record.Subdivisions[0].Names["en"]; ok {
				province = name
			}
		}
	}

	if record.City.Names != nil {
		if name, ok := record.City.Names["zh-CN"]; ok {
			city = name
		} else if name, ok := record.City.Names["en"]; ok {
			city = name
		}
	}

	latitude = record.Location.Latitude
	longitude = record.Location.Longitude

	if record.Country.IsoCode == "HK" {
		country = "中国"
		if province == "" {
			province = "香港"
		}
	}

	if record.Country.IsoCode == "TW" {
		country = "中国"
		if province == "" {
			province = "台湾"
		}
	}

	return country, province, city, latitude, longitude
}

func updateStats(remoteAddr string, statusCode int, isBlocked bool) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	currentStats.RequestCount++
	
	if !isBlocked {
		currentStats.PV++
	}

	cleanIP := getCleanIP(remoteAddr)
	if cleanIP != "" {
		currentStats.UniqueIP++
		
		now := time.Now()
		lastVisit, exists := visitorMap[cleanIP]
		
		if !exists || now.Sub(lastVisit) > 24*time.Hour {
			visitorMap[cleanIP] = now
			currentStats.UV++
		}
	}

	if isBlocked {
		currentStats.BlockedCount++
	}

	if statusCode >= 400 && statusCode < 500 {
		currentStats.FourXxError++
	} else if statusCode >= 500 {
		currentStats.FiveXxError++
	}

	totalRequests := currentStats.RequestCount
	if totalRequests > 0 {
		currentStats.FourXxErrorRate = float64(currentStats.FourXxError) / float64(totalRequests) * 100
		currentStats.FiveXxErrorRate = float64(currentStats.FiveXxError) / float64(totalRequests) * 100
		currentStats.FourXxBlockRate = float64(currentStats.BlockedCount) / float64(totalRequests) * 100
	}

	// Update database
	for i := 0; i < 5; i++ {
		_, err := db.Exec(
			"UPDATE statistics SET request_count = ?, pv = ?, uv = ?, unique_ip = ?, blocked_count = ?, attack_ip = ?, pv_peak = ?, block_peak = ?, four_xx_error = ?, four_xx_error_rate = ?, five_xx_error = ?, five_xx_error_rate = ?, four_xx_block_rate = ?, updated_at = ?",
			currentStats.RequestCount, currentStats.PV, currentStats.UV, currentStats.UniqueIP, currentStats.BlockedCount, currentStats.AttackIP,
			currentStats.PVPeak, currentStats.BlockPeak, currentStats.FourXxError, currentStats.FourXxErrorRate,
			currentStats.FiveXxError, currentStats.FiveXxErrorRate, currentStats.FourXxBlockRate, getUTCTimestamp(),
		)
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "SQLITE_BUSY") {
			time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
			continue
		}
		log.Printf("更新统计数据到数据库失败: %v", err)
		return
	}
}

func updateHistory() {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	now := time.Now()
	if lastUpdateTime.IsZero() {
		lastUpdateTime = now
		lastRequestCount = currentStats.RequestCount
		lastBlockedCount = currentStats.BlockedCount
		lastInboundBytes = trafficStats.InboundBytes
		lastOutboundBytes = trafficStats.OutboundBytes
		
		currentStats.QPS = 0
		currentStats.InboundRate = 0
		currentStats.OutboundRate = 0
		
		qpsHistory = append(qpsHistory, QPSHistory{
			Time: now.Format("15:04:05"),
			QPS:  0,
		})
		
		attackHistory = append(attackHistory, AttackHistory{
			Time:  now.Format("15:04:05"),
			Count: 0,
		})
		
		trafficHistory = append(trafficHistory, TrafficHistory{
			Time:     now.Format("15:04:05"),
			Inbound:  0,
			Outbound: 0,
		})
		
		return
	}

	elapsed := now.Sub(lastUpdateTime).Seconds()
	if elapsed >= 2.0 {
		requestDelta := currentStats.RequestCount - lastRequestCount
		blockedDelta := currentStats.BlockedCount - lastBlockedCount
		inboundDelta := trafficStats.InboundBytes - lastInboundBytes
		outboundDelta := trafficStats.OutboundBytes - lastOutboundBytes

		currentStats.QPS = int(float64(requestDelta) / elapsed)

		peakUpdated := false
		if int64(requestDelta) > currentStats.PVPeak {
			currentStats.PVPeak = int64(requestDelta)
			peakUpdated = true
		}
		if int64(blockedDelta) > currentStats.BlockPeak {
			currentStats.BlockPeak = int64(blockedDelta)
			peakUpdated = true
		}

		// Update database if peak values changed
		if peakUpdated {
			_, err := db.Exec(
				"UPDATE statistics SET pv_peak = ?, block_peak = ?, updated_at = ?",
				currentStats.PVPeak, currentStats.BlockPeak, getUTCTimestamp(),
			)
			if err != nil {
				log.Printf("更新统计峰值到数据库失败: %v", err)
			}
		}

		currentStats.InboundRate = int64(float64(inboundDelta) / elapsed)
		currentStats.OutboundRate = int64(float64(outboundDelta) / elapsed)

		qpsHistory = append(qpsHistory, QPSHistory{
			Time: now.Format("15:04:05"),
			QPS:  currentStats.QPS,
		})
		if len(qpsHistory) > 60 {
			qpsHistory = qpsHistory[len(qpsHistory)-60:]
		}

		attackHistory = append(attackHistory, AttackHistory{
			Time:  now.Format("15:04:05"),
			Count: int(blockedDelta),
		})
		if len(attackHistory) > 60 {
			attackHistory = attackHistory[len(attackHistory)-60:]
		}

		trafficHistory = append(trafficHistory, TrafficHistory{
			Time:     now.Format("15:04:05"),
			Inbound:  currentStats.InboundRate,
			Outbound: currentStats.OutboundRate,
		})
		if len(trafficHistory) > 60 {
			trafficHistory = trafficHistory[len(trafficHistory)-60:]
		}

		lastUpdateTime = now
		lastRequestCount = currentStats.RequestCount
		lastBlockedCount = currentStats.BlockedCount
		lastInboundBytes = trafficStats.InboundBytes
		lastOutboundBytes = trafficStats.OutboundBytes
	}
}

func createWAF(mode string, rules []string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile("config/coraza.conf").
		WithDirectivesFromFile("coreruleset/crs-setup.conf")
	
	if mode == "On" {
		cfg = cfg.WithDirectives("SecRuleEngine On")
	} else if mode == "DetectionOnly" {
		cfg = cfg.WithDirectives("SecRuleEngine DetectionOnly")
	} else if mode == "Off" {
		cfg = cfg.WithDirectives("SecRuleEngine Off")
	}
	
	for _, ruleFile := range rules {
		cfg = cfg.WithDirectivesFromFile("coreruleset/rules/" + ruleFile)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, err
	}

	return waf, nil
}

func createWAFInstance(name, mode string, rules []string) (*WAFInstance, error) {
	id := fmt.Sprintf("waf-%d", time.Now().UnixNano())
	
	waf, err := createWAF(mode, rules)
	if err != nil {
		return nil, err
	}

	rulesJSON, _ := json.Marshal(rules)
	createdAt := getUTCTimestamp()

	_, err = db.Exec(
		"INSERT INTO waf_instances (id, name, mode, rules, created_at) VALUES (?, ?, ?, ?, ?)",
		id, name, mode, string(rulesJSON), createdAt,
	)
	if err != nil {
		return nil, err
	}

	instance := &WAFInstance{
		ID:        id,
		Name:      name,
		Mode:      mode,
		Rules:     rules,
		WAF:       waf,
		CreatedAt: fmt.Sprintf("%d", createdAt),
	}

	wafMutex.Lock()
	wafInstances[id] = instance
	wafMutex.Unlock()

	return instance, nil
}

func createProxyInstance(name string, listenPort int, backend, wafID string, tlsEnabled bool, tlsCertFile, tlsKeyFile string, fallbackBackend string, forceHTTPS bool, httpListenPort int) (*ProxyInstance, error) {
	// 验证监听端口
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("监听端口必须在1-65535之间")
	}

	// 验证HTTP端口（如果启用了强制HTTPS）
	if forceHTTPS {
		if httpListenPort < 1 || httpListenPort > 65535 {
			return nil, fmt.Errorf("HTTP监听端口必须在1-65535之间")
		}
		if httpListenPort == listenPort {
			return nil, fmt.Errorf("HTTP监听端口不能和主监听端口相同")
		}
	}

	if listenPort == adminPort {
		return nil, fmt.Errorf("端口 %d 与管理服务端口冲突", listenPort)
	}

	if forceHTTPS && httpListenPort == adminPort {
		return nil, fmt.Errorf("HTTP端口 %d 与管理服务端口冲突", httpListenPort)
	}

	proxyMutex.RLock()
	for _, inst := range proxyInstances {
		if inst.ListenPort == listenPort {
			proxyMutex.RUnlock()
			return nil, fmt.Errorf("端口 %d 已被防护应用占用", listenPort)
		}
		if forceHTTPS && inst.HTTPListenPort == httpListenPort {
			proxyMutex.RUnlock()
			return nil, fmt.Errorf("HTTP端口 %d 已被防护应用占用", httpListenPort)
		}
	}
	proxyMutex.RUnlock()

	portForwardMutex.RLock()
	for _, inst := range portForwardInstances {
		if inst.ListenPort == listenPort {
			portForwardMutex.RUnlock()
			return nil, fmt.Errorf("端口 %d 已被端口转发占用", listenPort)
		}
		if forceHTTPS && inst.ListenPort == httpListenPort {
			portForwardMutex.RUnlock()
			return nil, fmt.Errorf("HTTP端口 %d 已被端口转发占用", httpListenPort)
		}
	}
	portForwardMutex.RUnlock()

	id := fmt.Sprintf("proxy-%d", time.Now().UnixNano())
	
	targetURL, err := url.Parse(backend)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("代理错误: %v", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		http.ServeFile(w, r, "web/html/502.html")
	}

	createdAt := getUTCTimestamp()

	tlsEnabledInt := 0
	if tlsEnabled {
		tlsEnabledInt = 1
	}
	forceHTTPSInt := 0
	if forceHTTPS {
		forceHTTPSInt = 1
	}

	_, err = db.Exec(
		"INSERT INTO proxy_instances (id, name, listen_port, backend, fallback_backend, waf_id, created_at, tls_enabled, tls_cert_file, tls_key_file, force_https, http_listen_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		id, name, listenPort, backend, fallbackBackend, wafID, createdAt, tlsEnabledInt, tlsCertFile, tlsKeyFile, forceHTTPSInt, httpListenPort,
	)
	if err != nil {
		return nil, err
	}

	instance := &ProxyInstance{
		ID:              id,
		Name:            name,
		ListenPort:      listenPort,
		Backend:         backend,
		FallbackBackend: fallbackBackend,
		WAFID:           wafID,
		Proxy:           proxy,
		TLSEnabled:      tlsEnabled,
		TLSCertFile:     tlsCertFile,
		TLSKeyFile:      tlsKeyFile,
		ForceHTTPS:      forceHTTPS,
		HTTPListenPort:  httpListenPort,
		DomainRules:     []*DomainRule{},
		CreatedAt:       fmt.Sprintf("%d", createdAt),
	}
	
	if wafID != "" {
		wafMutex.RLock()
		if wafInst, exists := wafInstances[wafID]; exists {
			instance.WAFName = wafInst.Name
		}
		wafMutex.RUnlock()
	}

	defaultRuleID := fmt.Sprintf("dr-%d", time.Now().UnixNano())
	_, err = db.Exec("INSERT INTO proxy_domain_rules (id, proxy_id, domain, backend, is_default, rule_type, redirect_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		defaultRuleID, id, "", "", 1, "close", "", createdAt)
	if err != nil {
		log.Printf("创建默认关闭规则失败: %v", err)
	}
	instance.DomainRules = loadDomainRules(id)

	proxyMutex.Lock()
	proxyInstances[id] = instance
	proxyMutex.Unlock()

	var handler http.Handler = instance.Proxy
	
	if instance.WAFID != "" {
		wafMutex.RLock()
		wafInst, exists := wafInstances[instance.WAFID]
		wafMutex.RUnlock()
		
		if exists {
			handler = &wafHandler{next: instance.Proxy, waf: wafInst.WAF, proxyID: instance.ID}
		} else {
			handler = &ipCheckHandler{next: instance.Proxy, proxyID: instance.ID}
		}
	} else {
		handler = &ipCheckHandler{next: instance.Proxy, proxyID: instance.ID}
	}

	if instance.ListenPort == adminPort {
		log.Printf("代理服务器 %s 端口 %d 与管理服务端口冲突，跳过启动", instance.Name, instance.ListenPort)
		return nil, fmt.Errorf("端口 %d 与管理服务端口冲突", instance.ListenPort)
	}

	log.Printf("启动代理服务器 %s 在端口 %d，后端: %s", instance.Name, instance.ListenPort, instance.Backend)
	
	var listener net.Listener
	if instance.TLSEnabled && instance.TLSCertFile != "" && instance.TLSKeyFile != "" {
		tlsConfig, err := loadTLSConfig(instance.TLSCertFile, instance.TLSKeyFile)
		if err != nil {
			log.Printf("代理服务器 %s 加载TLS配置失败: %v", instance.Name, err)
			return nil, fmt.Errorf("加载TLS配置失败: %v", err)
		}
		listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort), tlsConfig)
		if err != nil {
			log.Printf("代理服务器 %s TLS监听启动失败: %v", instance.Name, err)
			return nil, fmt.Errorf("TLS监听启动失败: %v", err)
		}
		log.Printf("代理服务器 %s HTTPS监听已启动在端口 %d", instance.Name, instance.ListenPort)
	} else {
		var err error
		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort))
		if err != nil {
			log.Printf("代理服务器 %s 启动失败: %v", instance.Name, err)
			
			db.Exec("DELETE FROM proxy_instances WHERE id = ?", instance.ID)
			proxyMutex.Lock()
			delete(proxyInstances, instance.ID)
			proxyMutex.Unlock()
			
			return nil, fmt.Errorf("端口 %d 已被占用", instance.ListenPort)
		}
	}

	instance.Server = &http.Server{
		Handler: handler,
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		if err := instance.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("代理服务器 %s 运行错误: %v", instance.Name, err)
		} else if err == http.ErrServerClosed {
			log.Printf("代理服务器 %s 已关闭", instance.Name)
		}
	}()

	// 如果启用了强制HTTPS，先测试HTTP端口是否可用
	if instance.ForceHTTPS && instance.HTTPListenPort > 0 && instance.TLSEnabled {
		// 先尝试监听HTTP端口测试是否可用
		testHTTPListener, err := net.Listen("tcp", fmt.Sprintf(":%d", instance.HTTPListenPort))
		if err != nil {
			// 测试失败，清理已创建的代理实例
			if instance.Server != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				instance.Server.Shutdown(ctx)
			}
			db.Exec("DELETE FROM proxy_instances WHERE id = ?", instance.ID)
			proxyMutex.Lock()
			delete(proxyInstances, instance.ID)
			proxyMutex.Unlock()
			return nil, fmt.Errorf("HTTP端口 %d 已被占用", instance.HTTPListenPort)
		}
		// 立即关闭测试监听
		testHTTPListener.Close()

		httpsPort := instance.ListenPort
		redirectHandler := func(w http.ResponseWriter, r *http.Request) {
			// 构建重定向URL
			host := r.Host
			// 移除可能存在的端口
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			// 添加HTTPS端口
			targetURL := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.URL.RequestURI())
			// 使用307重定向
			http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
		}

		instance.HTTPServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", instance.HTTPListenPort),
			Handler: http.HandlerFunc(redirectHandler),
		}

		go func() {
			time.Sleep(500 * time.Millisecond)
			log.Printf("HTTP重定向服务器 %s 已启动在端口 %d -> HTTPS %d", instance.Name, instance.HTTPListenPort, instance.ListenPort)
			if err := instance.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP重定向服务器 %s 运行错误: %v", instance.Name, err)
			} else if err == http.ErrServerClosed {
				log.Printf("HTTP重定向服务器 %s 已关闭", instance.Name)
			}
		}()
	}

	return instance, nil
}

func createPortForwardInstance(name, protocol string, listenPort int, targetAddress string, targetPort int, ipMode, actionMode string) (*PortForwardInstance, error) {
	// 验证监听端口
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("监听端口必须在1-65535之间")
	}

	// 验证目标端口
	if targetPort < 1 || targetPort > 65535 {
		return nil, fmt.Errorf("目标端口必须在1-65535之间")
	}

	if listenPort == adminPort {
		return nil, fmt.Errorf("端口 %d 与管理服务端口冲突", listenPort)
	}

	proxyMutex.RLock()
	for _, inst := range proxyInstances {
		if inst.ListenPort == listenPort {
			proxyMutex.RUnlock()
			return nil, fmt.Errorf("端口 %d 已被防护应用占用", listenPort)
		}
	}
	proxyMutex.RUnlock()

	portForwardMutex.RLock()
	for _, inst := range portForwardInstances {
		if inst.ListenPort == listenPort {
			portForwardMutex.RUnlock()
			return nil, fmt.Errorf("端口 %d 已被端口转发占用", listenPort)
		}
	}
	portForwardMutex.RUnlock()

	id := fmt.Sprintf("portforward-%d", time.Now().UnixNano())
	
	createdAt := getUTCTimestamp()

	_, err := db.Exec(
		"INSERT INTO port_forward_instances (id, name, protocol, listen_port, target_address, target_port, ip_mode, action_mode, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		id, name, protocol, listenPort, targetAddress, targetPort, ipMode, actionMode, "running", createdAt,
	)
	if err != nil {
		return nil, err
	}

	instance := &PortForwardInstance{
		ID:            id,
		Name:          name,
		Protocol:      protocol,
		ListenPort:    listenPort,
		TargetAddress: targetAddress,
		TargetPort:    targetPort,
		IPMode:        ipMode,
		ActionMode:    actionMode,
		Status:        "running",
		CreatedAt:     fmt.Sprintf("%d", createdAt),
	}

	// 先测试端口是否可以监听
	testListener, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		// 清理已创建的数据库记录
		db.Exec("DELETE FROM port_forward_instances WHERE id = ?", id)
		return nil, fmt.Errorf("端口 %d 已被占用", listenPort)
	}
	// 立即关闭测试监听
	testListener.Close()

	portForwardMutex.Lock()
	portForwardInstances[id] = instance
	portForwardMutex.Unlock()

	go startPortForward(instance)

	return instance, nil
}

func startPortForward(instance *PortForwardInstance) {
	if instance.Protocol == "tcp" {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort))
		if err != nil {
			log.Printf("端口转发 %s 启动失败: %v", instance.Name, err)
			instance.Status = "stopped"
			return
		}

		log.Printf("端口转发 %s 已启动: %s://%d -> %s:%d", instance.Name, instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort)

		stopChan := make(chan struct{})
		instance.Listener = listener
		instance.StopFunc = func() {
			listener.Close()
			close(stopChan)
		}

		go func() {
			for {
				select {
				case <-stopChan:
					return
				default:
					conn, err := listener.Accept()
					if err != nil {
						log.Printf("端口转发 %s 接受连接失败: %v", instance.Name, err)
						return
					}
					go handlePortForwardConnection(instance, conn)
				}
			}
		}()

	} else if instance.Protocol == "udp" {
		conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", instance.ListenPort))
		if err != nil {
			log.Printf("端口转发 %s 启动失败: %v", instance.Name, err)
			instance.Status = "stopped"
			return
		}

		log.Printf("端口转发 %s 已启动: %s://%d -> %s:%d", instance.Name, instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort)

		stopChan := make(chan struct{})
		instance.Listener = conn
		instance.StopFunc = func() {
			conn.Close()
			close(stopChan)
		}

		buf := make([]byte, 65535)
		go func() {
			for {
				select {
				case <-stopChan:
					return
				default:
					n, addr, err := conn.ReadFrom(buf)
					if err != nil {
						log.Printf("端口转发 %s 读取UDP失败: %v", instance.Name, err)
						return
					}
					go handlePortForwardUDP(instance, buf[:n], addr, conn)
				}
			}
		}()
	}
}

func handlePortForwardConnection(instance *PortForwardInstance, conn net.Conn) {
	defer conn.Close()

	cleanIP := getCleanIP(conn.RemoteAddr().String())

	mode := instance.IPMode
	actionMode := instance.ActionMode

	var isWhitelisted bool
	var isBlacklisted bool

	rows, err := db.Query("SELECT ip FROM ip_whitelist ORDER BY CASE WHEN source='custom' THEN 0 ELSE 1 END")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var whitelistIP string
			rows.Scan(&whitelistIP)
			if isIPInCIDR(cleanIP, whitelistIP) {
				isWhitelisted = true
				break
			}
		}
	}

	rows, err = db.Query("SELECT ip FROM ip_blacklist ORDER BY CASE WHEN source='custom' THEN 0 ELSE 1 END")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var blacklistIP string
			rows.Scan(&blacklistIP)
			if isIPInCIDR(cleanIP, blacklistIP) {
				isBlacklisted = true
				break
			}
		}
	}

	var ipCheckResult string
	var ipCheckAction string

	switch mode {
	case "whitelist-only":
		if isWhitelisted {
			ipCheckResult = "pass"
			ipCheckAction = "whitelist_match"
		} else {
			ipCheckAction = "whitelist_no_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
			} else {
				ipCheckResult = "block"
			}
		}
	case "blacklist-only":
		if isBlacklisted {
			ipCheckAction = "blacklist_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
			} else {
				ipCheckResult = "block"
			}
		} else {
			ipCheckResult = "pass"
			ipCheckAction = "blacklist_no_match"
		}
	default:
		ipCheckResult = "pass"
		ipCheckAction = "normal_mode"
	}

	logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fmt.Sprintf("%s://%d -> %s:%d", instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort), "port_forward", instance.Name, fmt.Sprintf("%s://%d -> %s:%d", instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort))

	if ipCheckResult == "block" || ipCheckResult == "observe" {
		country, province, city, _, _ := getGeoLocation(cleanIP)
		go sendWebhook("ip_blocked", WebhookIPBlockedData{
			IP:       cleanIP,
			Mode:     mode,
			Action:   ipCheckAction,
			Result:   ipCheckResult,
			URL:      fmt.Sprintf("%s://%d -> %s:%d", instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort),
			Country:  country,
			Province: province,
			City:     city,
		})
	}

	if ipCheckResult == "block" {
		return
	}

	targetConn, err := net.Dial(instance.Protocol, fmt.Sprintf("%s:%d", instance.TargetAddress, instance.TargetPort))
	if err != nil {
		log.Printf("端口转发 %s 连接目标失败: %v", instance.Name, err)
		return
	}
	defer targetConn.Close()

	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)
}

func handlePortForwardUDP(instance *PortForwardInstance, buf []byte, addr net.Addr, conn net.PacketConn) {
	cleanIP := getCleanIP(addr.String())

	mode := instance.IPMode
	actionMode := instance.ActionMode

	var isWhitelisted bool
	var isBlacklisted bool

	rows, err := db.Query("SELECT ip FROM ip_whitelist ORDER BY CASE WHEN source='custom' THEN 0 ELSE 1 END")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var whitelistIP string
			rows.Scan(&whitelistIP)
			if isIPInCIDR(cleanIP, whitelistIP) {
				isWhitelisted = true
				break
			}
		}
	}

	rows, err = db.Query("SELECT ip FROM ip_blacklist ORDER BY CASE WHEN source='custom' THEN 0 ELSE 1 END")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var blacklistIP string
			rows.Scan(&blacklistIP)
			if isIPInCIDR(cleanIP, blacklistIP) {
				isBlacklisted = true
				break
			}
		}
	}

	var ipCheckResult string
	var ipCheckAction string

	switch mode {
	case "whitelist-only":
		if isWhitelisted {
			ipCheckResult = "pass"
			ipCheckAction = "whitelist_match"
		} else {
			ipCheckAction = "whitelist_no_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
			} else {
				ipCheckResult = "block"
			}
		}
	case "blacklist-only":
		if isBlacklisted {
			ipCheckAction = "blacklist_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
			} else {
				ipCheckResult = "block"
			}
		} else {
			ipCheckResult = "pass"
			ipCheckAction = "blacklist_no_match"
		}
	default:
		ipCheckResult = "pass"
		ipCheckAction = "normal_mode"
	}

	logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fmt.Sprintf("%s://%d -> %s:%d", instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort), "port_forward", instance.Name, fmt.Sprintf("%s://%d -> %s:%d", instance.Protocol, instance.ListenPort, instance.TargetAddress, instance.TargetPort))

	if ipCheckResult == "block" {
		return
	}

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", instance.TargetAddress, instance.TargetPort))
	if err != nil {
		log.Printf("端口转发 %s 解析目标地址失败: %v", instance.Name, err)
		return
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("端口转发 %s 连接目标失败: %v", instance.Name, err)
		return
	}
	defer targetConn.Close()

	targetConn.Write(buf)

	responseBuf := make([]byte, 65535)
	targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := targetConn.ReadFromUDP(responseBuf)
	if err == nil {
		conn.WriteTo(responseBuf[:n], addr)
	}
}

type wafHandler struct {
	next http.Handler
	waf  coraza.WAF
	proxyID string
}

type ipCheckHandler struct {
	next http.Handler
	proxyID string
}

func (ic *ipCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cleanIP := getCleanIP(r.RemoteAddr)
	
	log.Printf("[ipCheckHandler] 处理请求: proxyID=%s, host=%s", ic.proxyID, r.Host)
	
	var instanceName string
	var forwardInfo string
	var matchedRule *DomainRule
	if ic.proxyID != "" {
		proxyMutex.RLock()
		if proxy, exists := proxyInstances[ic.proxyID]; exists {
			instanceName = proxy.Name
			host := r.Host
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			matchedRule = proxy.findBackendByDomain(host)
			log.Printf("[域名路由] 匹配结果: host=%s, ruleType=%s, backend=%s, redirectUrl=%s", host, matchedRule.RuleType, matchedRule.Backend, matchedRule.RedirectURL)
			forwardInfo = fmt.Sprintf("http://%d -> %s", proxy.ListenPort, matchedRule.Backend)
		}
		proxyMutex.RUnlock()
	}

	if matchedRule != nil {
		log.Printf("[域名路由] 处理请求: host=%s, ruleType=%s", r.Host, matchedRule.RuleType)
		switch matchedRule.RuleType {
		case "redirect":
			log.Printf("[域名路由] 执行重定向: %s -> %s", r.Host, matchedRule.RedirectURL)
			http.Redirect(w, r, matchedRule.RedirectURL, http.StatusTemporaryRedirect)
			return
		case "close":
			log.Printf("[域名路由] 关闭连接: %s", r.Host)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		default:
			backend := matchedRule.Backend
			if backend == "" {
				proxyMutex.RLock()
				if p, exists := proxyInstances[ic.proxyID]; exists {
					backend = p.FallbackBackend
					if backend == "" {
						backend = p.Backend
					}
				}
				proxyMutex.RUnlock()
			}
			proxy, err := url.Parse(backend)
			if err == nil {
				rp := httputil.NewSingleHostReverseProxy(proxy)
				rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
					log.Printf("域名路由代理错误: %v", err)
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusBadGateway)
					http.ServeFile(w, r, "web/html/502.html")
				}
				rp.ServeHTTP(w, r)
				return
			}
		}
	}
	
	if matchedRule == nil {
		log.Printf("[ipCheckHandler] matchedRule为nil，使用IP规则处理")
	}
	
	// 构建完整的URL
	fullURL := fmt.Sprintf("%s %s", r.Method, r.URL.String())
	if r.Host != "" {
		fullURL = fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.Host, r.URL.RequestURI())
		if r.URL.Scheme == "" {
			fullURL = fmt.Sprintf("http://%s%s", r.Host, r.URL.RequestURI())
		}
	}
	
	mode, actionMode, whitelistCount, blacklistCount, _ := getIPSettings()
	
	isWhitelisted := isIPInWhitelistCached(cleanIP)
	isBlacklisted := isIPInBlacklistCached(cleanIP)
	
	var ipCheckResult string
	var ipCheckAction string
	
	switch mode {
	case "whitelist-only":
		if whitelistCount == 0 {
			ipCheckResult = "pass"
			ipCheckAction = "whitelist_empty"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		} else if isWhitelisted {
			ipCheckResult = "pass"
			ipCheckAction = "whitelist_match"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		} else {
			ipCheckAction = "whitelist_no_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP白名单模式观察: %s (不在白名单中)", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "observe",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})
			} else {
				ipCheckResult = "block"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP白名单模式拒绝: %s (不在白名单中)", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "block",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				http.ServeFile(w, r, "web/html/ip-blocked.html")
				return
			}
		}
	case "blacklist-only":
		if blacklistCount == 0 {
			ipCheckResult = "pass"
			ipCheckAction = "blacklist_empty"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		} else if isBlacklisted {
			ipCheckAction = "blacklist_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP黑名单模式观察: %s", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "observe",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})
			} else {
				ipCheckResult = "block"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP黑名单拦截: %s", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "block",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				http.ServeFile(w, r, "web/html/ip-blocked.html")
				return
			}
		} else {
			ipCheckResult = "pass"
			ipCheckAction = "blacklist_no_match"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		}
	default:
		ipCheckResult = "pass"
		ipCheckAction = "normal"
		logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
	}
	
	ic.next.ServeHTTP(w, r)
}

type statsResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	size          int
	inboundBytes  int64
	outboundBytes int64
}

type statsRequestBody struct {
	io.ReadCloser
	srw *statsResponseWriter
}

func (r *statsRequestBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.srw.inboundBytes += int64(n)
	}
	return n, err
}

func (w *statsResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statsResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	w.outboundBytes += int64(n)
	return n, err
}

func (w *statsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer cannot hijack")
	}
	return hijacker.Hijack()
}

func flushTrafficStats(w *statsResponseWriter) {
	if w.inboundBytes > 0 || w.outboundBytes > 0 {
		statsMutex.Lock()
		trafficStats.InboundBytes += w.inboundBytes
		trafficStats.OutboundBytes += w.outboundBytes
		statsMutex.Unlock()
	}
}

func (wh *wafHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cleanIP := getCleanIP(r.RemoteAddr)
	
	var instanceName string
	var forwardInfo string
	if wh.proxyID != "" {
		proxyMutex.RLock()
		if proxy, exists := proxyInstances[wh.proxyID]; exists {
			instanceName = proxy.Name
			forwardInfo = fmt.Sprintf("http://%d -> %s", proxy.ListenPort, proxy.Backend)
		}
		proxyMutex.RUnlock()
	}
	
	// 构建完整的URL
	fullURL := fmt.Sprintf("%s %s", r.Method, r.URL.String())
	if r.Host != "" {
		fullURL = fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.Host, r.URL.RequestURI())
		if r.URL.Scheme == "" {
			fullURL = fmt.Sprintf("http://%s%s", r.Host, r.URL.RequestURI())
		}
	}
	
	mode, actionMode, whitelistCount, blacklistCount, _ := getIPSettings()
	
	isWhitelisted := isIPInWhitelistCached(cleanIP)
	isBlacklisted := isIPInBlacklistCached(cleanIP)
	
	var ipCheckResult string
	var ipCheckAction string
	
	switch mode {
	case "whitelist-only":
		if whitelistCount == 0 {
			ipCheckResult = "pass"
			ipCheckAction = "whitelist_empty"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		} else if isWhitelisted {
			ipCheckResult = "pass"
			ipCheckAction = "whitelist_match"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		} else {
			ipCheckAction = "whitelist_no_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP白名单模式观察: %s (不在白名单中)", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "observe",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})
			} else {
				ipCheckResult = "block"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP白名单模式拒绝: %s (不在白名单中)", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "block",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				http.ServeFile(w, r, "web/html/ip-blocked.html")
				return
			}
		}
	case "blacklist-only":
		if blacklistCount == 0 {
			ipCheckResult = "pass"
			ipCheckAction = "blacklist_empty"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		} else if isBlacklisted {
			ipCheckAction = "blacklist_match"
			if actionMode == "observe" {
				ipCheckResult = "observe"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP黑名单模式观察: %s", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "observe",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})
			} else {
				ipCheckResult = "block"
				logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
				log.Printf("IP黑名单拦截: %s", cleanIP)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("ip_blocked", WebhookIPBlockedData{
					IP:       cleanIP,
					Mode:     mode,
					Action:   ipCheckAction,
					Result:   "block",
					URL:      fullURL,
					Country:  country,
					Province: province,
					City:     city,
				})

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				http.ServeFile(w, r, "web/html/ip-blocked.html")
				return
			}
		} else {
			ipCheckResult = "pass"
			ipCheckAction = "blacklist_no_match"
			logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
		}
	default:
		ipCheckResult = "pass"
		ipCheckAction = "normal"
		logIPAccess(cleanIP, mode, ipCheckAction, ipCheckResult, fullURL, "reverse_proxy", instanceName, forwardInfo)
	}
	
	statsRW := &statsResponseWriter{
		ResponseWriter: w,
		statusCode:     200,
	}
	
	tx := wh.waf.NewTransaction()
	defer func() {
		rules, ruleIDs := getMatchedRules(tx)
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			userAgent = "Unknown"
		}
		
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		fullURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.String())
		
		if tx.IsInterrupted() {
			interruption := tx.Interruption()
			log.Printf("WAF 拦截 %s %s - User-Agent: %s - 规则ID: %d, 动作: %s - 拦截原因: %s - 匹配规则: %s", r.Method, fullURL, userAgent, interruption.RuleID, interruption.Action, interruption.Data, rules)
			saveAttackLog("blocked", fullURL, interruption.Data, r.RemoteAddr, rules, r.Method, wh.proxyID, 403, "", userAgent)
			updateStats(r.RemoteAddr, 403, true)

			country, province, city, _, _ := getGeoLocation(cleanIP)
			go sendWebhook("attack", WebhookAttackData{
				Action:     "blocked",
				URL:        fullURL,
				AttackType: interruption.Data,
				IP:         cleanIP,
				Rules:      rules,
				Method:     r.Method,
				ProxyID:    wh.proxyID,
				StatusCode: 403,
				Country:    country,
				Province:  province,
				City:      city,
			})
		} else if len(ruleIDs) > 0 {
			only901340 := true
			for _, id := range ruleIDs {
				if id != 901340 {
					only901340 = false
					break
				}
			}
			
			if only901340 {
				log.Printf("WAF 正常通过 %s %s - User-Agent: %s - 匹配规则: 无", r.Method, fullURL, userAgent)
				saveAttackLog("normal", fullURL, "正常请求", r.RemoteAddr, "无", r.Method, wh.proxyID, 200, ipCheckAction, userAgent)
			} else {
				log.Printf("WAF 未拦截通过 %s %s - User-Agent: %s - 匹配规则: %s", r.Method, fullURL, userAgent, rules)
				saveAttackLog("detected", fullURL, "检测到攻击", r.RemoteAddr, rules, r.Method, wh.proxyID, 200, "", userAgent)
				updateStats(r.RemoteAddr, 200, true)

				country, province, city, _, _ := getGeoLocation(cleanIP)
				go sendWebhook("attack", WebhookAttackData{
					Action:     "detected",
					URL:        fullURL,
					AttackType: "检测到攻击",
					IP:         cleanIP,
					Rules:      rules,
					Method:     r.Method,
					ProxyID:    wh.proxyID,
					StatusCode: 200,
					Country:    country,
					Province:  province,
					City:      city,
				})
			}
		} else {
			log.Printf("WAF 正常通过 %s %s - User-Agent: %s - 匹配规则: 无", r.Method, fullURL, userAgent)
			saveAttackLog("normal", fullURL, "正常请求", r.RemoteAddr, "无", r.Method, wh.proxyID, 200, ipCheckAction, userAgent)
		}
		tx.ProcessLogging()
		tx.Close()
		
		flushTrafficStats(statsRW)
		updateStats(r.RemoteAddr, statsRW.statusCode, false)
	}()

	tx.ProcessConnection(r.RemoteAddr, 0, "127.0.0.1", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, v := range r.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		statsRW.WriteHeader(http.StatusForbidden)
		rules, _ := getMatchedRules(tx)
		render403Page(statsRW, interruption, rules)

		country, province, city, _, _ := getGeoLocation(cleanIP)
		go sendWebhook("attack", WebhookAttackData{
			Action:     "blocked",
			URL:        fullURL,
			AttackType: interruption.Data,
			IP:         cleanIP,
			Rules:      rules,
			Method:     r.Method,
			ProxyID:    wh.proxyID,
			StatusCode: 403,
			Country:    country,
			Province:  province,
			City:      city,
		})
		return
	}

	interruption, _ = tx.ProcessRequestBody()
	if interruption != nil {
		statsRW.WriteHeader(http.StatusForbidden)
		rules, _ := getMatchedRules(tx)
		render403Page(statsRW, interruption, rules)

		country, province, city, _, _ := getGeoLocation(cleanIP)
		go sendWebhook("attack", WebhookAttackData{
			Action:     "blocked",
			URL:        fullURL,
			AttackType: interruption.Data,
			IP:         cleanIP,
			Rules:      rules,
			Method:     r.Method,
			ProxyID:    wh.proxyID,
			StatusCode: 403,
			Country:    country,
			Province:  province,
			City:      city,
		})
		return
	}

	var matchedRule *DomainRule
	if wh.proxyID != "" {
		proxyMutex.RLock()
		if proxy, exists := proxyInstances[wh.proxyID]; exists {
			host := r.Host
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			matchedRule = proxy.findBackendByDomain(host)
			log.Printf("[域名路由-WAF] 匹配结果: host=%s, ruleType=%s, backend=%s, redirectUrl=%s", host, matchedRule.RuleType, matchedRule.Backend, matchedRule.RedirectURL)
			forwardInfo = fmt.Sprintf("http://%d -> %s", proxy.ListenPort, matchedRule.Backend)
		}
		proxyMutex.RUnlock()
	}

	if matchedRule != nil {
		log.Printf("[域名路由-WAF] 处理请求: host=%s, ruleType=%s", r.Host, matchedRule.RuleType)
		switch matchedRule.RuleType {
		case "redirect":
			log.Printf("[域名路由-WAF] 执行重定向: %s -> %s", r.Host, matchedRule.RedirectURL)
			http.Redirect(w, r, matchedRule.RedirectURL, http.StatusTemporaryRedirect)
			return
		case "close":
			log.Printf("[域名路由-WAF] 关闭连接: %s", r.Host)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		default:
			backend := matchedRule.Backend
			if backend == "" {
				proxyMutex.RLock()
				if p, exists := proxyInstances[wh.proxyID]; exists {
					backend = p.FallbackBackend
					if backend == "" {
						backend = p.Backend
					}
				}
				proxyMutex.RUnlock()
			}
			proxy, err := url.Parse(backend)
			if err == nil {
				rp := httputil.NewSingleHostReverseProxy(proxy)
				rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
					log.Printf("域名路由代理错误: %v", err)
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusBadGateway)
					http.ServeFile(w, r, "web/html/502.html")
				}
				statsRW := &statsResponseWriter{ResponseWriter: w, statusCode: 200}
				r.Body = &statsRequestBody{ReadCloser: r.Body, srw: statsRW}
				rp.ServeHTTP(statsRW, r)
				return
			}
		}
	}

	proxyMutex.RLock()
	if p, exists := proxyInstances[wh.proxyID]; exists {
		forwardInfo = fmt.Sprintf("http://%d -> %s (fallback)", p.ListenPort, p.FallbackBackend)
	}
	proxyMutex.RUnlock()

	r.Body = &statsRequestBody{ReadCloser: r.Body, srw: statsRW}
	wh.next.ServeHTTP(statsRW, r)
}

func getCleanIP(ip string) string {
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}

func ipToUint32(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i := 0; i < 4; i++ {
		part, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0
		}
		result = (result << 8) | uint32(part)
	}
	return result
}

func isIPInCIDR(ip, cidr string) bool {
	if !strings.Contains(cidr, "/") {
		return ip == cidr
	}
	
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	return ipNet.Contains(parsedIP)
}

func logIPAccess(ip, mode, action, result, url string, forwardType, instanceName, forwardInfo string) {
	cleanIP := getCleanIP(ip)
	country, province, city, latitude, longitude := getGeoLocation(cleanIP)
	
	for i := 0; i < 5; i++ {
		_, err := db.Exec("INSERT INTO ip_access_logs (ip, mode, action, result, url, country, province, city, latitude, longitude, forward_type, instance_name, forward_info, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
			ip, mode, action, result, url, country, province, city, latitude, longitude, forwardType, instanceName, forwardInfo, getUTCTimestamp())
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "SQLITE_BUSY") {
			time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
			continue
		}
		log.Printf("记录IP访问日志失败: %v", err)
		return
	}
}

func saveAttackLog(action, url, attackType, ip, rules, method, proxyID string, statusCode int, filterType string, userAgent string) {
	logsMutex.Lock()
	defer logsMutex.Unlock()
	
	// 先清理 IP 地址，移除端口号
	cleanIP := getCleanIP(ip)
	country, province, city, latitude, longitude := getGeoLocation(cleanIP)
	platform, browser := parseUserAgent(userAgent)
	
	logEntry := AttackLog{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Action:     action,
		URL:        url,
		AttackType: attackType,
		IP:         cleanIP,
		Time:       getUTCTime(),
		Rules:      rules,
		Method:     method,
		ProxyID:    proxyID,
		StatusCode:  statusCode,
		Country:    country,
		Province:   province,
		City:       city,
		Latitude:   latitude,
		Longitude:  longitude,
		FilterType: filterType,
		Platform:   platform,
		Browser:    browser,
	}
	
	attackLogs = append(attackLogs, logEntry)
	
	if len(attackLogs) > 1000 {
		attackLogs = attackLogs[len(attackLogs)-1000:]
	}

	for i := 0; i < 5; i++ {
		_, err := db.Exec(
			"INSERT INTO attack_logs (id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type, platform, browser) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			logEntry.ID, logEntry.Action, logEntry.URL, logEntry.AttackType, logEntry.IP, logEntry.Time, logEntry.Rules, logEntry.Method, logEntry.ProxyID, logEntry.StatusCode, logEntry.Country, logEntry.Province, logEntry.City, logEntry.Latitude, logEntry.Longitude, logEntry.FilterType, logEntry.Platform, logEntry.Browser,
		)
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "SQLITE_BUSY") {
			time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
			continue
		}
		log.Printf("保存攻击日志到数据库失败: %v", err)
		return
	}
}

func parseUserAgent(userAgent string) (platform, browser string) {
	platform = "Unknown"
	browser = "Unknown"

	ua := strings.ToLower(userAgent)

	// 检测平台
	if strings.Contains(ua, "windows") {
		platform = "Windows"
	} else if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		platform = "MacOS"
	} else if strings.Contains(ua, "linux") && !strings.Contains(ua, "android") {
		platform = "Linux"
	} else if strings.Contains(ua, "android") {
		platform = "Android"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") {
		platform = "iOS"
	} else if strings.Contains(ua, "fedora") {
		platform = "Fedora"
	} else if strings.Contains(ua, "ubuntu") {
		platform = "Ubuntu"
	}

	// 检测浏览器
	if strings.Contains(ua, "firefox") && !strings.Contains(ua, "seamonkey") {
		browser = "Firefox"
	} else if strings.Contains(ua, "chrome") && !strings.Contains(ua, "chromium") && !strings.Contains(ua, "edge") && !strings.Contains(ua, "opr") {
		if strings.Contains(ua, "chrome mobile") || strings.Contains(ua, "chrome mobile webview") {
			browser = "Chrome Mobile"
		} else {
			browser = "Chrome"
		}
	} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") && !strings.Contains(ua, "chromium") && !strings.Contains(ua, "android") && !strings.Contains(ua, "edge") && !strings.Contains(ua, "opr") {
		if strings.Contains(ua, "mobile") {
			browser = "Mobile Safari"
		} else {
			browser = "Safari"
		}
	} else if strings.Contains(ua, "edge") {
		browser = "Edge"
	} else if strings.Contains(ua, "opera") || strings.Contains(ua, "opr") {
		browser = "Opera"
	} else if strings.Contains(ua, "msie") || strings.Contains(ua, "trident") {
		browser = "IE"
	} else if strings.Contains(ua, "brave") {
		browser = "Brave"
	} else if strings.Contains(ua, "vivaldi") {
		browser = "Vivaldi"
	} else if strings.Contains(ua, "arora") {
		browser = "Arora"
	} else if strings.Contains(ua, "kazehakase") {
		browser = "Kazehakase"
	} else if strings.Contains(ua, "aol") {
		browser = "AOL"
	} else if strings.Contains(ua, "sogou") {
		browser = "Sogou Explorer"
	} else if strings.Contains(ua, "qqbrowser") {
		browser = "QQ Browser"
	} else if strings.Contains(ua, "go-http-client") {
		browser = "Go-http-client"
	} else if strings.Contains(ua, "curl") {
		browser = "curl"
	} else if strings.Contains(ua, "python-requests") {
		browser = "python-requests"
	} else if strings.Contains(ua, "sqlmap") {
		browser = "sqlmap"
	} else if strings.Contains(ua, "wget") {
		browser = "Wget"
	} else if strings.Contains(ua, "googlebot") {
		browser = "Googlebot"
	} else if strings.Contains(ua, "bingbot") {
		browser = "bingbot"
	} else if strings.Contains(ua, "mj12bot") {
		browser = "MJ12bot"
	} else if strings.Contains(ua, "oai-searchbot") {
		browser = "OAI-SearchBot"
	} else if strings.Contains(ua, "bytespider") {
		browser = "Bytespider"
	} else if strings.Contains(ua, "dotbot") {
		browser = "DotBot"
	} else if strings.Contains(ua, "thinkbot") {
		browser = "ThinkBot"
	} else if strings.Contains(ua, "facebookexternalhit") {
		browser = "facebookexternalhit"
	} else if strings.Contains(ua, "facebookbot") {
		browser = "FacebookBot"
	} else if strings.Contains(ua, "huawei") {
		browser = "Huawei Browser"
	} else if strings.Contains(ua, "apple mail") {
		browser = "Apple Mail"
	} else if strings.Contains(ua, "headless") {
		browser = "HeadlessChrome"
	} else if strings.Contains(ua, "mozilla") {
		browser = "Mozilla"
	}

	return platform, browser
}

func render403Page(w http.ResponseWriter, interruption *types.Interruption, rules string) {
	htmlContent, err := os.ReadFile("web/html/403.html")
	if err != nil {
		log.Printf("读取 403.html 失败: %v", err)
		http.Error(w, "403 禁止访问", http.StatusForbidden)
		return
	}

	tmpl, err := template.New("403").Parse(string(htmlContent))
	if err != nil {
		log.Printf("解析模板失败: %v", err)
		w.Write(htmlContent)
		return
	}

	data := struct {
		RuleID       int
		Action       string
		Data         string
		MatchedRules string
	}{
		RuleID:       interruption.RuleID,
		Action:       interruption.Action,
		Data:         interruption.Data,
		MatchedRules: rules,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("执行模板失败: %v", err)
		w.Write(htmlContent)
	}
}

func getMatchedRules(tx types.Transaction) (string, []int) {
	matchedRules := tx.MatchedRules()
	ruleMap := make(map[int]string)
	ruleIDs := []int{}
	filteredRuleMap := make(map[int]string)
	filteredRuleIDs := []int{}
	seenMessages := make(map[string]bool)

	for _, rule := range matchedRules {
		ruleID := rule.Rule().ID()
		message := rule.Message()
		if message != "" {
			ruleMap[ruleID] = message
			ruleIDs = append(ruleIDs, ruleID)
			if ruleID != 901340 {
				filteredRuleMap[ruleID] = message
				filteredRuleIDs = append(filteredRuleIDs, ruleID)
			}
		}
	}

	var rules []string
	for id, msg := range filteredRuleMap {
		translatedMsg := translateMessage(msg)
		if !seenMessages[translatedMsg] {
			seenMessages[translatedMsg] = true
			escapedMsg := strings.ReplaceAll(translatedMsg, `"`, `\"`)
			rules = append(rules, fmt.Sprintf(`{"id": %d, "message": "%s"}`, id, escapedMsg))
		}
	}

	return strings.Join(rules, ","), ruleIDs
}

func loadPortForwardInstancesFromDB() error {
	rows, err := db.Query("SELECT id, name, protocol, listen_port, target_address, target_port, ip_mode, action_mode, status, created_at FROM port_forward_instances")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, name, protocol, targetAddress string
		var listenPort, targetPort int
		var ipMode, actionMode, status, createdAt string
		err := rows.Scan(&id, &name, &protocol, &listenPort, &targetAddress, &targetPort, &ipMode, &actionMode, &status, &createdAt)
		if err != nil {
			continue
		}

		instance := &PortForwardInstance{
			ID:            id,
			Name:          name,
			Protocol:      protocol,
			ListenPort:    listenPort,
			TargetAddress: targetAddress,
			TargetPort:    targetPort,
			IPMode:        ipMode,
			ActionMode:    actionMode,
			Status:        status,
			CreatedAt:     createdAt,
		}

		portForwardMutex.Lock()
		portForwardInstances[id] = instance
		portForwardMutex.Unlock()

		if status == "running" {
			go startPortForward(instance)
		}
	}

	return nil
}

func loadWAFInstancesFromDB() error {
	rows, err := db.Query("SELECT id, name, mode, rules, created_at FROM waf_instances")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, name, mode, rulesJSON, createdAt string
		err := rows.Scan(&id, &name, &mode, &rulesJSON, &createdAt)
		if err != nil {
			continue
		}

		var rules []string
		json.Unmarshal([]byte(rulesJSON), &rules)

		waf, err := createWAF(mode, rules)
		if err != nil {
			log.Printf("加载WAF实例 %s 失败: %v", id, err)
			continue
		}

		instance := &WAFInstance{
			ID:        id,
			Name:      name,
			Mode:      mode,
			Rules:     rules,
			WAF:       waf,
			CreatedAt: createdAt,
		}

		wafMutex.Lock()
		wafInstances[id] = instance
		wafMutex.Unlock()
	}

	return nil
}

func loadDomainRules(proxyID string) []*DomainRule {
	var rules []*DomainRule
	rows, err := db.Query("SELECT id, proxy_id, domain, backend, is_default, rule_type, redirect_url, created_at FROM proxy_domain_rules WHERE proxy_id = ?", proxyID)
	if err != nil {
		log.Printf("加载域名规则失败: %v", err)
		return rules
	}
	defer rows.Close()

	for rows.Next() {
		var rule DomainRule
		var isDefault int
		var ruleType, redirectURL sql.NullString
		err := rows.Scan(&rule.ID, &rule.ProxyID, &rule.Domain, &rule.Backend, &isDefault, &ruleType, &redirectURL, &rule.CreatedAt)
		if err != nil {
			log.Printf("扫描域名规则失败: %v", err)
			continue
		}
		rule.IsDefault = isDefault == 1
		if ruleType.Valid {
			rule.RuleType = ruleType.String
		} else {
			rule.RuleType = "proxy"
		}
		if redirectURL.Valid {
			rule.RedirectURL = redirectURL.String
		}
		rules = append(rules, &rule)
	}
	return rules
}

func (p *ProxyInstance) findBackendByDomain(host string) *DomainRule {
	log.Printf("[域名路由] 查找后端: host=%s, 规则数=%d", host, len(p.DomainRules))
	
	var defaultRule *DomainRule
	
	for _, rule := range p.DomainRules {
		if rule.IsDefault {
			defaultRule = rule
			continue
		}
		
		domains := strings.Split(rule.Domain, "\n")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			log.Printf("[域名路由] 检查规则: domain=%s, backend=%s, ruleType=%s", d, rule.Backend, rule.RuleType)
			if d == host {
				log.Printf("[域名路由] 匹配成功: %s -> %s (type: %s)", host, rule.Backend, rule.RuleType)
				return rule
			}
		}
	}
	
	log.Printf("[域名路由] 未匹配到规则，使用默认规则")
	
	if defaultRule != nil {
		log.Printf("[域名路由] 使用默认规则: type=%s, backend=%s", defaultRule.RuleType, defaultRule.Backend)
		return defaultRule
	}
	
	if p.FallbackBackend != "" {
		return &DomainRule{Backend: p.FallbackBackend, RuleType: "proxy"}
	}
	return &DomainRule{Backend: p.Backend, RuleType: "proxy"}
}

func loadProxyInstancesFromDB() error {
	rows, err := db.Query("SELECT id, name, listen_port, backend, fallback_backend, waf_id, created_at, tls_enabled, tls_cert_file, tls_key_file, force_https, http_listen_port FROM proxy_instances")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, name, backend, createdAt string
		var listenPort int
		var tlsEnabled int
		var forceHTTPS int
		var httpListenPort int
		var tlsCertFileNull, tlsKeyFileNull, wafIDNull, fallbackBackendNull sql.NullString
		err := rows.Scan(&id, &name, &listenPort, &backend, &fallbackBackendNull, &wafIDNull, &createdAt, &tlsEnabled, &tlsCertFileNull, &tlsKeyFileNull, &forceHTTPS, &httpListenPort)
		if err != nil {
			log.Printf("加载代理实例失败: %v", err)
			continue
		}

		tlsCertFile := ""
		if tlsCertFileNull.Valid {
			tlsCertFile = tlsCertFileNull.String
		}
		tlsKeyFile := ""
		if tlsKeyFileNull.Valid {
			tlsKeyFile = tlsKeyFileNull.String
		}
		wafID := ""
		if wafIDNull.Valid {
			wafID = wafIDNull.String
		}
		fallbackBackend := ""
		if fallbackBackendNull.Valid {
			fallbackBackend = fallbackBackendNull.String
		}

		targetURL, err := url.Parse(backend)
		if err != nil {
			log.Printf("解析防护应用 %s 的后端地址失败: %v", id, err)
			continue
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("代理错误: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			http.ServeFile(w, r, "web/html/502.html")
		}

		instance := &ProxyInstance{
			ID:              id,
			Name:            name,
			ListenPort:      listenPort,
			Backend:         backend,
			FallbackBackend: fallbackBackend,
			WAFID:           wafID,
			Proxy:           proxy,
			TLSEnabled:      tlsEnabled == 1,
			TLSCertFile:     tlsCertFile,
			TLSKeyFile:      tlsKeyFile,
			ForceHTTPS:      forceHTTPS == 1,
			HTTPListenPort:  httpListenPort,
			DomainRules:     loadDomainRules(id),
			CreatedAt:       createdAt,
		}

		if wafID != "" {
			wafMutex.RLock()
			if wafInst, exists := wafInstances[wafID]; exists {
				instance.WAFName = wafInst.Name
			}
			wafMutex.RUnlock()
		}

		proxyMutex.Lock()
		proxyInstances[id] = instance
		proxyMutex.Unlock()

		var handler http.Handler = instance.Proxy
		
		if instance.WAFID != "" {
			wafMutex.RLock()
			wafInst, exists := wafInstances[instance.WAFID]
			wafMutex.RUnlock()
			
			if exists {
				handler = &wafHandler{next: instance.Proxy, waf: wafInst.WAF, proxyID: instance.ID}
			} else {
				handler = &ipCheckHandler{next: instance.Proxy, proxyID: instance.ID}
			}
		} else {
			handler = &ipCheckHandler{next: instance.Proxy, proxyID: instance.ID}
		}

		if instance.ListenPort == adminPort {
			log.Printf("代理服务器 %s 端口 %d 与管理服务端口冲突，跳过启动", instance.Name, instance.ListenPort)
			continue
		}

		log.Printf("启动代理服务器 %s 在端口 %d，后端: %s", instance.Name, instance.ListenPort, instance.Backend)
		
		var listener net.Listener
		if instance.TLSEnabled && instance.TLSCertFile != "" && instance.TLSKeyFile != "" {
			tlsConfig, err := loadTLSConfig(instance.TLSCertFile, instance.TLSKeyFile)
			if err != nil {
				log.Printf("代理服务器 %s 加载TLS配置失败: %v", instance.Name, err)
				continue
			}
			listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort), tlsConfig)
			if err != nil {
				log.Printf("代理服务器 %s TLS监听启动失败: %v", instance.Name, err)
				continue
			}
			log.Printf("代理服务器 %s HTTPS监听已启动在端口 %d", instance.Name, instance.ListenPort)
		} else {
			var err error
			listener, err = net.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort))
			if err != nil {
				log.Printf("代理服务器 %s 启动失败: %v", instance.Name, err)
				
				db.Exec("DELETE FROM proxy_instances WHERE id = ?", instance.ID)
				proxyMutex.Lock()
				delete(proxyInstances, instance.ID)
				proxyMutex.Unlock()
				
				continue
			}
		}

		instance.Server = &http.Server{
			Handler: handler,
		}

		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := instance.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Printf("代理服务器 %s 运行错误: %v", instance.Name, err)
			} else if err == http.ErrServerClosed {
				log.Printf("代理服务器 %s 已关闭", instance.Name)
			}
		}()

		// 如果启用了强制HTTPS，启动HTTP重定向服务器
		if instance.ForceHTTPS && instance.HTTPListenPort > 0 && instance.TLSEnabled {
			httpsPort := instance.ListenPort
			redirectHandler := func(w http.ResponseWriter, r *http.Request) {
				// 构建重定向URL
				host := r.Host
				// 移除可能存在的端口
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				// 添加HTTPS端口
				targetURL := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.URL.RequestURI())
				// 使用307重定向
				http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
			}

			instance.HTTPServer = &http.Server{
				Addr:    fmt.Sprintf(":%d", instance.HTTPListenPort),
				Handler: http.HandlerFunc(redirectHandler),
			}

			go func() {
				time.Sleep(500 * time.Millisecond)
				log.Printf("HTTP重定向服务器 %s 已启动在端口 %d -> HTTPS %d", instance.Name, instance.HTTPListenPort, instance.ListenPort)
				if err := instance.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("HTTP重定向服务器 %s 运行错误: %v", instance.Name, err)
				} else if err == http.ErrServerClosed {
					log.Printf("HTTP重定向服务器 %s 已关闭", instance.Name)
				}
			}()
		}
	}

	return nil
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("证书文件(%s)或密钥文件(%s)无效: %v", certFile, keyFile, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie("session")
		if err != nil || session.Value == "" {
			http.Redirect(w, r, "/web/html/login.html", http.StatusSeeOther)
			return
		}

		var username string
		err = db.QueryRow("SELECT username FROM users WHERE username = ?", session.Value).Scan(&username)
		if err != nil {
			http.Redirect(w, r, "/web/html/login.html", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func readOnlyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie("session")
		if err != nil || session.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "需要登录才能修改数据",
			})
			return
		}

		var username string
		err = db.QueryRow("SELECT username FROM users WHERE username = ?", session.Value).Scan(&username)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "需要登录才能修改数据",
			})
			return
		}

		next(w, r)
	}
}

func handleAbout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	localTemplate, err := ioutil.ReadFile("web/html/about.html")
	if err != nil {
		log.Printf("读取本地关于页面模板失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("<p style='color: #666; text-align: center; padding: 40px;'>读取页面模板失败</p>"))
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var hasNewVersion bool
	var downloadURL string
	var downloadPlatform string
	var releaseNotes string
	var remoteVersionTxt string
	var remoteVersionInt int

	log.Printf("[About] 开始检查版本，localVersionInt=%d, frontendVersion=%s", localVersionInt, frontendVersion)

	versionURL := convertToMirrorURL("https://raw.githubusercontent.com/fgh1995/CorazaWafProxy/main/main.go")
	log.Printf("[About] 请求URL: %s", versionURL)

	resp, err := client.Get(versionURL)
	if err != nil {
		log.Printf("[About] 获取远程版本失败: %v", err)
	} else if resp.StatusCode != 200 {
		log.Printf("[About] 获取远程版本返回状态码: %d", resp.StatusCode)
	} else {
		defer resp.Body.Close()
		versionContent, _ := io.ReadAll(resp.Body)
		contentStr := string(versionContent)

		intMatch := regexp.MustCompile(`localVersionInt\s*=\s*(\d+)`).FindStringSubmatch(contentStr)
		if len(intMatch) == 2 {
			fmt.Sscanf(intMatch[1], "%d", &remoteVersionInt)
		}

		txtMatch := regexp.MustCompile(`frontendVersion\s*=\s*"([^"]+)"`).FindStringSubmatch(contentStr)
		if len(txtMatch) == 2 {
			remoteVersionTxt = txtMatch[1]
		}

		releaseNotesMatch := regexp.MustCompile(`(?s)ReleaseNotes\s*=\s*"([^"]+)"`).FindStringSubmatch(contentStr)
		if len(releaseNotesMatch) > 1 {
			releaseNotes = releaseNotesMatch[1]
		}

		downloadURL = getDownloadURL(remoteVersionTxt)
		downloadPlatform = "GitHub"

		log.Printf("[About] 远程版本: text=%s, int=%d, releaseNotes长度=%d", remoteVersionTxt, remoteVersionInt, len(releaseNotes))

		if remoteVersionInt > localVersionInt {
			hasNewVersion = true
			log.Printf("[About] 发现新版本: %d > %d", remoteVersionInt, localVersionInt)
		} else {
			log.Printf("[About] 当前已是最新版本: %d <= %d", remoteVersionInt, localVersionInt)
		}
	}

	result := string(localTemplate)
	result = strings.ReplaceAll(result, "{localversion}", frontendVersion)
	result = strings.ReplaceAll(result, "{remoteversion}", remoteVersionTxt)
	result = strings.ReplaceAll(result, "{hasnewversion}", strconv.FormatBool(hasNewVersion))
	result = strings.ReplaceAll(result, "{databaseversion}", getCurrentDBVersion())
	result = strings.ReplaceAll(result, "{downloadurl}", downloadURL)
	result = strings.ReplaceAll(result, "{downloadplatform}", downloadPlatform)
	result = strings.ReplaceAll(result, "{releasenotes}", releaseNotes)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(result))
}

func convertToMirrorURL(url string) string {
	if !strings.HasPrefix(url, "https://github.com/") && !strings.HasPrefix(url, "http://github.com/") {
		return url
	}

	var mirror string
	err := db.QueryRow("SELECT value FROM system_settings WHERE key = 'github_mirror'").Scan(&mirror)
	if err != nil || mirror == "" {
		return url
	}

	mirror = strings.TrimSuffix(mirror, "/")
	if strings.HasPrefix(url, "https://github.com/") {
		return strings.Replace(url, "https://github.com/", mirror+"/", 1)
	}
	return strings.Replace(url, "http://github.com/", mirror+"/", 1)
}

func getDownloadURL(tagName string) string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var filename string
	switch goos {
	case "windows":
		filename = fmt.Sprintf("CorazaWafProxy_windows_amd64.zip")
	case "linux":
		if goarch == "arm64" {
			filename = fmt.Sprintf("CorazaWafProxy_linux_arm64.tar.gz")
		} else {
			filename = fmt.Sprintf("CorazaWafProxy_linux_amd64.tar.gz")
		}
	case "darwin":
		if goarch == "arm64" {
			filename = fmt.Sprintf("CorazaWafProxy_darwin_arm64.tar.gz")
		} else {
			filename = fmt.Sprintf("CorazaWafProxy_darwin_amd64.tar.gz")
		}
	default:
		filename = fmt.Sprintf("CorazaWafProxy_windows_amd64.zip")
	}

	return convertToMirrorURL(fmt.Sprintf("https://github.com/fgh1995/CorazaWafProxy/releases/download/%s/%s", tagName, filename))
}

type UpdateCheckResult struct {
	HasNewVersion    bool   `json:"hasNewVersion"`
	LocalVersion     string `json:"localVersion"`
	RemoteVersion    string `json:"remoteVersion"`
	RemoteVersionInt int    `json:"remoteVersionInt"`
	DownloadURL      string `json:"downloadUrl"`
	DownloadPlatform string `json:"downloadPlatform"`
	ReleaseNotes     string `json:"releaseNotes"`
}

type GithubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
}

type GithubAsset struct {
	Name                 string `json:"name"`
	BrowserDownloadURL   string `json:"browser_download_url"`
}

func parseVersionFromTag(tag string) (versionInt int, versionTxt string) {
	versionTxt = tag
	re := regexp.MustCompile(`\((\d+)\)`)
	matches := re.FindStringSubmatch(tag)
	if len(matches) == 2 {
		fmt.Sscanf(matches[1], "%d", &versionInt)
	}
	return
}

func handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	result := UpdateCheckResult{
		LocalVersion: frontendVersion,
	}

	log.Printf("[版本检查] 开始检查版本，localVersionInt=%d", localVersionInt)

	versionURL := convertToMirrorURL("https://raw.githubusercontent.com/fgh1995/CorazaWafProxy/main/main.go")
	resp, err := client.Get(versionURL)
	if err != nil {
		log.Printf("[版本检查] 获取远程版本失败: %v", err)
		result.HasNewVersion = false
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[版本检查] 获取远程版本返回状态码: %d", resp.StatusCode)
		result.HasNewVersion = false
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
		return
	}

	versionContent, _ := io.ReadAll(resp.Body)
	contentStr := string(versionContent)

	var remoteVersionInt int
	intMatch := regexp.MustCompile(`localVersionInt\s*=\s*(\d+)`).FindStringSubmatch(contentStr)
	if len(intMatch) == 2 {
		fmt.Sscanf(intMatch[1], "%d", &remoteVersionInt)
	}

	txtMatch := regexp.MustCompile(`frontendVersion\s*=\s*"([^"]+)"`).FindStringSubmatch(contentStr)
	if len(txtMatch) == 2 {
		result.RemoteVersion = txtMatch[1]
	}

	releaseNotesMatch := regexp.MustCompile(`(?s)ReleaseNotes\s*=\s*"([^"]+)"`).FindStringSubmatch(contentStr)
	if len(releaseNotesMatch) > 1 {
		result.ReleaseNotes = releaseNotesMatch[1]
	}

	result.RemoteVersionInt = remoteVersionInt
	result.DownloadPlatform = "GitHub"
	result.DownloadURL = getDownloadURL(result.RemoteVersion)

	log.Printf("[版本检查] 远程版本: text=%s, int=%d", result.RemoteVersion, remoteVersionInt)

	if remoteVersionInt > localVersionInt {
		result.HasNewVersion = true
		log.Printf("[版本检查] 发现新版本: %d > %d", remoteVersionInt, localVersionInt)
	} else {
		result.HasNewVersion = false
		log.Printf("[版本检查] 当前已是最新版本: %d <= %d", remoteVersionInt, localVersionInt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

type ManualUpdateResult struct {
	Success      bool   `json:"success"`
	Message     string `json:"message"`
	NeedsRestart bool   `json:"needsRestart"`
	BackupPath  string `json:"backupPath,omitempty"`
}

func handleManualUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentGOOS := runtime.GOOS
	currentGOARCH := runtime.GOARCH

	currentExec, err := os.Executable()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  "无法获取当前程序路径: " + err.Error(),
		})
		return
	}

	file, header, err := r.FormFile("updatefile")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  "未上传更新文件: " + err.Error(),
		})
		return
	}
	defer file.Close()

	filename := header.Filename
	log.Printf("[手动更新] 收到更新文件: %s, 大小: %d bytes", filename, header.Size)

	ext := strings.ToLower(filepath.Ext(filename))
	isZip := ext == ".zip"
	isTarGz := ext == ".gz" && strings.HasSuffix(filename, ".tar.gz")
	isTgz := ext == ".tgz"

	if !isZip && !isTarGz && !isTgz {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  fmt.Sprintf("不支持的文件格式: %s，支持的格式: .zip, .tar.gz, .tgz", ext),
		})
		return
	}

	expectedExecName := getExpectedExecName(currentGOOS, currentGOARCH)
	hasMismatch := false
	var detectedGOOS, detectedGOARCH string

	if isZip {
		detectedGOOS, detectedGOARCH, err = detectArchFromZip(file, header.Size, expectedExecName)
		if err != nil {
			log.Printf("[手动更新] 无法从zip包检测架构: %v", err)
			hasMismatch = true
		}
	} else {
		detectedGOOS, detectedGOARCH, err = detectArchFromTarGz(file, header.Size, expectedExecName)
		if err != nil {
			log.Printf("[手动更新] 无法从tar.gz包检测架构: %v", err)
			hasMismatch = true
		}
	}

	if !hasMismatch && (detectedGOOS != currentGOOS || detectedGOARCH != currentGOARCH) {
		log.Printf("[手动更新] 架构不匹配: 当前(%s/%s) vs 包内(%s/%s)", currentGOOS, currentGOARCH, detectedGOOS, detectedGOARCH)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  fmt.Sprintf("架构不匹配！当前程序: %s/%s，更新包: %s/%s", currentGOOS, currentGOARCH, detectedGOOS, detectedGOARCH),
		})
		return
	}

	file.Seek(0, 0)

	tmpDir, err := ioutil.TempDir("", "coraza-update-*")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  "创建临时目录失败: " + err.Error(),
		})
		return
	}
	defer os.RemoveAll(tmpDir)

	var extractedExecPath string
	if isZip {
		extractedExecPath, err = extractZip(file, header.Size, tmpDir, expectedExecName)
	} else {
		extractedExecPath, err = extractTarGz(file, tmpDir, expectedExecName)
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  "解压更新包失败: " + err.Error(),
		})
		return
	}

	newExecPath := extractedExecPath
	updatingExecPath := currentExec + ".updating"

	if err := os.Rename(currentExec, updatingExecPath); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  "准备更新文件失败: " + err.Error(),
		})
		return
	}

	if err := atomicReplace(newExecPath, currentExec); err != nil {
		os.Rename(updatingExecPath, currentExec)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ManualUpdateResult{
			Success:  false,
			Message:  "替换程序失败: " + err.Error(),
		})
		return
	}

	os.Chmod(currentExec, 0755)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ManualUpdateResult{
		Success:      true,
		Message:      "更新成功！服务正在重启...",
		NeedsRestart: true,
	})

	go func() {
		time.Sleep(500 * time.Millisecond)
		execDir := filepath.Dir(currentExec)
		updateScriptPath := filepath.Join(execDir, "update-restart.bat")
		if currentGOOS == "windows" {
			scriptContent := fmt.Sprintf(`@echo off
:wait
ping -n 2 127.0.0.1 >nul
if exist "%s" goto wait
del "%s" 2>nul
del "%s" 2>nul
start "" "%s"
del "%%~f0" 2>nul
`, updatingExecPath, updatingExecPath, updateScriptPath, currentExec)
			updateScriptPath := filepath.Join(execDir, "update-restart.bat")
			ioutil.WriteFile(updateScriptPath, []byte(scriptContent), 0755)
			goexec := os.Getenv("COMSPEC")
			if goexec == "" {
				goexec = "cmd.exe"
			}
			exec.Command(goexec, "/C", "start", "", updateScriptPath).Start()
		} else {
			scriptContent := fmt.Sprintf(`#!/bin/bash
while [ -f "%s" ]; do
    sleep 0.5
done
rm -f "%s"
rm -f "%s"
"%s" &
rm -f "$0"
`, updatingExecPath, updatingExecPath, updateScriptPath, currentExec)
			updateScriptPath := filepath.Join(execDir, "update-restart.sh")
			ioutil.WriteFile(updateScriptPath, []byte(scriptContent), 0755)
			os.Chmod(updateScriptPath, 0755)
			exec.Command("/bin/bash", updateScriptPath).Start()
		}
		log.Println("[手动更新] 服务即将重启...")
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
}

func handleAutoUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpdateDownloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "无效的请求: " + err.Error(),
			Logs:    []string{"[错误] 解析请求失败: " + err.Error()},
		})
		return
	}

	downloadURL := req.DownloadURL
	platform := req.Platform

	if downloadURL == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "下载链接不能为空",
			Logs:    []string{"[错误] 下载链接为空"},
		})
		return
	}

	var logs []string
	addLog := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		logs = append(logs, msg)
		log.Println("[自动更新]", msg)
	}

	addLog("开始自动更新流程")
	addLog("下载平台: %s", platform)
	addLog("下载地址: %s", downloadURL)

	client := &http.Client{
		Timeout: 300 * time.Second,
	}

	addLog("正在下载更新包...")
	resp, err := client.Get(downloadURL)
	if err != nil {
		addLog("下载失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "下载更新包失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		addLog("下载失败，HTTP状态码: %d", resp.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: fmt.Sprintf("下载失败，HTTP状态码: %d", resp.StatusCode),
			Logs:    logs,
		})
		return
	}
	addLog("下载完成，状态码: %d", resp.StatusCode)

	currentGOOS := runtime.GOOS
	currentGOARCH := runtime.GOARCH
	currentExec, err := os.Executable()
	if err != nil {
		addLog("无法获取当前程序路径: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "无法获取当前程序路径: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	addLog("当前程序路径: %s", currentExec)
	addLog("目标平台: %s/%s", currentGOOS, currentGOARCH)

	tmpDir, err := ioutil.TempDir("", "coraza-autoupdate-*")
	if err != nil {
		addLog("创建临时目录失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "创建临时目录失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	defer os.RemoveAll(tmpDir)
	addLog("临时目录: %s", tmpDir)

	tmpFile := filepath.Join(tmpDir, "update-package")
	outFile, err := os.Create(tmpFile)
	if err != nil {
		addLog("创建临时文件失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "创建临时文件失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}

	addLog("正在保存更新包...")
	_, err = io.Copy(outFile, resp.Body)
	outFile.Close()
	if err != nil {
		addLog("保存更新包失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "保存更新包失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	addLog("更新包已保存")

	updateFile, err := os.Open(tmpFile)
	if err != nil {
		addLog("打开更新包失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "打开更新包失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	defer updateFile.Close()

	fileInfo, _ := updateFile.Stat()
	fileSize := fileInfo.Size()
	addLog("更新包大小: %d bytes", fileSize)

	expectedExecName := getExpectedExecName(currentGOOS, currentGOARCH)
	addLog("期望的可执行文件名: %s", expectedExecName)

	var extractedExecPath string
	addLog("正在解压更新包...")
	if strings.HasSuffix(downloadURL, ".zip") {
		extractedExecPath, err = extractZip(updateFile, fileSize, tmpDir, expectedExecName)
	} else {
		extractedExecPath, err = extractTarGz(updateFile, tmpDir, expectedExecName)
	}

	if err != nil {
		addLog("解压失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "解压更新包失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	addLog("解压完成，程序路径: %s", extractedExecPath)

	updatingExecPath := currentExec + ".updating"
	addLog("正在备份当前程序...")
	if err := os.Rename(currentExec, updatingExecPath); err != nil {
		addLog("备份失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "准备更新文件失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	addLog("备份文件: %s", updatingExecPath)

	addLog("正在替换程序...")
	if err := atomicReplace(extractedExecPath, currentExec); err != nil {
		os.Rename(updatingExecPath, currentExec)
		addLog("替换失败，回滚中: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AutoUpdateResult{
			Success: false,
			Message: "替换程序失败: " + err.Error(),
			Logs:    logs,
		})
		return
	}
	addLog("程序替换成功")

	os.Chmod(currentExec, 0755)

	addLog("更新流程完成，服务即将重启")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AutoUpdateResult{
		Success:      true,
		Message:      "更新成功！服务正在重启...",
		NeedsRestart: true,
		Logs:         logs,
	})

	go func() {
		time.Sleep(500 * time.Millisecond)
		execDir := filepath.Dir(currentExec)
		if currentGOOS == "windows" {
			scriptContent := fmt.Sprintf(`@echo off
:wait
ping -n 2 127.0.0.1 >nul
if exist "%s" goto wait
del "%s" 2>nul
start "" "%s"
del "%%~f0" 2>nul
`, updatingExecPath, updatingExecPath, currentExec)
			restartScriptPath := filepath.Join(execDir, "update-restart.bat")
			ioutil.WriteFile(restartScriptPath, []byte(scriptContent), 0755)
			goexec := os.Getenv("COMSPEC")
			if goexec == "" {
				goexec = "cmd.exe"
			}
			exec.Command(goexec, "/C", "start", "", restartScriptPath).Start()
		} else {
			scriptContent := fmt.Sprintf(`#!/bin/bash
while [ -f "%s" ]; do
    sleep 0.5
done
rm -f "%s"
"%s" &
rm -f "$0"
`, updatingExecPath, updatingExecPath, currentExec)
			restartScriptPath := filepath.Join(execDir, "update-restart.sh")
			ioutil.WriteFile(restartScriptPath, []byte(scriptContent), 0755)
			os.Chmod(restartScriptPath, 0755)
			exec.Command("/bin/bash", restartScriptPath).Start()
		}
		log.Println("[自动更新] 服务即将重启...")
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
}

type AutoUpdateResult struct {
	Success      bool     `json:"success"`
	Message     string   `json:"message"`
	NeedsRestart bool     `json:"needsRestart"`
	Logs         []string `json:"logs"`
}

type UpdateDownloadRequest struct {
	DownloadURL string `json:"downloadUrl"`
	Platform    string `json:"platform"`
}

func getExpectedExecName(goos, goarch string) string {
	switch goos {
	case "windows":
		if goarch == "arm64" {
			return "CorazaWafProxy-windows-arm64.exe"
		}
		return "CorazaWafProxy-windows-amd64.exe"
	case "linux":
		if goarch == "arm64" {
			return "coraza-waf-proxy-linux-arm64"
		}
		return "coraza-waf-proxy-linux-amd64"
	case "darwin":
		if goarch == "arm64" {
			return "coraza-waf-proxy-darwin-arm64"
		}
		return "coraza-waf-proxy-darwin-amd64"
	default:
		return "coraza-waf-proxy"
	}
}

func detectArchFromZip(file multipart.File, size int64, expectedName string) (goos, goarch string, err error) {
	zipr, err := zip.NewReader(file, size)
	if err != nil {
		return "", "", err
	}

	for _, f := range zipr.File {
		name := filepath.Base(f.Name)
		if name == expectedName || name == expectedName+".exe" {
			return parseArchFromFilename(name)
		}
	}
	return "", "", fmt.Errorf("未在压缩包中找到可执行文件 %s", expectedName)
}

func detectArchFromTarGz(file multipart.File, size int64, expectedName string) (goos, goarch string, err error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		name := filepath.Base(hdr.Name)
		if name == expectedName || name == expectedName+".exe" {
			return parseArchFromFilename(name)
		}
	}
	return "", "", fmt.Errorf("未在压缩包中找到可执行文件 %s", expectedName)
}

func parseArchFromFilename(filename string) (goos, goarch string, err error) {
	lower := strings.ToLower(filename)

	if strings.Contains(lower, "windows") {
		goos = "windows"
	} else if strings.Contains(lower, "linux") {
		goos = "linux"
	} else if strings.Contains(lower, "darwin") || strings.Contains(lower, "macos") {
		goos = "darwin"
	} else {
		return "", "", fmt.Errorf("无法识别操作系统: %s", filename)
	}

	if strings.Contains(lower, "arm64") {
		goarch = "arm64"
	} else if strings.Contains(lower, "amd64") || strings.Contains(lower, "x86_64") {
		goarch = "amd64"
	} else {
		return "", "", fmt.Errorf("无法识别架构: %s", filename)
	}

	return goos, goarch, nil
}

func extractZip(file multipart.File, size int64, destDir, expectedName string) (string, error) {
	zipr, err := zip.NewReader(file, size)
	if err != nil {
		return "", err
	}

	var extractedPath string
	for _, f := range zipr.File {
		name := strings.ReplaceAll(f.Name, "/", string(filepath.Separator))

		if strings.HasPrefix(name, "data"+string(filepath.Separator)) {
			continue
		}

		if filepath.Base(name) == expectedName || filepath.Base(name) == expectedName+".exe" {
			extractedPath = filepath.Join(destDir, filepath.Base(name))
			rc, err := f.Open()
			if err != nil {
				return "", err
			}

			outFile, err := os.OpenFile(extractedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return "", err
			}

			if _, err := io.Copy(outFile, rc); err != nil {
				rc.Close()
				outFile.Close()
				return "", err
			}
			rc.Close()
			outFile.Close()
			continue
		}

		headerPath := filepath.Join(destDir, name)
		if strings.HasSuffix(name, string(filepath.Separator)) {
			os.MkdirAll(headerPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(headerPath), 0755)
		rc, err := f.Open()
		if err != nil {
			return "", err
		}

		outFile, err := os.OpenFile(headerPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			rc.Close()
			return "", err
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			rc.Close()
			outFile.Close()
			return "", err
		}
		rc.Close()
		outFile.Close()
	}

	if extractedPath == "" {
		return "", fmt.Errorf("未找到可执行文件")
	}

	return extractedPath, nil
}

func extractTarGz(file multipart.File, destDir, expectedName string) (string, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var extractedPath string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		name := hdr.Name

		if strings.HasPrefix(name, "data/") {
			continue
		}

		headerPath := filepath.Join(destDir, name)

		if hdr.FileInfo().Mode().IsDir() {
			os.MkdirAll(headerPath, 0755)
			continue
		}

		if filepath.Base(name) == expectedName || filepath.Base(name) == expectedName+".exe" {
			extractedPath = headerPath
		}

		os.MkdirAll(filepath.Dir(headerPath), 0755)
		outFile, err := os.OpenFile(headerPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			return "", err
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return "", err
		}
		outFile.Close()
	}

	if extractedPath == "" {
		return "", fmt.Errorf("未找到可执行文件")
	}

	return extractedPath, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

func atomicReplace(src, dst string) error {
	err := copyFile(src, dst)
	if err != nil {
		return err
	}
	return os.Remove(src)
}

type SystemInfo struct {
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	NumCPU       int    `json:"numCpu"`
	GoVersion    string `json:"goVersion"`
	ProgramPath  string `json:"programPath"`
	ProgramExe   string `json:"programExe"`
	LocalVersion string `json:"localVersion"`
}

func handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	execPath, _ := os.Executable()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SystemInfo{
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		NumCPU:       runtime.NumCPU(),
		GoVersion:    runtime.Version(),
		ProgramPath:  execPath,
		ProgramExe:   filepath.Base(execPath),
		LocalVersion: frontendVersion,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		var password string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&password)
		if err != nil || password != req.Password {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "用户名或密码错误",
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    req.Username,
			Path:     "/",
			MaxAge:   3600 * 24,
			HttpOnly: true,
		})

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/web/html/login.html", http.StatusSeeOther)
}

func handleDBVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	version := getCurrentDBVersion()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"version": version,
		"latest":  currentDBVersion,
		"needUpgrade": version != currentDBVersion,
	})
}

func handleDBUpgrade(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	version := getCurrentDBVersion()
	if version == currentDBVersion {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "数据库已经是最新版本",
		})
		return
	}

	upgradeSteps := getSequentialUpgradeSteps(version)
	if len(upgradeSteps) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "不支持的数据库版本或已是最新版本",
		})
		return
	}

	go func() {
		err := performSequentialUpgrade(version, upgradeSteps)
		if err != nil {
			setUpgradeError(err.Error())
			log.Printf("数据库升级失败: %v", err)
		}
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "数据库升级已开始",
		"version": currentDBVersion,
	})
}

func getSequentialUpgradeSteps(currentVersion string) []string {
	var steps []string
	versions := []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"}
	currentIdx := 0
	
	for i, v := range versions {
		if v == currentVersion {
			currentIdx = i
			break
		}
	}
	
	for i := currentIdx + 1; i < len(versions); i++ {
		steps = append(steps, versions[i])
	}
	
	return steps
}

func performSequentialUpgrade(fromVersion string, steps []string) error {
	initUpgradeProgress()

	currentVersion := fromVersion
	totalSteps := len(steps)

	for stepIdx, targetVersion := range steps {
		log.Printf("升级数据库: %s -> %s", currentVersion, targetVersion)
		updateUpgradeProgress("upgrading", stepIdx, totalSteps, fmt.Sprintf("升级到版本 %s...", targetVersion))

		var err error
		switch targetVersion {
		case "1.1":
			err = upgradeTo11()
		case "1.2":
			err = upgradeTo12()
		case "1.3":
			err = upgradeTo13()
		case "1.4":
			err = upgradeTo14()
		case "1.5":
			err = upgradeTo15()
		case "1.6":
			err = upgradeTo16()
		default:
			err = fmt.Errorf("未知的升级目标版本: %s", targetVersion)
		}

		if err != nil {
			return fmt.Errorf("升级到 %s 失败: %w", targetVersion, err)
		}

		updateUpgradeProgress("upgrading", stepIdx+1, totalSteps, fmt.Sprintf("完成版本 %s", targetVersion))
		currentVersion = targetVersion
	}

	updateUpgradeProgress("completed", totalSteps, totalSteps, "所有升级完成")
	setUpgradeCompleted()
	log.Printf("数据库升级完成: %s -> %s", fromVersion, currentDBVersion)
	
	log.Println("数据库升级完成，3秒后自动重启以应用新数据...")
	time.Sleep(3 * time.Second)
	restartProgram()
	
	return nil
}

func handleDBUpgradeProgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	stage, current, total, stepName, completed, errMsg := getUpgradeProgress()
	
	if errMsg != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"stage":   stage,
			"current": current,
			"total":   total,
			"step":    stepName,
			"completed": completed,
			"error":   errMsg,
		})
		return
	}
	
	if completed {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"stage":     "completed",
			"current":   total,
			"total":     total,
			"step":      stepName,
			"completed": completed,
			"message":   "数据库升级完成",
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"stage":     stage,
		"current":   current,
		"total":     total,
		"step":      stepName,
		"completed": completed,
	})
}

func handleCurrentUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	session, err := r.Cookie("session")
	if err != nil || session.Value == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "未登录",
		})
		return
	}
	
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE username = ?", session.Value).Scan(&username)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "用户不存在",
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": username,
	})
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	
	session, err := r.Cookie("session")
	if err != nil || session.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "未登录",
		})
		return
	}
	
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
		NewUsername string `json:"newUsername"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "无效的请求",
		})
		return
	}
	
	var currentPassword string
	var currentUsername string
	err = db.QueryRow("SELECT username, password FROM users WHERE username = ?", session.Value).Scan(&currentUsername, &currentPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "查询用户失败",
		})
		return
	}
	
	if currentPassword != req.OldPassword {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "原密码错误",
		})
		return
	}
	
	newUsername := req.NewUsername
	if newUsername == "" {
		newUsername = currentUsername
	}
	
	if req.NewPassword == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "新密码不能为空",
		})
		return
	}
	
	tx, err := db.Begin()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "数据库事务失败",
		})
		return
	}
	defer tx.Rollback()
	
	_, err = tx.Exec("DELETE FROM users WHERE username = ?", currentUsername)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "更新用户失败",
		})
		return
	}
	
	_, err = tx.Exec("INSERT INTO users (username, password) VALUES (?, ?)", newUsername, req.NewPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "保存新用户失败",
		})
		return
	}
	
	if err = tx.Commit(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "提交事务失败",
		})
		return
	}
	
	if newUsername != currentUsername {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    newUsername,
			Path:     "/",
			MaxAge:   3600 * 24,
			HttpOnly: true,
		})
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"username": newUsername,
	})
}

func handleWAFInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "POST" {
		var req struct {
			Name  string   `json:"name"`
			Mode  string   `json:"mode"`
			Rules []string `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		instance, err := createWAFInstance(req.Name, req.Mode, req.Rules)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建WAF实例失败: " + err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"instance": instance,
		})
	} else {
		wafMutex.RLock()
		proxyMutex.RLock()
		instances := make([]*WAFInstance, 0, len(wafInstances))
		for _, inst := range wafInstances {
			instanceCopy := *inst
			boundCount := 0
			for _, proxy := range proxyInstances {
				if proxy.WAFID == inst.ID {
					boundCount++
				}
			}
			instanceCopy.BoundProxyCount = boundCount
			instances = append(instances, &instanceCopy)
		}
		wafMutex.RUnlock()
		proxyMutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"instances": instances,
		})
	}
}

func handleWAFInstance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	id := strings.TrimPrefix(r.URL.Path, "/api/waf-instances/")

	if r.Method == "PUT" {
		var req struct {
			Name  string   `json:"name"`
			Mode  string   `json:"mode"`
			Rules []string `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		wafMutex.RLock()
		instance, exists := wafInstances[id]
		wafMutex.RUnlock()

		if !exists {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "WAF实例不存在",
			})
			return
		}

		waf, err := createWAF(req.Mode, req.Rules)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建WAF失败: " + err.Error(),
			})
			return
		}

		rulesJSON, _ := json.Marshal(req.Rules)
		_, err = db.Exec("UPDATE waf_instances SET name = ?, mode = ?, rules = ? WHERE id = ?", 
			req.Name, req.Mode, string(rulesJSON), id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "更新失败",
			})
			return
		}

		instance.Name = req.Name
		instance.Mode = req.Mode
		instance.Rules = req.Rules
		instance.WAF = waf

		proxyMutex.Lock()
		var instancesToRestart []*ProxyInstance
		for _, inst := range proxyInstances {
			if inst.WAFID == id {
				inst.WAFName = req.Name
				instancesToRestart = append(instancesToRestart, inst)
			}
		}
		proxyMutex.Unlock()

		for _, inst := range instancesToRestart {
			if inst.Server != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				inst.Server.Shutdown(ctx)
				time.Sleep(600 * time.Millisecond)
			}

			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", inst.ListenPort))
			if err != nil {
				log.Printf("重启代理服务器 %s 失败: %v", inst.Name, err)
				continue
			}

			handler := &wafHandler{next: inst.Proxy, waf: waf, proxyID: inst.ID}
			inst.Server = &http.Server{
				Handler: handler,
			}

			go func() {
				time.Sleep(500 * time.Millisecond)
				if err := inst.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
					log.Printf("代理服务器 %s 运行错误: %v", inst.Name, err)
				} else if err == http.ErrServerClosed {
					log.Printf("代理服务器 %s 已关闭", inst.Name)
				}
			}()

			log.Printf("重启代理服务器 %s (WAF已更新)", inst.Name)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"instance": instance,
		})
		return
	}

	if r.Method == "DELETE" {
		proxyMutex.Lock()
		var instancesToRestart []*ProxyInstance
		for _, inst := range proxyInstances {
			if inst.WAFID == id {
				inst.WAFID = ""
				inst.WAFName = ""
				instancesToRestart = append(instancesToRestart, inst)
			}
		}
		proxyMutex.Unlock()

		for _, inst := range instancesToRestart {
			if inst.Server != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				inst.Server.Shutdown(ctx)
				time.Sleep(600 * time.Millisecond)
			}

			_, err := db.Exec("UPDATE proxy_instances SET waf_id = '' WHERE id = ?", inst.ID)
			if err != nil {
				log.Printf("更新防护应用 %s 失败: %v", inst.ID, err)
			}

			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", inst.ListenPort))
			if err != nil {
				log.Printf("重启代理服务器 %s 失败: %v", inst.Name, err)
				continue
			}

			inst.Server = &http.Server{
				Handler: inst.Proxy,
			}

			go func() {
				time.Sleep(500 * time.Millisecond)
				if err := inst.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
					log.Printf("代理服务器 %s 运行错误: %v", inst.Name, err)
				} else if err == http.ErrServerClosed {
					log.Printf("代理服务器 %s 已关闭", inst.Name)
				}
			}()

			log.Printf("重启代理服务器 %s (已取消WAF关联)", inst.Name)
		}

		_, err := db.Exec("DELETE FROM waf_instances WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除失败",
			})
			return
		}

		wafMutex.Lock()
		delete(wafInstances, id)
		wafMutex.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func loadCertificatesFromDB() error {
	rows, err := db.Query("SELECT id, name, domains, provider, cert_file, key_file, ca_file, expires_at, auto_renew, status, created_at, cloudflare_api_token, cloudflare_email, acme_kid, acme_hmac_key, acme_server_url, acme_email FROM certificates")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, name, domains, provider, certFile, keyFile, caFile, createdAt, cloudflareAPIToken, cloudflareEmail, acmeKid, acmeHmacKey, acmeServerURL, acmeEmail string
		var autoRenew int
		var status string
		var certFileNull, keyFileNull, caFileNull sql.NullString
		var expiresAtNull sql.NullInt64
		err := rows.Scan(&id, &name, &domains, &provider, &certFileNull, &keyFileNull, &caFileNull, &expiresAtNull, &autoRenew, &status, &createdAt, &cloudflareAPIToken, &cloudflareEmail, &acmeKid, &acmeHmacKey, &acmeServerURL, &acmeEmail)
		if err != nil {
			log.Printf("加载证书行扫描失败: %v", err)
			continue
		}

		if certFileNull.Valid {
			certFile = certFileNull.String
		}
		if keyFileNull.Valid {
			keyFile = keyFileNull.String
		}
		if caFileNull.Valid {
			caFile = caFileNull.String
		}

		var expiresAt int64
		if expiresAtNull.Valid {
			expiresAt = expiresAtNull.Int64
		}

		cert := &Certificate{
			ID:                 id,
			Name:               name,
			Domains:            domains,
			Provider:           provider,
			CertFile:           certFile,
			KeyFile:            keyFile,
			CaFile:             caFile,
			ExpiresAt:          expiresAt,
			AutoRenew:          autoRenew == 1,
			Status:             status,
			CreatedAt:          createdAt,
			CloudflareAPIToken: cloudflareAPIToken,
			CloudflareEmail:    cloudflareEmail,
			AcmeKid:           acmeKid,
			AcmeHmacKey:       acmeHmacKey,
			AcmeServerURL:     acmeServerURL,
			AcmeEmail:         acmeEmail,
		}
		if status == "pending" {
			log.Printf("[证书] 检测到 pending 状态的证书 %s (后端可能已重启)，标记为失败", id)
			cert.Status = "failed"
			db.Exec("UPDATE certificates SET status = ? WHERE id = ?", "failed", id)
		} else {
			cert.Status = getCertificateStatus(expiresAt)
		}

		certificateMutex.Lock()
		certificates[id] = cert
		certificateMutex.Unlock()
	}

	return nil
}

func getCertificateStatus(expiresAt int64) string {
	if expiresAt == 0 {
		return "pending"
	}
	if expiresAt < time.Now().Unix() {
		return "expired"
	}
	return "valid"
}

func handleCertificates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "POST" {
		var req struct {
			Name              string `json:"name"`
			Domains           string `json:"domains"`
			Provider          string `json:"provider"`
			AutoRenew         bool   `json:"autoRenew"`
			CloudflareAPIToken string `json:"cloudflareApiToken"`
			CloudflareEmail    string `json:"cloudflareEmail"`
			AcmeKid           string `json:"acmeKid"`
			AcmeHmacKey       string `json:"acmeHmacKey"`
			AcmeServerURL     string `json:"acmeServerUrl"`
			AcmeEmail         string `json:"acmeEmail"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		id := fmt.Sprintf("cert-%d", time.Now().UnixNano())
		createdAt := getUTCTimestamp()
		providerName := convertProviderName(req.Provider)

		_, err := db.Exec(
			"INSERT INTO certificates (id, name, domains, provider, auto_renew, status, created_at, cloudflare_api_token, cloudflare_email, acme_kid, acme_hmac_key, acme_server_url, acme_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			id, req.Name, req.Domains, providerName, boolToInt(req.AutoRenew), "pending", createdAt, req.CloudflareAPIToken, req.CloudflareEmail, req.AcmeKid, req.AcmeHmacKey, req.AcmeServerURL, req.AcmeEmail,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建证书失败: " + err.Error(),
			})
			return
		}

		cert := &Certificate{
			ID:                 id,
			Name:               req.Name,
			Domains:            req.Domains,
			Provider:           req.Provider,
			AutoRenew:          req.AutoRenew,
			Status:             "pending",
			CreatedAt:          fmt.Sprintf("%d", createdAt),
			CloudflareAPIToken: req.CloudflareAPIToken,
			CloudflareEmail:    req.CloudflareEmail,
			AcmeKid:           req.AcmeKid,
			AcmeHmacKey:       req.AcmeHmacKey,
			AcmeServerURL:     req.AcmeServerURL,
			AcmeEmail:         req.AcmeEmail,
		}

		certificateMutex.Lock()
		certificates[id] = cert
		certificateMutex.Unlock()

		stopChan := make(chan struct{})
		certStopChannels.Store(id, stopChan)

		go func() {
			if err := requestCertificate(cert); err != nil {
				log.Printf("证书申请失败: %v", err)
				certificateMutex.Lock()
				cert.Status = "failed"
				db.Exec("UPDATE certificates SET status = ? WHERE id = ?", "failed", cert.ID)
				certificateMutex.Unlock()
			}
			certStopChannels.Delete(id)
		}()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"cert":    cert,
			"id":      id,
		})
		return
	}

	certificateMutex.RLock()
	certs := make([]*Certificate, 0, len(certificates))
	for _, cert := range certificates {
		certs = append(certs, cert)
	}
	certificateMutex.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"certificates": certs,
	})
}

func handleCertificateLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/certificates/")
	id = strings.TrimSuffix(id, "/logs")

	logs := getCertLogs(id)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"certId":  id,
		"logs":    logs,
	})
}

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/certificates/")

	if r.Method == "DELETE" {
		certificateMutex.Lock()
		cert, exists := certificates[id]
		certificateMutex.Unlock()

		certFile, keyFile, caFile := "", "", ""
		if exists && cert != nil {
			certFile = cert.CertFile
			keyFile = cert.KeyFile
			caFile = cert.CaFile
		}

		_, err := db.Exec("DELETE FROM certificates WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除失败: " + err.Error(),
			})
			return
		}

		certificateMutex.Lock()
		delete(certificates, id)
		certificateMutex.Unlock()

		clearCertLogs(id)

		if certFile != "" {
			os.Remove(certFile)
		}
		if keyFile != "" {
			os.Remove(keyFile)
		}
		if caFile != "" {
			os.Remove(caFile)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	if r.Method == "PUT" {
		var req struct {
			Name              string `json:"name"`
			Domains           string `json:"domains"`
			Provider          string `json:"provider"`
			AutoRenew         bool   `json:"autoRenew"`
			CloudflareAPIToken string `json:"cloudflareApiToken"`
			AcmeEmail         string `json:"acmeEmail"`
			AcmeKid           string `json:"acmeKid"`
			AcmeHmacKey       string `json:"acmeHmacKey"`
			AcmeServerURL     string `json:"acmeServerUrl"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		certificateMutex.Lock()
		cert, exists := certificates[id]
		if !exists {
			certificateMutex.Unlock()
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "证书不存在",
			})
			return
		}

		cert.Name = req.Name
		cert.Domains = req.Domains
		cert.Provider = convertProviderName(req.Provider)
		cert.AutoRenew = req.AutoRenew
		cert.CloudflareAPIToken = req.CloudflareAPIToken
		cert.AcmeEmail = req.AcmeEmail
		cert.AcmeKid = req.AcmeKid
		cert.AcmeHmacKey = req.AcmeHmacKey
		cert.AcmeServerURL = req.AcmeServerURL
		certificateMutex.Unlock()

		providerName := convertProviderName(req.Provider)
		_, err := db.Exec("UPDATE certificates SET name = ?, domains = ?, provider = ?, auto_renew = ?, cloudflare_api_token = ?, acme_email = ?, acme_kid = ?, acme_hmac_key = ?, acme_server_url = ? WHERE id = ?",
			req.Name, req.Domains, providerName, boolToInt(req.AutoRenew), req.CloudflareAPIToken, req.AcmeEmail, req.AcmeKid, req.AcmeHmacKey, req.AcmeServerURL, id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "更新失败: " + err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"cert":    cert,
		})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func handleCertificateRenew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/certificates/")
	id = strings.TrimSuffix(id, "/renew")

	certificateMutex.RLock()
	cert, exists := certificates[id]
	certificateMutex.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "证书不存在",
		})
		return
	}

	stopChan := make(chan struct{})
	certStopChannels.Store(id, stopChan)

	go func() {
		if err := requestCertificate(cert); err != nil {
			log.Printf("证书续期失败: %v", err)
		}
		certStopChannels.Delete(id)
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "证书续期请求已提交",
	})
}

func handleCertificateStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/certificates/")
	id = strings.TrimSuffix(id, "/stop")

	if stopChan, exists := certStopChannels.Load(id); exists {
		close(stopChan.(chan struct{}))
		certStopChannels.Delete(id)

		certificateMutex.Lock()
		if cert, ok := certificates[id]; ok {
			cert.Status = "stopped"
			db.Exec("UPDATE certificates SET status = ? WHERE id = ?", "stopped", id)
		}
		certificateMutex.Unlock()

		addCertLog(id, "证书申请已手动停止")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "证书申请已停止",
		})
		return
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "证书申请不在进行中",
	})
}

func handleCertificateRetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/certificates/")
	id = strings.TrimSuffix(id, "/retry")

	certificateMutex.Lock()
	cert, exists := certificates[id]
	if !exists {
		certificateMutex.Unlock()
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "证书不存在",
		})
		return
	}

	if cert.Status != "failed" {
		certificateMutex.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "只有申请失败的证书才能重试",
		})
		return
	}

	cert.Status = "pending"
	db.Exec("UPDATE certificates SET status = ? WHERE id = ?", "pending", id)
	certificateMutex.Unlock()

	addCertLog(id, "开始重试证书申请...")
	go func() {
		if err := requestCertificate(cert); err != nil {
			log.Printf("证书申请失败: %v", err)
			certificateMutex.Lock()
			cert.Status = "failed"
			db.Exec("UPDATE certificates SET status = ? WHERE id = ?", "failed", cert.ID)
			certificateMutex.Unlock()
		}
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "证书申请已重新启动",
	})
}

func convertProviderName(provider string) string {
	if provider == "letsencrypt" {
		return "Let's Encrypt"
	}
	return provider
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func requestCertificate(cert *Certificate) error {
	addCertLog(cert.ID, "开始申请证书...")
	domains := strings.Split(cert.Domains, ",")
	if len(domains) == 0 || domains[0] == "" {
		return fmt.Errorf("域名列表为空")
	}

	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}

	certDir := "./data/certs"
	os.MkdirAll(certDir, 0755)

	keyPath := certDir + "/" + cert.ID + ".key"
	certPath := certDir + "/" + cert.ID + ".crt"
	caPath := certDir + "/" + cert.ID + ".ca.crt"
	accountKeyPath := certDir + "/" + cert.ID + ".account.key"

	accountKey, err := loadOrCreateUserKey(accountKeyPath)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 加载账户密钥失败 - %v", err))
		return fmt.Errorf("加载账户密钥失败: %v", err)
	}
	addCertLog(cert.ID, "账户密钥加载成功")

	certKey, err := loadOrCreateUserKey(keyPath)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 加载证书密钥失败 - %v", err))
		return fmt.Errorf("加载证书密钥失败: %v", err)
	}
	addCertLog(cert.ID, "证书密钥加载成功")

	cloudflarePtr := cert.CloudflareAPIToken
	if cloudflarePtr == "" {
		cloudflarePtr = os.Getenv("CF_API_TOKEN")
	}

	addCertLog(cert.ID, "配置 Cloudflare DNS 提供商...")
	cloudflareProvider, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          cloudflarePtr,
		TTL:                120,
		PropagationTimeout: 24 * time.Hour,
	})
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: Cloudflare DNS 提供商创建失败 - %v", err))
		return fmt.Errorf("创建Cloudflare DNS提供商失败: %v", err)
	}
	addCertLog(cert.ID, "Cloudflare DNS 提供商创建成功")

	serverURL := cert.AcmeServerURL
	if serverURL == "" {
		serverURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	addCertLog(cert.ID, fmt.Sprintf("使用 ACME 服务器: %s", serverURL))

	acmeKid := cert.AcmeKid
	hmacKey := cert.AcmeHmacKey
	acmeEmail := cert.AcmeEmail

	user := &acmeUser{
		Email: acmeEmail,
		key:   accountKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = serverURL
	config.Certificate.KeyType = certcrypto.EC384

	client, err := lego.NewClient(config)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: ACME 客户端创建失败 - %v", err))
		return fmt.Errorf("创建ACME客户端失败: %v", err)
	}

	err = client.Challenge.SetDNS01Provider(cloudflareProvider)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 设置 DNS 提供商失败 - %v", err))
		return fmt.Errorf("设置DNS提供商失败: %v", err)
	}

	addCertLog(cert.ID, "正在注册 ACME 账户...")
	if acmeKid == "" || hmacKey == "" {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			addCertLog(cert.ID, fmt.Sprintf("错误: ACME 账户注册失败 - %v", err))
			return fmt.Errorf("注册ACME账户失败: %v", err)
		}
		user.Registration = reg
		cert.AcmeKid = reg.URI
		db.Exec("UPDATE certificates SET acme_kid = ?, acme_server_url = ? WHERE id = ?",
			reg.URI, serverURL, cert.ID)
		addCertLog(cert.ID, fmt.Sprintf("ACME 账户注册成功，Kid: %s", reg.URI))
	} else {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:          acmeKid,
			HmacEncoded:  hmacKey,
		})
		if err != nil {
			addCertLog(cert.ID, fmt.Sprintf("错误: EAB 注册失败 - %v", err))
			return fmt.Errorf("使用EAB注册ACME账户失败: %v", err)
		}
		user.Registration = reg
		cert.AcmeKid = reg.URI
		db.Exec("UPDATE certificates SET acme_kid = ?, acme_server_url = ? WHERE id = ?",
			reg.URI, serverURL, cert.ID)
		addCertLog(cert.ID, fmt.Sprintf("EAB 注册成功，Kid: %s", reg.URI))
	}

	addCertLog(cert.ID, fmt.Sprintf("正在申请证书，域名: %v", domains))
	addCertLog(cert.ID, "等待 DNS 记录传播（请耐心等待，不要关闭程序）...")

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 生成 CSR 失败 - %v", err))
		return fmt.Errorf("生成CSR失败: %v", err)
	}

	pemCsr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	block, _ := pem.Decode(pemCsr)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 解析 CSR 失败 - %v", err))
		return fmt.Errorf("解析CSR失败: %v", err)
	}

	request := certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: true,
	}

	certRes, err := client.Certificate.ObtainForCSR(request)
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 证书申请失败 - %v", err))
		return fmt.Errorf("申请证书失败: %v", err)
	}
	addCertLog(cert.ID, "证书申请成功，正在保存...")

	keyBytes, err := x509.MarshalECPrivateKey(certKey.(*ecdsa.PrivateKey))
	if err != nil {
		addCertLog(cert.ID, fmt.Sprintf("错误: 序列化私钥失败 - %v", err))
		return fmt.Errorf("序列化私钥失败: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	ioutil.WriteFile(keyPath, keyPEM, 0600)

	certBytes := certRes.Certificate
	if !bytes.HasPrefix(certBytes, []byte("-----BEGIN")) {
		certBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	}
	ioutil.WriteFile(certPath, certBytes, 0644)

	if len(certRes.IssuerCertificate) > 0 {
		caBytes := certRes.IssuerCertificate
		if !bytes.HasPrefix(caBytes, []byte("-----BEGIN")) {
			caBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
		}
		ioutil.WriteFile(caPath, caBytes, 0644)
	}

	expiresAt := time.Now().AddDate(0, 0, 89).Unix()

	certificateMutex.Lock()
	cert.CertFile = certPath
	cert.KeyFile = keyPath
	cert.CaFile = caPath
	cert.ExpiresAt = expiresAt
	cert.Status = "valid"
	certificateMutex.Unlock()

	db.Exec("UPDATE certificates SET cert_file = ?, key_file = ?, ca_file = ?, expires_at = ?, status = ? WHERE id = ?",
		certPath, keyPath, caPath, expiresAt, "valid", cert.ID)

	updateProxyCertificates(certPath, keyPath)

	addCertLog(cert.ID, fmt.Sprintf("证书申请完成! 到期时间: %s", time.Unix(expiresAt, 0).Format("2006-01-02")))
	log.Printf("证书申请成功: %s, 到期时间: %s", cert.Name, time.Unix(expiresAt, 0).Format("2006-01-02"))
	return nil
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func loadOrCreateUserKey(keyPath string) (crypto.PrivateKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		data, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return parsePrivateKey(data)
	}

	privateKey, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	data, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: data})
	ioutil.WriteFile(keyPath, keyPEM, 0600)
	return privateKey, nil
}

func generatePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func parsePrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("无法解析PEM格式私钥")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func updateProxyCertificates(certFile, keyFile string) {
	proxyMutex.RLock()
	defer proxyMutex.RUnlock()

	for _, inst := range proxyInstances {
		if inst.TLSEnabled {
			inst.TLSCertFile = certFile
			inst.TLSKeyFile = keyFile

			db.Exec("UPDATE proxy_instances SET tls_cert_file = ?, tls_key_file = ? WHERE id = ?",
				certFile, keyFile, inst.ID)

			log.Printf("更新代理 %s 的证书为: %s", inst.Name, certFile)
		}
	}
}

func startCertificateAutoRenewal() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			certificateMutex.RLock()
			for _, cert := range certificates {
				if cert.AutoRenew && cert.ExpiresAt > 0 {
					daysUntilExpiry := (cert.ExpiresAt - time.Now().Unix()) / 86400
					if daysUntilExpiry <= 7 {
						go func() {
							if err := requestCertificate(cert); err != nil {
								log.Printf("自动续期失败: %v", err)
							} else {
								log.Printf("证书 %s 自动续期成功", cert.Name)
							}
						}()
					}
				}
			}
			certificateMutex.RUnlock()
		}
	}()
}

func handleProxyInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "POST" {
		var req struct {
			Name            string `json:"name"`
			ListenPort      int    `json:"listenPort"`
			Backend         string `json:"backend"`
			FallbackBackend string `json:"fallbackBackend"`
			WAFID           string `json:"wafId"`
			TLSEnabled      bool   `json:"tlsEnabled"`
			TLSCertFile    string `json:"tlsCertFile"`
			TLSKeyFile     string `json:"tlsKeyFile"`
			ForceHTTPS      bool   `json:"forceHttps"`
			HTTPListenPort  int    `json:"httpListenPort"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		instance, err := createProxyInstance(req.Name, req.ListenPort, req.Backend, req.WAFID, req.TLSEnabled, req.TLSCertFile, req.TLSKeyFile, req.FallbackBackend, req.ForceHTTPS, req.HTTPListenPort)
		if err != nil {
			log.Printf("创建防护应用失败: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建防护应用失败: " + err.Error(),
			})
			return
		}

		log.Printf("创建防护应用成功: %s", instance.ID)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"instance": instance,
		})
	} else {
		proxyMutex.RLock()
		wafMutex.RLock()
		instances := make([]*ProxyInstance, 0, len(proxyInstances))
		for _, inst := range proxyInstances {
			instanceCopy := *inst
			if instanceCopy.WAFID != "" {
				if wafInst, exists := wafInstances[instanceCopy.WAFID]; exists {
					instanceCopy.WAFName = wafInst.Name
				}
			}
			instances = append(instances, &instanceCopy)
		}
		wafMutex.RUnlock()
		proxyMutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"instances": instances,
		})
	}
}

func handleProxyInstance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	id := strings.TrimPrefix(r.URL.Path, "/api/proxy-instances/")

	if r.Method == "PUT" {
		var req struct {
			Name            string `json:"name"`
			ListenPort      int    `json:"listenPort"`
			Backend         string `json:"backend"`
			FallbackBackend string `json:"fallbackBackend"`
			WAFID           string `json:"wafId"`
			TLSEnabled      bool   `json:"tlsEnabled"`
			TLSCertFile     string `json:"tlsCertFile"`
			TLSKeyFile      string `json:"tlsKeyFile"`
			ForceHTTPS      bool   `json:"forceHttps"`
			HTTPListenPort  int    `json:"httpListenPort"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		proxyMutex.RLock()
		instance, exists := proxyInstances[id]
		proxyMutex.RUnlock()

		if !exists {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "防护应用不存在",
			})
			return
		}

		// 验证监听端口
		if req.ListenPort < 1 || req.ListenPort > 65535 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "监听端口必须在1-65535之间",
			})
			return
		}

		// 验证HTTP端口（如果启用了强制HTTPS）
		if req.ForceHTTPS {
			if req.HTTPListenPort < 1 || req.HTTPListenPort > 65535 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "HTTP监听端口必须在1-65535之间",
				})
				return
			}
			if req.HTTPListenPort == req.ListenPort {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "HTTP监听端口不能和主监听端口相同",
				})
				return
			}
		}

		if req.ListenPort == adminPort {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "端口 " + fmt.Sprintf("%d", req.ListenPort) + " 与管理服务端口冲突",
			})
			return
		}

		if req.ForceHTTPS && req.HTTPListenPort == adminPort {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "HTTP端口 " + fmt.Sprintf("%d", req.HTTPListenPort) + " 与管理服务端口冲突",
			})
			return
		}

		oldPort := instance.ListenPort
		oldWAFID := instance.WAFID
		oldBackend := instance.Backend
		oldFallbackBackend := instance.FallbackBackend
		oldName := instance.Name
		oldTLSEnabled := instance.TLSEnabled
		oldTLSCertFile := instance.TLSCertFile
		oldTLSKeyFile := instance.TLSKeyFile
		oldForceHTTPS := instance.ForceHTTPS
		oldHTTPListenPort := instance.HTTPListenPort

		targetURL, err := url.Parse(req.Backend)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的后端地址",
			})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("代理错误: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			http.ServeFile(w, r, "web/html/502.html")
		}

		var handler http.Handler = proxy
		
		if req.WAFID != "" {
			wafMutex.RLock()
			if wafInst, exists := wafInstances[req.WAFID]; exists {
				handler = &wafHandler{next: proxy, waf: wafInst.WAF, proxyID: instance.ID}
			}
			wafMutex.RUnlock()
		} else {
			handler = &ipCheckHandler{next: proxy, proxyID: instance.ID}
		}
		
		log.Printf("[更新代理] WAF绑定变化检测: oldWAFID=%s, req.WAFID=%s, 使用handler=%T", oldWAFID, req.WAFID, handler)

		if oldPort == req.ListenPort && oldWAFID == req.WAFID && req.Backend == oldBackend && req.Name == oldName && oldTLSEnabled == req.TLSEnabled && oldTLSCertFile == req.TLSCertFile && oldTLSKeyFile == req.TLSKeyFile && oldForceHTTPS == req.ForceHTTPS && oldHTTPListenPort == req.HTTPListenPort {
			log.Printf("更新代理服务器 %s: 无需重启", instance.Name)

			_, err = db.Exec("UPDATE proxy_instances SET name = ?, listen_port = ?, backend = ?, fallback_backend = ?, waf_id = ?, tls_enabled = ?, tls_cert_file = ?, tls_key_file = ?, force_https = ?, http_listen_port = ? WHERE id = ?",
				req.Name, req.ListenPort, req.Backend, req.FallbackBackend, req.WAFID, req.TLSEnabled, req.TLSCertFile, req.TLSKeyFile, req.ForceHTTPS, req.HTTPListenPort, id)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "更新失败",
				})
				return
			}

			instance.Name = req.Name
			instance.Backend = req.Backend
			instance.FallbackBackend = req.FallbackBackend
			instance.WAFID = req.WAFID
			instance.TLSEnabled = req.TLSEnabled
			instance.TLSCertFile = req.TLSCertFile
			instance.TLSKeyFile = req.TLSKeyFile
			instance.ForceHTTPS = req.ForceHTTPS
			instance.HTTPListenPort = req.HTTPListenPort
			instance.Proxy = proxy
			
			if req.WAFID != "" {
				wafMutex.RLock()
				if wafInst, exists := wafInstances[req.WAFID]; exists {
					instance.WAFName = wafInst.Name
				} else {
					instance.WAFName = ""
				}
				wafMutex.RUnlock()
			} else {
				instance.WAFName = ""
			}
		} else if oldPort == req.ListenPort && oldForceHTTPS == req.ForceHTTPS && oldHTTPListenPort == req.HTTPListenPort {
			if instance.Server != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				instance.Server.Shutdown(ctx)
				time.Sleep(600 * time.Millisecond)
			}

			_, err = db.Exec("UPDATE proxy_instances SET name = ?, listen_port = ?, backend = ?, fallback_backend = ?, waf_id = ?, tls_enabled = ?, tls_cert_file = ?, tls_key_file = ?, force_https = ?, http_listen_port = ? WHERE id = ?",
				req.Name, req.ListenPort, req.Backend, req.FallbackBackend, req.WAFID, req.TLSEnabled, req.TLSCertFile, req.TLSKeyFile, req.ForceHTTPS, req.HTTPListenPort, id)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "更新失败",
				})
				return
			}

			instance.Name = req.Name
			instance.Backend = req.Backend
			instance.FallbackBackend = req.FallbackBackend
			instance.WAFID = req.WAFID
			instance.TLSEnabled = req.TLSEnabled
			instance.TLSCertFile = req.TLSCertFile
			instance.TLSKeyFile = req.TLSKeyFile
			instance.ForceHTTPS = req.ForceHTTPS
			instance.HTTPListenPort = req.HTTPListenPort
			instance.Proxy = proxy
			
			if req.WAFID != "" {
				wafMutex.RLock()
				if wafInst, exists := wafInstances[req.WAFID]; exists {
					instance.WAFName = wafInst.Name
				} else {
					instance.WAFName = ""
				}
				wafMutex.RUnlock()
			} else {
				instance.WAFName = ""
			}

			instance.Server = &http.Server{
				Handler: handler,
			}

			var listener net.Listener
			if req.TLSEnabled && req.TLSCertFile != "" && req.TLSKeyFile != "" {
				tlsConfig, err := loadTLSConfig(req.TLSCertFile, req.TLSKeyFile)
				if err != nil {
					log.Printf("代理服务器 %s 加载TLS配置失败: %v", instance.Name, err)
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "加载TLS配置失败: " + err.Error(),
					})
					return
				}
				listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort), tlsConfig)
				if err != nil {
					log.Printf("代理服务器 %s TLS监听失败: %v", instance.Name, err)
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "TLS监听失败: " + err.Error(),
					})
					return
				}
				log.Printf("代理服务器 %s 启用HTTPS", instance.Name)
			} else {
				var err error
				listener, err = net.Listen("tcp", fmt.Sprintf(":%d", instance.ListenPort))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "端口 " + fmt.Sprintf("%d", instance.ListenPort) + " 已被占用",
					})
					return
				}
			}

			go func() {
				time.Sleep(500 * time.Millisecond)
				if err := instance.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
					log.Printf("代理服务器 %s 运行错误: %v", instance.Name, err)
				} else if err == http.ErrServerClosed {
					log.Printf("代理服务器 %s 已关闭", instance.Name)
				}
			}()

			// 处理 HTTP 重定向服务器
			if oldForceHTTPS != req.ForceHTTPS || oldHTTPListenPort != req.HTTPListenPort {
				// 停止旧的 HTTP 服务器
				if instance.HTTPServer != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					instance.HTTPServer.Shutdown(ctx)
					time.Sleep(600 * time.Millisecond)
				}

				// 如果启用了强制 HTTPS，启动新的 HTTP 重定向服务器
				if req.ForceHTTPS && req.HTTPListenPort > 0 && req.TLSEnabled {
					// 先测试HTTP端口是否可用
					testHTTPListener, err := net.Listen("tcp", fmt.Sprintf(":%d", req.HTTPListenPort))
					if err != nil {
						// 测试失败，返回错误
						w.WriteHeader(http.StatusInternalServerError)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"success": false,
							"error":   "HTTP端口 " + fmt.Sprintf("%d", req.HTTPListenPort) + " 已被占用",
						})
						return
					}
					testHTTPListener.Close()

					httpsPort := req.ListenPort
					redirectHandler := func(w http.ResponseWriter, r *http.Request) {
						host := r.Host
						if idx := strings.Index(host, ":"); idx != -1 {
							host = host[:idx]
						}
						targetURL := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.URL.RequestURI())
						http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
					}

					instance.HTTPServer = &http.Server{
						Addr:    fmt.Sprintf(":%d", req.HTTPListenPort),
						Handler: http.HandlerFunc(redirectHandler),
					}

					go func() {
						time.Sleep(500 * time.Millisecond)
						log.Printf("HTTP重定向服务器 %s 已启动在端口 %d -> HTTPS %d", instance.Name, req.HTTPListenPort, req.ListenPort)
						if err := instance.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
							log.Printf("HTTP重定向服务器 %s 运行错误: %v", instance.Name, err)
						} else if err == http.ErrServerClosed {
							log.Printf("HTTP重定向服务器 %s 已关闭", instance.Name)
						}
					}()
				}
			}

			log.Printf("更新代理服务器 %s: 端口 %d (未变化), TLS: %v", instance.Name, oldPort, req.TLSEnabled)
		} else {
			if instance.Server != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				instance.Server.Shutdown(ctx)
				time.Sleep(600 * time.Millisecond)
			}

			if instance.HTTPServer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				instance.HTTPServer.Shutdown(ctx)
				time.Sleep(600 * time.Millisecond)
			}

			var listener net.Listener
			if req.TLSEnabled && req.TLSCertFile != "" && req.TLSKeyFile != "" {
				tlsConfig, err := loadTLSConfig(req.TLSCertFile, req.TLSKeyFile)
				if err != nil {
					log.Printf("代理服务器 %s 加载TLS配置失败: %v", req.Name, err)
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "加载TLS配置失败: " + err.Error(),
					})
					return
				}
				listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", req.ListenPort), tlsConfig)
				if err != nil {
					log.Printf("代理服务器 %s TLS监听失败: %v", req.Name, err)
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "TLS监听失败: " + err.Error(),
					})
					return
				}
				log.Printf("代理服务器 %s 启用HTTPS", req.Name)
			} else {
				var err error
				listener, err = net.Listen("tcp", fmt.Sprintf(":%d", req.ListenPort))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "端口 " + fmt.Sprintf("%d", req.ListenPort) + " 已被占用",
					})
					return
				}
			}

			_, err = db.Exec("UPDATE proxy_instances SET name = ?, listen_port = ?, backend = ?, fallback_backend = ?, waf_id = ?, tls_enabled = ?, tls_cert_file = ?, tls_key_file = ?, force_https = ?, http_listen_port = ? WHERE id = ?",
				req.Name, req.ListenPort, req.Backend, req.FallbackBackend, req.WAFID, req.TLSEnabled, req.TLSCertFile, req.TLSKeyFile, req.ForceHTTPS, req.HTTPListenPort, id)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "更新失败",
				})
				return
			}

			instance.Name = req.Name
			instance.ListenPort = req.ListenPort
			instance.Backend = req.Backend
			instance.FallbackBackend = req.FallbackBackend
			instance.WAFID = req.WAFID
			instance.TLSEnabled = req.TLSEnabled
			instance.TLSCertFile = req.TLSCertFile
			instance.TLSKeyFile = req.TLSKeyFile
			instance.ForceHTTPS = req.ForceHTTPS
			instance.HTTPListenPort = req.HTTPListenPort
			instance.Proxy = proxy
			
			if req.WAFID != "" {
				wafMutex.RLock()
				if wafInst, exists := wafInstances[req.WAFID]; exists {
					instance.WAFName = wafInst.Name
				} else {
					instance.WAFName = ""
				}
				wafMutex.RUnlock()
			} else {
				instance.WAFName = ""
			}

			instance.Server = &http.Server{
				Handler: handler,
			}

			go func() {
				time.Sleep(500 * time.Millisecond)
				if err := instance.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
					log.Printf("代理服务器 %s 运行错误: %v", instance.Name, err)
				} else if err == http.ErrServerClosed {
					log.Printf("代理服务器 %s 已关闭", instance.Name)
				}
			}()

			// 如果启用了强制 HTTPS，启动 HTTP 重定向服务器
			if req.ForceHTTPS && req.HTTPListenPort > 0 && req.TLSEnabled {
				// 先测试HTTP端口是否可用
				testHTTPListener, err := net.Listen("tcp", fmt.Sprintf(":%d", req.HTTPListenPort))
				if err != nil {
					// 测试失败，先关闭已经启动的主服务器
					if instance.Server != nil {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						instance.Server.Shutdown(ctx)
					}
					// 然后回滚数据库
					db.Exec("UPDATE proxy_instances SET name = ?, listen_port = ?, backend = ?, fallback_backend = ?, waf_id = ?, tls_enabled = ?, tls_cert_file = ?, tls_key_file = ?, force_https = ?, http_listen_port = ? WHERE id = ?",
						oldName, oldPort, oldBackend, oldFallbackBackend, oldWAFID, oldTLSEnabled, oldTLSCertFile, oldTLSKeyFile, oldForceHTTPS, oldHTTPListenPort, id)
					instance.Name = oldName
					instance.ListenPort = oldPort
					instance.Backend = oldBackend
					instance.FallbackBackend = oldFallbackBackend
					instance.WAFID = oldWAFID
					instance.TLSEnabled = oldTLSEnabled
					instance.TLSCertFile = oldTLSCertFile
					instance.TLSKeyFile = oldTLSKeyFile
					instance.ForceHTTPS = oldForceHTTPS
					instance.HTTPListenPort = oldHTTPListenPort

					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "HTTP端口 " + fmt.Sprintf("%d", req.HTTPListenPort) + " 已被占用",
					})
					return
				}
				testHTTPListener.Close()

				httpsPort := req.ListenPort
				redirectHandler := func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
					if idx := strings.Index(host, ":"); idx != -1 {
						host = host[:idx]
					}
					targetURL := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.URL.RequestURI())
					http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
				}

				instance.HTTPServer = &http.Server{
					Addr:    fmt.Sprintf(":%d", req.HTTPListenPort),
					Handler: http.HandlerFunc(redirectHandler),
				}

				go func() {
					time.Sleep(500 * time.Millisecond)
					log.Printf("HTTP重定向服务器 %s 已启动在端口 %d -> HTTPS %d", instance.Name, req.HTTPListenPort, req.ListenPort)
					if err := instance.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						log.Printf("HTTP重定向服务器 %s 运行错误: %v", instance.Name, err)
					} else if err == http.ErrServerClosed {
						log.Printf("HTTP重定向服务器 %s 已关闭", instance.Name)
					}
				}()
			}

			log.Printf("更新代理服务器 %s: 端口 %d -> %d, WAF: %s -> %s", instance.Name, oldPort, instance.ListenPort, oldWAFID, instance.WAFID)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"instance": instance,
		})
		return
	}

	if r.Method == "DELETE" {
		proxyMutex.RLock()
		instance, exists := proxyInstances[id]
		proxyMutex.RUnlock()

		if exists {
			if instance.Server != nil {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					instance.Server.Shutdown(ctx)
				}()
			}
			if instance.HTTPServer != nil {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					instance.HTTPServer.Shutdown(ctx)
				}()
			}
		}

		_, err := db.Exec("DELETE FROM proxy_instances WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除失败",
			})
			return
		}

		proxyMutex.Lock()
		delete(proxyInstances, id)
		proxyMutex.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func handleDomainRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "POST" {
		var req struct {
			ProxyID     string `json:"proxyId"`
			Domain      string `json:"domain"`
			Backend     string `json:"backend"`
			IsDefault   bool   `json:"isDefault"`
			RuleType    string `json:"ruleType"`
			RedirectURL string `json:"redirectUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		if req.Domain == "" && !req.IsDefault {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "域名不能为空",
			})
			return
		}

		if req.RuleType == "" {
			req.RuleType = "proxy"
		}

		id := fmt.Sprintf("dr-%d", time.Now().UnixNano())
		createdAt := time.Now().Unix()

		isDefault := 0
		if req.IsDefault {
			isDefault = 1
			db.Exec("UPDATE proxy_domain_rules SET is_default = 0 WHERE proxy_id = ?", req.ProxyID)
		}

		_, err := db.Exec("INSERT INTO proxy_domain_rules (id, proxy_id, domain, backend, is_default, rule_type, redirect_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			id, req.ProxyID, req.Domain, req.Backend, isDefault, req.RuleType, req.RedirectURL, createdAt)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建失败: " + err.Error(),
			})
			return
		}

		proxyMutex.RLock()
		if inst, ok := proxyInstances[req.ProxyID]; ok {
			inst.DomainRules = loadDomainRules(req.ProxyID)
		}
		proxyMutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"rule": DomainRule{
				ID:          id,
				ProxyID:     req.ProxyID,
				Domain:      req.Domain,
				Backend:     req.Backend,
				IsDefault:   req.IsDefault,
				RuleType:    req.RuleType,
				RedirectURL: req.RedirectURL,
				CreatedAt:   fmt.Sprintf("%d", createdAt),
			},
		})
		return
	}

	if r.Method == "PUT" {
		var req struct {
			ID          string `json:"id"`
			Domain      string `json:"domain"`
			Backend     string `json:"backend"`
			IsDefault   bool   `json:"isDefault"`
			RuleType    string `json:"ruleType"`
			RedirectURL string `json:"redirectUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}
		log.Printf("[域名规则] 收到更新请求: id=%s, domain=%s, backend=%s, isDefault=%v, ruleType=%s, redirectUrl=%s", req.ID, req.Domain, req.Backend, req.IsDefault, req.RuleType, req.RedirectURL)

		var proxyID string
		err := db.QueryRow("SELECT proxy_id FROM proxy_domain_rules WHERE id = ?", req.ID).Scan(&proxyID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "规则不存在",
			})
			return
		}

		if req.Domain == "" && !req.IsDefault {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "域名不能为空",
			})
			return
		}

		if req.RuleType == "" {
			req.RuleType = "proxy"
		}

		isDefault := 0
		if req.IsDefault {
			isDefault = 1
			db.Exec("UPDATE proxy_domain_rules SET is_default = 0 WHERE proxy_id = ?", proxyID)
		}

		_, err = db.Exec("UPDATE proxy_domain_rules SET domain = ?, backend = ?, is_default = ?, rule_type = ?, redirect_url = ? WHERE id = ?",
			req.Domain, req.Backend, isDefault, req.RuleType, req.RedirectURL, req.ID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "更新失败: " + err.Error(),
			})
			return
		}

		proxyMutex.RLock()
		if inst, ok := proxyInstances[proxyID]; ok {
			inst.DomainRules = loadDomainRules(proxyID)
			log.Printf("[域名规则] 已更新内存中的规则，当前规则数: %d", len(inst.DomainRules))
			for i, r := range inst.DomainRules {
				log.Printf("[域名规则]   规则[%d]: id=%s, domain=%s, isDefault=%v, ruleType=%s", i, r.ID, r.Domain, r.IsDefault, r.RuleType)
			}
		} else {
			log.Printf("[域名规则] 警告: 找不到 proxyID=%s 的代理实例", proxyID)
		}
		proxyMutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	proxyMutex.RLock()
	var allRules []DomainRule
	for _, inst := range proxyInstances {
		for _, rule := range inst.DomainRules {
			allRules = append(allRules, *rule)
		}
	}
	proxyMutex.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rules":  allRules,
	})
}

func handleDomainRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := strings.TrimPrefix(r.URL.Path, "/api/domain-rules/")

	if r.Method == "GET" {
		var rule DomainRule
		var isDefault int
		var ruleType, redirectURL sql.NullString
		err := db.QueryRow("SELECT id, proxy_id, domain, backend, is_default, rule_type, redirect_url, created_at FROM proxy_domain_rules WHERE id = ?", id).Scan(
			&rule.ID, &rule.ProxyID, &rule.Domain, &rule.Backend, &isDefault, &ruleType, &redirectURL, &rule.CreatedAt)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "规则不存在",
			})
			return
		}
		rule.IsDefault = isDefault == 1
		if ruleType.Valid {
			rule.RuleType = ruleType.String
		} else {
			rule.RuleType = "proxy"
		}
		if redirectURL.Valid {
			rule.RedirectURL = redirectURL.String
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"rule":    rule,
		})
		return
	}

	if r.Method == "DELETE" {
		var proxyID string
		err := db.QueryRow("SELECT proxy_id FROM proxy_domain_rules WHERE id = ?", id).Scan(&proxyID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "规则不存在",
			})
			return
		}

		_, err = db.Exec("DELETE FROM proxy_domain_rules WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除失败: " + err.Error(),
			})
			return
		}

		proxyMutex.RLock()
		if inst, ok := proxyInstances[proxyID]; ok {
			inst.DomainRules = loadDomainRules(proxyID)
		}
		proxyMutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func handlePortForwardInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "POST" {
		var req struct {
			Name          string `json:"name"`
			Protocol      string `json:"protocol"`
			ListenPort    int    `json:"listenPort"`
			TargetAddress string `json:"targetAddress"`
			TargetPort    int    `json:"targetPort"`
			IPMode        string `json:"ipMode"`
			ActionMode    string `json:"actionMode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		if req.Protocol != "tcp" && req.Protocol != "udp" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "协议必须是tcp或udp",
			})
			return
		}

		instance, err := createPortForwardInstance(req.Name, req.Protocol, req.ListenPort, req.TargetAddress, req.TargetPort, req.IPMode, req.ActionMode)
		if err != nil {
			log.Printf("创建端口转发失败: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建端口转发失败: " + err.Error(),
			})
			return
		}

		log.Printf("创建端口转发成功: %s", instance.ID)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"instance": instance,
		})
	} else {
		portForwardMutex.RLock()
		instances := make([]*PortForwardInstance, 0, len(portForwardInstances))
		for _, inst := range portForwardInstances {
			instanceCopy := *inst
			instances = append(instances, &instanceCopy)
		}
		portForwardMutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    instances,
		})
	}
}

func handlePortForwardInstance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	id := strings.TrimPrefix(r.URL.Path, "/api/port-forward-instances/")

	if r.Method == "PUT" {
		var req struct {
			Name          string `json:"name"`
			Protocol      string `json:"protocol"`
			ListenPort    int    `json:"listenPort"`
			TargetAddress string `json:"targetAddress"`
			TargetPort    int    `json:"targetPort"`
			IPMode        string `json:"ipMode"`
			ActionMode    string `json:"actionMode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		portForwardMutex.RLock()
		instance, exists := portForwardInstances[id]
		portForwardMutex.RUnlock()

		if !exists {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "端口转发实例不存在",
			})
			return
		}

		// 验证监听端口
		if req.ListenPort < 1 || req.ListenPort > 65535 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "监听端口必须在1-65535之间",
			})
			return
		}

		// 验证目标端口
		if req.TargetPort < 1 || req.TargetPort > 65535 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "目标端口必须在1-65535之间",
			})
			return
		}

		if req.ListenPort == adminPort {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "端口 " + fmt.Sprintf("%d", req.ListenPort) + " 与管理服务端口冲突",
			})
			return
		}

		proxyMutex.RLock()
		for _, inst := range proxyInstances {
			if inst.ListenPort == req.ListenPort && inst.ID != id {
				proxyMutex.RUnlock()
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "端口 " + fmt.Sprintf("%d", req.ListenPort) + " 已被防护应用占用",
				})
				return
			}
		}
		proxyMutex.RUnlock()

		portForwardMutex.RLock()
		for _, inst := range portForwardInstances {
			if inst.ListenPort == req.ListenPort && inst.ID != id {
				portForwardMutex.RUnlock()
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "端口 " + fmt.Sprintf("%d", req.ListenPort) + " 已被端口转发占用",
				})
				return
			}
		}
		portForwardMutex.RUnlock()

		oldProtocol := instance.Protocol
		oldPort := instance.ListenPort
		oldTargetAddress := instance.TargetAddress
		oldTargetPort := instance.TargetPort
		oldIPMode := instance.IPMode
		oldActionMode := instance.ActionMode

		instance.Name = req.Name
		instance.Protocol = req.Protocol
		instance.ListenPort = req.ListenPort
		instance.TargetAddress = req.TargetAddress
		instance.TargetPort = req.TargetPort
		instance.IPMode = req.IPMode
		instance.ActionMode = req.ActionMode

		_, err := db.Exec("UPDATE port_forward_instances SET name = ?, protocol = ?, listen_port = ?, target_address = ?, target_port = ?, ip_mode = ?, action_mode = ? WHERE id = ?", 
			req.Name, req.Protocol, req.ListenPort, req.TargetAddress, req.TargetPort, req.IPMode, req.ActionMode, id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "更新失败",
			})
			return
		}

		if oldProtocol == req.Protocol && oldPort == req.ListenPort && oldTargetAddress == req.TargetAddress && oldTargetPort == req.TargetPort && oldIPMode == req.IPMode && oldActionMode == req.ActionMode {
			log.Printf("更新端口转发 %s: 无需重启", instance.Name)
		} else {
			if instance.StopFunc != nil {
				instance.StopFunc()
				time.Sleep(500 * time.Millisecond)
			}
			go startPortForward(instance)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"instance": instance,
		})
		return
	}

	if r.Method == "DELETE" {
		portForwardMutex.RLock()
		instance, exists := portForwardInstances[id]
		portForwardMutex.RUnlock()

		if exists {
			instance.Status = "stopped"
			if instance.StopFunc != nil {
				instance.StopFunc()
			}
		}

		_, err := db.Exec("DELETE FROM port_forward_instances WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除失败",
			})
			return
		}

		portForwardMutex.Lock()
		delete(portForwardInstances, id)
		portForwardMutex.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func handleAvailableRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	rules, err := loadAvailableRules()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "加载规则失败: " + err.Error(),
		})
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rules":   rules,
	})
}

func loadAvailableRules() ([]RuleInfo, error) {
	var rules []RuleInfo
	
	entries, err := os.ReadDir("coreruleset/rules")
	if err != nil {
		return nil, err
	}
	
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		
		ruleInfo := getRuleInfoFromFileName(entry.Name())
		if ruleInfo != nil {
			rules = append(rules, *ruleInfo)
		}
	}
	
	return rules, nil
}

func getRuleInfoFromFileName(fileName string) *RuleInfo {
	re := regexp.MustCompile(`\d{3}`)
	matches := re.FindStringSubmatch(fileName)
	
	if len(matches) == 0 {
		return nil
	}
	
	ruleID := matches[0]
	chineseName := ruleNameMap[ruleID]
	if chineseName == "" {
		chineseName = "未知规则"
	}
	
	return &RuleInfo{
		Code:        fileName,
		ID:          ruleID,
		Name:        chineseName,
		Description: "",
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "DELETE" {
		search := r.URL.Query().Get("search")
		logsMutex.Lock()
		defer logsMutex.Unlock()

		if search != "" {
			searchPattern := "%" + search + "%"
			result, err := db.Exec("DELETE FROM attack_logs WHERE url LIKE ? OR ip LIKE ? OR attack_type LIKE ? OR rules LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ?", searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
			if err != nil {
				log.Printf("删除搜索结果失败: %v", err)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "删除日志失败",
				})
				return
			}
			affected, _ := result.RowsAffected()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"deleted": affected,
			})
			return
		}

		attackLogs = []AttackLog{}

		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)

		_, err := db.Exec("DELETE FROM attack_logs")
		if err != nil {
			log.Printf("清空攻击日志失败: %v", err)
		}

		_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		if err != nil {
			log.Printf("wal_checkpoint(TRUNCATE)失败: %v", err)
		}

		_, err = db.Exec("VACUUM")
		if err != nil {
			log.Printf("VACUUM失败: %v", err)
		}

		db.SetMaxOpenConns(0)
		db.SetMaxIdleConns(2)

		closeDB()
		if err := initDB(); err != nil {
			log.Printf("重新连接数据库失败: %v", err)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		return
	}
	
	filter := r.URL.Query().Get("filter")
	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")
	search := r.URL.Query().Get("search")
	
	page := 1
	pageSize := 20
	
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	
	if pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}
	
	offset := (page - 1) * pageSize

	var countQuery string
	var dataQuery string
	var args []interface{}

	searchClause := ""
	searchPattern := ""
	if search != "" {
		searchPattern = "%" + search + "%"
		searchClause = " AND (url LIKE ? OR ip LIKE ? OR attack_type LIKE ? OR rules LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ?)"
	}

	if filter == "normal" {
		countQuery = "SELECT COUNT(*) FROM attack_logs WHERE action = 'normal'" + searchClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'normal'" + searchClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
		if search != "" {
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
	} else if filter == "normal-green" {
		countQuery = "SELECT COUNT(*) FROM attack_logs WHERE action = 'normal' AND filter_type IN ('whitelist_match', 'blacklist_no_match', 'whitelist_empty', 'blacklist_empty', 'normal')" + searchClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'normal' AND filter_type IN ('whitelist_match', 'blacklist_no_match', 'whitelist_empty', 'blacklist_empty', 'normal')" + searchClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
		if search != "" {
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
	} else if filter == "normal-yellow" {
		countQuery = "SELECT COUNT(*) FROM attack_logs WHERE action = 'normal' AND filter_type IN ('whitelist_no_match', 'blacklist_match')" + searchClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'normal' AND filter_type IN ('whitelist_no_match', 'blacklist_match')" + searchClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
		if search != "" {
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
	} else if filter == "detected" {
		countQuery = "SELECT COUNT(*) FROM attack_logs WHERE action = 'detected'" + searchClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'detected'" + searchClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
		if search != "" {
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
	} else if filter == "blocked" {
		countQuery = "SELECT COUNT(*) FROM attack_logs WHERE action = 'blocked'" + searchClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action = 'blocked'" + searchClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
		if search != "" {
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
	} else if filter == "attack" {
		countQuery = "SELECT COUNT(*) FROM attack_logs WHERE action != 'normal'" + searchClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs WHERE action != 'normal'" + searchClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
		if search != "" {
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
	} else {
		var whereClause string
		if search != "" {
			whereClause = " WHERE (url LIKE ? OR ip LIKE ? OR attack_type LIKE ? OR rules LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ?)"
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}
		countQuery = "SELECT COUNT(*) FROM attack_logs" + whereClause
		dataQuery = "SELECT id, action, url, attack_type, ip, time, rules, method, proxy_id, status_code, country, province, city, latitude, longitude, filter_type FROM attack_logs" + whereClause + " ORDER BY time DESC LIMIT ? OFFSET ?"
	}
	
	var total int
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "查询日志总数失败",
		})
		return
	}

	args = append(args, pageSize, offset)
	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "查询日志失败",
		})
		return
	}
	defer rows.Close()
	
	logs := make([]AttackLog, 0)
	for rows.Next() {
		var entry AttackLog
		var attackType sql.NullString
		var proxyID sql.NullString
		var country sql.NullString
		var province sql.NullString
		var city sql.NullString
		var latitude sql.NullFloat64
		var longitude sql.NullFloat64
		var filterType sql.NullString
		
		err := rows.Scan(&entry.ID, &entry.Action, &entry.URL, &attackType, &entry.IP, &entry.Time, &entry.Rules, &entry.Method, &proxyID, &entry.StatusCode, &country, &province, &city, &latitude, &longitude, &filterType)
		if err != nil {
			log.Printf("扫描记录失败: %v", err)
			continue
		}
		
		if attackType.Valid {
			entry.AttackType = attackType.String
		}
		if proxyID.Valid {
			entry.ProxyID = proxyID.String
		}
		if country.Valid {
			entry.Country = country.String
		}
		if province.Valid {
			entry.Province = province.String
		}
		if city.Valid {
			entry.City = city.String
		}
		if latitude.Valid {
			entry.Latitude = latitude.Float64
		}
		if longitude.Valid {
			entry.Longitude = longitude.Float64
		}
		if filterType.Valid {
			entry.FilterType = filterType.String
		}
		
		if entry.Rules != "" && entry.Rules != "无" {
			entry.Rules = translateAndDeduplicateRules(entry.Rules)
		}
		
		logs = append(logs, entry)
	}
	
	totalPages := (total + pageSize - 1) / pageSize
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"data":       logs,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
	})
}

func handleStatistics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	statsMutex.RLock()
	defer statsMutex.RUnlock()
	
	attackIPs := 0
	countryStats := make(map[string]int)
	provinceStats := make(map[string]int)
	accessCountryStats := make(map[string]int)
	accessProvinceStats := make(map[string]int)
	detectedCountryStats := make(map[string]int)
	detectedProvinceStats := make(map[string]int)
	blockedCountryStats := make(map[string]int)
	blockedProvinceStats := make(map[string]int)
	
	rows, err := db.Query("SELECT ip, country, province, action FROM attack_logs")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "查询攻击IP失败",
		})
		return
	}
	defer rows.Close()
	
	for rows.Next() {
		var ip, country, province, action string
		rows.Scan(&ip, &country, &province, &action)
		
		if country != "" {
			accessCountryStats[country]++
		}
		if country == "中国" && province != "" {
			accessProvinceStats[province]++
		}
		
		if action != "normal" {
			attackIPs++
			countryStats[country]++
			if country == "中国" && province != "" {
				provinceStats[province]++
			}
		}
		
		if action == "detected" {
			if country != "" {
				detectedCountryStats[country]++
			}
			if country == "中国" && province != "" {
				detectedProvinceStats[province]++
			}
		}
		
		if action == "blocked" {
			if country != "" {
				blockedCountryStats[country]++
			}
			if country == "中国" && province != "" {
				blockedProvinceStats[province]++
			}
		}
	}
	
	ipAccessRows, err := db.Query("SELECT ip, country, province, mode, action, result FROM ip_access_logs WHERE result != 'pass'")
	if err == nil {
		defer ipAccessRows.Close()
		for ipAccessRows.Next() {
			var ip, country, province, mode, action, result string
			ipAccessRows.Scan(&ip, &country, &province, &mode, &action, &result)
			
			if country != "" {
				accessCountryStats[country]++
			}
			if country == "中国" && province != "" {
				accessProvinceStats[province]++
			}
			
			attackIPs++
			countryStats[country]++
			if country == "中国" && province != "" {
				provinceStats[province]++
			}
			
			if result == "observe" {
				if country != "" {
					detectedCountryStats[country]++
				}
				if country == "中国" && province != "" {
					detectedProvinceStats[province]++
				}
			}
			
			if result == "block" {
				if country != "" {
					blockedCountryStats[country]++
				}
				if country == "中国" && province != "" {
					blockedProvinceStats[province]++
				}
			}
		}
	}
	
	uniqueIPs := make(map[string]bool)
	rows, err = db.Query("SELECT DISTINCT ip FROM attack_logs")
	if err == nil {
		for rows.Next() {
			var ip string
			rows.Scan(&ip)
			uniqueIPs[ip] = true
		}
		rows.Close()
	}
	
	ipAccessRows, err = db.Query("SELECT DISTINCT ip FROM ip_access_logs WHERE result != 'pass'")
	if err == nil {
		defer ipAccessRows.Close()
		for ipAccessRows.Next() {
			var ip string
			ipAccessRows.Scan(&ip)
			uniqueIPs[ip] = true
		}
	}
	
	stats := currentStats
	stats.UniqueIP = len(uniqueIPs)
	stats.AttackIP = attackIPs
	stats.GeoDistribution = countryStats
	stats.ProvinceDistribution = provinceStats
	stats.AccessGeoDistribution = accessCountryStats
	stats.AccessProvinceDistribution = accessProvinceStats
	stats.DetectedGeoDistribution = detectedCountryStats
	stats.DetectedProvinceDistribution = detectedProvinceStats
	stats.BlockedGeoDistribution = blockedCountryStats
	stats.BlockedProvinceDistribution = blockedProvinceStats
	
	if stats.QPS > 0 {
		stats.AvgResponseTime = 1000 / int64(stats.QPS)
	} else {
		stats.AvgResponseTime = 0
	}

	json.NewEncoder(w).Encode(stats)
}

func handleStatisticsHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	statsMutex.RLock()
	defer statsMutex.RUnlock()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"qpsHistory":     qpsHistory,
		"attackHistory":  attackHistory,
		"trafficHistory": trafficHistory,
		"trafficStats":   trafficStats,
	})
}

type TopStatsItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func handleClientStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// 获取limit参数，默认5
	limit := 5
	if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
		if parsedLimit, err := strconv.Atoi(limitParam); err == nil {
			limit = parsedLimit
		}
	}
	
	platformStats := make(map[string]int)
	browserStats := make(map[string]int)
	
	rows, err := db.Query("SELECT platform, browser FROM attack_logs WHERE platform IS NOT NULL AND browser IS NOT NULL")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "查询客户端统计失败",
		})
		return
	}
	defer rows.Close()
	
	for rows.Next() {
		var platform, browser string
		rows.Scan(&platform, &browser)
		
		if platform != "" && platform != "Unknown" {
			platformStats[platform]++
		}
		if browser != "" && browser != "Unknown" {
			browserStats[browser]++
		}
	}
	
	platformList := make([]TopStatsItem, 0, len(platformStats))
	for name, count := range platformStats {
		platformList = append(platformList, TopStatsItem{Name: name, Count: count})
	}
	
	sort.Slice(platformList, func(i, j int) bool {
		return platformList[i].Count > platformList[j].Count
	})
	
	if limit > 0 && len(platformList) > limit {
		platformList = platformList[:limit]
	}
	
	browserList := make([]TopStatsItem, 0, len(browserStats))
	for name, count := range browserStats {
		browserList = append(browserList, TopStatsItem{Name: name, Count: count})
	}
	
	sort.Slice(browserList, func(i, j int) bool {
		return browserList[i].Count > browserList[j].Count
	})
	
	if limit > 0 && len(browserList) > limit {
		browserList = browserList[:limit]
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"platforms": platformList,
		"browsers": browserList,
	})
}

type IPWhitelistEntry struct {
	ID          int    `json:"id"`
	IP          string `json:"ip"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

type IPBlacklistEntry struct {
	ID          int    `json:"id"`
	IP          string `json:"ip"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

func handleIPWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "GET" {
		rows, err := db.Query("SELECT id, ip, description, created_at FROM ip_whitelist ORDER BY id DESC")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "查询白名单失败",
			})
			return
		}
		defer rows.Close()
		
		entries := make([]IPWhitelistEntry, 0)
		for rows.Next() {
			var entry IPWhitelistEntry
			err := rows.Scan(&entry.ID, &entry.IP, &entry.Description, &entry.CreatedAt)
			if err != nil {
				continue
			}
			entries = append(entries, entry)
		}
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    entries,
		})
	} else if r.Method == "POST" {
		if strings.Contains(r.URL.Path, "/batch") {
			var req struct {
				IPs []string `json:"ips"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "请求参数错误",
				})
				return
			}
			
			tx, err := db.Begin()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "开始事务失败",
				})
				return
			}
			
			_, err = tx.Exec("DELETE FROM ip_whitelist")
			if err != nil {
				tx.Rollback()
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "清空白名单失败",
				})
				return
			}
			
			if len(req.IPs) > 0 {
				utcTime := getUTCTime()
				stmt, err := tx.Prepare("INSERT INTO ip_whitelist (ip, description, created_at) VALUES (?, ?, ?)")
				if err != nil {
					tx.Rollback()
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "准备语句失败",
					})
					return
				}
				defer stmt.Close()
				
				for _, ip := range req.IPs {
					_, err = stmt.Exec(ip, "", utcTime)
					if err != nil {
						tx.Rollback()
						w.WriteHeader(http.StatusInternalServerError)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"success": false,
							"error":   fmt.Sprintf("添加IP %s失败", ip),
						})
						return
					}
				}
			}
			
			err = tx.Commit()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "提交事务失败",
				})
				return
			}
			
			go refreshIPCache()
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
			})
		} else {
			var req struct {
				IP          string `json:"ip"`
				Description string `json:"description"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "请求参数错误",
				})
				return
			}
			
			if req.IP == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "IP地址不能为空",
				})
				return
			}
			
			_, err = db.Exec("INSERT INTO ip_whitelist (ip, description, created_at) VALUES (?, ?, ?)", req.IP, req.Description, getUTCTime())
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "添加白名单失败",
				})
				return
			}
			
			go refreshIPCache()
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
			})
		}
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "ID不能为空",
			})
			return
		}
		
		_, err := db.Exec("DELETE FROM ip_whitelist WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除白名单失败",
			})
			return
		}
		
		go refreshIPCache()
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}

func handleIPAccessLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "GET" {
		page := r.URL.Query().Get("page")
		pageSize := r.URL.Query().Get("pageSize")
		modeFilter := r.URL.Query().Get("mode")
		resultFilter := r.URL.Query().Get("result")
		ipFilter := r.URL.Query().Get("ip")
		search := r.URL.Query().Get("search")
		
		pageNum := 1
		pageSizeNum := 20
		
		if page != "" {
			num, err := strconv.Atoi(page)
			if err == nil && num > 0 {
				pageNum = num
			}
		}
		
		if pageSize != "" {
			num, err := strconv.Atoi(pageSize)
			if err == nil && num > 0 && num <= 100 {
				pageSizeNum = num
			}
		}
		
		offset := (pageNum - 1) * pageSizeNum
		
		var whereClause string
		var args []interface{}
		
		if modeFilter != "" {
			whereClause = " WHERE mode = ?"
			args = append(args, modeFilter)
		}
		
		if resultFilter != "" {
			if whereClause != "" {
				whereClause += " AND result = ?"
			} else {
				whereClause = " WHERE result = ?"
			}
			args = append(args, resultFilter)
		}
		
		if ipFilter != "" {
			if whereClause != "" {
				whereClause += " AND ip = ?"
			} else {
				whereClause = " WHERE ip = ?"
			}
			args = append(args, ipFilter)
		}

		if search != "" {
			if whereClause != "" {
				whereClause += " AND (url LIKE ? OR ip LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ? OR instance_name LIKE ?)"
			} else {
				whereClause = " WHERE (url LIKE ? OR ip LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ? OR instance_name LIKE ?)"
			}
			searchPattern := "%" + search + "%"
			args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
		}

		countQuery := "SELECT COUNT(*) FROM ip_access_logs" + whereClause
		var total int
		err := db.QueryRow(countQuery, args...).Scan(&total)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "查询日志总数失败",
			})
			return
		}
		
		query := "SELECT id, ip, mode, action, result, url, country, province, city, latitude, longitude, forward_type, instance_name, forward_info, created_at FROM ip_access_logs" + whereClause + " ORDER BY id DESC LIMIT ? OFFSET ?"
		args = append(args, pageSizeNum, offset)
		
		rows, err := db.Query(query, args...)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "查询日志失败",
			})
			return
		}
		defer rows.Close()
		
		type IPAccessLogEntry struct {
			ID          int     `json:"id"`
			IP          string  `json:"ip"`
			Mode        string  `json:"mode"`
			Action      string  `json:"action"`
			Result      string  `json:"result"`
			URL         string  `json:"url"`
			Country     string  `json:"country"`
			Province    string  `json:"province"`
			City        string  `json:"city"`
			Latitude    float64 `json:"latitude"`
			Longitude   float64 `json:"longitude"`
			ForwardType string  `json:"forward_type"`
			InstanceName string `json:"instance_name"`
			ForwardInfo string  `json:"forward_info"`
			CreatedAt   string  `json:"created_at"`
		}
		
		entries := make([]IPAccessLogEntry, 0)
		for rows.Next() {
			var entry IPAccessLogEntry
			var url sql.NullString
			var country sql.NullString
			var province sql.NullString
			var city sql.NullString
			var latitude sql.NullFloat64
			var longitude sql.NullFloat64
			var forwardType sql.NullString
			var instanceName sql.NullString
			var forwardInfo sql.NullString
			err := rows.Scan(&entry.ID, &entry.IP, &entry.Mode, &entry.Action, &entry.Result, &url, &country, &province, &city, &latitude, &longitude, &forwardType, &instanceName, &forwardInfo, &entry.CreatedAt)
			if err != nil {
				continue
			}
			if url.Valid {
				entry.URL = url.String
			}
			if country.Valid {
				entry.Country = country.String
			}
			if province.Valid {
				entry.Province = province.String
			}
			if city.Valid {
				entry.City = city.String
			}
			if latitude.Valid {
				entry.Latitude = latitude.Float64
			}
			if longitude.Valid {
				entry.Longitude = longitude.Float64
			}
			if forwardType.Valid {
				entry.ForwardType = forwardType.String
			}
			if instanceName.Valid {
				entry.InstanceName = instanceName.String
			}
			if forwardInfo.Valid {
				entry.ForwardInfo = forwardInfo.String
			}
			entries = append(entries, entry)
		}
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"data":     entries,
			"total":    total,
			"page":     pageNum,
			"pageSize": pageSizeNum,
		})
	} else if r.Method == "DELETE" {
		search := r.URL.Query().Get("search")
		logsMutex.Lock()
		defer logsMutex.Unlock()

		if search != "" {
			searchPattern := "%" + search + "%"
			result, err := db.Exec("DELETE FROM ip_access_logs WHERE url LIKE ? OR ip LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ? OR instance_name LIKE ?", searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
			if err != nil {
				log.Printf("删除IP访问日志搜索结果失败: %v", err)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "删除日志失败",
				})
				return
			}
			affected, _ := result.RowsAffected()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"deleted": affected,
			})
			return
		}

		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)

		_, err := db.Exec("DELETE FROM ip_access_logs")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "清空日志失败",
			})
			return
		}

		_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		if err != nil {
			log.Printf("wal_checkpoint(TRUNCATE)失败: %v", err)
		}

		_, err = db.Exec("VACUUM")
		if err != nil {
			log.Printf("VACUUM失败: %v", err)
		}

		db.SetMaxOpenConns(0)
		db.SetMaxIdleConns(2)

		closeDB()
		if err := initDB(); err != nil {
			log.Printf("重新连接数据库失败: %v", err)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}

func handleIPAccessLogsReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	startDate := r.URL.Query().Get("start")
	endDate := r.URL.Query().Get("end")

	if startDate == "" || endDate == "" {
		now := time.Now()
		startDate = now.Format("2006-01-02")
		endDate = now.Format("2006-01-02")
	}

	type DailyStat struct {
		Date   string `json:"date"`
		Normal int    `json:"normal"`
		Attack int    `json:"attack"`
	}

	type AttackTypeStat struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}

	type GeoStat struct {
		Location string `json:"location"`
		Count    int    `json:"count"`
	}

	type HourlyStat struct {
		Hour  int `json:"hour"`
		Count int `json:"count"`
	}

	type TopIP struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}

	var totalRequests, normalTraffic, attackTraffic, observeTraffic, abnormalIPs int

	err := db.QueryRow(`
		SELECT 
			COALESCE(SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END), 0) as normal_traffic,
			COALESCE(SUM(CASE WHEN result = 'block' THEN 1 ELSE 0 END), 0) as attack_traffic,
			COALESCE(SUM(CASE WHEN result = 'observe' THEN 1 ELSE 0 END), 0) as observe_traffic,
			COALESCE(COUNT(DISTINCT CASE WHEN result != 'pass' THEN ip END), 0) as abnormal_ips
		FROM ip_access_logs 
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ?
	`, startDate, endDate).Scan(&normalTraffic, &attackTraffic, &observeTraffic, &abnormalIPs)

	if err != nil {
		log.Printf("查询报表统计数据失败: %v", err)
	}

	totalRequests = normalTraffic + attackTraffic + observeTraffic

	dailyRows, err := db.Query(`
		SELECT 
			DATE(datetime(created_at, 'unixepoch', '+8 hours')) as date,
			COALESCE(SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END), 0) as normal,
			COALESCE(SUM(CASE WHEN result = 'block' THEN 1 ELSE 0 END), 0) as attack
		FROM ip_access_logs 
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ?
		GROUP BY DATE(datetime(created_at, 'unixepoch', '+8 hours'))
		ORDER BY date
	`, startDate, endDate)
	
	dailyStats := make([]DailyStat, 0)
	if dailyRows != nil {
		for dailyRows.Next() {
			var stat DailyStat
			dailyRows.Scan(&stat.Date, &stat.Normal, &stat.Attack)
			dailyStats = append(dailyStats, stat)
		}
		dailyRows.Close()
	}

	attackTypeRows, err := db.Query(`
		SELECT 
			COALESCE(action, 'unknown') as type,
			COUNT(*) as count
		FROM ip_access_logs 
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ? AND result = 'block'
		GROUP BY action
		ORDER BY count DESC
		LIMIT 10
	`, startDate, endDate)

	attackTypeStats := make([]AttackTypeStat, 0)
	if attackTypeRows != nil {
		for attackTypeRows.Next() {
			var stat AttackTypeStat
			attackTypeRows.Scan(&stat.Type, &stat.Count)
			attackTypeStats = append(attackTypeStats, stat)
		}
		attackTypeRows.Close()
	}

	geoRows, err := db.Query(`
		SELECT 
			COALESCE(country, '未知') || ' ' || COALESCE(province, '') || ' ' || COALESCE(city, '') as location,
			COUNT(*) as count
		FROM ip_access_logs 
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ?
		GROUP BY country, province, city
		ORDER BY count DESC
		LIMIT 10
	`, startDate, endDate)

	geoStats := make([]GeoStat, 0)
	if geoRows != nil {
		for geoRows.Next() {
			var stat GeoStat
			geoRows.Scan(&stat.Location, &stat.Count)
			stat.Location = strings.TrimSpace(stat.Location)
			geoStats = append(geoStats, stat)
		}
		geoRows.Close()
	}

	hourlyRows, err := db.Query(`
		SELECT 
			CAST(strftime('%H', datetime(created_at, 'unixepoch', '+8 hours')) AS INTEGER) as hour,
			COUNT(*) as count
		FROM ip_access_logs 
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ?
		GROUP BY hour
		ORDER BY hour
	`, startDate, endDate)

	hourlyStats := make([]HourlyStat, 0)
	hourlyMap := make(map[int]int)
	if hourlyRows != nil {
		for hourlyRows.Next() {
			var stat HourlyStat
			hourlyRows.Scan(&stat.Hour, &stat.Count)
			hourlyMap[stat.Hour] = stat.Count
		}
		hourlyRows.Close()
	}
	for i := 0; i < 24; i++ {
		hourlyStats = append(hourlyStats, HourlyStat{Hour: i, Count: hourlyMap[i]})
	}

	topAttackIPRows, err := db.Query(`
		SELECT ip, COUNT(*) as count
		FROM ip_access_logs
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ? AND result IN ('block', 'observe')
		GROUP BY ip
		ORDER BY count DESC
		LIMIT 10
	`, startDate, endDate)

	topAttackIPs := make([]TopIP, 0)
	if topAttackIPRows != nil {
		for topAttackIPRows.Next() {
			var ip TopIP
			topAttackIPRows.Scan(&ip.IP, &ip.Count)
			topAttackIPs = append(topAttackIPs, ip)
		}
		topAttackIPRows.Close()
	}

	topAbnormalIPRows, err := db.Query(`
		SELECT ip, COUNT(*) as count
		FROM ip_access_logs 
		WHERE DATE(datetime(created_at, 'unixepoch', '+8 hours')) >= ? AND DATE(datetime(created_at, 'unixepoch', '+8 hours')) <= ? AND result != 'pass'
		GROUP BY ip
		ORDER BY count DESC
		LIMIT 10
	`, startDate, endDate)

	topAbnormalIPs := make([]TopIP, 0)
	if topAbnormalIPRows != nil {
		for topAbnormalIPRows.Next() {
			var ip TopIP
			topAbnormalIPRows.Scan(&ip.IP, &ip.Count)
			topAbnormalIPs = append(topAbnormalIPs, ip)
		}
		topAbnormalIPRows.Close()
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"totalRequests":   totalRequests,
			"normalTraffic":  normalTraffic,
			"attackTraffic":  attackTraffic,
			"observeTraffic": observeTraffic,
			"abnormalIPs":    abnormalIPs,
			"dailyStats":     dailyStats,
			"attackTypeStats": attackTypeStats,
			"geoStats":       geoStats,
			"hourlyStats":    hourlyStats,
			"topAttackIPs":   topAttackIPs,
			"topAbnormalIPs": topAbnormalIPs,
		},
	})
}

func handleTrendData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	date := r.URL.Query().Get("date")
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}

	compareType := r.URL.Query().Get("compare")
	if compareType == "" {
		compareType = "prev-day"
	}

	var compareDate string
	if compareType == "prev-day" {
		d, _ := time.Parse("2006-01-02", date)
		compareDate = d.AddDate(0, 0, -1).Format("2006-01-02")
	} else {
		d, _ := time.Parse("2006-01-02", date)
		compareDate = d.AddDate(0, 0, -7).Format("2006-01-02")
	}

	type HourlyTrend struct {
		Hour           int `json:"hour"`
		AbnormalIPCount int `json:"abnormal_ip_count"`
		BlockCount     int `json:"block_count"`
		ObserveCount   int `json:"observe_count"`
	}

	getHourlyTrend := func(queryDate string) []HourlyTrend {
		rows, err := db.Query(`
			SELECT 
				CAST(strftime('%H', 
					CASE 
						WHEN typeof(created_at) = 'integer' THEN created_at 
						WHEN typeof(created_at) = 'text' THEN 
							CASE WHEN created_at GLOB '[0-9]*' THEN CAST(created_at AS INTEGER) 
							ELSE strftime('%s', created_at) END 
					END, 
					'unixepoch', 'localtime') AS INTEGER) as hour,
				COALESCE(COUNT(DISTINCT CASE WHEN result != 'pass' THEN ip END), 0) as abnormal_ip_count,
				COALESCE(SUM(CASE WHEN result = 'block' THEN 1 ELSE 0 END), 0) as block_count,
				COALESCE(SUM(CASE WHEN result = 'observe' THEN 1 ELSE 0 END), 0) as observe_count
			FROM ip_access_logs 
			WHERE DATE(
				CASE 
					WHEN typeof(created_at) = 'integer' THEN created_at 
					WHEN typeof(created_at) = 'text' THEN 
						CASE WHEN created_at GLOB '[0-9]*' THEN CAST(created_at AS INTEGER) 
						ELSE strftime('%s', created_at) END 
				END, 
				'unixepoch', 'localtime') = ?
			GROUP BY hour
			ORDER BY hour
		`, queryDate)

		if err != nil {
			log.Printf("查询趋势数据失败: %v", err)
			return make([]HourlyTrend, 0)
		}
		defer rows.Close()

		hourlyMap := make(map[int]HourlyTrend)
		for rows.Next() {
			var trend HourlyTrend
			rows.Scan(&trend.Hour, &trend.AbnormalIPCount, &trend.BlockCount, &trend.ObserveCount)
			hourlyMap[trend.Hour] = trend
		}

		result := make([]HourlyTrend, 24)
		for i := 0; i < 24; i++ {
			if t, ok := hourlyMap[i]; ok {
				result[i] = t
			} else {
				result[i] = HourlyTrend{Hour: i, AbnormalIPCount: 0, BlockCount: 0, ObserveCount: 0}
			}
		}
		return result
	}

	todayTrend := getHourlyTrend(date)
	compareTrend := getHourlyTrend(compareDate)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"date":         date,
			"compareDate":  compareDate,
			"compareType":  compareType,
			"todayTrend":   todayTrend,
			"compareTrend": compareTrend,
		},
	})
}

func handleSystemSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		var adminPortStr string
		err := db.QueryRow("SELECT value FROM system_settings WHERE key = ?", "admin_port").Scan(&adminPortStr)
		if err != nil {
			adminPortStr = "15501"
		}

		var githubMirror string
		err = db.QueryRow("SELECT value FROM system_settings WHERE key = ?", "github_mirror").Scan(&githubMirror)
		if err != nil {
			githubMirror = ""
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      true,
			"adminPort":    adminPortStr,
			"githubMirror": githubMirror,
		})
	} else if r.Method == "PUT" {
		var req struct {
			AdminPort    string `json:"adminPort"`
			GithubMirror string `json:"githubMirror"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		var err error
		if req.AdminPort != "" {
			newPort, atoiErr := strconv.Atoi(req.AdminPort)
			if atoiErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "端口格式错误",
				})
				return
			}
			err = atoiErr

			if newPort < 1024 || newPort > 65535 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "端口必须在1024-65535之间",
				})
				return
			}

			proxyMutex.RLock()
			for _, instance := range proxyInstances {
				if instance.ListenPort == newPort {
					proxyMutex.RUnlock()
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "端口 " + req.AdminPort + " 已被防护应用占用",
					})
					return
				}
			}
			proxyMutex.RUnlock()

			if isPortInUse(newPort) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "端口 " + req.AdminPort + " 已被其他程序占用",
				})
				return
			}

			_, err = db.Exec("UPDATE system_settings SET value = ?, updated_at = ? WHERE key = ?",
				req.AdminPort, getUTCTimestamp(), "admin_port")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "更新设置失败",
				})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "管理端口已更新，服务将在3秒后重启",
			})

			go func() {
				time.Sleep(3 * time.Second)
				log.Println("正在重启服务以应用新的管理端口...")
				restartProgram()
			}()
			return
		}

		if req.GithubMirror != "" {
			_, err = db.Exec("UPDATE system_settings SET value = ?, updated_at = ? WHERE key = ?",
				req.GithubMirror, getUTCTimestamp(), "github_mirror")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "更新设置失败",
				})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "设置已更新",
		})
	}
}

func isPortInUse(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	listener.Close()
	return false
}

type WebhookPayload struct {
	Event     string `json:"event"`
	Timestamp string `json:"timestamp"`
	Data      interface{} `json:"data"`
}

type WebhookAttackData struct {
	Action     string `json:"action"`
	URL        string `json:"url"`
	AttackType string `json:"attackType"`
	IP         string `json:"ip"`
	Rules      string `json:"rules"`
	Method     string `json:"method"`
	ProxyID    string `json:"proxyId"`
	StatusCode int    `json:"statusCode"`
	Country    string `json:"country"`
	Province   string `json:"province"`
	City       string `json:"city"`
}

type WebhookIPBlockedData struct {
	IP      string `json:"ip"`
	Mode    string `json:"mode"`
	Action  string `json:"action"`
	Result  string `json:"result"`
	URL     string `json:"url"`
	Country string `json:"country"`
	Province string `json:"province"`
	City    string `json:"city"`
}

func buildMarkdownMessage(event string, data interface{}) string {
	var content string

	switch d := data.(type) {
	case WebhookAttackData:
		emoji := "🚨"
		if d.Action == "test" {
			emoji = "🧪"
		}
		content = fmt.Sprintf(`%s **WAF攻击告警**

> **事件**: %s
> **攻击类型**: %s
> **IP地址**: %s
> **请求URL**: %s
> **请求方法**: %s
> **HTTP状态**: %d
> **规则ID**: %s
> **地理位置**: %s %s %s`, emoji, d.Action, d.AttackType, d.IP, d.URL, d.Method, d.StatusCode, d.Rules, d.Country, d.Province, d.City)

	case WebhookIPBlockedData:
		title := "🚫 **IP拦截通知**"
		if d.Result == "observe" {
			title = "👁️ **IP观察通知**"
		}
		
		modeCN := map[string]string{
			"whitelist-only":  "白名单模式",
			"blacklist-only": "黑名单模式",
			"normal":         "正常模式",
		}
		actionCN := map[string]string{
			"whitelist_match":     "白名单匹配",
			"whitelist_no_match": "白名单不匹配",
			"blacklist_match":    "黑名单匹配",
			"blacklist_no_match": "黑名单不匹配",
			"whitelist_empty":    "白名单为空",
			"blacklist_empty":   "黑名单为空",
			"normal_mode":       "正常模式",
		}
		
		modeText := modeCN[d.Mode]
		if modeText == "" {
			modeText = d.Mode
		}
		actionText := actionCN[d.Action]
		if actionText == "" {
			actionText = d.Action
		}
		
		content = fmt.Sprintf(`%s

> **IP地址**: %s
> **模式**: %s
> **原因**: %s
> **请求URL**: %s
> **地理位置**: %s %s %s`, title, d.IP, modeText, actionText, d.URL, d.Country, d.Province, d.City)

	default:
		content = fmt.Sprintf("📢 **Webhook通知**: %s", event)
	}

	return content
}

func getWebhookSettings() (enabled bool, url, secret, events string, timeout int, msgType string) {
	err := db.QueryRow("SELECT enabled, url, secret, events, timeout, COALESCE(msg_type, 'markdown') FROM webhook_settings ORDER BY id DESC LIMIT 1").Scan(&enabled, &url, &secret, &events, &timeout, &msgType)
	if err != nil {
		return false, "", "", "attack,ip_blocked", 5, "markdown"
	}
	return
}

func sendWebhook(event string, data interface{}) {
	enabled, url, secret, events, timeout, _ := getWebhookSettings()
	if !enabled || url == "" {
		log.Printf("Webhook未启用或URL为空，event=%s", event)
		return
	}

	log.Printf("Webhook配置检查: enabled=%v, url=%s, events=%s, event=%s", enabled, url, events, event)

	eventList := strings.Split(events, ",")
	eventFound := false
	for _, e := range eventList {
		if strings.TrimSpace(e) == event {
			eventFound = true
			break
		}
	}
	if !eventFound {
		log.Printf("Webhook事件 %s 未启用，跳过", event)
		return
	}

	log.Printf("Webhook触发事件: %s", event)

	content := buildMarkdownMessage(event, data)
	markdownPayload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": content,
		},
	}
	jsonData, err := json.Marshal(markdownPayload)
	if err != nil {
		log.Printf("Webhook Markdown序列化失败: %v", err)
		return
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Webhook请求创建失败: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(jsonData)
		signature := fmt.Sprintf("sha256=%x", mac.Sum(nil))
		req.Header.Set("X-Webhook-Signature", signature)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Webhook请求发送失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Webhook %s 发送成功", event)
	} else {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Webhook %s 发送失败: %d %s", event, resp.StatusCode, string(body))
	}
}

func handleWebhookSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		var enabled bool
		var url, secret, events, msgType string
		var timeout int
		err := db.QueryRow("SELECT enabled, url, secret, events, timeout, COALESCE(msg_type, 'markdown') FROM webhook_settings ORDER BY id DESC LIMIT 1").Scan(&enabled, &url, &secret, &events, &timeout, &msgType)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "获取webhook配置失败",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"enabled":  enabled,
				"url":      url,
				"secret":   secret,
				"events":   events,
				"timeout":  timeout,
				"msgType":  msgType,
			},
		})
	} else if r.Method == "PUT" {
		var req struct {
			Enabled  bool   `json:"enabled"`
			URL      string `json:"url"`
			Secret   string `json:"secret"`
			Events   string `json:"events"`
			Timeout  int    `json:"timeout"`
			MsgType  string `json:"msgType"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的请求",
			})
			return
		}

		if req.MsgType == "" {
			req.MsgType = "markdown"
		}

		if req.Enabled && req.URL == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "启用webhook时必须填写URL",
			})
			return
		}

		if req.Timeout < 1 || req.Timeout > 60 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "超时时间必须在1-60秒之间",
			})
			return
		}

		_, err := db.Exec("INSERT INTO webhook_settings (enabled, url, secret, events, timeout, msg_type, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			req.Enabled, req.URL, req.Secret, req.Events, req.Timeout, req.MsgType, getUTCTimestamp())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "保存webhook配置失败",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Webhook配置已保存",
		})
	} else if r.Method == "POST" {
		enabled, url, secret, _, timeout, _ := getWebhookSettings()
		if !enabled || url == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Webhook未启用或URL未配置",
			})
			return
		}

		testData := WebhookAttackData{
			Action:     "test",
			URL:        "http://example.com/test?param=<script>alert('xss')</script>",
			AttackType: "XSS Test Attack",
			IP:         "192.168.1.100",
			Rules:      "[{\"id\": 941310, \"message\": \"XSS Attack\"}]",
			Method:     "GET",
			ProxyID:    "test-proxy",
			StatusCode: 403,
			Country:   "CN",
			Province:  "Beijing",
			City:      "Beijing",
		}

		content := buildMarkdownMessage("test", testData)
		markdownPayload := map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"content": content,
			},
		}
		jsonData, err := json.Marshal(markdownPayload)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "序列化测试数据失败",
			})
			return
		}

		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "创建请求失败",
			})
			return
		}

		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(jsonData)
			signature := fmt.Sprintf("sha256=%x", mac.Sum(nil))
			req.Header.Set("X-Webhook-Signature", signature)
		}

		resp, err := client.Do(req)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "发送测试请求失败: " + err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "测试请求发送成功",
				"statusCode": resp.StatusCode,
				"responseBody": string(body),
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "测试请求失败",
				"statusCode": resp.StatusCode,
				"responseBody": string(body),
			})
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "不支持的请求方法",
		})
	}
}

func restartProgram() {
	executable, err := os.Executable()
	if err != nil {
		log.Printf("获取可执行文件路径失败: %v", err)
		os.Exit(1)
	}
	
	cmd := exec.Command(executable)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	
	err = cmd.Start()
	if err != nil {
		log.Printf("启动新进程失败: %v", err)
		os.Exit(1)
	}
	
	log.Printf("新进程已启动 (PID: %d)，退出当前进程", cmd.Process.Pid)
	os.Exit(0)
}

func handleIPBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "GET" {
		rows, err := db.Query("SELECT id, ip, description, created_at FROM ip_blacklist ORDER BY id DESC")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "查询黑名单失败",
			})
			return
		}
		defer rows.Close()
		
		entries := make([]IPBlacklistEntry, 0)
		for rows.Next() {
			var entry IPBlacklistEntry
			err := rows.Scan(&entry.ID, &entry.IP, &entry.Description, &entry.CreatedAt)
			if err != nil {
				continue
			}
			entries = append(entries, entry)
		}
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    entries,
		})
	} else if r.Method == "POST" {
		if strings.Contains(r.URL.Path, "/batch") {
			var req struct {
				IPs []string `json:"ips"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "请求参数错误",
				})
				return
			}
			
			tx, err := db.Begin()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "开始事务失败",
				})
				return
			}
			
			_, err = tx.Exec("DELETE FROM ip_blacklist")
			if err != nil {
				tx.Rollback()
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "清空黑名单失败",
				})
				return
			}
			
			if len(req.IPs) > 0 {
				utcTime := getUTCTime()
				stmt, err := tx.Prepare("INSERT INTO ip_blacklist (ip, description, created_at) VALUES (?, ?, ?)")
				if err != nil {
					tx.Rollback()
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": false,
						"error":   "准备语句失败",
					})
					return
				}
				defer stmt.Close()
				
				for _, ip := range req.IPs {
					_, err = stmt.Exec(ip, "", utcTime)
					if err != nil {
						tx.Rollback()
						w.WriteHeader(http.StatusInternalServerError)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"success": false,
							"error":   fmt.Sprintf("添加IP %s失败", ip),
						})
						return
					}
				}
			}
			
			err = tx.Commit()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "提交事务失败",
				})
				return
			}
			
			go refreshIPCache()
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
			})
		} else {
			var req struct {
				IP          string `json:"ip"`
				Description string `json:"description"`
			}
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "请求参数错误",
				})
				return
			}
			
			if req.IP == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "IP地址不能为空",
				})
				return
			}
			
			_, err = db.Exec("INSERT INTO ip_blacklist (ip, description, created_at) VALUES (?, ?, ?)", req.IP, req.Description, getUTCTime())
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "添加黑名单失败",
				})
				return
			}
			
			go refreshIPCache()
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
			})
		}
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "ID不能为空",
			})
			return
		}
		
		_, err := db.Exec("DELETE FROM ip_blacklist WHERE id = ?", id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "删除黑名单失败",
			})
			return
		}
		
		go refreshIPCache()
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}

func handleIPSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "GET" {
		var mode string
		var actionMode string
		err := db.QueryRow("SELECT mode, action_mode FROM ip_settings ORDER BY id DESC LIMIT 1").Scan(&mode, &actionMode)
		if err != nil {
			mode = "normal"
			actionMode = "block"
		}
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"mode":        mode,
			"action_mode": actionMode,
		})
	} else if r.Method == "POST" {
		var req struct {
			Mode        string `json:"mode"`
			ActionMode  string `json:"action_mode"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "请求参数错误",
			})
			return
		}
		
		if req.Mode != "normal" && req.Mode != "whitelist-only" && req.Mode != "blacklist-only" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的模式",
			})
			return
		}
		
		if req.ActionMode != "observe" && req.ActionMode != "block" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "无效的动作模式",
			})
			return
		}
		
		_, err = db.Exec("INSERT INTO ip_settings (mode, action_mode, updated_at) VALUES (?, ?, ?)", req.Mode, req.ActionMode, getUTCTime())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "设置模式失败",
			})
			return
		}
		
		go refreshIPCache()
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}

func handleRIRImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		RIRUrl string   `json:"rir_url"`
		Rules  []string `json:"rules"`
		ListType string  `json:"list_type"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "请求参数错误",
		})
		return
	}
	
	if req.ListType != "whitelist" && req.ListType != "blacklist" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "无效的列表类型",
		})
		return
	}
	
	if req.RIRUrl == "" {
		req.RIRUrl = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	}
	
	go func() {
		rirImportProgress = struct {
			Status    string
			Processed int
			Total     int
			Found     int
			Message   string
		}{
			Status:  "starting",
			Message: "开始获取RIR数据...",
		}
		
		log.Printf("开始获取RIR数据: %s", req.RIRUrl)
		resp, err := http.Get(req.RIRUrl)
		if err != nil {
			rirImportProgress.Status = "error"
			rirImportProgress.Message = fmt.Sprintf("获取RIR数据失败: %v", err)
			log.Printf("错误: 获取RIR数据失败: %v", err)
			return
		}
		defer resp.Body.Close()
		
		rirImportProgress.Status = "fetching"
		rirImportProgress.Message = "正在获取RIR数据..."
		
		scanner := bufio.NewScanner(resp.Body)
		var filteredIPs []string
		var lineCount int
		
		rirImportProgress.Status = "parsing"
		rirImportProgress.Message = "开始解析RIR数据..."
		
		for scanner.Scan() {
			lineCount++
			line := strings.TrimSpace(scanner.Text())
			
			if lineCount%10000 == 0 {
				rirImportProgress.Processed = lineCount
				rirImportProgress.Found = len(filteredIPs)
				rirImportProgress.Message = fmt.Sprintf("已处理 %d 行数据，已找到 %d 个匹配的IP段", lineCount, len(filteredIPs))
			}
			
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			fields := strings.Split(line, "|")
			if len(fields) < 6 {
				continue
			}
			
			cc := strings.TrimSpace(fields[1])
			ipType := strings.TrimSpace(fields[2])
			start := strings.TrimSpace(fields[3])
			value := strings.TrimSpace(fields[4])
			
			matched := false
			for _, rule := range req.Rules {
				ruleParts := strings.Split(rule, "|")
				if len(ruleParts) != 2 {
					continue
				}
				
				ruleCC := strings.TrimSpace(ruleParts[0])
				ruleType := strings.TrimSpace(ruleParts[1])
				
				if cc == ruleCC && ipType == ruleType {
					matched = true
					break
				}
			}
			
			if matched {
				var ipRange string
				if ipType == "ipv4" {
					valueNum, err := strconv.Atoi(value)
					if err != nil {
						continue
					}
					
					prefixLen := 32
					for i := 31; i >= 0; i-- {
						if valueNum == (1 << uint(i)) {
							prefixLen = i
							break
						}
					}
					
					ipRange = fmt.Sprintf("%s/%d", start, prefixLen)
				} else if ipType == "ipv6" {
					prefixLen, err := strconv.Atoi(value)
					if err != nil {
						continue
					}
					ipRange = fmt.Sprintf("%s/%d", start, prefixLen)
				} else {
					continue
				}
				
				filteredIPs = append(filteredIPs, ipRange)
			}
		}
		
		if err := scanner.Err(); err != nil {
			rirImportProgress.Status = "error"
			rirImportProgress.Message = fmt.Sprintf("读取RIR数据流失败: %v", err)
			log.Printf("错误: 读取RIR数据流失败: %v", err)
			return
		}
		
		rirImportProgress.Processed = lineCount
		rirImportProgress.Found = len(filteredIPs)
		rirImportProgress.Message = fmt.Sprintf("RIR数据解析完成，共处理 %d 行，找到 %d 个匹配的IP段", lineCount, len(filteredIPs))
		
		if len(filteredIPs) == 0 {
			rirImportProgress.Status = "completed"
			rirImportProgress.Message = "没有匹配的IP段"
			return
		}
		
		var tableName string
		if req.ListType == "whitelist" {
			tableName = "ip_whitelist"
		} else {
			tableName = "ip_blacklist"
		}
		
		rirImportProgress.Status = "saving"
		rirImportProgress.Total = len(filteredIPs)
		rirImportProgress.Message = fmt.Sprintf("开始将 %d 个IP段保存到 %s 表", len(filteredIPs), tableName)
		
		tx, err := db.Begin()
		if err != nil {
			rirImportProgress.Status = "error"
			rirImportProgress.Message = fmt.Sprintf("开始事务失败: %v", err)
			log.Printf("错误: 开始事务失败: %v", err)
			return
		}
		
		utcTime := getUTCTime()
		successCount := 0
		for idx, ip := range filteredIPs {
			_, err = tx.Exec(fmt.Sprintf("INSERT INTO %s (ip, description, source, created_at) VALUES (?, 'RIR导入', 'rir', ?)", tableName), ip, utcTime)
			if err != nil {
				log.Printf("添加IP失败 [%d/%d]: %s - %v", idx+1, len(filteredIPs), ip, err)
			} else {
				successCount++
			}
			
			if idx > 0 && idx%1000 == 0 {
				rirImportProgress.Processed = idx + 1
				rirImportProgress.Message = fmt.Sprintf("已保存 %d/%d 个IP段", idx+1, len(filteredIPs))
			}
		}
		
		rirImportProgress.Message = fmt.Sprintf("准备提交事务，成功保存 %d 个IP段", successCount)
		
		err = tx.Commit()
		if err != nil {
			rirImportProgress.Status = "error"
			rirImportProgress.Message = fmt.Sprintf("提交事务失败: %v", err)
			log.Printf("错误: 提交事务失败: %v", err)
			return
		}
		
		rirImportProgress.Status = "completed"
		rirImportProgress.Message = fmt.Sprintf("RIR导入成功，共保存 %d 个IP段到 %s", successCount, tableName)
		log.Printf("RIR导入成功，共保存 %d 个IP段到 %s", successCount, tableName)
	}()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "导入任务已启动",
	})
}

func handleRIRImportProgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    rirImportProgress.Status,
		"processed": rirImportProgress.Processed,
		"total":     rirImportProgress.Total,
		"found":     rirImportProgress.Found,
		"message":   rirImportProgress.Message,
	})
}

func main() {
	log.Println("========================================")
	log.Printf("🛡️  Coraza WAF Proxy %s", frontendVersion)
	log.Println("========================================")
	
	err := initDB()
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	log.Println("数据库初始化成功")

	err = createDefaultUser()
	if err != nil {
		log.Fatalf("创建默认用户失败: %v", err)
	}

	var adminPortStr string
	err = db.QueryRow("SELECT value FROM system_settings WHERE key = ?", "admin_port").Scan(&adminPortStr)
	if err != nil {
		adminPortStr = "15501"
		_, err = db.Exec("INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)", "admin_port", adminPortStr, getUTCTimestamp())
		if err != nil {
			log.Printf("插入默认管理端口失败: %v", err)
		}
	}
	adminPort, err = strconv.Atoi(adminPortStr)
	if err != nil {
		adminPort = 15501
		log.Printf("管理端口解析失败，使用默认端口 %d", adminPort)
	}

	err = initGeoIP()
	if err != nil {
		log.Printf("GeoIP初始化失败: %v", err)
	}

	err = loadWAFInstancesFromDB()
	if err != nil {
		log.Printf("加载WAF实例失败: %v", err)
	}

	updateHistory()
	refreshTrendCache()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			updateHistory()
		}
	}()

	go func() {
		for {
			now := time.Now().UTC()
			nextHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(1 * time.Hour)
			waitDuration := nextHour.Sub(now)
			log.Printf("[趋势缓存] 下次刷新时间: %v 后 (UTC %v)", waitDuration, nextHour.Format("15:04:05"))
			time.Sleep(waitDuration)
			refreshTrendCache()
		}
	}()

	go wsHub.run()

	mux := http.NewServeMux()
	
	
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", readOnlyMiddleware(handleLogout))
	mux.HandleFunc("/api/current-user", handleCurrentUser)
	mux.HandleFunc("/api/about", handleAbout)
	mux.HandleFunc("/api/check-update", handleCheckUpdate)
	mux.HandleFunc("/api/system-info", handleSystemInfo)
	mux.HandleFunc("/api/manual-update", handleManualUpdate)
	mux.HandleFunc("/api/auto-update", handleAutoUpdate)
	mux.HandleFunc("/api/db-version", handleDBVersion)
	mux.HandleFunc("/api/db-upgrade", readOnlyMiddleware(handleDBUpgrade))
	mux.HandleFunc("/api/db-upgrade-progress", handleDBUpgradeProgress)
	mux.HandleFunc("/api/change-password", readOnlyMiddleware(handleChangePassword))
	mux.HandleFunc("/api/server-ip", handleServerIP)
	mux.HandleFunc("/api/ip-location", handleIPLocation)
	mux.HandleFunc("/api/waf-instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			readOnlyMiddleware(handleWAFInstances)(w, r)
		} else {
			handleWAFInstances(w, r)
		}
	})
	mux.HandleFunc("/api/waf-instances/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" || r.Method == "DELETE" {
			readOnlyMiddleware(handleWAFInstance)(w, r)
		} else {
			handleWAFInstance(w, r)
		}
	})
	mux.HandleFunc("/api/proxy-instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			readOnlyMiddleware(handleProxyInstances)(w, r)
		} else {
			handleProxyInstances(w, r)
		}
	})
	mux.HandleFunc("/api/proxy-instances/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" || r.Method == "DELETE" {
			readOnlyMiddleware(handleProxyInstance)(w, r)
		} else {
			handleProxyInstance(w, r)
		}
	})
	mux.HandleFunc("/api/domain-rules", handleDomainRules)
	mux.HandleFunc("/api/domain-rules/", handleDomainRule)
	mux.HandleFunc("/api/certificates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			readOnlyMiddleware(handleCertificates)(w, r)
		} else {
			handleCertificates(w, r)
		}
	})
	mux.HandleFunc("/api/certificates/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/renew") {
			if r.Method == "POST" {
				readOnlyMiddleware(handleCertificateRenew)(w, r)
			} else {
				handleCertificateRenew(w, r)
			}
		} else if strings.HasSuffix(path, "/stop") {
			if r.Method == "POST" {
				readOnlyMiddleware(handleCertificateStop)(w, r)
			} else {
				handleCertificateStop(w, r)
			}
		} else if strings.HasSuffix(path, "/retry") {
			if r.Method == "POST" {
				readOnlyMiddleware(handleCertificateRetry)(w, r)
			} else {
				handleCertificateRetry(w, r)
			}
		} else if strings.HasSuffix(path, "/logs") {
			handleCertificateLogs(w, r)
		} else {
			if r.Method == "PUT" || r.Method == "DELETE" {
				readOnlyMiddleware(handleCertificate)(w, r)
			} else {
				handleCertificate(w, r)
			}
		}
	})
	mux.HandleFunc("/api/certificates/*/logs", handleCertificateLogs)
	mux.HandleFunc("/api/port-forward-instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			readOnlyMiddleware(handlePortForwardInstances)(w, r)
		} else {
			handlePortForwardInstances(w, r)
		}
	})
	mux.HandleFunc("/api/port-forward-instances/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" || r.Method == "DELETE" {
			readOnlyMiddleware(handlePortForwardInstance)(w, r)
		} else {
			handlePortForwardInstance(w, r)
		}
	})
	mux.HandleFunc("/api/available-rules", handleAvailableRules)
	mux.HandleFunc("/api/logs", handleLogs)
	mux.HandleFunc("/api/statistics", handleStatistics)
	mux.HandleFunc("/api/statistics/history", handleStatisticsHistory)
	mux.HandleFunc("/api/ip-whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "DELETE" {
			readOnlyMiddleware(handleIPWhitelist)(w, r)
		} else {
			handleIPWhitelist(w, r)
		}
	})
	mux.HandleFunc("/api/ip-whitelist/batch", readOnlyMiddleware(handleIPWhitelist))
	mux.HandleFunc("/api/ip-blacklist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "DELETE" {
			readOnlyMiddleware(handleIPBlacklist)(w, r)
		} else {
			handleIPBlacklist(w, r)
		}
	})
	mux.HandleFunc("/api/ip-blacklist/batch", readOnlyMiddleware(handleIPBlacklist))
	mux.HandleFunc("/api/ip-settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			readOnlyMiddleware(handleIPSettings)(w, r)
		} else {
			handleIPSettings(w, r)
		}
	})
	mux.HandleFunc("/api/ip-access-logs", handleIPAccessLogs)
	mux.HandleFunc("/api/ip-access-logs/report", handleIPAccessLogsReport)
	mux.HandleFunc("/api/trend-data", handleTrendData)
	mux.HandleFunc("/api/client-stats", handleClientStats)
	mux.HandleFunc("/api/rir-import", readOnlyMiddleware(handleRIRImport))
	mux.HandleFunc("/api/rir-import-progress", handleRIRImportProgress)
	mux.HandleFunc("/api/system-settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			readOnlyMiddleware(handleSystemSettings)(w, r)
		} else {
			handleSystemSettings(w, r)
		}
	})

	mux.HandleFunc("/api/webhook-settings", readOnlyMiddleware(handleWebhookSettings))
	mux.HandleFunc("/api/defense-test", readOnlyMiddleware(handleDefenseTest))
	mux.HandleFunc("/ws", handleWebSocket)
	
	mux.HandleFunc("/web/html/admin.html", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		content, err := os.ReadFile("web/html/admin.html")
		if err != nil {
			http.Error(w, "Failed to read admin.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(strings.ReplaceAll(string(content), "{localversion}", frontendVersion)))
	}))
	mux.HandleFunc("/web/js/admin.js", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/js/admin.js")
	}))
	mux.HandleFunc("/web/js/lib/echarts.min.js", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/js/lib/echarts.min.js")
	}))
	mux.HandleFunc("/web/html/dashboard.html", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/html/dashboard.html")
	}))
	mux.HandleFunc("/web/html/defense-test.html", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/html/defense-test.html")
	}))
	mux.HandleFunc("/web/html/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/html/login.html")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			http.ServeFile(w, r, "web/html/404.html")
			return
		}
		session, err := r.Cookie("session")
		if err != nil || session.Value == "" {
			http.Redirect(w, r, "/web/html/admin.html", http.StatusSeeOther)
			return
		}
		var username string
		err = db.QueryRow("SELECT username FROM users WHERE username = ?", session.Value).Scan(&username)
		if err != nil {
			http.Redirect(w, r, "/web/html/admin.html", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/web/html/admin.html", http.StatusSeeOther)
	})
	mux.Handle("/tiles/", http.StripPrefix("/tiles/", http.FileServer(http.Dir("static/tiles"))))
	mux.Handle("/sounds/", http.StripPrefix("/sounds/", http.FileServer(http.Dir("static/sounds"))))
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.Handle("/login.html", http.FileServer(http.Dir("web/html")))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", adminPort),
		Handler: mux,
	}

	go func() {
		log.Printf("管理服务启动在端口 %d", adminPort)
		log.Printf("默认用户: admin/admin")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	err = loadProxyInstancesFromDB()
	if err != nil {
		log.Printf("加载防护应用失败: %v", err)
	}

	err = loadPortForwardInstancesFromDB()
	if err != nil {
		log.Printf("加载端口转发实例失败: %v", err)
	}

	err = loadCertificatesFromDB()
	if err != nil {
		log.Printf("加载证书实例失败: %v", err)
	}

	startCertificateAutoRenewal()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在优雅关闭...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyMutex.RLock()
	for _, instance := range proxyInstances {
		if instance.Server != nil {
			log.Printf("正在关闭代理服务器 %s...", instance.Name)
			instance.Server.Shutdown(ctx)
		}
	}
	proxyMutex.RUnlock()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("服务器关闭错误: %v", err)
	}

	log.Println("正在执行数据库 checkpoint...")
	_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err != nil {
		log.Printf("Checkpoint执行失败: %v", err)
	} else {
		log.Println("Checkpoint执行成功，数据已合并到主数据库")
	}

	log.Println("正在关闭数据库连接...")
	err = db.Close()
	if err != nil {
		log.Printf("数据库关闭失败: %v", err)
	} else {
		log.Println("数据库连接已关闭")
	}

	log.Println("程序已安全退出")
}

func handleServerIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	log.Printf("开始获取服务器IP...")
	
	ipServices := []string{
		"https://ddns.oray.com/checkip",
		"http://v4.66666.host:66/ip",
		"https://myip.ipip.net",
		"http://v4.666666.host:66/ip",
		"https://4.ipw.cn",
		"https://ip.3322.net",
	}
	
	var ip string
	var lastErr error
	
	for _, service := range ipServices {
		log.Printf("尝试从 %s 获取IP...", service)
		resp, err := http.Get(service)
		if err != nil {
			log.Printf("从 %s 获取IP失败: %v", service, err)
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("读取 %s 响应失败: %v", service, err)
			lastErr = err
			continue
		}
		
		ipStr := strings.TrimSpace(string(body))
		log.Printf("从 %s 获取到原始内容: %s", service, ipStr)
		
		re := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
		matches := re.FindStringSubmatch(ipStr)
		if len(matches) > 0 {
			ip = matches[0]
			log.Printf("从 %s 提取到IP: %s", service, ip)
			break
		}
	}
	
	if ip == "" {
		log.Printf("所有IP查询接口都失败了，最后错误: %v", lastErr)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("获取服务器IP失败: %v", lastErr),
		})
		return
	}
	
	log.Printf("成功获取服务器IP: %s", ip)
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"ip":      ip,
	})
}

func handleIPLocation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		log.Printf("IP地址不能为空")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "IP地址不能为空",
		})
		return
	}
	
	log.Printf("查询IP地理位置: %s", ip)
	
	cleanIP := getCleanIP(ip)
	if cleanIP == "" {
		log.Printf("无效的IP地址: %s", ip)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "无效的IP地址",
		})
		return
	}
	country, province, city, latitude, longitude := getGeoLocation(cleanIP)

	log.Printf("查询结果 - 国家: %s, 省份: %s, 城市: %s, 纬度: %f, 经度: %f",
		country, province, city, latitude, longitude)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"latitude":  latitude,
		"longitude": longitude,
		"country":   country,
		"province":  province,
		"city":      city,
	})
}

type DefenseTestRequest struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Payload  string `json:"payload"`
}

type DefenseTestResult struct {
	Success    bool   `json:"success"`
	Blocked    bool   `json:"blocked"`
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
	Duration   int64  `json:"duration"`
}

func handleDefenseTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "POST" {
		var req DefenseTestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			json.NewEncoder(w).Encode(DefenseTestResult{
				Success: false,
				Message: "无效的请求格式",
			})
			return
		}

		if req.URL == "" {
			json.NewEncoder(w).Encode(DefenseTestResult{
				Success: false,
				Message: "目标URL不能为空",
			})
			return
		}

		startTime := time.Now()

		targetURL, err := url.Parse(req.URL)
		if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
			json.NewEncoder(w).Encode(DefenseTestResult{
				Success: false,
				Message: "无效的URL格式",
			})
			return
		}

		var reqPayload *http.Request
		switch req.Type {
		case "SQLI", "XSS", "RCE", "LFI", "RFI":
			encodedPayload := url.QueryEscape(req.Payload)
			testURL := req.URL
			if strings.Contains(testURL, "?") {
				testURL = testURL + "&q=" + encodedPayload
			} else {
				testURL = testURL + "?q=" + encodedPayload
			}
			reqPayload, _ = http.NewRequest("GET", testURL, nil)
			reqPayload.Header.Set("User-Agent", "DefenseTest/1.0")
		case "Scanner":
			reqPayload, _ = http.NewRequest("GET", req.URL, nil)
			reqPayload.Header.Set("User-Agent", req.Payload)
		default:
			json.NewEncoder(w).Encode(DefenseTestResult{
				Success: false,
				Message: "未知的攻击类型",
			})
			return
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(reqPayload)
		duration := time.Since(startTime).Milliseconds()

		if err != nil {
			if strings.Contains(err.Error(), "connection refused") ||
				strings.Contains(err.Error(), "timeout") ||
				strings.Contains(err.Error(), "no such host") {
				json.NewEncoder(w).Encode(DefenseTestResult{
					Success:    true,
					Blocked:    true,
					StatusCode: 0,
					Message:    "目标不可达或连接超时",
					Duration:   duration,
				})
				return
			}
			json.NewEncoder(w).Encode(DefenseTestResult{
				Success:  false,
				Message:  fmt.Sprintf("请求失败: %v", err),
				Duration: duration,
			})
			return
		}
		defer resp.Body.Close()

		blocked := false
		message := "请求正常通过"
		if resp.StatusCode == 403 {
			blocked = true
			message = "请求被WAF拦截"
		} else if resp.StatusCode == 302 || resp.StatusCode == 301 {
			blocked = true
			message = "请求被重定向(可能WAF拦截)"
		}

		json.NewEncoder(w).Encode(DefenseTestResult{
			Success:    true,
			Blocked:    blocked,
			StatusCode: resp.StatusCode,
			Message:    message,
			Duration:   duration,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "仅支持POST请求",
		})
	}
}
