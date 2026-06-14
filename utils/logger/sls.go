package logger

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
)

type AliyunSLSConfig struct {
	Enabled         bool
	Endpoint        string
	ProjectName     string
	LogStoreName    string
	Topic           string
	AccessKeyID     string
	AccessKeySecret string
}

type LogContent struct {
	Key   *string `protobuf:"bytes,1,req,name=key" json:"key,omitempty"`
	Value *string `protobuf:"bytes,2,req,name=value" json:"value,omitempty"`
}

func (m *LogContent) Reset()         { *m = LogContent{} }
func (m *LogContent) String() string { return proto.CompactTextString(m) }
func (*LogContent) ProtoMessage()    {}

type Log struct {
	Time     *uint32       `protobuf:"varint,1,req,name=time" json:"time,omitempty"`
	Contents []*LogContent `protobuf:"bytes,2,rep,name=contents" json:"contents,omitempty"`
}

func (m *Log) Reset()         { *m = Log{} }
func (m *Log) String() string { return proto.CompactTextString(m) }
func (*Log) ProtoMessage()    {}

type LogGroup struct {
	Logs   []*Log  `protobuf:"bytes,1,rep,name=logs" json:"logs,omitempty"`
	Topic  *string `protobuf:"bytes,3,opt,name=topic" json:"topic,omitempty"`
	Source *string `protobuf:"bytes,4,opt,name=source" json:"source,omitempty"`
}

func (m *LogGroup) Reset()         { *m = LogGroup{} }
func (m *LogGroup) String() string { return proto.CompactTextString(m) }
func (*LogGroup) ProtoMessage()    {}

type SLSHook struct {
	cfg    AliyunSLSConfig
	client *http.Client
	now    func() time.Time
}

func NewSLSHook(cfg AliyunSLSConfig) (*SLSHook, error) {
	cfg = ApplySLSEnv(cfg)
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Endpoint == "" || cfg.ProjectName == "" || cfg.LogStoreName == "" ||
		cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" {
		return nil, fmt.Errorf("aliyun sls config incomplete")
	}
	if _, err := url.ParseRequestURI(normalizeEndpoint(cfg.Endpoint)); err != nil {
		return nil, fmt.Errorf("aliyun sls endpoint invalid: %v", err)
	}
	return &SLSHook{
		cfg:    cfg,
		client: &http.Client{Timeout: 3 * time.Second},
		now:    time.Now,
	}, nil
}

func ApplySLSEnv(cfg AliyunSLSConfig) AliyunSLSConfig {
	override := func(env string, dest *string) {
		if v := os.Getenv(env); v != "" {
			*dest = v
		}
	}
	override("CONNAUTH_SLS_ENDPOINT", &cfg.Endpoint)
	override("CONNAUTH_SLS_PROJECT", &cfg.ProjectName)
	override("CONNAUTH_SLS_LOGSTORE", &cfg.LogStoreName)
	override("CONNAUTH_SLS_TOPIC", &cfg.Topic)
	override("ALIYUN_SLS_ACCESS_KEY_ID", &cfg.AccessKeyID)
	override("ALIYUN_SLS_ACCESS_KEY_SECRET", &cfg.AccessKeySecret)
	return cfg
}

func (h *SLSHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *SLSHook) Fire(entry *logrus.Entry) error {
	fields := safeSLSFields(entry)
	now := h.now()
	sec := uint32(now.Unix())
	contents := make([]*LogContent, 0, len(fields)+1)
	contents = append(contents, logContent("level", entry.Level.String()))
	for _, key := range sortedKeys(fields) {
		contents = append(contents, logContent(key, fmt.Sprint(fields[key])))
	}
	group := &LogGroup{
		Logs:  []*Log{{Time: &sec, Contents: contents}},
		Topic: &h.cfg.Topic,
	}
	body, err := proto.Marshal(group)
	if err != nil {
		return err
	}
	return h.putLogs(body, now)
}

func safeSLSFields(entry *logrus.Entry) map[string]interface{} {
	allowed := map[string]bool{
		"event":     true,
		"source_ip": true,
		"port":      true,
		"client_id": true,
		"key_id":    true,
		"result":    true,
	}
	out := make(map[string]interface{})
	for k, v := range entry.Data {
		if allowed[k] {
			out[k] = v
		}
	}
	return out
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func logContent(key string, value string) *LogContent {
	return &LogContent{Key: proto.String(key), Value: proto.String(value)}
}

func (h *SLSHook) putLogs(body []byte, now time.Time) error {
	endpoint := normalizeEndpoint(h.cfg.Endpoint)
	u := strings.TrimRight(endpoint, "/") + "/logstores/" + url.PathEscape(h.cfg.LogStoreName) + "/shards/lb"
	req, err := http.NewRequest("POST", u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if shouldPrefixProjectHost(req.URL.Hostname()) {
		host := h.cfg.ProjectName + "." + req.URL.Host
		req.URL.Host = host
		req.Host = host
	}
	date := now.UTC().Format(http.TimeFormat)
	contentMD5 := md5Hex(body)
	req.Header.Set("Date", date)
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-MD5", contentMD5)
	req.Header.Set("x-log-apiversion", "0.6.0")
	bodySize := strconv.Itoa(len(body))
	req.Header.Set("x-log-bodyrawsize", bodySize)
	req.Header.Set("x-log-signaturemethod", "hmac-sha1")
	req.Header.Set("Authorization", "LOG "+h.cfg.AccessKeyID+":"+h.signature("POST", contentMD5, "application/x-protobuf", date, bodySize, req.URL.EscapedPath()))
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("aliyun sls put logs failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func shouldPrefixProjectHost(hostname string) bool {
	return hostname != "127.0.0.1" && hostname != "localhost"
}

func (h *SLSHook) signature(method string, contentMD5 string, contentType string, date string, bodySize string, resource string) string {
	canonicalHeaders := "x-log-apiversion:0.6.0\n" +
		"x-log-bodyrawsize:" + bodySize + "\n" +
		"x-log-signaturemethod:hmac-sha1"
	msg := method + "\n" + contentMD5 + "\n" + contentType + "\n" + date + "\n" + canonicalHeaders + "\n" + resource
	mac := hmac.New(sha1.New, []byte(h.cfg.AccessKeySecret))
	_, _ = mac.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func md5Hex(body []byte) string {
	sum := md5.Sum(body)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func normalizeEndpoint(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	return "https://" + endpoint
}
