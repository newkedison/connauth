package logger

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
)

func TestApplySLSEnvOverridesConfig(t *testing.T) {
	t.Setenv("CONNAUTH_SLS_ENDPOINT", "sls.example.com")
	t.Setenv("CONNAUTH_SLS_PROJECT", "env-project")
	t.Setenv("CONNAUTH_SLS_LOGSTORE", "env-logstore")
	t.Setenv("CONNAUTH_SLS_TOPIC", "env-topic")
	t.Setenv("ALIYUN_SLS_ACCESS_KEY_ID", "env-id")
	t.Setenv("ALIYUN_SLS_ACCESS_KEY_SECRET", "env-secret")

	cfg := ApplySLSEnv(AliyunSLSConfig{
		Endpoint:        "file-endpoint",
		ProjectName:     "file-project",
		LogStoreName:    "file-logstore",
		Topic:           "file-topic",
		AccessKeyID:     "file-id",
		AccessKeySecret: "file-secret",
	})
	if cfg.Endpoint != "sls.example.com" ||
		cfg.ProjectName != "env-project" ||
		cfg.LogStoreName != "env-logstore" ||
		cfg.Topic != "env-topic" ||
		cfg.AccessKeyID != "env-id" ||
		cfg.AccessKeySecret != "env-secret" {
		t.Fatalf("expected env values to override config: %+v", cfg)
	}
}

func TestSLSHookFiltersSecretFieldsAndSendsSafeMetadata(t *testing.T) {
	var received LogGroup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/logstores/auth-log/shards/lb") {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Fatal("expected authorization header")
		}
		if r.Header.Get("x-log-bodyrawsize") == "" || r.Header.Get("x-log-apiversion") != "0.6.0" {
			t.Fatalf("expected SLS headers, got %#v", r.Header)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := proto.Unmarshal(body, &received); err != nil {
			t.Fatalf("unmarshal log group: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook, err := NewSLSHook(AliyunSLSConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		ProjectName:     "project",
		LogStoreName:    "auth-log",
		Topic:           "auth",
		AccessKeyID:     "id",
		AccessKeySecret: "secret",
	})
	if err != nil {
		t.Fatalf("new sls hook: %v", err)
	}
	hook.now = func() time.Time { return time.Unix(1700000000, 0) }
	entry := logrus.NewEntry(logrus.New()).WithFields(logrus.Fields{
		"event":                "auth",
		"source_ip":            "192.0.2.10",
		"port":                 40022,
		"client_id":            "workstation",
		"key_id":               "primary-2026-06",
		"result":               "ok",
		"token":                "token-abcdefghijklmnopqrstuvwxyz",
		"authkey":              "abcdefghijklmnopqrstuvwxyz123456",
		"AccessKeySecret":      "secret",
		"raw_payload":          "ciphertext",
		"access_key_secret":    "secret",
		"aliyun_access_secret": "secret",
	})
	entry.Level = logrus.InfoLevel
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("fire sls hook: %v", err)
	}

	if len(received.Logs) != 1 {
		t.Fatalf("expected one log, got %d", len(received.Logs))
	}
	fields := map[string]string{}
	for _, c := range received.Logs[0].Contents {
		fields[*c.Key] = *c.Value
	}
	if fields["event"] != "auth" || fields["source_ip"] != "192.0.2.10" || fields["client_id"] != "workstation" {
		t.Fatalf("safe fields missing: %#v", fields)
	}
	for _, forbidden := range []string{"token", "authkey", "AccessKeySecret", "raw_payload", "access_key_secret", "aliyun_access_secret"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("forbidden field %s was sent: %#v", forbidden, fields)
		}
	}
}

func TestNewSLSHookRejectsIncompleteEnabledConfig(t *testing.T) {
	if _, err := NewSLSHook(AliyunSLSConfig{Enabled: true}); err == nil {
		t.Fatal("expected incomplete enabled SLS config to fail")
	}
}
