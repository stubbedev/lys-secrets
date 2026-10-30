package bitwarden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stubbedev/lys-secrets/vault"
)

func keyFromB64(t *testing.T, s string) SymmetricKey {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	k, err := symmetricKeyFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyB64(k SymmetricKey) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte(nil), k.enc...), k.mac...))
}

const (
	sdkSendUserKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg=="
	sdkSendKey     = "2.KLv/j0V4Ebs0dwyPdtt4vw==|jcrFuNYN1Qb3onBlwvtxUV/KpdnR1LPRL4EsCoXNAt4=|gHSywGy4Rj/RsCIZFwze4s2AACYKBtqDXTrQXjkgtIE="
	sdkSendName    = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw="
	sdkSendText    = "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0="
	sdkSendURLKey  = "Pgui0FK85cNhBGWHAlBHBw"
	sdkAccessID    = "ct2APRQtJk-BLLDwAYqhRA"
)

func TestShareableKeyMatchesBitwarden(t *testing.T) {
	for _, c := range []struct{ secret, info, want string }{
		{"&/$%F1a895g67HlX", "", "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ=="},
		{"67t9b5g67$%Dh89n", "test", "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng=="},
	} {
		k, err := deriveShareableKey([]byte(c.secret), "test_key", c.info)
		if err != nil || keyB64(k) != c.want {
			t.Errorf("shareable key of %q/%q = %s, %v", c.secret, c.info, keyB64(k), err)
		}
	}
}

func TestSendKeyMatchesBitwarden(t *testing.T) {
	user := keyFromB64(t, "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==")
	k, err := openSendKey(user, "2.+1KUfOX8A83Xkwk1bumo/w==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g=")
	if err != nil || keyB64(k) != "IR9ImHGm6rRuIjiN7csj94bcZR5WYTJj5GtNfx33zm6tJCHUl+QZlpNPba8g2yn70KnOHsAODLcR0um6E3MAlg==" {
		t.Errorf("send key = %s, %v", keyB64(k), err)
	}
	if _, err := deriveSendKey(make([]byte, 15)); err == nil {
		t.Error("a 15-byte Send key was taken")
	}
}

func TestDecryptSendMatchesBitwarden(t *testing.T) {
	user := keyFromB64(t, sdkSendUserKey)
	raw := `{"id":"3d80dd72-2d14-4f26-812c-b0f0018aa144","accessId":"` + sdkAccessID + `","type":0,"name":"` + sdkSendName + `","text":{"text":"` + sdkSendText + `","hidden":false},"key":"` + sdkSendKey + `","maxAccessCount":null,"accessCount":0,"password":null,"disabled":false,"revisionDate":"2024-01-07T23:56:48.207363Z","expirationDate":null,"deletionDate":"2024-01-14T23:56:48Z"}`
	var sd SyncSend
	if err := json.Unmarshal([]byte(raw), &sd); err != nil {
		t.Fatal(err)
	}
	got := decryptSend(user, sd)
	want := vault.Send{ID: "3d80dd72-2d14-4f26-812c-b0f0018aa144", Type: vault.SendText, Name: "Test", Deletion: time.Date(2024, 1, 14, 23, 56, 48, 0, time.UTC)}
	if !got.Deletion.Equal(want.Deletion) {
		t.Errorf("deletion = %v", got.Deletion)
	}
	got.Deletion = want.Deletion
	if got != want {
		t.Errorf("send = %+v, want %+v", got, want)
	}
	material, err := user.DecryptString(sdkSendKey)
	if err != nil || base64.RawURLEncoding.EncodeToString([]byte(material)) != sdkSendURLKey {
		t.Fatalf("send key material = %q, %v", material, err)
	}
	key, _ := deriveSendKey([]byte(material))
	if text, err := key.DecryptString(sdkSendText); err != nil || text != "This is a test" {
		t.Errorf("text = %q, %v", text, err)
	}
	if h, err := sendPasswordHash("abc123", []byte(material)); err != nil || h != "vTIDfdj3FTDbejmMf+mJWpYdMXsxfeSd1Sma3sjCtiQ=" {
		t.Errorf("password hash = %s, %v", h, err)
	}
	if bad := decryptSend(keyFromB64(t, "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q=="), sd); !bad.Undecryptable || bad.Name != sd.ID {
		t.Errorf("under another user key = %+v", bad)
	}
}

func TestEncryptTextSendRoundTrip(t *testing.T) {
	user := keyFromB64(t, sdkSendUserKey)
	material, _ := base64.RawURLEncoding.DecodeString(sdkSendURLKey)
	deletion := time.Date(2026, 11, 6, 12, 0, 0, 0, time.FixedZone("CET", 3600))
	req, err := encryptTextSend(user, material, vault.NewTextSend{Name: "Wifi", Text: "hunter22", Deletion: deletion, MaxAccessCount: 3, Password: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(req)
	for _, plain := range []string{"Wifi", "hunter22", "abc123", sdkSendURLKey} {
		if strings.Contains(string(raw), plain) {
			t.Errorf("the request carries %q: %s", plain, raw)
		}
	}
	if req.Password != "vTIDfdj3FTDbejmMf+mJWpYdMXsxfeSd1Sma3sjCtiQ=" || req.AuthType != sendAuthPassword || *req.MaxAccessCount != 3 || req.DeletionDate != "2026-11-06T11:00:00Z" || req.Type != vault.SendText {
		t.Errorf("request = %s", raw)
	}
	var sd SyncSend
	if err := json.Unmarshal(raw, &sd); err != nil {
		t.Fatal(err)
	}
	sd.ID = "s1"
	if got := decryptSend(user, sd); got.Name != "Wifi" || !got.HasPassword || got.MaxAccessCount != 3 || !got.Deletion.Equal(deletion) {
		t.Errorf("decrypted = %+v", got)
	}
	key, _ := openSendKey(user, req.Key)
	if text, err := key.DecryptString(req.Text.Text); err != nil || text != "hunter22" {
		t.Errorf("text = %q, %v", text, err)
	}
	open, err := encryptTextSend(user, material, vault.NewTextSend{Name: "n", Text: "t", Deletion: deletion})
	raw, _ = json.Marshal(open)
	if err != nil || open.AuthType != sendAuthNone || strings.Contains(string(raw), "password") || strings.Contains(string(raw), "maxAccessCount") {
		t.Errorf("an open Send = %s, %v", raw, err)
	}
	for n, want := range map[int]bool{687: true, 688: false} {
		s, _ := key.EncryptString(strings.Repeat("x", n))
		if got := len(s) <= 1000; got != want {
			t.Errorf("%d bytes encrypt to %d characters", n, len(s))
		}
	}
}

func TestSendURL(t *testing.T) {
	material, _ := base64.RawURLEncoding.DecodeString(sdkSendURLKey)
	for server, want := range map[string]string{
		vault.CloudUS:               "https://send.bitwarden.com/#" + sdkAccessID + "/" + sdkSendURLKey,
		vault.CloudEU:               "https://vault.bitwarden.eu/#/send/" + sdkAccessID + "/" + sdkSendURLKey,
		"https://vw.example.org/":   "https://vw.example.org/#/send/" + sdkAccessID + "/" + sdkSendURLKey,
		"https://example.org/vault": "https://example.org/vault/#/send/" + sdkAccessID + "/" + sdkSendURLKey,
	} {
		s, err := vault.ParseServer(server)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := NewClient(s, Device{}).sendURL(sdkAccessID, material); err != nil || got != want {
			t.Errorf("%s: %s, %v", server, got, err)
		}
	}
	us, _ := vault.ParseServer(vault.CloudUS)
	for _, bad := range []string{"", "a/b", "a#b", "a b"} {
		if _, err := NewClient(us, Device{}).sendURL(bad, material); err == nil {
			t.Errorf("access id %q was taken", bad)
		}
	}
}

func TestServerTime(t *testing.T) {
	for raw, want := range map[string]time.Time{
		`"2024-01-07T23:56:48.207363Z"`: time.Date(2024, 1, 7, 23, 56, 48, 207363000, time.UTC),
		`"2024-01-14T23:56:48+01:00"`:   time.Date(2024, 1, 14, 22, 56, 48, 0, time.UTC),
		`"2024-01-14T23:56:48.1234567"`: time.Date(2024, 1, 14, 23, 56, 48, 123456700, time.UTC),
	} {
		var st serverTime
		if err := json.Unmarshal([]byte(raw), &st); err != nil || !st.Equal(want) {
			t.Errorf("%s = %v, %v", raw, st.Time, err)
		}
	}
	var st serverTime
	if err := json.Unmarshal([]byte(`"yesterday"`), &st); err == nil {
		t.Error("an unreadable date was taken")
	}
}

func TestSendAPI(t *testing.T) {
	var body []byte
	var deleted string
	f := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /api/sends": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer at" {
				reply(401, `{"message":"no"}`)(w, r)
				return
			}
			body, _ = io.ReadAll(r.Body)
			reply(200, `{"id":"s1","accessId":"`+sdkAccessID+`","type":0,"name":"2.n","key":"2.k","deletionDate":"2026-11-06T11:00:00Z"}`)(w, r)
		},
		"DELETE /api/sends/{id}": func(w http.ResponseWriter, r *http.Request) {
			deleted = r.PathValue("id")
			if deleted != "s1" {
				reply(404, `{"message":"Resource not found."}`)(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		},
	})
	c := testClient(f)
	created, err := c.CreateSend(context.Background(), "at", sendRequest{Type: vault.SendText, Name: "2.n"})
	if err != nil || created.ID != "s1" || created.AccessID != sdkAccessID || !created.DeletionDate.Equal(time.Date(2026, 11, 6, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("created = %+v, %v", created, err)
	}
	if !strings.Contains(string(body), `"name":"2.n"`) || !strings.Contains(string(body), `"authType":0`) {
		t.Errorf("request = %s", body)
	}
	if err := c.DeleteSend(context.Background(), "at", "s1"); err != nil {
		t.Errorf("delete = %v", err)
	}
	var ae *APIError
	if err := c.DeleteSend(context.Background(), "at", "../x"); !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("delete an unknown Send = %v", err)
	}
	g := newFakeServer(t, map[string]http.HandlerFunc{"POST /api/sends": reply(200, `{"id":"s1"}`)})
	if _, err := testClient(g).CreateSend(context.Background(), "at", sendRequest{}); err == nil {
		t.Error("an answer without an access id was taken")
	}
}
