// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// cdnFront stands in for a CDN tunnel front between the miner and
// the edge: it adds its own headers and cookie, weakens the ETag, appends
// to Vary and replaces Server, and on request tampers with what the miner
// committed to.
func cdnFront(t *testing.T, origin string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(&httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) },
		ModifyResponse: func(response *http.Response) error {
			h := response.Header
			h.Set("Cf-Ray", "8e0f1a2b3c4d5e6f-FRA")
			h.Set("Cf-Cache-Status", "DYNAMIC")
			h.Set("Server", "cdn-front")
			h.Add("Vary", "Accept-Encoding")
			h.Set("Nel", `{"success_fraction":0,"max_age":604800}`)
			h.Set("Report-To", `{"group":"cf-nel","max_age":604800}`)
			h.Set("Alt-Svc", `h3=":443"; ma=86400`)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Add("Set-Cookie", "__cf_bm=abc; path=/; HttpOnly; Secure")
			h.Add("Set-Cookie", "_cfuvid=def; path=/")
			if etag := h.Get("Etag"); etag != "" {
				h.Set("Etag", "W/"+etag)
			}
			switch response.Request.URL.Query().Get("tamper") {
			case "type":
				h.Set("Content-Type", "text/html")
			case "cookie":
				h.Add("Set-Cookie", "session=attacker")
			case "location":
				h.Set("Location", "https://elsewhere.example/")
			}
			return nil
		},
	})
	t.Cleanup(front.Close)
	return front
}

// TestReceiptHeaderDigestSurvivesGoWireAndCDNFront reproduces the two
// honest-mismatch sources: Go net/http trims and unfolds values on the wire
// (the responder digests raw values), and a tunnel front adds headers the
// responder never sent. The responder's digest over its raw header map
// must equal the digest over what a client receives, while a change to a
// committed header still changes the digest.
func TestReceiptHeaderDigestSurvivesGoWireAndCDNFront(t *testing.T) {
	digests := make(chan [32]byte, 8)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "  text/plain;\tcharset=utf-8 \t")
		h.Set("Location", "/next\r\n")
		h.Set("Content-Disposition", "inline;\r\n filename=\"a.txt\"")
		h.Add("Set-Cookie", " sid=1; Path=/ ")
		h.Add("Set-Cookie", "theme=dark")
		h.Set("Etag", `"v1"`)
		h.Set("X-App", "1")
		digest, err := ReceiptHTTPHeaderSHA256(h)
		if err != nil {
			t.Error(err)
		}
		digests <- digest
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, "body")
	}))
	t.Cleanup(origin.Close)
	front := cdnFront(t, origin.URL)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(query string) (http.Header, [32]byte) {
		t.Helper()
		response, err := client.Get(front.URL + "/x?" + query)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.Header, <-digests
	}

	header, sent := get("")
	if got := header.Get("Content-Type"); got == "  text/plain;\tcharset=utf-8 \t" || header.Get("Cf-Ray") == "" ||
		len(header.Values("Set-Cookie")) != 4 || !strings.HasPrefix(header.Get("Etag"), "W/") {
		t.Fatalf("transport did not trim values or add CDN headers: content-type %q, headers %v", got, header)
	}
	received, err := ReceiptHTTPHeaderSHA256(header)
	if err != nil {
		t.Fatal(err)
	}
	if received != sent {
		t.Fatalf("honest response mismatched after Go wire normalisation and CDN front: %v", header)
	}
	for _, tamper := range []string{"type", "cookie", "location"} {
		header, sent := get("tamper=" + tamper)
		received, _ := ReceiptHTTPHeaderSHA256(header)
		if received == sent {
			t.Fatalf("committed header change %q did not change the receipt header digest", tamper)
		}
	}
}

func TestReceiptHeaderValueIsIdempotentAndCommittedSetIsExplicit(t *testing.T) {
	for _, value := range []string{"", " ", "a", " a ", "a\r\n b", "\ta \t\tb\n", "a,  b", "x\r\r\ny"} {
		once := ReceiptHeaderValue(value)
		if ReceiptHeaderValue(once) != once || strings.ContainsAny(once, "\t\r\n") || strings.Contains(once, "  ") ||
			strings.TrimSpace(once) != once {
			t.Fatalf("ReceiptHeaderValue(%q) = %q is not canonical", value, once)
		}
	}
	base := [][2]string{{"Content-Type", "text/plain"}, {"Set-Cookie", "sid=1"}}
	want, _ := ReceiptHeaderSHA256(base)
	for _, ignored := range [][2]string{{"Date", "x"}, {"Server", "x"}, {"Cache-Control", "no-store"}, {"Etag", "\"x\""},
		{"Vary", "x"}, {"Cf-Ray", "x"}, {"X-Ms-Reserved-Answer", "x"}, {"Set-Cookie", "__cf_bm=x"},
		{"Set-Cookie", " cf_clearance=x"}, {"Set-Cookie", "__cflb=x"}, {"Set-Cookie", "_cfuvid=x"}} {
		if got, _ := ReceiptHeaderSHA256(append(append([][2]string(nil), base...), ignored)); got != want {
			t.Fatalf("%v must not enter the receipt header digest", ignored)
		}
	}
	for _, appCookie := range []string{"cf_session=x", "_cfg=x", "__cfx=x", "cfuvid=x", "__cfseq=x", "sid=x"} {
		if got, _ := ReceiptHeaderSHA256(append(append([][2]string(nil), base...), [2]string{"Set-Cookie", appCookie})); got == want {
			t.Fatalf("application cookie %q must stay committed", appCookie)
		}
	}
	for _, cdnCookie := range []string{"__cfseq-abc=1", "cf_chl_rc_ni=1", "__CF_BM=1", "cf_use_ob=0", "__cfwaitingroom=x"} {
		if got, _ := ReceiptHeaderSHA256(append(append([][2]string(nil), base...), [2]string{"Set-Cookie", cdnCookie})); got != want {
			t.Fatalf("CDN cookie %q must not enter the digest", cdnCookie)
		}
	}
	for name := range receiptCommittedHeaders {
		if got, _ := ReceiptHeaderSHA256(append(append([][2]string(nil), base...), [2]string{name, "v"})); got == want {
			t.Fatalf("committed header %s does not enter the digest", name)
		}
	}
	if got, _ := ReceiptHeaderSHA256([][2]string{{"Set-Cookie", "sid=1"}, {"Content-Type", "text/plain"}}); got != want {
		t.Fatal("order across names must not matter")
	}
	swapped, _ := ReceiptHeaderSHA256([][2]string{{"Content-Type", "text/plain"}, {"Set-Cookie", "a=1"}, {"Set-Cookie", "b=2"}})
	ordered, _ := ReceiptHeaderSHA256([][2]string{{"Content-Type", "text/plain"}, {"Set-Cookie", "b=2"}, {"Set-Cookie", "a=1"}})
	if swapped == ordered {
		t.Fatal("order within a name is committed")
	}
}
