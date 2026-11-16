package sep10

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Every connection goes to the bridge endpoint, and only for the home-domain
// name: a URL on any other host is refused at the dialer, before a byte leaves.
func TestTheDialerReachesOnlyTheEndpointAndOnlyForTheName(t *testing.T) {
	var hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "bridge.example:8084", "p", 5*time.Second, func() int64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.exchange(context.Background(), http.MethodGet, "http://bridge.example:8084/x", nil, 100); err != nil {
		t.Fatalf("name: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "bridge.example:8084" {
		t.Errorf("hosts = %v", hosts)
	}
	_, err = c.exchange(context.Background(), http.MethodGet, "http://elsewhere.example:8084/x", nil, 100)
	if err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Errorf("other host: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("a request reached the server for another host: %v", hosts)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.example/", http.StatusFound)
	}))
	defer srv.Close()
	home := strings.TrimPrefix(srv.URL, "http://")
	c, _ := NewClient(srv.URL, home, "p", 5*time.Second, func() int64 { return 0 })
	_, err := c.exchange(context.Background(), http.MethodGet, srv.URL+"/x", nil, 100)
	he, ok := err.(*HTTPError)
	if !ok || he.Status != http.StatusFound {
		t.Fatalf("err = %v", err)
	}
}
