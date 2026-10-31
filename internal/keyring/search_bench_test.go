package keyring

import (
	"strconv"
	"testing"
)

func BenchmarkSearch(b *testing.B) {
	c, err := New("Login", []byte("pw"), testKDF, t0)
	if err != nil {
		b.Fatal(err)
	}
	for i := range 1000 {
		attrs := map[string]string{
			"xdg:schema": "org.gnome.keyring.NetworkPassword",
			"server":     "host" + strconv.Itoa(i%100) + ".example",
			"user":       "user" + strconv.Itoa(i),
			"protocol":   "https",
		}
		if _, _, err := c.CreateItem("item", attrs, []byte("s"), "text/plain", false, t0); err != nil {
			b.Fatal(err)
		}
	}
	query := map[string]string{"xdg:schema": "org.gnome.keyring.NetworkPassword", "server": "host7.example", "user": "user507"}
	for b.Loop() {
		if got := c.Search(query); len(got) != 1 {
			b.Fatalf("search found %d items, want 1", len(got))
		}
	}
}
