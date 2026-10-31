package service

import (
	"strconv"
	"testing"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

func BenchmarkSearchVault(b *testing.B) {
	vc := &vaultColl{open: true, logins: map[dbus.ObjectPath]VaultLogin{}}
	for i := range 2000 {
		id := "login" + strconv.Itoa(i)
		vc.logins[vaultItemPath(id)] = VaultLogin{
			ID: id, Name: "Site " + strconv.Itoa(i), Username: "user" + strconv.Itoa(i),
			URI: "https://host" + strconv.Itoa(i%200) + ".example", Folder: "Work",
		}
	}
	s := &Service{vault: vc}
	query := map[string]string{"xdg:schema": vaultSchema, "uri": "https://host7.example", "username": "user1207"}
	for b.Loop() {
		if got := s.searchVaultLocked(query); len(got) != 1 {
			b.Fatalf("search found %d logins, want 1", len(got))
		}
	}
}
