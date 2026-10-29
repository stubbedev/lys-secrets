package bitwarden

import (
	"errors"
	"testing"

	"github.com/stubbedev/lys-secrets/vault"
)

// The Secret Service sees only the folder's logins that may leave the
// vault unasked: with a password, fully decrypted, not behind the
// reprompt. Their passwords come out by id and folder only; a locked
// vault shows none.
func TestFolderLogins(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a,
		Item{ID: "mail", Type: vault.ItemLogin, Folder: "Desktop", Name: "Mail", Username: "ada", Password: "pw", URIs: []string{"https://mail.example.com", "https://m.example.com"}},
		Item{ID: "bank", Type: vault.ItemLogin, Folder: "Desktop", Name: "Bank", Password: "pw", Reprompt: true},
		Item{ID: "broken", Type: vault.ItemLogin, Folder: "Desktop", Name: "Broken", Password: "pw", Undecryptable: true},
		Item{ID: "empty", Type: vault.ItemLogin, Folder: "Desktop", Name: "Empty"},
		Item{ID: "note", Type: vault.ItemSecureNote, Folder: "Desktop", Name: "Note", Notes: "n"},
		Item{ID: "other", Type: vault.ItemLogin, Folder: "Personal", Name: "Other", Password: "pw"},
	)
	logins, open := s.FolderLogins("Desktop")
	want := FolderLogin{ID: "mail", Name: "Mail", Username: "ada", URI: "https://mail.example.com", Folder: "Desktop"}
	if !open || len(logins) != 1 || logins[0] != want {
		t.Fatalf("logins = %+v, %v; want only %+v", logins, open, want)
	}
	if pw, err := s.FolderPassword("Desktop", "mail"); err != nil || string(pw) != "pw" {
		t.Errorf("password = %q, %v", pw, err)
	}
	for _, c := range []struct{ folder, id string }{{"Desktop", "bank"}, {"Desktop", "broken"}, {"Personal", "mail"}, {"Desktop", "absent"}} {
		if pw, err := s.FolderPassword(c.folder, c.id); !errors.Is(err, vault.ErrNoSuchItem) {
			t.Errorf("%s in %s = %q, %v", c.id, c.folder, pw, err)
		}
	}
	s.Lock()
	if logins, open := s.FolderLogins("Desktop"); open || logins != nil {
		t.Errorf("a locked vault shows %+v", logins)
	}
	if _, err := s.FolderPassword("Desktop", "mail"); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("a locked vault's password = %v", err)
	}
}
