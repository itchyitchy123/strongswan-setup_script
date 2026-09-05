package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct{ validationFails bool }

func (r fakeRunner) Run(name string, args ...string) ([]byte, error) {
	if name == "ipsec" && len(args) > 0 && args[0] == "checkconfig" && r.validationFails {
		return []byte("invalid configuration"), errors.New("failed")
	}
	if name == "ipsec" && len(args) > 0 && args[0] == "statusall" {
		return []byte("office"), nil
	}
	return nil, nil
}

func valid() options {
	return options{profile: string(pskClient), name: "office", gateway: "vpn.example.com", remoteID: "vpn.example.com", localID: "%any", psk: "secret", remoteTS: "10.10.0.0/16", ike: "aes256gcm16-prfsha384-ecp384!", esp: "aes256gcm16-ecp384!", conf: "/tmp/ipsec.conf", secrets: "/tmp/ipsec.secrets"}
}
func TestRenderDoesNotExposeSecretInConnection(t *testing.T) {
	o := valid()
	conf, secrets := render(o)
	if strings.Contains(conf, o.psk) || !strings.Contains(secrets, `PSK "secret"`) {
		t.Fatal("secret rendering is incorrect")
	}
	if !strings.Contains(conf, "auto=add") {
		t.Fatal("safe default must be add")
	}
}
func TestDefaultRouteNeedsExplicitAcknowledgement(t *testing.T) {
	o := valid()
	o.remoteTS = "0.0.0.0/0"
	if err := validate(&o); err == nil {
		t.Fatal("accepted full tunnel without acknowledgement")
	}
	o.fullTunnel = true
	if err := validate(&o); err != nil {
		t.Fatal(err)
	}
}
func TestRemoteIdentityCannotBeAnyByDefault(t *testing.T) {
	o := valid()
	o.remoteID = "%any"
	if err := validate(&o); err == nil {
		t.Fatal("accepted unsafe identity")
	}
}
func TestSecretNewlineIsRejected(t *testing.T) {
	o := valid()
	o.psk = "first\nsecond"
	if err := validate(&o); err == nil {
		t.Fatal("accepted a multiline secret")
	}
}
func TestSecretFileMustBePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(path, []byte("secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(path); err == nil {
		t.Fatal("accepted a world-readable secret file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	value, err := readSecretFile(path)
	if err != nil || value != "secret" {
		t.Fatalf("secret file read failed: %q, %v", value, err)
	}
}
func TestManagedReplacementPreservesOtherConfiguration(t *testing.T) {
	got, err := managedReplace("config setup\n# BEGIN strongswan-setup office\nold\n# END strongswan-setup office\nconn keep\n", "office", "new\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "old") || !strings.Contains(got, "conn keep") || !strings.Contains(got, "new") {
		t.Fatal(got)
	}
}
func TestMalformedManagedBlockIsRejected(t *testing.T) {
	if _, err := managedReplace("# BEGIN strongswan-setup office\n", "office", "new\n"); err == nil {
		t.Fatal("accepted an unterminated managed block")
	}
}
func TestAtomicWriteAndRestore(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "ipsec.conf")
	if err := os.WriteFile(p, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := takeSnapshot(p, filepath.Join(d, "backups"), "stamp")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(p, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "old" {
		t.Fatal(string(b))
	}
}
func TestValidationFailureRestoresFilesAndRestarts(t *testing.T) {
	d := t.TempDir()
	o := valid()
	o.conf = filepath.Join(d, "ipsec.conf")
	o.secrets = filepath.Join(d, "ipsec.secrets")
	o.backupDir = filepath.Join(d, "backups")
	if err := os.WriteFile(o.conf, []byte("old config\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.secrets, []byte("old secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conf, secrets := render(o)
	if err := apply(o, conf, secrets, "", fakeRunner{validationFails: true}, io.Discard); err == nil {
		t.Fatal("expected validation failure")
	}
	gotConf, _ := os.ReadFile(o.conf)
	gotSecrets, _ := os.ReadFile(o.secrets)
	if string(gotConf) != "old config\n" || string(gotSecrets) != "old secret\n" {
		t.Fatal("rollback did not restore original files")
	}
}
