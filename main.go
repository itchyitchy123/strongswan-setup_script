// strongswan-setup safely installs one legacy strongSwan (starter/stroke) connection.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	defaultConf    = "/etc/ipsec.conf"
	defaultSecrets = "/etc/ipsec.secrets"
	backupLimit    = 10
)

type profile string

const (
	eap       profile = "eap"
	pskClient profile = "psk-client"
	site      profile = "site-to-site"
)

type options struct {
	profile, name, gateway, remoteID, localID, username, password, psk                string
	passwordFile, pskFile                                                             string
	remoteTS, localTS, caCert, ike, esp                                               string
	conf, secrets, caDir, backupDir                                                   string
	nonInteractive, yes, dryRun, check, remove, list, version, installPackages, start bool
	fullTunnel, allowAnyRemoteID, useSystemCA                                         bool
	probeHost, rollbackID                                                             string
	output                                                                            string
}

type runner interface {
	Run(string, ...string) ([]byte, error)
}
type systemRunner struct{}

func (systemRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func main() {
	opts, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
	if err := run(opts, systemRunner{}, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func parseFlags() (options, error) {
	o := options{localID: "%any", ike: "aes256gcm16-prfsha384-ecp384!", esp: "aes256gcm16-ecp384!", conf: defaultConf, secrets: defaultSecrets, caDir: "/etc/ipsec.d/cacerts", backupDir: "/var/backups/strongswan-setup", output: "text"}
	config := findConfigPath(os.Args[1:])
	if config != "" {
		if err := loadJSONConfig(&o, config); err != nil {
			return o, err
		}
	}
	flag.StringVar(&config, "config", config, "JSON configuration file; flags override its values")
	flag.StringVar(&o.profile, "profile", o.profile, "eap, psk-client, or site-to-site")
	flag.StringVar(&o.name, "name", o.name, "connection name")
	flag.StringVar(&o.gateway, "gateway", o.gateway, "VPN gateway hostname or IP")
	flag.StringVar(&o.remoteID, "remote-id", o.remoteID, "expected gateway IKE identity")
	flag.StringVar(&o.localID, "local-id", o.localID, "local IKE identity")
	flag.StringVar(&o.username, "username", o.username, "EAP username")
	flag.StringVar(&o.password, "password", o.password, "EAP password (prefer stdin in interactive mode)")
	flag.StringVar(&o.passwordFile, "password-file", o.passwordFile, "root-only file containing the EAP password")
	flag.StringVar(&o.psk, "psk", o.psk, "pre-shared key (prefer stdin in interactive mode)")
	flag.StringVar(&o.pskFile, "psk-file", o.pskFile, "root-only file containing the pre-shared key")
	flag.StringVar(&o.remoteTS, "remote-ts", o.remoteTS, "remote CIDRs, comma separated")
	flag.StringVar(&o.localTS, "local-ts", o.localTS, "local protected CIDRs, comma separated")
	flag.StringVar(&o.caCert, "ca-cert", o.caCert, "CA certificate for EAP gateway validation")
	flag.StringVar(&o.ike, "ike", o.ike, "approved IKE proposal")
	flag.StringVar(&o.esp, "esp", o.esp, "approved ESP proposal")
	flag.StringVar(&o.conf, "ipsec-conf", o.conf, "ipsec.conf path")
	flag.StringVar(&o.secrets, "ipsec-secrets", o.secrets, "ipsec.secrets path")
	flag.StringVar(&o.caDir, "ca-dir", o.caDir, "CA certificate directory")
	flag.StringVar(&o.backupDir, "backup-dir", o.backupDir, "root-only backup directory")
	flag.BoolVar(&o.nonInteractive, "non-interactive", o.nonInteractive, "require all required flags")
	flag.BoolVar(&o.yes, "yes", o.yes, "apply without final confirmation")
	flag.BoolVar(&o.dryRun, "dry-run", o.dryRun, "render and validate without writes or commands")
	flag.BoolVar(&o.check, "check", o.check, "run non-mutating host and network readiness diagnostics")
	flag.BoolVar(&o.remove, "remove", o.remove, "remove the named managed connection")
	flag.BoolVar(&o.list, "list", o.list, "list connections managed by this program")
	flag.BoolVar(&o.version, "version", o.version, "print program version")
	flag.BoolVar(&o.installPackages, "install-packages", o.installPackages, "install legacy strongSwan packages")
	flag.BoolVar(&o.start, "start", o.start, "bring this connection up after installation")
	flag.BoolVar(&o.fullTunnel, "full-tunnel", o.fullTunnel, "explicitly permit 0.0.0.0/0 and ::/0")
	flag.BoolVar(&o.allowAnyRemoteID, "allow-any-remote-id", o.allowAnyRemoteID, "allow unsafe remote identity %any")
	flag.BoolVar(&o.useSystemCA, "use-system-ca", o.useSystemCA, "do not copy CA; trust existing ipsec.d CA store")
	flag.StringVar(&o.probeHost, "probe-host", o.probeHost, "optional host:port TCP health probe after connection starts")
	flag.StringVar(&o.rollbackID, "rollback", o.rollbackID, "restore a backup transaction ID")
	flag.StringVar(&o.output, "output", o.output, "text or json")
	flag.Parse()
	return o, nil
}

func findConfigPath(args []string) string {
	for i, arg := range args {
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
		if arg == "--config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func loadJSONConfig(o *options, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	values := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	strings := map[string]*string{
		"profile": &o.profile, "name": &o.name, "gateway": &o.gateway, "remote_id": &o.remoteID, "local_id": &o.localID,
		"username": &o.username, "password_file": &o.passwordFile, "psk_file": &o.pskFile, "remote_ts": &o.remoteTS, "local_ts": &o.localTS,
		"ca_cert": &o.caCert, "ike": &o.ike, "esp": &o.esp, "ipsec_conf": &o.conf, "ipsec_secrets": &o.secrets,
		"ca_dir": &o.caDir, "backup_dir": &o.backupDir, "probe_host": &o.probeHost, "output": &o.output,
	}
	booleans := map[string]*bool{
		"non_interactive": &o.nonInteractive, "yes": &o.yes, "dry_run": &o.dryRun, "check": &o.check, "remove": &o.remove, "list": &o.list,
		"install_packages": &o.installPackages, "start": &o.start, "full_tunnel": &o.fullTunnel,
		"allow_any_remote_id": &o.allowAnyRemoteID, "use_system_ca": &o.useSystemCA,
	}
	for key, raw := range values {
		if target, ok := strings[key]; ok {
			if err := json.Unmarshal(raw, target); err != nil {
				return fmt.Errorf("config %q: %w", key, err)
			}
			continue
		}
		if target, ok := booleans[key]; ok {
			if err := json.Unmarshal(raw, target); err != nil {
				return fmt.Errorf("config %q: %w", key, err)
			}
			continue
		}
		return fmt.Errorf("config contains unsupported key %q", key)
	}
	return nil
}

func run(o options, r runner, in io.Reader, out io.Writer) error {
	if o.version {
		fmt.Fprintln(out, "strongswan-setup dev")
		return nil
	}
	if o.rollbackID != "" {
		return rollbackTransaction(o, r, in, out)
	}
	if o.list {
		return listManaged(o.conf, out)
	}
	if o.remove {
		return removeManaged(o, r, in, out)
	}
	if err := hydrateSecrets(&o); err != nil {
		return err
	}
	reader := bufio.NewReader(in)
	if !o.nonInteractive && !o.dryRun {
		if err := collectInteractive(&o, reader, in == os.Stdin, out); err != nil {
			return err
		}
	}
	if err := validate(&o); err != nil {
		return err
	}
	if o.output != "text" && o.output != "json" {
		return errors.New("--output must be text or json")
	}
	conf, secrets := render(o)
	emitPlan(o, conf, out)
	if o.dryRun {
		emitResult(o, out, "dry-run")
		return nil
	}
	if o.check {
		service, err := detectLegacyService(r)
		if err != nil {
			return err
		}
		if err := preflight(o, r, out); err != nil {
			return err
		}
		return diagnostics(o, service, r, out)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if !o.yes && !confirm(reader, out, "Apply this change?") {
		return errors.New("cancelled; no changes made")
	}
	if err := refuseModernBackend(r); err != nil {
		return err
	}
	if o.installPackages {
		if err := installPackages(r); err != nil {
			return err
		}
	}
	service, err := detectLegacyService(r)
	if err != nil {
		return err
	}
	if err := preflight(o, r, out); err != nil {
		return err
	}
	err = apply(o, conf, secrets, service, r, out)
	if err == nil {
		emitResult(o, out, "installed")
	}
	return err
}

func listManaged(conf string, out io.Writer) error {
	data, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	for _, match := range regexp.MustCompile(`(?m)^# BEGIN strongswan-setup ([A-Za-z0-9_.-]+)$`).FindAllStringSubmatch(string(data), -1) {
		fmt.Fprintln(out, match[1])
	}
	return nil
}

func removeManaged(o options, r runner, in io.Reader, out io.Writer) error {
	if !nameRE.MatchString(o.name) {
		return errors.New("--remove requires a valid --name")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := refuseModernBackend(r); err != nil {
		return err
	}
	if !o.yes && !confirm(bufio.NewReader(in), out, "Remove this managed connection?") {
		return errors.New("cancelled; no changes made")
	}
	service, err := detectLegacyService(r)
	if err != nil {
		return err
	}
	unlock, err := acquireLock(o.backupDir)
	if err != nil {
		return err
	}
	defer unlock()
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	confSnap, err := takeSnapshot(o.conf, o.backupDir, stamp)
	if err != nil {
		return err
	}
	secretsSnap, err := takeSnapshot(o.secrets, o.backupDir, stamp)
	if err != nil {
		return err
	}
	if err := writeManifest(o.backupDir, stamp, confSnap, secretsSnap); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var recovery []error
		if err := secretsSnap.restore(); err != nil {
			recovery = append(recovery, err)
		}
		if err := confSnap.restore(); err != nil {
			recovery = append(recovery, err)
		}
		if len(recovery) == 0 {
			if err := restart(service, r); err != nil {
				recovery = append(recovery, err)
			}
		}
		if len(recovery) > 0 {
			return fmt.Errorf("%w; removal rollback incomplete: %w", cause, errors.Join(recovery...))
		}
		return fmt.Errorf("%w; removal rolled back", cause)
	}
	conf, err := os.ReadFile(o.conf)
	if err != nil {
		return err
	}
	secrets, err := os.ReadFile(o.secrets)
	if err != nil {
		return err
	}
	newConf, err := managedReplace(string(conf), o.name, "")
	if err != nil {
		return err
	}
	newSecrets, err := managedReplace(string(secrets), o.name, "")
	if err != nil {
		return err
	}
	if err := writeAtomic(o.conf, []byte(newConf), 0644); err != nil {
		return rollback(err)
	}
	if err := writeAtomic(o.secrets, []byte(newSecrets), 0600); err != nil {
		return rollback(err)
	}
	for _, path := range []string{o.conf, o.secrets} {
		if err := restoreSecurityContext(path); err != nil {
			return rollback(err)
		}
	}
	if output, err := r.Run("ipsec", "checkconfig"); err != nil {
		return rollback(fmt.Errorf("configuration validation failed: %s", strings.TrimSpace(string(output))))
	}
	if err := restart(service, r); err != nil {
		return rollback(err)
	}
	pruneBackups(o.backupDir)
	fmt.Fprintf(out, "Removed managed connection %q. Its CA file was retained because it may be shared.\n", o.name)
	return nil
}

func rollbackTransaction(o options, r runner, in io.Reader, out io.Writer) error {
	if !regexp.MustCompile(`^[0-9TZ.]+$`).MatchString(o.rollbackID) {
		return errors.New("--rollback must be a transaction ID from the backup directory")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := refuseModernBackend(r); err != nil {
		return err
	}
	if !o.yes && !confirm(bufio.NewReader(in), out, "Restore this backup transaction?") {
		return errors.New("cancelled; no changes made")
	}
	service, err := detectLegacyService(r)
	if err != nil {
		return err
	}
	unlock, err := acquireLock(o.backupDir)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(filepath.Join(o.backupDir, o.rollbackID, "manifest.json"))
	if err != nil {
		return err
	}
	manifest := backupManifest{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("read rollback manifest: %w", err)
	}
	if len(manifest.Files) == 0 {
		return errors.New("rollback manifest is empty")
	}
	for _, file := range manifest.Files {
		if !filepath.IsAbs(file.Path) {
			return errors.New("rollback manifest contains a non-absolute path")
		}
		if !file.Existed {
			if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		contents, err := os.ReadFile(filepath.Join(o.backupDir, o.rollbackID, filepath.Base(file.Path)))
		if err != nil {
			return err
		}
		if err := writeAtomic(file.Path, contents, os.FileMode(file.Mode)); err != nil {
			return err
		}
	}
	if output, err := r.Run("ipsec", "checkconfig"); err != nil {
		return fmt.Errorf("restored configuration failed validation: %s", strings.TrimSpace(string(output)))
	}
	if err := restart(service, r); err != nil {
		return err
	}
	fmt.Fprintf(out, "Restored transaction %s.\n", o.rollbackID)
	return nil
}

func emitPlan(o options, conf string, out io.Writer) {
	if o.output == "json" {
		return
	}
	fmt.Fprint(out, "\nPlanned connection (secrets are never displayed):\n\n")
	fmt.Fprintln(out, conf)
	fmt.Fprintf(out, "Files: %s, %s\n", o.conf, o.secrets)
	if o.caCert != "" {
		fingerprint, _ := certificateFingerprint(o.caCert)
		fmt.Fprintf(out, "CA: %s\nCA SHA-256: %s\n", caTarget(o), fingerprint)
	}
}
func emitResult(o options, out io.Writer, status string) {
	if o.output == "json" {
		_ = json.NewEncoder(out).Encode(map[string]string{"status": status, "connection": o.name, "profile": o.profile, "ipsec_conf": o.conf, "ipsec_secrets": o.secrets})
		return
	}
	fmt.Fprintf(out, "Result: %s\n", status)
}

func hydrateSecrets(o *options) error {
	if o.password != "" && o.passwordFile != "" {
		return errors.New("use only one of --password and --password-file")
	}
	if o.psk != "" && o.pskFile != "" {
		return errors.New("use only one of --psk and --psk-file")
	}
	if o.passwordFile != "" {
		value, err := readSecretFile(o.passwordFile)
		if err != nil {
			return err
		}
		o.password = value
	}
	if o.pskFile != "" {
		value, err := readSecretFile(o.pskFile)
		if err != nil {
			return err
		}
		o.psk = value
	}
	return nil
}

func readSecretFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("secret file %s must be a regular file with mode 0600 or stricter", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
}

func collectInteractive(o *options, in *bufio.Reader, terminal bool, out io.Writer) error {
	reader := in
	ask := func(label, current string, secret bool) (string, error) {
		if current != "" {
			return current, nil
		}
		fmt.Fprintf(out, "%s: ", label)
		if secret && terminal {
			_ = exec.Command("stty", "-echo").Run()
			defer func() { _ = exec.Command("stty", "echo").Run(); fmt.Fprintln(out) }()
		}
		value, err := reader.ReadString('\n')
		if err != nil && len(value) == 0 {
			return "", err
		}
		return strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"), nil
	}
	value, err := ask("Profile (eap, psk-client, site-to-site)", string(o.profile), false)
	if err != nil {
		return err
	}
	o.profile = value
	o.name, err = ask("Connection name", o.name, false)
	if err != nil {
		return err
	}
	o.gateway, err = ask("VPN gateway", o.gateway, false)
	if err != nil {
		return err
	}
	o.remoteID, err = ask("Expected remote IKE identity", o.remoteID, false)
	if err != nil {
		return err
	}
	switch o.profile {
	case string(eap):
		o.username, err = ask("EAP username", o.username, false)
		if err != nil {
			return err
		}
		o.password, err = ask("EAP password", o.password, true)
		if err != nil {
			return err
		}
		o.remoteTS, err = ask("Remote protected CIDRs (use --full-tunnel for default routes)", o.remoteTS, false)
		if err != nil {
			return err
		}
		o.caCert, err = ask("CA certificate path", o.caCert, false)
	case string(pskClient):
		o.psk, err = ask("Pre-shared key", o.psk, true)
		if err != nil {
			return err
		}
		o.remoteTS, err = ask("Remote protected CIDRs (use --full-tunnel for default routes)", o.remoteTS, false)
	case string(site):
		o.localTS, err = ask("Local protected CIDR", o.localTS, false)
		if err != nil {
			return err
		}
		o.remoteTS, err = ask("Remote protected CIDR", o.remoteTS, false)
		if err != nil {
			return err
		}
		o.psk, err = ask("Pre-shared key", o.psk, true)
	}
	return err
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var hostRE = regexp.MustCompile(`^[A-Za-z0-9._:%-]+$`)
var specialIdentityRE = regexp.MustCompile(`^%[A-Za-z0-9_.:-]+$`)
var proposalRE = regexp.MustCompile(`^[A-Za-z0-9_,!+.-]+$`)

func validate(o *options) error {
	if o.profile != string(eap) && o.profile != string(pskClient) && o.profile != string(site) {
		return errors.New("--profile must be eap, psk-client, or site-to-site")
	}
	if !nameRE.MatchString(o.name) {
		return errors.New("--name contains invalid characters")
	}
	if !hostRE.MatchString(o.gateway) {
		return errors.New("--gateway must be a hostname or IP address without spaces")
	}
	if o.remoteID == "" {
		return errors.New("--remote-id is required; do not guess gateway identity")
	}
	if o.remoteID == "%any" && !o.allowAnyRemoteID {
		return errors.New("remote identity %any is unsafe; use the certificate identity or explicitly pass --allow-any-remote-id")
	}
	for label, value := range map[string]string{"remote identity": o.remoteID, "local identity": o.localID, "username": o.username} {
		if strings.ContainsAny(value, "\r\n#") {
			return fmt.Errorf("%s contains unsafe characters", label)
		}
	}
	for label, value := range map[string]string{"IKE proposal": o.ike, "ESP proposal": o.esp} {
		if !proposalRE.MatchString(value) {
			return fmt.Errorf("%s contains unsupported characters", label)
		}
	}
	for label, value := range map[string]string{"password": o.password, "pre-shared key": o.psk} {
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s may not contain a newline", label)
		}
	}
	if o.profile == string(eap) {
		if o.username == "" || o.password == "" {
			return errors.New("EAP requires --username and --password")
		}
		if o.caCert == "" && !o.useSystemCA {
			return errors.New("EAP requires --ca-cert; --use-system-ca is an explicit trust-store override")
		}
	}
	if (o.profile == string(pskClient) || o.profile == string(site)) && o.psk == "" {
		return errors.New("PSK profiles require --psk")
	}
	if o.profile == string(site) && o.localTS == "" {
		return errors.New("site-to-site requires --local-ts")
	}
	if o.remoteTS == "" {
		return errors.New("--remote-ts is required; use --full-tunnel to allow default routes")
	}
	if err := validateSelectors("remote traffic selector", o.remoteTS, o.fullTunnel); err != nil {
		return err
	}
	if o.localTS != "" {
		if err := validateSelectors("local traffic selector", o.localTS, false); err != nil {
			return err
		}
	}
	if o.caCert != "" {
		if _, err := certificateFingerprint(o.caCert); err != nil {
			return err
		}
	}
	return nil
}
func validateSelectors(label, raw string, fullTunnel bool) error {
	for _, selector := range strings.Split(raw, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(selector))
		if err != nil {
			return fmt.Errorf("%s contains invalid CIDR %q", label, selector)
		}
		if (p == netip.MustParsePrefix("0.0.0.0/0") || p == netip.MustParsePrefix("::/0")) && !fullTunnel {
			return fmt.Errorf("%s includes a default route; pass --full-tunnel to acknowledge it", label)
		}
	}
	return nil
}

func escape(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value)
}
func identity(value string) string {
	if specialIdentityRE.MatchString(value) {
		return value
	}
	return `"` + escape(value) + `"`
}
func render(o options) (string, string) {
	auto := "add"
	if o.start {
		auto = "start"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# BEGIN strongswan-setup %s\nconn %s\n    keyexchange=ikev2\n    type=tunnel\n    auto=%s\n    left=%%defaultroute\n", o.name, o.name, auto)
	fmt.Fprintf(&b, "    ike=%s\n    esp=%s\n    ikelifetime=8h\n    lifetime=1h\n    rekeymargin=3m\n", o.ike, o.esp)
	switch o.profile {
	case string(eap):
		fmt.Fprintf(&b, "    leftsourceip=%%config\n    leftauth=eap-mschapv2\n    leftid=%s\n    eap_identity=%s\n    right=%s\n    rightid=%s\n    rightauth=pubkey\n    rightsubnet=%s\n", identity(o.username), identity(o.username), o.gateway, identity(o.remoteID), o.remoteTS)
	case string(pskClient):
		fmt.Fprintf(&b, "    leftsourceip=%%config\n    leftid=%s\n    leftauth=psk\n    right=%s\n    rightid=%s\n    rightauth=psk\n    rightsubnet=%s\n", identity(o.localID), o.gateway, identity(o.remoteID), o.remoteTS)
	case string(site):
		fmt.Fprintf(&b, "    leftid=%s\n    leftsubnet=%s\n    leftauth=psk\n    right=%s\n    rightid=%s\n    rightsubnet=%s\n    rightauth=psk\n", identity(o.localID), o.localTS, o.gateway, identity(o.remoteID), o.remoteTS)
	}
	mobike := "yes"
	if o.profile == string(site) {
		mobike = "no"
	}
	fmt.Fprintf(&b, "    fragmentation=yes\n    mobike=%s\n    dpdaction=restart\n    dpddelay=30s\n    dpdtimeout=120s\n    closeaction=restart\n# END strongswan-setup %s\n", mobike, o.name)
	secret := "# BEGIN strongswan-setup " + o.name + "\n"
	if o.profile == string(eap) {
		secret += identity(o.username) + ` : EAP "` + escape(o.password) + "\"\n"
	} else {
		secret += identity(o.localID) + " " + identity(o.remoteID) + ` : PSK "` + escape(o.psk) + "\"\n"
	}
	return b.String(), secret + "# END strongswan-setup " + o.name + "\n"
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo strongswan-setup ...) so ownership and service state are reliable")
	}
	return nil
}
func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprintf(out, "%s [y/N]: ", prompt)
	var answer string
	_, _ = fmt.Fscanln(in, &answer)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}
func installPackages(r runner) error {
	if _, err := exec.LookPath("apt-get"); err == nil {
		if _, err := r.Run("apt-get", "update"); err != nil {
			return err
		}
		_, err := r.Run("apt-get", "install", "-y", "strongswan", "strongswan-pki", "libcharon-extra-plugins")
		return err
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		_, err := r.Run("dnf", "install", "-y", "strongswan")
		return err
	}
	if _, err := exec.LookPath("yum"); err == nil {
		_, err := r.Run("yum", "install", "-y", "strongswan")
		return err
	}
	return errors.New("no supported package manager found")
}

func detectLegacyService(r runner) (string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		if _, ipsecErr := exec.LookPath("ipsec"); ipsecErr == nil {
			return "", nil
		}
		return "", errors.New("neither systemctl nor ipsec is installed")
	}
	for _, unit := range []string{"strongswan-starter.service", "ipsec.service"} {
		if _, err := r.Run("systemctl", "cat", unit); err == nil {
			return unit, nil
		}
	}
	if err := refuseModernBackend(r); err != nil {
		return "", err
	}
	if _, err := exec.LookPath("ipsec"); err == nil {
		return "", nil
	}
	return "", errors.New("no legacy strongSwan starter service found")
}
func refuseModernBackend(r runner) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	if unit, err := r.Run("systemctl", "cat", "strongswan.service"); err == nil && strings.Contains(string(unit), "swanctl") {
		return errors.New("strongswan.service uses the modern swanctl backend; refusing to alter deprecated ipsec.conf")
	}
	return nil
}
func preflight(o options, r runner, out io.Writer) error {
	if strings.ContainsAny(o.gateway, ":") {
		if o.output == "text" {
			fmt.Fprintf(out, "Preflight: gateway is an IP literal: %s\n", o.gateway)
		}
	} else if ips, err := net.LookupHost(o.gateway); err != nil || len(ips) == 0 {
		return fmt.Errorf("gateway DNS lookup failed for %s: %w", o.gateway, err)
	} else {
		if o.output == "text" {
			fmt.Fprintf(out, "Preflight: %s resolves to %s\n", o.gateway, strings.Join(ips, ", "))
		}
	}
	version, err := r.Run("ipsec", "--version")
	if err != nil || !strings.Contains(strings.ToLower(string(version)), "strongswan") {
		return errors.New("ipsec command is not a detectable strongSwan legacy backend")
	}
	if _, err := exec.LookPath("ip"); err == nil {
		if route, routeErr := r.Run("ip", "route", "get", o.gateway); routeErr != nil {
			return fmt.Errorf("no route to VPN gateway %s", o.gateway)
		} else {
			if o.output == "text" {
				fmt.Fprintf(out, "Preflight route: %s\n", strings.TrimSpace(string(route)))
			}
		}
	}
	if o.profile == string(eap) {
		plugins, pluginErr := r.Run("ipsec", "listplugins")
		if pluginErr != nil || !strings.Contains(string(plugins), "eap-mschapv2") {
			return errors.New("EAP-MSCHAPv2 plugin is not available; install the distribution's extra charon plugins")
		}
	}
	if o.profile == string(site) {
		forwarding, forwardErr := r.Run("sysctl", "-n", "net.ipv4.ip_forward")
		if forwardErr != nil || strings.TrimSpace(string(forwarding)) != "1" {
			return errors.New("site-to-site requires net.ipv4.ip_forward=1; enable it explicitly before installation")
		}
	}
	if o.output == "text" {
		fmt.Fprintln(out, "Preflight: confirm UDP 500/4500, NAT, firewall, routes, system clock, and (for gateways) forwarding separately.")
	}
	return nil
}
func diagnostics(o options, service string, r runner, out io.Writer) error {
	fmt.Fprintf(out, "Readiness diagnostics for legacy service %q:\n", service)
	for _, check := range [][]string{
		{"sysctl", "-n", "net.ipv4.ip_forward"},
		{"sysctl", "-n", "net.ipv4.conf.all.rp_filter"},
		{"sysctl", "-n", "net.ipv4.conf.default.rp_filter"},
		{"ip", "-details", "link", "show", "type", "xfrm"},
	} {
		result, err := r.Run(check[0], check[1:]...)
		if err != nil {
			fmt.Fprintf(out, "  WARN %-38s unavailable\n", strings.Join(check, " "))
			continue
		}
		fmt.Fprintf(out, "  OK   %-38s %s\n", strings.Join(check, " "), strings.TrimSpace(string(result)))
	}
	fmt.Fprintln(out, "Review firewall/NAT policy manually: this program never changes it.")
	return nil
}

type snapshot struct {
	path, backup string
	existed      bool
	mode         os.FileMode
}

type backupFile struct {
	Path    string
	Existed bool
	Mode    uint32
}

type backupManifest struct{ Files []backupFile }

func writeManifest(backupDir, stamp string, snapshots ...snapshot) error {
	manifest := backupManifest{}
	for _, s := range snapshots {
		if s.path != "" {
			manifest.Files = append(manifest.Files, backupFile{Path: s.path, Existed: s.existed, Mode: uint32(s.mode.Perm())})
		}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(backupDir, stamp, "manifest.json"), data, 0600)
}

func takeSnapshot(path, backupDir, stamp string) (snapshot, error) {
	s := snapshot{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return s, fmt.Errorf("refusing to replace symlinked configuration file %s", path)
	}
	s.existed, s.mode = true, info.Mode()
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return s, err
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		return s, err
	}
	transactionDir := filepath.Join(backupDir, stamp)
	if err := os.MkdirAll(transactionDir, 0700); err != nil {
		return s, err
	}
	s.backup = filepath.Join(transactionDir, filepath.Base(path))
	return s, writeAtomic(s.backup, data, info.Mode().Perm())
}
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".strongswan-setup-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func restoreSecurityContext(path string) error {
	if _, err := exec.LookPath("restorecon"); err != nil {
		return nil
	}
	if output, err := exec.Command("restorecon", path).CombinedOutput(); err != nil {
		return fmt.Errorf("restore SELinux context for %s: %s", path, strings.TrimSpace(string(output)))
	}
	return nil
}
func (s snapshot) restore() error {
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := os.ReadFile(s.backup)
	if err != nil {
		return err
	}
	return writeAtomic(s.path, data, s.mode.Perm())
}
func managedReplace(existing, name, block string) (string, error) {
	begin, end := "# BEGIN strongswan-setup "+name, "# END strongswan-setup "+name
	var kept []string
	skipping := false
	blocks := 0
	for _, line := range strings.Split(existing, "\n") {
		if line == begin {
			if skipping || blocks > 0 {
				return "", fmt.Errorf("managed block for %q is malformed or duplicated", name)
			}
			skipping = true
			blocks++
			continue
		}
		if line == end {
			if !skipping {
				return "", fmt.Errorf("managed block for %q has an unmatched end marker", name)
			}
			skipping = false
			continue
		}
		if !skipping {
			kept = append(kept, line)
		}
	}
	if skipping {
		return "", fmt.Errorf("managed block for %q has no end marker", name)
	}
	result := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if result != "" {
		result += "\n\n"
	}
	return result + block, nil
}
func caTarget(o options) string {
	sum, _ := certificateFingerprint(o.caCert)
	return filepath.Join(o.caDir, "strongswan-setup-"+sum[:16]+".pem")
}
func certificateFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		if block, _ := pem.Decode(data); block != nil {
			cert, err = x509.ParseCertificate(block.Bytes)
		}
	}
	if err != nil {
		return "", fmt.Errorf("CA certificate %s is not parseable X.509: %w", path, err)
	}
	if !cert.IsCA {
		return "", fmt.Errorf("certificate %s is not marked as a certificate authority", path)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}
func apply(o options, renderedConf, renderedSecrets, service string, r runner, out io.Writer) (err error) {
	unlock, err := acquireLock(o.backupDir)
	if err != nil {
		return err
	}
	defer unlock()
	defer pruneBackups(o.backupDir)
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	confSnap, err := takeSnapshot(o.conf, o.backupDir, stamp)
	if err != nil {
		return err
	}
	secretsSnap, err := takeSnapshot(o.secrets, o.backupDir, stamp)
	if err != nil {
		return err
	}
	var caSnap snapshot
	if o.caCert != "" {
		caSnap, err = takeSnapshot(caTarget(o), o.backupDir, stamp)
		if err != nil {
			return err
		}
	}
	if err := writeManifest(o.backupDir, stamp, confSnap, secretsSnap, caSnap); err != nil {
		return err
	}
	rolledBack := false
	rollback := func(cause error) error {
		if rolledBack {
			return cause
		}
		rolledBack = true
		var recovery []error
		if o.caCert != "" {
			if err := caSnap.restore(); err != nil {
				recovery = append(recovery, fmt.Errorf("restore CA: %w", err))
			}
		}
		if err := secretsSnap.restore(); err != nil {
			recovery = append(recovery, fmt.Errorf("restore secrets: %w", err))
		}
		if err := confSnap.restore(); err != nil {
			recovery = append(recovery, fmt.Errorf("restore configuration: %w", err))
		}
		if len(recovery) == 0 {
			if err := restart(service, r); err != nil {
				recovery = append(recovery, err)
			}
		}
		if len(recovery) > 0 {
			return fmt.Errorf("%w; rollback incomplete: %w", cause, errors.Join(recovery...))
		}
		return fmt.Errorf("%w; previous configuration and daemon state restored", cause)
	}
	oldConf, _ := os.ReadFile(o.conf)
	oldSecrets, _ := os.ReadFile(o.secrets)
	newConf, err := managedReplace(string(oldConf), o.name, renderedConf)
	if err != nil {
		return err
	}
	newSecrets, err := managedReplace(string(oldSecrets), o.name, renderedSecrets)
	if err != nil {
		return err
	}
	if err = writeAtomic(o.conf, []byte(newConf), 0644); err != nil {
		return rollback(err)
	}
	if err = writeAtomic(o.secrets, []byte(newSecrets), 0600); err != nil {
		return rollback(err)
	}
	if o.caCert != "" {
		data, readErr := os.ReadFile(o.caCert)
		if readErr != nil {
			return rollback(readErr)
		}
		if err = writeAtomic(caTarget(o), data, 0644); err != nil {
			return rollback(err)
		}
	}
	paths := []string{o.conf, o.secrets}
	if o.caCert != "" {
		paths = append(paths, caTarget(o))
	}
	for _, path := range paths {
		if err := restoreSecurityContext(path); err != nil {
			return rollback(err)
		}
	}
	if output, checkErr := r.Run("ipsec", "checkconfig"); checkErr != nil {
		return rollback(fmt.Errorf("configuration validation failed: %s", strings.TrimSpace(string(output))))
	}
	if err = restart(service, r); err != nil {
		return rollback(err)
	}
	status, statusErr := r.Run("ipsec", "statusall")
	if statusErr != nil || !strings.Contains(string(status), o.name) {
		return rollback(errors.New("connection was not loaded after restart"))
	}
	if o.start && !strings.Contains(string(status), o.name+"[") {
		return rollback(errors.New("connection did not establish an IKE SA"))
	}
	if o.probeHost != "" && o.start {
		conn, dialErr := net.DialTimeout("tcp", o.probeHost, 5*time.Second)
		if dialErr != nil {
			return rollback(fmt.Errorf("health probe failed: %w", dialErr))
		}
		conn.Close()
	}
	if o.output == "text" {
		fmt.Fprintf(out, "Setup complete. Backup snapshots are in %s\nConnect: ipsec up %s\nStatus:  ipsec statusall\n", o.backupDir, o.name)
	}
	return nil
}
func acquireLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ".strongswan-setup.lock")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another strongswan-setup transaction is running")
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
func restart(service string, r runner) error {
	var output []byte
	var err error
	if service != "" {
		output, err = r.Run("systemctl", "restart", service)
	} else {
		output, err = r.Run("ipsec", "restart")
	}
	if err != nil {
		return fmt.Errorf("strongSwan restart failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}
func pruneBackups(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var transactions []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			transactions = append(transactions, entry)
		}
	}
	sort.Slice(transactions, func(i, j int) bool {
		a, _ := transactions[i].Info()
		b, _ := transactions[j].Info()
		return a.ModTime().After(b.ModTime())
	})
	for i, entry := range transactions {
		if i >= backupLimit {
			_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
		}
	}
}
