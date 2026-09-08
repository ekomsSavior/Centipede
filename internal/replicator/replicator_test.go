package replicator

import (
	"strings"
	"testing"
)

func TestCloudDefaultUsers(t *testing.T) {
	cases := map[string]bool{
		"aws":   false,
		"azure": false,
		"gcp":   false,
	}
	for provider := range cases {
		users := cloudDefaultUsers(provider)
		if len(users) == 0 {
			t.Fatalf("no default users for %s", provider)
		}
		cases[provider] = true
	}
	// provider-specific defaults must not be identical to the generic list
	aws := strings.Join(cloudDefaultUsers("aws"), ",")
	if !strings.Contains(aws, "ec2-user") {
		t.Fatalf("aws defaults should include ec2-user: %s", aws)
	}
	az := strings.Join(cloudDefaultUsers("azure"), ",")
	if !strings.Contains(az, "azureuser") {
		t.Fatalf("azure defaults should include azureuser: %s", az)
	}
}

func TestExtractSSHPrivateKeys(t *testing.T) {
	userdata := `#!/bin/bash
echo provisioning
cat > /home/ec2-user/.ssh/id_ed25519 <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
ZmFrZWtleQ==
-----END OPENSSH PRIVATE KEY-----
EOF
`
	keys := extractSSHPrivateKeys(userdata)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from user-data, got %d", len(keys))
	}
	if !strings.Contains(keys[0], "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("unexpected key payload: %q", keys[0])
	}
	// lowercase marker handling: openssh keys use "openssh" as the marker
	if !strings.Contains(strings.ToLower(keys[0]), "-----begin openssh private key-----") {
		t.Fatalf("lowercase marker parse failed")
	}
	if got := extractSSHPrivateKeys("no keys here"); len(got) != 0 {
		t.Fatalf("expected no keys, got %d", len(got))
	}
}

func TestDirectedSpreadBadVector(t *testing.T) {
	r := New()
	_, err := r.DirectedSpread("10.0.0.1", "carrier-pigeon", "", "")
	if err == nil {
		t.Fatal("expected unsupported vector error")
	}
	if !strings.Contains(err.Error(), "unsupported vector") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDirectedSpreadRequiresTarget(t *testing.T) {
	r := New()
	if _, err := r.DirectedSpread("", "ssh-key", "", ""); err == nil {
		t.Fatal("expected missing-target error")
	}
}
