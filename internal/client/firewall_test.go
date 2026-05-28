package client_test

import (
	"context"
	"testing"

	"github.com/yellowhat/terraform-provider-hetznerrobot/internal/client"
)

//nolint:gochecknoglobals
var testFirewall = client.Firewall{
	IP:                       "1.2.3.4",
	WhitelistHetznerServices: true,
	Status:                   "active",
	Rules: client.FirewallRules{
		//exhaustruct:ignore
		Input: []client.FirewallRule{
			{
				Name:     "allow-ssh",
				SrcIP:    "0.0.0.0/0",
				DstPort:  "22",
				Protocol: "tcp",
				Action:   "accept",
			},
			{
				Name:     "allow-http",
				SrcIP:    "0.0.0.0/0",
				DstPort:  "80",
				Protocol: "tcp",
				Action:   "accept",
			},
		},
	},
}

// testFirewallIPv6 mirrors testFirewall with filter_ipv6 enabled and adds an
// IPv6 SSH rule alongside the IPv4 ones, to exercise SetFirewall's handling of
// the per-rule ip_version field and the top-level filter_ipv6 field on the
// wire. GET round-trip is covered by TestGetFirewall against the default v4
// fixture; the mock server returns a single fixed example so we can't easily
// vary the GET response per test, but POST request validation against the
// OpenAPI schema catches malformed payloads regardless.
//
//nolint:gochecknoglobals
var testFirewallIPv6 = client.Firewall{
	IP:                       "1.2.3.4",
	WhitelistHetznerServices: true,
	FilterIPv6:               true,
	Status:                   "active",
	Rules: client.FirewallRules{
		//exhaustruct:ignore
		Input: []client.FirewallRule{
			{
				IPVersion: "ipv4",
				Name:      "allow-ssh",
				SrcIP:     "0.0.0.0/0",
				DstPort:   "22",
				Protocol:  "tcp",
				Action:    "accept",
			},
			{
				IPVersion: "ipv4",
				Name:      "allow-http",
				SrcIP:     "0.0.0.0/0",
				DstPort:   "80",
				Protocol:  "tcp",
				Action:    "accept",
			},
			{
				IPVersion: "ipv6",
				Name:      "allow-ssh-v6",
				SrcIP:     "::/0",
				DstPort:   "22",
				Protocol:  "tcp",
				Action:    "accept",
			},
		},
	},
}

func TestGetFirewall(t *testing.T) {
	t.Parallel()

	server := mockServer()
	defer server.Close()

	client := client.New(&client.ProviderConfig{
		Username: testUsername,
		Password: testPassword,
		BaseURL:  server.URL,
	})

	firewall, err := client.GetFirewall(context.Background(), testFirewall.IP)
	if err != nil {
		t.Errorf("GetFirewall() error: %v", err)
	}

	if testFirewall.IP != firewall.IP {
		t.Errorf("IP: want %v, got %v", testFirewall.IP, firewall.IP)
	}

	if testFirewall.WhitelistHetznerServices != firewall.WhitelistHetznerServices {
		t.Errorf(
			"WhitelistHetznerServices: want %t, got %t",
			testFirewall.WhitelistHetznerServices,
			firewall.WhitelistHetznerServices,
		)
	}

	if testFirewall.Status != firewall.Status {
		t.Errorf("Status: want %v, got %v", testFirewall.Status, firewall.Status)
	}

	if len(testFirewall.Rules.Input) != len(firewall.Rules.Input) {
		t.Errorf(
			"Rules length: want %d, got %d",
			len(testFirewall.Rules.Input),
			len(firewall.Rules.Input),
		)
	}

	for i, wantRule := range testFirewall.Rules.Input {
		gotRule := firewall.Rules.Input[i]
		if wantRule.Name != gotRule.Name {
			t.Errorf("Rule[%d] Name: want %v, got %v", i, wantRule.Name, gotRule.Name)
		}

		if wantRule.SrcIP != gotRule.SrcIP {
			t.Errorf("Rule[%d] SrcIP: want %v, got %v", i, wantRule.SrcIP, gotRule.SrcIP)
		}

		if wantRule.DstPort != gotRule.DstPort {
			t.Errorf(
				"Rule[%d] DstPort: want %v, got %v",
				i,
				wantRule.DstPort,
				gotRule.DstPort,
			)
		}

		if wantRule.Protocol != gotRule.Protocol {
			t.Errorf(
				"Rule[%d] Protocol: want %v, got %v",
				i,
				wantRule.Protocol,
				gotRule.Protocol,
			)
		}

		if wantRule.Action != gotRule.Action {
			t.Errorf("Rule[%d] Action: want %v, got %v", i, wantRule.Action, gotRule.Action)
		}
	}
}

func TestSetFirewall(t *testing.T) {
	t.Parallel()

	server := mockServer()
	defer server.Close()

	client := client.New(&client.ProviderConfig{
		Username: testUsername,
		Password: testPassword,
		BaseURL:  server.URL,
	})

	err := client.SetFirewall(context.Background(), testFirewall)
	if err != nil {
		t.Errorf("SetFirewall() error: %v", err)
	}
}

// TestSetFirewallIPv6 exercises SetFirewall with the IPv6 fixture. The mock
// server validates the POST body against the OpenAPI schema, so a malformed
// filter_ipv6 / ip_version payload would fail validation and surface here.
func TestSetFirewallIPv6(t *testing.T) {
	t.Parallel()

	server := mockServer()
	defer server.Close()

	client := client.New(&client.ProviderConfig{
		Username: testUsername,
		Password: testPassword,
		BaseURL:  server.URL,
	})

	err := client.SetFirewall(context.Background(), testFirewallIPv6)
	if err != nil {
		t.Errorf("SetFirewall() error: %v", err)
	}
}
