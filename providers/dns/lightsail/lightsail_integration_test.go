package lightsail

import (
	"context"
	"testing"

	"github.com/go-acme/lego/v4/providers/dns/internal/awsclient"
	"github.com/stretchr/testify/require"
)

func TestLiveTTL(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	domain := envTest.GetDomain()

	err = provider.Present(domain, "foo", "bar")
	require.NoError(t, err)

	// we need a separate Lightsail client here as the one in the DNS provider is unexported.
	fqdn := "_acme-challenge." + domain

	ctx := context.Background()

	// Load credentials for verification
	config := &Config{Region: "us-east-1"}
	creds, err := loadAWSCredentials(config)
	require.NoError(t, err)

	// Create a client for verification
	client := NewLightsailClient(creds, maxRetries)

	defer func() {
		errC := provider.CleanUp(domain, "foo", "bar")
		if errC != nil {
			t.Log(errC)
		}
	}()

	request := &GetDomainRequest{
		DomainName: domain,
	}

	resp, err := client.GetDomain(ctx, request)
	require.NoError(t, err)

	entries := resp.Domain.DomainEntries
	for _, entry := range entries {
		if awsclient.StringValue(entry.Type) == "TXT" && awsclient.StringValue(entry.Name) == fqdn {
			return
		}
	}

	t.Fatalf("Could not find a TXT record for _acme-challenge.%s", domain)
}
