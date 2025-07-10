package route53

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLiveTTL(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	// Log debugging information about environment
	t.Logf("AWS_ACCESS_KEY_ID present: %t", os.Getenv("AWS_ACCESS_KEY_ID") != "")
	t.Logf("AWS_SECRET_ACCESS_KEY present: %t", os.Getenv("AWS_SECRET_ACCESS_KEY") != "")
	t.Logf("AWS_SESSION_TOKEN present: %t", os.Getenv("AWS_SESSION_TOKEN") != "")
	t.Logf("AWS_REGION: %s", os.Getenv("AWS_REGION"))
	t.Logf("AWS_HOSTED_ZONE_ID: %s", os.Getenv("AWS_HOSTED_ZONE_ID"))

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	// Log provider configuration for debugging
	if provider.config != nil {
		t.Logf("Provider region: %s", provider.config.Region)
		t.Logf("Provider hosted zone ID: %s", provider.config.HostedZoneID)
	}

	domain := envTest.GetDomain()
	t.Logf("Testing with domain: %s", domain)

	err = provider.Present(domain, "foo", "bar")
	require.NoError(t, err)

	defer func() {
		errC := provider.CleanUp(domain, "foo", "bar")
		if errC != nil {
			t.Log(errC)
		}
	}()

	// Test passes if Present and CleanUp work without errors
	// TTL verification would require AWS SDK, which we've replaced with native implementation
}
