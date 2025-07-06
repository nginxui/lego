package lightsail

import (
	"os"
	"testing"

	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/go-acme/lego/v4/providers/dns/internal/awsclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	envAwsNamespace = "AWS_"

	envAwsAccessKeyID     = envAwsNamespace + "ACCESS_KEY_ID"
	envAwsSecretAccessKey = envAwsNamespace + "SECRET_ACCESS_KEY"
	envAwsRegion          = envAwsNamespace + "REGION"
	envAwsHostedZoneID    = envAwsNamespace + "HOSTED_ZONE_ID"
)

var envTest = tester.NewEnvTest(
	envAwsAccessKeyID,
	envAwsSecretAccessKey,
	envAwsRegion,
	envAwsHostedZoneID).
	WithDomain(EnvDNSZone).
	WithLiveTestRequirements(envAwsAccessKeyID, envAwsSecretAccessKey, EnvDNSZone)

func makeProvider(serverURL string) *DNSProvider {
	creds := &awsclient.AWSCredentials{
		AccessKeyID:     "abc",
		SecretAccessKey: "123",
		SessionToken:    "",
		Region:          "mock-region",
	}

	client := NewLightsailClient(creds, 1)
	// Override endpoint for testing
	client.awsClient = awsclient.NewAWSClient(creds, "lightsail", serverURL, 1)

	return &DNSProvider{
		client: client,
		config: NewDefaultConfig(),
	}
}

func TestCredentialsFromEnv(t *testing.T) {
	defer envTest.RestoreEnv()
	envTest.ClearEnv()

	_ = os.Setenv(envAwsAccessKeyID, "test-access-key")
	_ = os.Setenv(envAwsSecretAccessKey, "test-secret-key")
	_ = os.Setenv("AWS_REGION", "us-east-1")

	config := &Config{
		Region: "us-east-1",
	}

	creds, err := loadAWSCredentials(config)
	require.NoError(t, err, "Expected credentials to be loaded from environment")

	expected := &awsclient.AWSCredentials{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		SessionToken:    "",
		Region:          "us-east-1",
	}
	assert.Equal(t, expected, creds)
}

func TestDNSProvider_Present(t *testing.T) {
	mockResponses := map[string]MockResponse{
		"/": {StatusCode: 200, Body: `{"operation":{"id":"test-operation-id","status":"Succeeded","isTerminal":true}}`},
	}

	serverURL := newMockServer(t, mockResponses)

	provider := makeProvider(serverURL)

	domain := "example.com"
	keyAuth := "123456d=="

	err := provider.Present(domain, "", keyAuth)
	require.NoError(t, err, "Expected Present to return no error")
}

func TestDNSProvider_CleanUp(t *testing.T) {
	mockResponses := map[string]MockResponse{
		"/": {StatusCode: 200, Body: `{"operation":{"id":"test-operation-id","status":"Succeeded","isTerminal":true}}`},
	}

	serverURL := newMockServer(t, mockResponses)

	provider := makeProvider(serverURL)

	domain := "example.com"
	keyAuth := "123456d=="

	err := provider.CleanUp(domain, "", keyAuth)
	require.NoError(t, err, "Expected CleanUp to return no error")
}
