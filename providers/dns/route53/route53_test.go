package route53

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/go-acme/lego/v4/providers/dns/internal/awsclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envDomain = "R53_DOMAIN"

var envTest = tester.NewEnvTest(
	EnvAccessKeyID,
	EnvSecretAccessKey,
	EnvRegion,
	EnvHostedZoneID,
	EnvMaxRetries,
	EnvPrivateZone,
	EnvTTL,
	EnvPropagationTimeout,
	EnvPollingInterval,
	EnvWaitForRecordSetsChanged).
	WithDomain(envDomain).
	WithLiveTestRequirements(EnvAccessKeyID, EnvSecretAccessKey, EnvRegion, envDomain)

func makeTestProvider(t *testing.T, serverURL string) *DNSProvider {
	t.Helper()

	creds := &awsclient.AWSCredentials{
		AccessKeyID:     "abc",
		SecretAccessKey: "123",
		SessionToken:    " ",
		Region:          "mock-region",
	}

	client := NewRoute53ClientWithEndpoint(creds, 1, serverURL)

	return &DNSProvider{
		client: client,
		config: NewDefaultConfig(),
	}
}

func Test_getHostedZoneID_FromEnv(t *testing.T) {
	defer envTest.RestoreEnv()
	envTest.ClearEnv()

	expectedZoneID := "zoneID"

	_ = os.Setenv(EnvHostedZoneID, expectedZoneID)
	_ = os.Setenv(EnvAccessKeyID, "test-key")
	_ = os.Setenv(EnvSecretAccessKey, "test-secret")

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	hostedZoneID, err := provider.getHostedZoneID(context.Background(), "whatever")
	require.NoError(t, err, "HostedZoneID")

	assert.Equal(t, expectedZoneID, hostedZoneID)
}

func TestNewDefaultConfig(t *testing.T) {
	defer envTest.RestoreEnv()

	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected *Config
	}{
		{
			desc: "default configuration",
			expected: &Config{
				MaxRetries:               5,
				TTL:                      10,
				PropagationTimeout:       2 * time.Minute,
				PollingInterval:          4 * time.Second,
				WaitForRecordSetsChanged: true,
			},
		},
		{
			desc: "set values",
			envVars: map[string]string{
				EnvMaxRetries:               "10",
				EnvTTL:                      "99",
				EnvPropagationTimeout:       "60",
				EnvPollingInterval:          "60",
				EnvHostedZoneID:             "abc123",
				EnvWaitForRecordSetsChanged: "false",
			},
			expected: &Config{
				MaxRetries:         10,
				TTL:                99,
				PropagationTimeout: 60 * time.Second,
				PollingInterval:    60 * time.Second,
				HostedZoneID:       "abc123",
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			envTest.ClearEnv()
			for key, value := range test.envVars {
				_ = os.Setenv(key, value)
			}

			config := NewDefaultConfig()

			assert.Equal(t, test.expected, config)
		})
	}
}

func TestDNSProvider_Present(t *testing.T) {
	mockResponses := MockResponseMap{
		"/2013-04-01/hostedzonesbyname":        {StatusCode: 200, Body: ListHostedZonesByNameResponseBody},
		"/2013-04-01/hostedzone/ABCDEFG/rrset": {StatusCode: 200, Body: ChangeResourceRecordSetsResponseBody},
		"/2013-04-01/change/123456":            {StatusCode: 200, Body: GetChangeResponseBody},
		"/2013-04-01/hostedzone/ABCDEFG/rrset?name=_acme-challenge.example.com.&type=TXT": {
			StatusCode: 200,
			Body:       "",
		},
	}

	serverURL := setupTest(t, mockResponses)

	defer envTest.RestoreEnv()
	envTest.ClearEnv()
	provider := makeTestProvider(t, serverURL)

	domain := "example.com"
	keyAuth := "123456d=="

	err := provider.Present(domain, "", keyAuth)
	require.NoError(t, err, "Expected Present to return no error")
}

func Test_loadAWSCredentials(t *testing.T) {
	testCases := []struct {
		desc      string
		env       map[string]string
		config    *Config
		wantCreds *awsclient.AWSCredentials
		wantErr   string
	}{
		{
			desc: "static credentials",
			config: &Config{
				AccessKeyID:     "one",
				SecretAccessKey: "two",
			},
			wantCreds: &awsclient.AWSCredentials{
				AccessKeyID:     "one",
				SecretAccessKey: "two",
				SessionToken:    "",
				Region:          "us-east-1",
			},
		},
		{
			desc: "static credentials with session token",
			config: &Config{
				AccessKeyID:     "one",
				SecretAccessKey: "two",
				SessionToken:    "three",
			},
			wantCreds: &awsclient.AWSCredentials{
				AccessKeyID:     "one",
				SecretAccessKey: "two",
				SessionToken:    "three",
				Region:          "us-east-1",
			},
		},
		{
			desc: "static credentials with region",
			config: &Config{
				AccessKeyID:     "one",
				SecretAccessKey: "two",
				Region:          "us-west-2",
			},
			wantCreds: &awsclient.AWSCredentials{
				AccessKeyID:     "one",
				SecretAccessKey: "two",
				SessionToken:    "",
				Region:          "us-west-2",
			},
		},
		{
			desc:   "credentials from env",
			config: &Config{},
			env: map[string]string{
				"AWS_ACCESS_KEY_ID":     "env-key",
				"AWS_SECRET_ACCESS_KEY": "env-secret",
				"AWS_REGION":            "env-region",
			},
			wantCreds: &awsclient.AWSCredentials{
				AccessKeyID:     "env-key",
				SecretAccessKey: "env-secret",
				SessionToken:    "",
				Region:          "env-region",
			},
		},
		{
			desc:    "missing credentials",
			config:  &Config{},
			env:     map[string]string{},
			wantErr: "AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.env)

			creds, err := loadAWSCredentials(test.config)
			requireErr(t, err, test.wantErr)

			if err != nil {
				return
			}

			assert.Equal(t, test.wantCreds, creds)
		})
	}
}

func requireErr(t *testing.T, err error, wantErr string) {
	t.Helper()

	switch {
	case err != nil && wantErr == "":
		// force the assertion error.
		require.NoError(t, err)

	case err == nil && wantErr != "":
		// force the assertion error.
		require.EqualError(t, err, wantErr)

	case err != nil && wantErr != "":
		require.EqualError(t, err, wantErr)
	}
}
