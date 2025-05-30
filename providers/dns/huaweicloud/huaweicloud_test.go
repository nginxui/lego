package huaweicloud

import (
	"testing"
	"time"

	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/stretchr/testify/require"
)

const envDomain = envNamespace + "DOMAIN"

var envTest = tester.NewEnvTest(EnvAccessKeyID, EnvSecretAccessKey, EnvRegion).
	WithLiveTestRequirements(EnvAccessKeyID, EnvSecretAccessKey).
	WithDomain(envDomain)

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		// The "success" cannot be tested because there is an API call that require a valid authentication.
		{
			desc: "missing credentials",
			envVars: map[string]string{
				EnvAccessKeyID:     "",
				EnvSecretAccessKey: "",
				EnvRegion:          "",
			},
			expected: "huaweicloud: some credentials information are missing: HUAWEICLOUD_ACCESS_KEY_ID,HUAWEICLOUD_SECRET_ACCESS_KEY",
		},
		{
			desc: "missing access id",
			envVars: map[string]string{
				EnvAccessKeyID:     "",
				EnvSecretAccessKey: "456",
				EnvRegion:          "cn-east-2",
			},
			expected: "huaweicloud: some credentials information are missing: HUAWEICLOUD_ACCESS_KEY_ID",
		},
		{
			desc: "missing secret key",
			envVars: map[string]string{
				EnvAccessKeyID:     "123",
				EnvSecretAccessKey: "",
				EnvRegion:          "cn-east-2",
			},
			expected: "huaweicloud: some credentials information are missing: HUAWEICLOUD_SECRET_ACCESS_KEY",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if test.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.provider)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc            string
		accessKeyID     string
		secretAccessKey string
		region          string
		expected        string
	}{
		// The "success" cannot be tested because there is an API call that require a valid authentication.
		{
			desc:     "missing credentials",
			expected: "huaweicloud: credentials missing",
		},
		{
			desc:            "missing secret id",
			secretAccessKey: "456",
			region:          "cn-east-2",
			expected:        "huaweicloud: credentials missing",
		},
		{
			desc:        "missing secret key",
			accessKeyID: "123",
			region:      "cn-east-2",
			expected:    "huaweicloud: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.AccessKeyID = test.accessKeyID
			config.SecretAccessKey = test.secretAccessKey
			config.Region = test.region

			p, err := NewDNSProviderConfig(config)

			if test.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.provider)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestLivePresent(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
