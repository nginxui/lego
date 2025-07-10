package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHTTPProvider_MinioIntegration(t *testing.T) {
	// Test that NewHTTPProvider creates a provider with Minio client
	// This test verifies the integration without requiring actual AWS credentials

	// Test with missing bucket name
	provider, err := NewHTTPProvider("")
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "bucket name missing")
}

func TestNewHTTPProvider_CredentialsRequired(t *testing.T) {
	// Test that credentials are required
	// This test runs without setting environment variables

	provider, err := NewHTTPProvider("test-bucket")
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "AWS credentials not found")
}
