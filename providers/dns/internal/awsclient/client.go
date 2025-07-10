// Package awsclient provides a native AWS HTTP client implementation
// that replaces AWS SDK dependencies for DNS providers.
package awsclient

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AWSCredentials holds AWS authentication credentials
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	ExpiresAt       time.Time // For temporary credentials
	Source          string    // Debug: source of credentials
}

// IsExpired checks if temporary credentials have expired
func (c *AWSCredentials) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false // Permanent credentials don't expire
	}
	return time.Now().After(c.ExpiresAt.Add(-10 * time.Minute)) // Refresh 10 minutes before expiry
}

// IsTemporary returns true if these are temporary credentials
func (c *AWSCredentials) IsTemporary() bool {
	return c.SessionToken != ""
}

// Validate checks if credentials are properly configured
func (c *AWSCredentials) Validate() error {
	if c.AccessKeyID == "" {
		return fmt.Errorf("AWS Access Key ID is empty")
	}
	if c.SecretAccessKey == "" {
		return fmt.Errorf("AWS Secret Access Key is empty")
	}
	if c.Region == "" {
		return fmt.Errorf("AWS Region is empty")
	}
	if c.IsExpired() {
		return fmt.Errorf("AWS credentials have expired (source: %s)", c.Source)
	}
	return nil
}

// AWSClient provides common AWS API functionality
type AWSClient struct {
	credentials *AWSCredentials
	httpClient  *http.Client
	endpoint    string
	service     string
	maxRetries  int
}

// NewAWSClient creates a new AWS client
func NewAWSClient(creds *AWSCredentials, service, endpoint string, maxRetries int) *AWSClient {
	return &AWSClient{
		credentials: creds,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		endpoint:    endpoint,
		service:     service,
		maxRetries:  maxRetries,
	}
}

// LoadAWSCredentials loads AWS credentials from various sources following AWS credential chain
func LoadAWSCredentials(region string) (*AWSCredentials, error) {
	creds := &AWSCredentials{
		Region: region,
	}

	// Step 1: Try environment variables first
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		if secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey != "" {
			creds.AccessKeyID = accessKey
			creds.SecretAccessKey = secretKey
			creds.Source = "environment_variables"
			
			// Optional session token for temporary credentials
			if sessionToken := os.Getenv("AWS_SESSION_TOKEN"); sessionToken != "" {
				creds.SessionToken = sessionToken
				creds.Source = "environment_variables_with_session_token"
			}
			
			// Optional region override
			if envRegion := os.Getenv("AWS_REGION"); envRegion != "" {
				creds.Region = envRegion
			}
			
			if creds.Region == "" {
				creds.Region = "us-east-1" // Default region
			}
			
			// Validate credentials before returning
			if err := creds.Validate(); err != nil {
				return nil, fmt.Errorf("invalid credentials from environment: %w", err)
			}
			
			return creds, nil
		}
	}

	// Step 2: Try shared credentials file
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "default"
	}
	
	if sharedCreds, err := loadSharedCredentials(profile); err == nil {
		creds.AccessKeyID = sharedCreds.AccessKeyID
		creds.SecretAccessKey = sharedCreds.SecretAccessKey
		creds.SessionToken = sharedCreds.SessionToken
		creds.Source = fmt.Sprintf("shared_credentials_file_profile_%s", profile)
		
		// Use provided region or fall back to shared config
		if creds.Region == "" {
			if sharedRegion, _ := loadSharedRegion(profile); sharedRegion != "" {
				creds.Region = sharedRegion
			}
		}
		
		if creds.Region == "" {
			creds.Region = "us-east-1" // Default region
		}
		
		// Validate credentials before returning
		if err := creds.Validate(); err != nil {
			return nil, fmt.Errorf("invalid credentials from shared file: %w", err)
		}
		
		return creds, nil
	}

	// Step 3: Try container/instance metadata (EC2 IAM roles)
	if instanceCreds, err := loadInstanceCredentials(); err == nil {
		creds.AccessKeyID = instanceCreds.AccessKeyID
		creds.SecretAccessKey = instanceCreds.SecretAccessKey
		creds.SessionToken = instanceCreds.SessionToken
		creds.Source = "instance_metadata"
		
		if creds.Region == "" {
			if instanceRegion, _ := getInstanceRegion(); instanceRegion != "" {
				creds.Region = instanceRegion
			}
		}
		
		if creds.Region == "" {
			creds.Region = "us-east-1" // Default region
		}
		
		// Validate credentials before returning
		if err := creds.Validate(); err != nil {
			return nil, fmt.Errorf("invalid credentials from instance metadata: %w", err)
		}
		
		return creds, nil
	}

	return nil, fmt.Errorf("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables, configure shared credentials file (~/.aws/credentials), or use an IAM role")
}

// loadSharedCredentials loads credentials from shared credentials file
func loadSharedCredentials(profile string) (*AWSCredentials, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Check for custom credentials file path
	credFile := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credFile == "" {
		credFile = filepath.Join(homeDir, ".aws", "credentials")
	}

	file, err := os.Open(credFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentProfile string
	creds := &AWSCredentials{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for profile section
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentProfile = strings.Trim(line, "[]")
			continue
		}

		// Parse key-value pairs
		if currentProfile == profile && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "aws_access_key_id":
					creds.AccessKeyID = value
				case "aws_secret_access_key":
					creds.SecretAccessKey = value
				case "aws_session_token":
					creds.SessionToken = value
				}
			}
		}
	}

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("incomplete credentials in profile %s", profile)
	}

	return creds, nil
}

// loadSharedRegion loads region from shared config file
func loadSharedRegion(profile string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Check for custom config file path
	configFile := os.Getenv("AWS_CONFIG_FILE")
	if configFile == "" {
		configFile = filepath.Join(homeDir, ".aws", "config")
	}

	file, err := os.Open(configFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentProfile string
	targetProfile := profile
	if targetProfile == "default" {
		targetProfile = "default"
	} else {
		targetProfile = "profile " + profile
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentProfile = strings.Trim(line, "[]")
			continue
		}

		if currentProfile == targetProfile && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				if key == "region" {
					return value, nil
				}
			}
		}
	}

	return "", fmt.Errorf("region not found in profile %s", profile)
}

// loadInstanceCredentials loads credentials from EC2 instance metadata
func loadInstanceCredentials() (*AWSCredentials, error) {
	// Check for ECS container credentials first
	if credURI := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); credURI != "" {
		return loadContainerCredentials(credURI)
	}

	// Check for EC2 instance metadata
	return loadEC2Credentials()
}

// loadContainerCredentials loads credentials from ECS container metadata
func loadContainerCredentials(relativeURI string) (*AWSCredentials, error) {
	// This is a simplified implementation
	// In a full implementation, you would make HTTP requests to the metadata endpoint
	return nil, fmt.Errorf("container credentials not implemented")
}

// loadEC2Credentials loads credentials from EC2 instance metadata
func loadEC2Credentials() (*AWSCredentials, error) {
	// This is a simplified implementation
	// In a full implementation, you would make HTTP requests to the instance metadata service
	return nil, fmt.Errorf("EC2 instance credentials not implemented")
}

// getInstanceRegion gets the region from EC2 instance metadata
func getInstanceRegion() (string, error) {
	// This is a simplified implementation
	// In a full implementation, you would query the instance metadata service
	return "", fmt.Errorf("instance region not implemented")
}

// SignRequest signs an HTTP request using AWS Signature Version 4
func (c *AWSClient) SignRequest(req *http.Request, body []byte) error {
	now := time.Now().UTC()

	// Set required headers for signing
	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))

	if c.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.credentials.SessionToken)
	}

	// Create canonical request
	canonicalRequest := c.createCanonicalRequest(req, body)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request",
		now.Format("20060102"), c.credentials.Region, c.service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		now.Format("20060102T150405Z"),
		credentialScope,
		c.sha256Hash(canonicalRequest))

	// Calculate signature
	signature := c.calculateSignature(stringToSign, now)

	// Set authorization header
	authorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.credentials.AccessKeyID,
		credentialScope,
		c.getSignedHeaders(req),
		signature)

	req.Header.Set("Authorization", authorization)

	return nil
}

// createCanonicalRequest creates the canonical request for AWS Signature Version 4
func (c *AWSClient) createCanonicalRequest(req *http.Request, body []byte) string {
	// HTTP method
	method := req.Method

	// Canonical URI
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical query string
	canonicalQueryString := req.URL.RawQuery
	if canonicalQueryString != "" {
		// Parse and sort query parameters
		values, _ := url.ParseQuery(canonicalQueryString)
		var sortedParams []string
		for key, vals := range values {
			for _, val := range vals {
				sortedParams = append(sortedParams, fmt.Sprintf("%s=%s",
					url.QueryEscape(key), url.QueryEscape(val)))
			}
		}
		sort.Strings(sortedParams)
		canonicalQueryString = strings.Join(sortedParams, "&")
	}

	// Canonical headers
	canonicalHeaders := c.getCanonicalHeaders(req)

	// Signed headers
	signedHeaders := c.getSignedHeaders(req)

	// Payload hash
	var payloadHash string
	if body != nil {
		payloadHash = c.sha256Hash(string(body))
	} else {
		payloadHash = c.sha256Hash("")
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, canonicalURI, canonicalQueryString,
		canonicalHeaders, signedHeaders, payloadHash)
}

// getCanonicalHeaders returns the canonical headers string
func (c *AWSClient) getCanonicalHeaders(req *http.Request) string {
	var headers []string
	for name, values := range req.Header {
		name = strings.ToLower(name)
		for _, value := range values {
			headers = append(headers, fmt.Sprintf("%s:%s", name, strings.TrimSpace(value)))
		}
	}
	sort.Strings(headers)
	return strings.Join(headers, "\n") + "\n"
}

// getSignedHeaders returns the signed headers string
func (c *AWSClient) getSignedHeaders(req *http.Request) string {
	var headers []string
	for name := range req.Header {
		headers = append(headers, strings.ToLower(name))
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

// calculateSignature calculates the AWS Signature Version 4 signature
func (c *AWSClient) calculateSignature(stringToSign string, now time.Time) string {
	dateKey := c.hmacSHA256([]byte("AWS4"+c.credentials.SecretAccessKey), now.Format("20060102"))
	regionKey := c.hmacSHA256(dateKey, c.credentials.Region)
	serviceKey := c.hmacSHA256(regionKey, c.service)
	signingKey := c.hmacSHA256(serviceKey, "aws4_request")
	signature := c.hmacSHA256(signingKey, stringToSign)
	return hex.EncodeToString(signature)
}

// hmacSHA256 computes HMAC-SHA256
func (c *AWSClient) hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// sha256Hash computes SHA256 hash
func (c *AWSClient) sha256Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// StringPtr returns a pointer to the string value
func StringPtr(s string) *string {
	return &s
}

// BoolPtr returns a pointer to the bool value
func BoolPtr(b bool) *bool {
	return &b
}

// StringValue returns the value of the string pointer or empty string if nil
func StringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Endpoint returns the client endpoint
func (c *AWSClient) Endpoint() string {
	return c.endpoint
}

// Do executes the HTTP request
func (c *AWSClient) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}
