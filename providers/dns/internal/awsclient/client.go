// Package awsclient provides a native AWS HTTP client implementation
// that replaces AWS SDK dependencies for DNS providers.
package awsclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
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

// LoadAWSCredentials loads AWS credentials from environment variables
func LoadAWSCredentials(region string) (*AWSCredentials, error) {
	creds := &AWSCredentials{
		Region: region,
	}

	// Load from environment variables
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		creds.AccessKeyID = accessKey
	}
	if secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey != "" {
		creds.SecretAccessKey = secretKey
	}
	if sessionToken := os.Getenv("AWS_SESSION_TOKEN"); sessionToken != "" {
		creds.SessionToken = sessionToken
	}
	if envRegion := os.Getenv("AWS_REGION"); envRegion != "" {
		creds.Region = envRegion
	}

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
	}

	if creds.Region == "" {
		creds.Region = "us-east-1" // Default region
	}

	return creds, nil
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
