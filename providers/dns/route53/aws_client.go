package route53

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/providers/dns/internal/awsclient"
)

// AWS Route53 API types
type ResourceRecord struct {
	Value *string `xml:"Value"`
}

type ResourceRecordSet struct {
	Name            *string          `xml:"Name"`
	Type            string           `xml:"Type"`
	TTL             *int64           `xml:"TTL"`
	ResourceRecords []ResourceRecord `xml:"ResourceRecords>ResourceRecord"`
}

type Change struct {
	Action            string             `xml:"Action"`
	ResourceRecordSet *ResourceRecordSet `xml:"ResourceRecordSet"`
}

type ChangeBatch struct {
	Comment string   `xml:"Comment"`
	Changes []Change `xml:"Changes>Change"`
}

type ChangeResourceRecordSetsRequest struct {
	XMLName     xml.Name     `xml:"ChangeResourceRecordSetsRequest"`
	Xmlns       string       `xml:"xmlns,attr"`
	ChangeBatch *ChangeBatch `xml:"ChangeBatch"`
}

type ChangeInfo struct {
	Id     *string `xml:"Id"`
	Status string  `xml:"Status"`
}

type ChangeResourceRecordSetsResponse struct {
	ChangeInfo *ChangeInfo `xml:"ChangeInfo"`
}

type GetChangeResponse struct {
	ChangeInfo *ChangeInfo `xml:"ChangeInfo"`
}

type HostedZone struct {
	Id     *string `xml:"Id"`
	Name   *string `xml:"Name"`
	Config struct {
		PrivateZone bool `xml:"PrivateZone"`
	} `xml:"Config"`
}

type ListHostedZonesByNameResponse struct {
	HostedZones []HostedZone `xml:"HostedZones>HostedZone"`
}

type ListResourceRecordSetsResponse struct {
	ResourceRecordSets []ResourceRecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
}

// Route53Client represents a native Route53 client
type Route53Client struct {
	client *awsclient.AWSClient
}

// NewRoute53Client creates a new Route53 client
func NewRoute53Client(creds *awsclient.AWSCredentials, maxRetries int) *Route53Client {
	client := awsclient.NewAWSClient(creds, "route53", "https://route53.amazonaws.com", maxRetries)
	return &Route53Client{
		client: client,
	}
}

// NewRoute53ClientWithEndpoint creates a new Route53 client with custom endpoint (for testing)
func NewRoute53ClientWithEndpoint(creds *awsclient.AWSCredentials, maxRetries int, endpoint string) *Route53Client {
	client := awsclient.NewAWSClient(creds, "route53", endpoint, maxRetries)
	return &Route53Client{
		client: client,
	}
}

// ChangeResourceRecordSets calls the Route53 ChangeResourceRecordSets API
func (c *Route53Client) ChangeResourceRecordSets(ctx context.Context, hostedZoneID string, request *ChangeResourceRecordSetsRequest) (*ChangeResourceRecordSetsResponse, error) {
	path := fmt.Sprintf("/2013-04-01/hostedzone/%s/rrset", hostedZoneID)

	body, err := xml.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.makeRequest(ctx, "POST", path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response ChangeResourceRecordSetsResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// GetChange calls the Route53 GetChange API
func (c *Route53Client) GetChange(ctx context.Context, changeID string) (*GetChangeResponse, error) {
	// Remove /change/ prefix if present
	changeID = strings.TrimPrefix(changeID, "/change/")
	path := fmt.Sprintf("/2013-04-01/change/%s", changeID)

	resp, err := c.makeRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response GetChangeResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// ListResourceRecordSets calls the Route53 ListResourceRecordSets API
func (c *Route53Client) ListResourceRecordSets(ctx context.Context, hostedZoneID, startRecordName, startRecordType string) (*ListResourceRecordSetsResponse, error) {
	path := fmt.Sprintf("/2013-04-01/hostedzone/%s/rrset", hostedZoneID)

	params := url.Values{}
	if startRecordName != "" {
		params.Set("name", startRecordName)
	}
	if startRecordType != "" {
		params.Set("type", startRecordType)
	}

	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	resp, err := c.makeRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response ListResourceRecordSetsResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// ListHostedZonesByName calls the Route53 ListHostedZonesByName API
func (c *Route53Client) ListHostedZonesByName(ctx context.Context, dnsName string) (*ListHostedZonesByNameResponse, error) {
	path := "/2013-04-01/hostedzonesbyname"

	params := url.Values{}
	if dnsName != "" {
		params.Set("dnsname", dnsName)
	}

	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	resp, err := c.makeRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response ListHostedZonesByNameResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// makeRequest makes an HTTP request with AWS Signature Version 4 authentication
func (c *Route53Client) makeRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	u, err := url.Parse(c.client.Endpoint() + path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/xml")
	if body != nil {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	// Sign the request with AWS Signature Version 4
	if err := c.client.SignRequest(req, body); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return c.client.Do(req)
}

// handleErrorResponse handles error responses from AWS
func (c *Route53Client) handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("route53: HTTP %d: failed to read error response", resp.StatusCode)
	}

	// Try to parse AWS error response
	type AWSError struct {
		XMLName xml.Name `xml:"ErrorResponse"`
		Error   struct {
			Type    string `xml:"Type"`
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Error"`
		RequestId string `xml:"RequestId"`
	}

	var awsErr AWSError
	if parseErr := xml.Unmarshal(body, &awsErr); parseErr == nil && awsErr.Error.Code != "" {
		// Provide specific guidance for common error codes
		switch awsErr.Error.Code {
		case "InvalidClientTokenId":
			return fmt.Errorf("route53: authentication failed - invalid access key ID. Please verify your AWS_ACCESS_KEY_ID is correct and has not been rotated")
		case "SignatureDoesNotMatch":
			return fmt.Errorf("route53: authentication failed - signature mismatch. Please verify your AWS_SECRET_ACCESS_KEY is correct")
		case "TokenRefreshRequired":
			return fmt.Errorf("route53: session token expired. Please refresh your AWS credentials or remove AWS_SESSION_TOKEN if using permanent keys")
		case "AccessDenied":
			return fmt.Errorf("route53: access denied. Please ensure your AWS credentials have the required Route53 permissions")
		case "Throttling":
			return fmt.Errorf("route53: API rate limit exceeded. Please retry after a delay")
		case "NoSuchHostedZone":
			return fmt.Errorf("route53: hosted zone not found. Please verify AWS_HOSTED_ZONE_ID is correct")
		default:
			return fmt.Errorf("route53: HTTP %d: %s (%s) - %s [RequestId: %s]", 
				resp.StatusCode, awsErr.Error.Code, awsErr.Error.Type, awsErr.Error.Message, awsErr.RequestId)
		}
	}

	// Fall back to raw response if parsing fails
	return fmt.Errorf("route53: HTTP %d: %s", resp.StatusCode, string(body))
}

// loadAWSCredentials loads AWS credentials from various sources
func loadAWSCredentials(config *Config) (*awsclient.AWSCredentials, error) {
	// If credentials are provided in config, use them
	if config.AccessKeyID != "" && config.SecretAccessKey != "" {
		region := config.Region
		if region == "" {
			region = "us-east-1" // Default region for Route53
		}
		return &awsclient.AWSCredentials{
			AccessKeyID:     config.AccessKeyID,
			SecretAccessKey: config.SecretAccessKey,
			SessionToken:    config.SessionToken,
			Region:          region,
		}, nil
	}

	// Load from environment variables with default region
	region := config.Region
	if region == "" {
		if envRegion := os.Getenv(EnvRegion); envRegion != "" {
			region = envRegion
		} else {
			region = "us-east-1" // Default region for Route53
		}
	}

	creds, err := awsclient.LoadAWSCredentials(region)
	if err != nil {
		// Enhanced error message with debugging information
		var debugInfo []string

		// Check environment variables
		if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
			debugInfo = append(debugInfo, "AWS_ACCESS_KEY_ID is set")
		} else {
			debugInfo = append(debugInfo, "AWS_ACCESS_KEY_ID is not set")
		}

		if os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
			debugInfo = append(debugInfo, "AWS_SECRET_ACCESS_KEY is set")
		} else {
			debugInfo = append(debugInfo, "AWS_SECRET_ACCESS_KEY is not set")
		}

		if os.Getenv("AWS_SESSION_TOKEN") != "" {
			debugInfo = append(debugInfo, "AWS_SESSION_TOKEN is set")
		}

		if os.Getenv("AWS_REGION") != "" {
			debugInfo = append(debugInfo, fmt.Sprintf("AWS_REGION=%s", os.Getenv("AWS_REGION")))
		}

		// Check for shared credentials file
		homeDir, _ := os.UserHomeDir()
		credFile := filepath.Join(homeDir, ".aws", "credentials")
		if _, credErr := os.Stat(credFile); credErr == nil {
			debugInfo = append(debugInfo, "shared credentials file exists at ~/.aws/credentials")
		} else {
			debugInfo = append(debugInfo, "shared credentials file not found at ~/.aws/credentials")
		}

		return nil, fmt.Errorf("failed to load AWS credentials: %w\nDebugging info:\n- %s",
			err, strings.Join(debugInfo, "\n- "))
	}

	// Override with session token if provided in config
	if config.SessionToken != "" {
		creds.SessionToken = config.SessionToken
	}

	return creds, nil
}
