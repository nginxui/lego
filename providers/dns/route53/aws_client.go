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
		return fmt.Errorf("HTTP %d: failed to read error response", resp.StatusCode)
	}

	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
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
		return nil, err
	}

	// Override with session token if provided in config
	if config.SessionToken != "" {
		creds.SessionToken = config.SessionToken
	}

	return creds, nil
}
