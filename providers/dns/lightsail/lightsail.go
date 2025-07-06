// Package lightsail implements a DNS provider for solving the DNS-01 challenge using AWS Lightsail DNS.
package lightsail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/internal/awsclient"
)

// Environment variables names.
const (
	envNamespace = "LIGHTSAIL_"

	EnvRegion  = envNamespace + "REGION"
	EnvDNSZone = "DNS_ZONE"

	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

const maxRetries = 5

var _ challenge.ProviderTimeout = (*DNSProvider)(nil)

// AWS Lightsail API types
type DomainEntry struct {
	ID      *string           `json:"id,omitempty"`
	Name    *string           `json:"name,omitempty"`
	Target  *string           `json:"target,omitempty"`
	IsAlias *bool             `json:"isAlias,omitempty"`
	Type    *string           `json:"type,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

type CreateDomainEntryRequest struct {
	DomainName  string       `json:"domainName"`
	DomainEntry *DomainEntry `json:"domainEntry"`
}

type DeleteDomainEntryRequest struct {
	DomainName  string       `json:"domainName"`
	DomainEntry *DomainEntry `json:"domainEntry"`
}

type GetDomainRequest struct {
	DomainName string `json:"domainName"`
}

type Operation struct {
	ID               *string   `json:"id,omitempty"`
	ResourceName     *string   `json:"resourceName,omitempty"`
	ResourceType     *string   `json:"resourceType,omitempty"`
	CreatedAt        *float64  `json:"createdAt,omitempty"`
	Location         *Location `json:"location,omitempty"`
	IsTerminal       *bool     `json:"isTerminal,omitempty"`
	OperationDetails *string   `json:"operationDetails,omitempty"`
	OperationType    *string   `json:"operationType,omitempty"`
	Status           *string   `json:"status,omitempty"`
	StatusChangedAt  *float64  `json:"statusChangedAt,omitempty"`
	ErrorCode        *string   `json:"errorCode,omitempty"`
	ErrorDetails     *string   `json:"errorDetails,omitempty"`
}

type Location struct {
	AvailabilityZone *string `json:"availabilityZone,omitempty"`
	RegionName       *string `json:"regionName,omitempty"`
}

type CreateDomainEntryResponse struct {
	Operation *Operation `json:"operation,omitempty"`
}

type DeleteDomainEntryResponse struct {
	Operation *Operation `json:"operation,omitempty"`
}

type Domain struct {
	Name          *string       `json:"name,omitempty"`
	DomainEntries []DomainEntry `json:"domainEntries,omitempty"`
}

type GetDomainResponse struct {
	Domain *Domain `json:"domain,omitempty"`
}

// LightsailClient represents a native Lightsail client
type LightsailClient struct {
	awsClient *awsclient.AWSClient
}

// NewLightsailClient creates a new Lightsail client
func NewLightsailClient(creds *awsclient.AWSCredentials, maxRetries int) *LightsailClient {
	endpoint := fmt.Sprintf("https://lightsail.%s.amazonaws.com", creds.Region)
	awsClient := awsclient.NewAWSClient(creds, "lightsail", endpoint, maxRetries)
	return &LightsailClient{
		awsClient: awsClient,
	}
}

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	DNSZone            string
	Region             string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	client *LightsailClient
	config *Config
}

// NewDNSProvider returns a DNSProvider instance configured for the AWS Lightsail service.
//
// AWS Credentials are automatically detected in the following locations
// and prioritized in the following order:
//  1. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
//     [AWS_SESSION_TOKEN], [DNS_ZONE], [LIGHTSAIL_REGION]
//  2. Shared credentials file (defaults to ~/.aws/credentials)
//  3. Amazon EC2 IAM role
//
// public hosted zone via the FQDN.
//
// See also: https://github.com/aws/aws-sdk-go/wiki/configuring-sdk
func NewDNSProvider() (*DNSProvider, error) {
	config := NewDefaultConfig()

	config.DNSZone = env.GetOrFile(EnvDNSZone)
	config.Region = env.GetOrDefaultString(EnvRegion, "us-east-1")

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for AWS Lightsail.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("lightsail: the configuration of the DNS provider is nil")
	}

	// Load AWS credentials
	creds, err := loadAWSCredentials(config)
	if err != nil {
		return nil, fmt.Errorf("lightsail: failed to load AWS credentials: %w", err)
	}

	// Create native Lightsail client
	client := NewLightsailClient(creds, maxRetries)

	return &DNSProvider{
		config: config,
		client: client,
	}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, _, keyAuth string) error {
	ctx := context.Background()
	info := dns01.GetChallengeInfo(domain, keyAuth)

	request := &CreateDomainEntryRequest{
		DomainName: d.config.DNSZone,
		DomainEntry: &DomainEntry{
			Name:   awsclient.StringPtr(info.EffectiveFQDN),
			Target: awsclient.StringPtr(strconv.Quote(info.Value)),
			Type:   awsclient.StringPtr("TXT"),
		},
	}

	_, err := d.client.CreateDomainEntry(ctx, request)
	if err != nil {
		return fmt.Errorf("lightsail: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, _, keyAuth string) error {
	ctx := context.Background()
	info := dns01.GetChallengeInfo(domain, keyAuth)

	request := &DeleteDomainEntryRequest{
		DomainName: d.config.DNSZone,
		DomainEntry: &DomainEntry{
			Name:   awsclient.StringPtr(info.EffectiveFQDN),
			Type:   awsclient.StringPtr("TXT"),
			Target: awsclient.StringPtr(strconv.Quote(info.Value)),
		},
	}

	_, err := d.client.DeleteDomainEntry(ctx, request)
	if err != nil {
		return fmt.Errorf("lightsail: %w", err)
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// loadAWSCredentials loads AWS credentials from various sources
func loadAWSCredentials(config *Config) (*awsclient.AWSCredentials, error) {
	return awsclient.LoadAWSCredentials(config.Region)
}

// CreateDomainEntry calls the Lightsail CreateDomainEntry API
func (c *LightsailClient) CreateDomainEntry(ctx context.Context, request *CreateDomainEntryRequest) (*CreateDomainEntryResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.makeRequest(ctx, "CreateDomainEntry", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response CreateDomainEntryResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// DeleteDomainEntry calls the Lightsail DeleteDomainEntry API
func (c *LightsailClient) DeleteDomainEntry(ctx context.Context, request *DeleteDomainEntryRequest) (*DeleteDomainEntryResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.makeRequest(ctx, "DeleteDomainEntry", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response DeleteDomainEntryResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// GetDomain calls the Lightsail GetDomain API
func (c *LightsailClient) GetDomain(ctx context.Context, request *GetDomainRequest) (*GetDomainResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.makeRequest(ctx, "GetDomain", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var response GetDomainResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// makeRequest makes an HTTP request with AWS Signature Version 4 authentication
func (c *LightsailClient) makeRequest(ctx context.Context, action string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.awsClient.Endpoint()+"/", bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "Lightsail_20161128."+action)
	if body != nil {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	// Sign the request with AWS Signature Version 4
	if err := c.awsClient.SignRequest(req, body); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return c.awsClient.Do(req)
}

// handleErrorResponse handles error responses from AWS
func (c *LightsailClient) handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("HTTP %d: failed to read error response", resp.StatusCode)
	}

	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
}
