// Package s3 implements an HTTP provider for solving the HTTP-01 challenge using S3-compatible storage.
package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// HTTPProvider implements ChallengeProvider for `http-01` challenge.
type HTTPProvider struct {
	bucket string
	client *minio.Client
}

// NewHTTPProvider returns a HTTPProvider instance with a configured s3 bucket and minio client.
// Credentials must be passed in the environment variables.
func NewHTTPProvider(bucket string) (*HTTPProvider, error) {
	if bucket == "" {
		return nil, errors.New("s3: bucket name missing")
	}

	// Get AWS credentials from environment variables
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")
	region := os.Getenv("AWS_REGION")

	if accessKeyID == "" || secretAccessKey == "" {
		return nil, errors.New("s3: AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
	}

	if region == "" {
		region = "us-east-1" // Default region
	}

	// Determine S3 endpoint based on region
	endpoint := fmt.Sprintf("s3.%s.amazonaws.com", region)

	// Create credentials
	var creds *credentials.Credentials
	if sessionToken != "" {
		creds = credentials.NewStaticV4(accessKeyID, secretAccessKey, sessionToken)
	} else {
		creds = credentials.NewStaticV4(accessKeyID, secretAccessKey, "")
	}

	// Initialize minio client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  creds,
		Secure: true,
		Region: region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: unable to create S3 client: %w", err)
	}

	return &HTTPProvider{
		bucket: bucket,
		client: client,
	}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)` by creating a file in the given s3 bucket.
func (s *HTTPProvider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()

	objectName := strings.Trim(http01.ChallengePath(token), "/")

	// Upload the challenge file
	// Note: For HTTP-01 challenge, the bucket should be configured with public read access
	// or appropriate bucket policies to allow public access to challenge files
	_, err := s.client.PutObject(ctx, s.bucket, objectName, bytes.NewReader([]byte(keyAuth)), int64(len(keyAuth)), minio.PutObjectOptions{
		ContentType: "text/plain",
	})
	if err != nil {
		return fmt.Errorf("s3: failed to upload token to s3: %w", err)
	}
	return nil
}

// CleanUp removes the file created for the challenge.
func (s *HTTPProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()

	objectName := strings.Trim(http01.ChallengePath(token), "/")

	err := s.client.RemoveObject(ctx, s.bucket, objectName, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("s3: could not remove file in s3 bucket after HTTP challenge: %w", err)
	}

	return nil
}
