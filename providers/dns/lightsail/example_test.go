package lightsail_test

import (
	"fmt"
	"log"

	"github.com/go-acme/lego/v4/providers/dns/lightsail"
)

func ExampleNewDNSProvider() {
	// Set environment variables for AWS credentials
	// AWS_ACCESS_KEY_ID=your_access_key
	// AWS_SECRET_ACCESS_KEY=your_secret_key
	// AWS_REGION=us-east-1 (optional, defaults to us-east-1)
	// DNS_ZONE=your_domain.com

	provider, err := lightsail.NewDNSProvider()
	if err != nil {
		log.Fatal(err)
	}

	// Use the provider with lego
	fmt.Printf("Lightsail DNS provider created successfully")
	_ = provider
	// Output: Lightsail DNS provider created successfully
}

func ExampleNewDNSProviderConfig() {
	config := lightsail.NewDefaultConfig()
	config.DNSZone = "example.com"
	config.Region = "us-east-1"

	provider, err := lightsail.NewDNSProviderConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Use the provider with lego
	fmt.Printf("Lightsail DNS provider created with config")
	_ = provider
	// Output: Lightsail DNS provider created with config
}
