package client

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type KeyServiceBuilder struct {
	keyServices []keyservice.KeyServiceClient
}

func NewKeyServiceBuilder() *KeyServiceBuilder {
	return &KeyServiceBuilder{}
}

func (b *KeyServiceBuilder) AddLocalKeyService() {
	b.keyServices = append(b.keyServices, keyservice.NewLocalClient())
}

func (b *KeyServiceBuilder) AddKeyServiceWithURI(ctx context.Context, keyServiceURI string) error {
	url, err := url.Parse(keyServiceURI)
	if err != nil {
		return fmt.Errorf("failed to parse key service URI: %w", err)
	}
	addr := url.Host
	if url.Scheme == "unix" {
		addr = url.Path
	}
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(
			func(ctx context.Context, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, url.Scheme, addr)
			},
		))
	if err != nil {
		return fmt.Errorf("failed to dial key service: %w", err)
	}
	b.keyServices = append(b.keyServices, keyservice.NewKeyServiceClient(conn))
	return nil
}

func (b *KeyServiceBuilder) Build() ([]keyservice.KeyServiceClient, error) {
	if len(b.keyServices) == 0 {
		return nil, fmt.Errorf("no key service specified. Please either enable the local key service or specify at least one key service URI")
	}
	return b.keyServices, nil
}

func (b *KeyServiceBuilder) MustBuild() []keyservice.KeyServiceClient {
	keyServices, err := b.Build()
	if err != nil {
		panic(err)
	}
	return keyServices
}

func DefaultKeyService() []keyservice.KeyServiceClient {
	b := NewKeyServiceBuilder()
	b.AddLocalKeyService()
	return b.MustBuild()
}
