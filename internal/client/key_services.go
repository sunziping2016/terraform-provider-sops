package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type KeyServiceOpts struct {
	DisableLocalKeyService bool
	KeyServiceURIs         []string
}

var DefaultKeyServiceOpts = &KeyServiceOpts{}

func NewKeyServices(o *KeyServiceOpts) ([]keyservice.KeyServiceClient, error) {
	var svcs []keyservice.KeyServiceClient
	if !o.DisableLocalKeyService {
		svcs = append(svcs, keyservice.NewLocalClient())
	}
	var errs []error
	for _, uri := range o.KeyServiceURIs {
		url, err := url.Parse((uri))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse key service URI %s: %w", uri, err))
			continue
		}
		addr := url.Host
		if url.Scheme == "unix" {
			addr = url.Path
		}
		conn, err := grpc.Dial(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(
				func(ctx context.Context, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, url.Scheme, addr)
				},
			))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to dial key service at %s: %w", uri, err))
			continue
		}
		svcs = append(svcs, keyservice.NewKeyServiceClient(conn))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return svcs, nil
}
