package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	log "github.com/hashicorp/go-hclog"

	"github.com/fnproject/fdk-go"
	plugin "github.com/hashicorp/vault-plugin-auth-oci"
	"github.com/hashicorp/vault/api"
)

const (
	AddressKey  = "VAULT_ADDR"
	MountKey    = "mount"
	OciMount    = "oci"
	RoleKey     = "role"
	AuthTypeKey = "auth_type"
)

func main() {
	fdk.Handle(fdk.HandlerFunc(myHandler))
}

func myHandler(ctx context.Context, in io.Reader, out io.Writer) {
	fdkContext := fdk.GetContext(ctx)
	configMap := fdkContext.Config()

	config := api.DefaultConfig()
	config.Address = os.Getenv(configMap[AddressKey])
	client, err := api.NewClient(config)
	if err != nil {
		log.L().Error("Unable to initialize a Vault client", "err", err)
	}
	var argMap map[string]string
	argMap[MountKey] = OciMount
	argMap[RoleKey] = configMap[RoleKey]
	argMap[AuthTypeKey] = configMap[AuthTypeKey]

	cli := &plugin.CLIHandler{}
	secret, err := cli.Auth(client, argMap)
	if err != nil {
		log.L().Error("Authentication failed", "err", err)
	} else {
		log.L().Info("Authentication succeeded!")
	}
	err = json.NewEncoder(out).Encode(&secret)
	if err != nil {
		log.L().Warn("json encoding of secret output failed", "err", err, "secret", secret)
	}
}
