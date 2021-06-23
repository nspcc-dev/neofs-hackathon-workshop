package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/encoding/address"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

func die(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	// read credentials for container owner account
	containerAcc, err := openWallet("path/to/container_owner_wallet.json", "<WalletAddress>")
	die(err)

	// read credentials for special account
	specialAcc, err := openWallet("path/to/special_wallet.json", "<WalletAddress>")
	die(err)

	// parse container id
	containerID := cid.New()
	err = containerID.Parse("<ContainerID>")
	die(err)

	// create API Client
	cli, err := client.New(
		client.WithURIAddress("st2.storage.fs.neo.org:8080", nil),
		client.WithDefaultPrivateKey(&containerAcc.PrivateKey().PrivateKey),
	)
	die(err)

	// update eACL
	err = updateEACL(updateEACLparams{
		ctx:              ctx,
		cli:              cli,
		containerID:      containerID,
		specialPublicKey: specialAcc.PrivateKey().PublicKey().Bytes(),
	})
	die(err)

	fmt.Println("EACL updated")
}

type updateEACLparams struct {
	ctx              context.Context
	cli              client.Client
	containerID      *cid.ID
	specialPublicKey []byte
}

func updateEACL(p updateEACLparams) error {
	table := eacl.NewTable()
	table.SetCID(p.containerID)

	// ALLOW : GET : []FILTERS : []TARGETS

	// Record 1 : Access to secret file for special account
	record1 := eacl.NewRecord()
	record1.SetAction(eacl.ActionAllow)
	record1.SetOperation(eacl.OperationGet)
	record1.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, "Secret.jpg")
	target1 := eacl.NewTarget()
	target1.SetBinaryKeys([][]byte{p.specialPublicKey})
	record1.SetTargets(target1)

	// Record 2: Deny access to secret file for all others
	record2 := eacl.NewRecord()
	record2.SetAction(eacl.ActionDeny)
	record2.SetOperation(eacl.OperationGet)
	record2.AddObjectAttributeFilter(eacl.MatchStringEqual, object.AttributeFileName, "Secret.jpg")
	target2 := eacl.NewTarget()
	target2.SetRole(eacl.RoleOthers)
	record2.SetTargets(target2)

	table.AddRecord(record1)
	table.AddRecord(record2)

	return p.cli.SetEACL(p.ctx, table)
}

func openWallet(walletPath, walletAddr string) (*wallet.Account, error) {
	pwd, err := input.ReadPassword("Enter password > ")
	if err != nil {
		return nil, err
	}

	w, err := wallet.NewWalletFromFile(walletPath)
	if err != nil {
		return nil, err
	}

	h, err := address.StringToUint160(walletAddr)
	if err != nil {
		return nil, err
	}

	acc := w.GetAccount(h)
	if acc == nil {
		return nil, errors.New("account missing")
	}

	err = acc.Decrypt(pwd, keys.NEP2ScryptParams())

	return acc, err
}
