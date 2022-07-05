package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/lightclient/rpctestgen/testgen"
)

// runGenerator generates test fixtures against the specified client and writes
// them to the output directory.
func runGenerator(ctx context.Context) error {
	args := ctx.Value(ARGS).(*Args)

	// Initialize generated chain.
	chain, err := initChain(ctx, args)
	if err != nil {
		return err
	}

	// Start Ethereum client.
	client, err := spawnClient(ctx, args, chain)
	if err != nil {
		return err
	}
	defer client.Close()

	// Connect ethclient to Ethereum client.
	handler, err := newEthclientHandler(client.HttpAddr())
	if err != nil {
		return err
	}
	defer handler.Close()

	// Generate test fixtures for all methods. Store them in the format:
	// outputDir/methodName/testName.io
	fmt.Println("filling tests...")
	tests := testgen.AllMethods
	for _, methodTest := range tests {
		methodDir := fmt.Sprintf("%s/%s", args.OutDir, methodTest.MethodName)
		if err := mkdir(methodDir); err != nil {
			return err
		}
		for _, test := range methodTest.Tests {
			filename := fmt.Sprintf("%s/%s.io", methodDir, test.Name)
			fmt.Printf("generating %s", filename)
			// Write the exchange for each test in a separte file.
			handler.RotateLog(filename)

			// Fail test fill if request exceeds timeout.
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			err := test.Run(ctx, testgen.NewT(handler.ethclient, handler.rpc, chain.bc))
			if err != nil {
				fmt.Println(" fail.")
				fmt.Fprintf(os.Stderr, "failed to fill %s/%s: %s\n", methodTest.MethodName, test.Name, err)
				continue
			}
			fmt.Println("  done.")
		}
	}
	return nil
}

type chainData struct {
	bc     *core.BlockChain
	gspec  *core.Genesis
	blocks []*types.Block
}

// initChain either attempts to read the chain config from args.ChainDir or it
// generates a fresh test chain.
func initChain(ctx context.Context, args *Args) (*chainData, error) {
	var chain chainData
	if args.ChainDir != "" {
		chain.gspec = &core.Genesis{}
		if g, err := ioutil.ReadFile(fmt.Sprintf("%s/genesis.json", args.ChainDir)); err != nil {
			return nil, err
		} else if err := json.Unmarshal(g, chain.gspec); err != nil {
			return nil, err
		}
		b, err := readChain(fmt.Sprintf("%s/chain.rlp", args.ChainDir))
		if err != nil {
			return nil, err
		}
		chain.blocks = b
	} else {
		// Make consensus engine.
		var engine consensus.Engine
		if args.Ethash {
			config := ethash.Config{
				PowMode:        ethash.ModeFake,
				CachesInMem:    2,
				DatasetsOnDisk: 2,
				DatasetDir:     args.EthashDir,
			}
			if args.Ethash {
				config.PowMode = ethash.ModeNormal
			}
			engine = ethash.New(config, nil, false)
		} else if args.Clique {
			clique.New()
		}

		// Generate test chain and write to output directory.
		chain.gspec, chain.blocks = genSimpleChain(engine)
		if err := mkdir(args.OutDir); err != nil {
			return nil, err
		}
		if err := writeChain(args.OutDir, chain.gspec, chain.blocks); err != nil {
			return nil, err
		}
	}

	// Create BlockChain to verify client responses against.
	db := rawdb.NewMemoryDatabase()
	chain.gspec.MustCommit(db)

	var err error
	chain.bc, err = core.NewBlockChain(db, nil, chain.gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := chain.bc.InsertChain(chain.blocks); err != nil {
		return nil, err
	}
	return &chain, nil
}

// spawnClient starts an Ethereum client on a separate thread.
//
// It waits until the client is responding to JSON-RPC requests
// before returning.
func spawnClient(ctx context.Context, args *Args, chain *chainData) (Client, error) {
	var (
		client Client
		err    error
	)

	// Initialize specified client and start it in a separate thread.
	switch args.ClientType {
	case "geth":
		client, err = newGethClient(ctx, args.ClientBin, chain.gspec, chain.blocks, args.Verbose)
		if err != nil {
			return nil, err
		}
		client.Start(ctx, args.Verbose)
	default:
		return nil, fmt.Errorf("unsupported client: %s", args.ClientType)
	}

	// Try to connect for 5 seconds. Error otherwise.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = tryConnection(ctx, fmt.Sprintf("http://%s:%s", HOST, PORT), 500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// mkdir makes a directory at the specified path, if it doesn't already exist.
func mkdir(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}

// tryConnection checks if a client's JSON-RPC API is accepting requests.
func tryConnection(ctx context.Context, addr string, waitTime time.Duration) error {
	c, err := rpc.DialHTTPWithClient(addr, http.DefaultClient)
	if err != nil {
		return err
	}
	e := ethclient.NewClient(c)
	for {
		if _, err := e.BlockNumber(ctx); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry timeout: %w", err)
		case <-time.After(waitTime):
		}
	}
	return nil
}
