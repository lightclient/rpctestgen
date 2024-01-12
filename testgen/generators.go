package testgen

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	addr common.Address
	pk   *ecdsa.PrivateKey

	contract = common.HexToAddress("0000000000000000000000000000000000031ec7")
)

func init() {
	pk, _ = crypto.HexToECDSA("9c647b8b7c4e7c3490668fb6c11473619db80c93704c70893d3813af4090c39c")
	addr = crypto.PubkeyToAddress(pk.PublicKey) // 658bdf435d810c91414ec09147daa6db62406379
}

type T struct {
	eth   *ethclient.Client
	geth  *gethclient.Client
	rpc   *rpc.Client
	chain *core.BlockChain
}

func NewT(eth *ethclient.Client, geth *gethclient.Client, rpc *rpc.Client, chain *core.BlockChain) *T {
	return &T{eth, geth, rpc, chain}
}

// MethodTests is a collection of tests for a certain JSON-RPC method.
type MethodTests struct {
	Name  string
	Tests []Test
}

// Test is a wrapper for a function that performs an interaction with the
// client.
type Test struct {
	Name  string
	About string
	Run   func(context.Context, *T) error
}

// AllMethods is a slice of all JSON-RPC methods with tests.
var AllMethods = []MethodTests{
	EthBlockNumber,
	EthGetBlockByNumber,
	EthGetBlockByHash,
	// EthGetHeaderByNumber,
	// EthGetHeaderByHash,
	EthGetProof,
	EthChainID,
	EthGetBalance,
	EthGetCode,
	EthGetStorage,
	EthCall,
	EthSimulate,
	EthEstimateGas,
	EthCreateAccessList,
	EthGetBlockTransactionCountByNumber,
	EthGetBlockTransactionCountByHash,
	EthGetTransactionByBlockHashAndIndex,
	EthGetTransactionByBlockNumberAndIndex,
	EthGetTransactionCount,
	EthGetTransactionByHash,
	EthGetTransactionReceipt,
	EthGetBlockReceipts,
	EthSendRawTransaction,
	EthGasPrice,
	EthMaxPriorityFeePerGas,
	EthSyncing,
	EthFeeHistory,
	// EthGetUncleByBlockNumberAndIndex,
	DebugGetRawHeader,
	DebugGetRawBlock,
	DebugGetRawReceipts,
	DebugGetRawTransaction,
}

// EthBlockNumber stores a list of all tests against the method.
var EthBlockNumber = MethodTests{
	"eth_blockNumber",
	[]Test{
		{
			"simple-test",
			"retrieves the client's current block number",
			func(ctx context.Context, t *T) error {
				got, err := t.eth.BlockNumber(ctx)
				if err != nil {
					return err
				} else if want := t.chain.CurrentHeader().Number.Uint64(); got != want {
					return fmt.Errorf("unexpect current block number (got: %d, want: %d)", got, want)
				}
				return nil
			},
		},
	},
}

// EthChainID stores a list of all tests against the method.
var EthChainID = MethodTests{
	"eth_chainId",
	[]Test{
		{
			"get-chain-id",
			"retrieves the client's current chain id",
			func(ctx context.Context, t *T) error {
				got, err := t.eth.ChainID(ctx)
				if err != nil {
					return err
				} else if want := t.chain.Config().ChainID.Uint64(); got.Uint64() != want {
					return fmt.Errorf("unexpect chain id (got: %d, want: %d)", got, want)
				}
				return nil
			},
		},
	},
}

// EthGetHeaderByNumber stores a list of all tests against the method.
var EthGetHeaderByNumber = MethodTests{
	"eth_getHeaderByNumber",
	[]Test{
		{
			"get-header-by-number",
			"gets a header by number",
			func(ctx context.Context, t *T) error {
				var got *types.Header
				err := t.rpc.CallContext(ctx, got, "eth_getHeaderByNumber", "0x1")
				if err != nil {
					return err
				}
				want := t.chain.GetHeaderByNumber(1)
				if reflect.DeepEqual(got, want) {
					return fmt.Errorf("unexpected header (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
	},
}

// EthGetHeaderByHash stores a list of all tests against the method.
var EthGetHeaderByHash = MethodTests{
	"eth_getHeaderByHash",
	[]Test{
		{
			"get-header-by-hash",
			"gets a header by hash",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetHeaderByNumber(1)
				var got *types.Header
				err := t.rpc.CallContext(ctx, got, "eth_getHeaderByHash", want.Hash())
				if err != nil {
					return err
				}
				if reflect.DeepEqual(got, want) {
					return fmt.Errorf("unexpected header (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
	},
}

// EthGetCode stores a list of all tests against the method.
var EthGetCode = MethodTests{
	"eth_getCode",
	[]Test{
		{
			"get-code",
			"gets code for 0xaa",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				var got hexutil.Bytes
				err := t.rpc.CallContext(ctx, &got, "eth_getCode", addr, "latest")
				if err != nil {
					return err
				}
				state, _ := t.chain.State()
				want := state.GetCode(addr)
				if !bytes.Equal(got, want) {
					return fmt.Errorf("unexpected code (got: %s, want %s)", got, want)
				}
				return nil
			},
		},
	},
}

// EthGetStorage stores a list of all tests against the method.
var EthGetStorage = MethodTests{
	"eth_getStorage",
	[]Test{
		{
			"get-storage",
			"gets storage for 0xaa",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				key := common.Hash{0x01}
				got, err := t.eth.StorageAt(ctx, addr, key, nil)
				if err != nil {
					return err
				}
				state, _ := t.chain.State()
				want := state.GetState(addr, key)
				if !bytes.Equal(got, want.Bytes()) {
					return fmt.Errorf("unexpected storage value (got: %s, want %s)", got, want)
				}
				return nil
			},
		},
	},
}

// EthGetBlockByHash stores a list of all tests against the method.
var EthGetBlockByHash = MethodTests{
	"eth_getBlockByHash",
	[]Test{
		{
			"get-block-by-hash",
			"gets block 1",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetHeaderByNumber(1)
				got, err := t.eth.BlockByHash(ctx, want.Hash())
				if err != nil {
					return err
				}
				if got.Hash() != want.Hash() {
					return fmt.Errorf("unexpected block (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
		{
			"get-block-by-empty-hash",
			"gets block empty hash",
			func(ctx context.Context, t *T) error {
				_, err := t.eth.BlockByHash(ctx, common.Hash{})
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("expected not found error")
				}
				return nil
			},
		},
		{
			"get-block-by-notfound-hash",
			"gets block not found hash",
			func(ctx context.Context, t *T) error {
				_, err := t.eth.BlockByHash(ctx, common.HexToHash("deadbeef"))
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("expected not found error")
				}
				return nil
			},
		},
	},
}

// EthChainID stores a list of all tests against the method.
var EthGetBalance = MethodTests{
	"eth_getBalance",
	[]Test{
		{
			"get-balance",
			"retrieves the an account's balance",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				got, err := t.eth.BalanceAt(ctx, addr, nil)
				if err != nil {
					return err
				}
				state, _ := t.chain.State()
				want := state.GetBalance(addr)
				if got.Uint64() != want.Uint64() {
					return fmt.Errorf("unexpect balance (got: %d, want: %d)", got, want)
				}
				return nil
			},
		},
		{
			"get-balance-blockhash",
			"retrieves the an account's balance at a specific blockhash",
			func(ctx context.Context, t *T) error {
				var (
					block = t.chain.GetBlockByNumber(1)
					addr  = common.Address{0xaa}
					got   hexutil.Big
				)
				if err := t.rpc.CallContext(ctx, &got, "eth_getBalance", addr, block.Hash()); err != nil {
					return err
				}
				state, _ := t.chain.StateAt(block.Root())
				want := state.GetBalance(addr)
				if got.ToInt().Uint64() != want.Uint64() {
					return fmt.Errorf("unexpect balance (got: %d, want: %d)", got.ToInt(), want)
				}
				return nil
			},
		},
	},
}

// EthGetBlockByNumber stores a list of all tests against the method.
var EthGetBlockByNumber = MethodTests{
	"eth_getBlockByNumber",
	[]Test{
		{
			"get-genesis",
			"gets block 0",
			func(ctx context.Context, t *T) error {
				block, err := t.eth.BlockByNumber(ctx, common.Big0)
				if err != nil {
					return err
				}
				if n := block.Number().Uint64(); n != 0 {
					return fmt.Errorf("expected block 0, got block %d", n)
				}
				return nil
			},
		},
		{
			"get-latest",
			"gets block latest",
			func(ctx context.Context, t *T) error {
				block, err := t.eth.BlockByNumber(ctx, nil)
				if err != nil {
					return err
				}
				if n := block.Number().Uint64(); n != 9 {
					return fmt.Errorf("expected block 9, got block %d", n)
				}
				return nil
			},
		},
		{
			"get-safe",
			"gets block safe",
			func(ctx context.Context, t *T) error {
				block, err := t.eth.BlockByNumber(ctx, big.NewInt(int64(rpc.SafeBlockNumber)))
				if err != nil {
					return err
				}
				if n := block.Number().Uint64(); n != 9 {
					return fmt.Errorf("expected block 9, got block %d", n)
				}
				return nil
			},
		},
		{
			"get-finalized",
			"gets block finalized",
			func(ctx context.Context, t *T) error {
				block, err := t.eth.BlockByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
				if err != nil {
					return err
				}
				if n := block.Number().Uint64(); n != 9 {
					return fmt.Errorf("expected block 9, got block %d", n)
				}
				return nil
			},
		},
		{
			"get-block-n",
			"gets block 2",
			func(ctx context.Context, t *T) error {
				block, err := t.eth.BlockByNumber(ctx, common.Big2)
				if err != nil {
					return err
				}
				if n := block.Number().Uint64(); n != 2 {
					return fmt.Errorf("expected block 2, got block %d", n)
				}
				return nil
			},
		},
		{
			"get-block-notfound",
			"gets block notfound",
			func(ctx context.Context, t *T) error {
				_, err := t.eth.BlockByNumber(ctx, big.NewInt(1000))
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("get a non-existent block should return notfound")
				}
				return nil
			},
		},
	},
}

// EthCall stores a list of all tests against the method.
var EthCall = MethodTests{
	"eth_call",
	[]Test{
		{
			"call-simple-transfer",
			"simulates a simple transfer",
			func(ctx context.Context, t *T) error {
				msg := ethereum.CallMsg{From: common.Address{0xaa}, To: &common.Address{0x01}, Gas: 100000}
				got, err := t.eth.CallContract(ctx, msg, nil)
				if err != nil {
					return err
				}
				if len(got) != 0 {
					return fmt.Errorf("unexpected return value (got: %s, want: nil)", hexutil.Bytes(got))
				}
				return nil
			},
		},
		{
			"call-simple-contract",
			"simulates a simple contract call with no return",
			func(ctx context.Context, t *T) error {
				aa := common.Address{0xaa}
				msg := ethereum.CallMsg{From: aa, To: &aa}
				got, err := t.eth.CallContract(ctx, msg, nil)
				if err != nil {
					return err
				}
				if len(got) != 0 {
					return fmt.Errorf("unexpected return value (got: %s, want: nil)", hexutil.Bytes(got))
				}
				return nil
			},
		},
	},
}

// EthSimulate stores a list of all tests against the method.
var EthSimulate = MethodTests{
	"eth_simulateV1",
	[]Test{
		{
			"ethSimulate-simple",
			"simulates a ethSimulate transfer",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(1000)},
							},
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							}, {
								From:  &common.Address{0xc1},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
							}},
						},
					},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-simple-with-validation-no-funds",
			"simulates a ethSimulate transfer with validation and not enough funds",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(1000)},
							},
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							}, {
								From:  &common.Address{0xc1},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
							}},
						},
					},
					Validation: false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-simple-no-funds",
			"simulates a simple ethSimulate transfer when account has no funds",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							}, {
								From:  &common.Address{0xc1},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
							}},
						},
					},
					Validation: false,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-overwrite-existing-contract",
			"overwrites existing contract with new contract",
			func(ctx context.Context, t *T) error {
				contractAddr := common.HexToAddress("0000000000000000000000000000000000031ec7")
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &contractAddr,
								Input: hex2Bytes("a9059cbb0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000a"), // transfer(address,uint256)
							}},
						},
						{
							StateOverrides: &StateOverride{
								contractAddr: OverrideAccount{Code: getBlockProperties()},
							},
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &contractAddr,
								Input: hex2Bytes("a9059cbb0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000a"), // transfer(address,uint256)
							}},
						},
					},
					Validation: false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},

		{
			"ethSimulate-overflow-nonce",
			"test to overflow nonce",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Nonce: getUint64Ptr(0xFFFFFFFFFFFFFFFF)},
							},
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc0},
									To:   &common.Address{0xc1},
								},
								{
									From: &common.Address{0xc0},
									To:   &common.Address{0xc1},
								},
							},
						},
					},
					Validation: false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-overflow-nonce-validation",
			"test to overflow nonce-validation",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Nonce: getUint64Ptr(0xFFFFFFFFFFFFFFFF)},
							},
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc0},
									To:   &common.Address{0xc1},
								},
								{
									From: &common.Address{0xc0},
									To:   &common.Address{0xc1},
								},
							},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-simple-no-funds-with-balance-querying",
			"simulates a simple ethSimulate transfer when account has no funds with querying balances before and after",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code: getBalanceGetter(),
							},
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c000000000000000000000000000000000000000"), // gets balance of c0
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c100000000000000000000000000000000000000"), // gets balance of c1
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c000000000000000000000000000000000000000"), // gets balance of c0
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c100000000000000000000000000000000000000"), // gets balance of c1
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c000000000000000000000000000000000000000"), // gets balance of c0
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c100000000000000000000000000000000000000"), // gets balance of c1
							},
						},
					}},
					Validation: false,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-check-that-balance-is-there-after-new-block",
			"checks that balances are kept to next block",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(10000),
							},
							common.Address{0xc2}: OverrideAccount{
								Code: getBalanceGetter(),
							},
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c000000000000000000000000000000000000000"), // gets balance of c0
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c100000000000000000000000000000000000000"), // gets balance of c1
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							},
						},
					}, {
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c000000000000000000000000000000000000000"), // gets balance of c0
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("f8b2cb4f000000000000000000000000c100000000000000000000000000000000000000"), // gets balance of c1
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-simple-no-funds-with-validation",
			"simulates a simple ethSimulate transfer when account has no funds with validation",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
								Nonce: getUint64Ptr(0),
							}, {
								From:  &common.Address{0xc1},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
								Nonce: getUint64Ptr(1),
							}},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-simple-no-funds-with-validation-without-nonces",
			"simulates a simple ethSimulate transfer when account has no funds with validation. This should fail as the nonce is not set for the second transaction.",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
								Nonce: getUint64Ptr(0),
							}, {
								From:  &common.Address{0xc1},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
							}},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-simple-send-from-contract",
			"Sending eth from contract",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(1000), Code: getEthForwarder()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-simple-send-from-contract-no-balance",
			"Sending eth from contract without balance",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Code: getEthForwarder()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-simple-send-from-contract-with-validation",
			"Sending eth from contract with validation enabled",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(1000), Code: getEthForwarder()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
					Validation:     true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-transfer-over-BlockStateCalls",
			"simulates a transfering value over multiple BlockStateCalls",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(5000)},
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(2000),
							}, {
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc3},
								Value: *newRPCBalance(2000),
							},
						},
					}, {
						StateOverrides: &StateOverride{
							{0xc3}: OverrideAccount{Balance: newRPCBalance(5000)},
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc1},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
							}, {
								From:  &common.Address{0xc3},
								To:    &common.Address{0xc2},
								Value: *newRPCBalance(1000),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-override-block-num",
			"simulates calls overriding the block num",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(11)),
						},
						Calls: []TransactionArgs{
							{
								From: &common.Address{0xc0},
								Input: &hexutil.Bytes{
									0x43,             // NUMBER
									0x60, 0x00, 0x52, // MSTORE offset 0
									0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN
								},
							},
						},
					}, {
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(12)),
						},
						Calls: []TransactionArgs{{
							From: &common.Address{0xc1},
							Input: &hexutil.Bytes{
								0x43,             // NUMBER
								0x60, 0x00, 0x52, // MSTORE offset 0
								0x60, 0x20, 0x60, 0x00, 0xf3,
							},
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-block-num-order-38020",
			"simulates calls with invalid block num order (-38020)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(12)),
						},
						Calls: []TransactionArgs{{
							From: &common.Address{0xc1},
							Input: &hexutil.Bytes{
								0x43,             // NUMBER
								0x60, 0x00, 0x52, // MSTORE offset 0
								0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN
							},
						}},
					}, {
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(11)),
						},
						Calls: []TransactionArgs{{
							From: &common.Address{0xc0},
							Input: &hexutil.Bytes{
								0x43,             // NUMBER
								0x60, 0x00, 0x52, // MSTORE offset 0
								0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN
							},
						}},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-block-timestamp-order-38021",
			"Error: simulates calls with invalid timestamp order (-38021)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(12),
							},
						}, {
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(11),
							},
						},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-block-timestamp-non-increment",
			"Error: simulates calls with timestamp staying the same",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(12),
							},
						}, {
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(12),
							},
						},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-block-timestamps-incrementing",
			"checks that you can set timestamp and increment it in next block",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(11),
							},
						}, {
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(12),
							},
						},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-block-timestamp-auto-increment",
			"Error: simulates calls with timestamp incrementing over another",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(11),
							},
						},
						{
							BlockOverrides: &BlockOverrides{},
						},
						{
							BlockOverrides: &BlockOverrides{
								Time: getUint64Ptr(12),
							},
						},
						{
							BlockOverrides: &BlockOverrides{},
						},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-set-read-storage",
			"simulates calls setting and reading from storage contract",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code: hex2Bytes("608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220404e37f487a89a932dca5e77faaf6ca2de3b991f93d230604b1b8daaef64766264736f6c63430008070033"),
							},
						},
						Calls: []TransactionArgs{{
							// Set value to 5
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("6057361d0000000000000000000000000000000000000000000000000000000000000005"),
						}, {
							// Read value
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("2e64cec1"),
						},
						},
					}},
				}
				res := make([]interface{}, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-logs",
			"simulates calls with logs",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								// Yul Code:
								// object "Test" {
								//    code {
								//        let hash:u256 := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
								//        log1(0, 0, hash)
								//        return (0, 0)
								//    }
								// }
								Code: hex2Bytes("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80600080a1600080f3"),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("6057361d0000000000000000000000000000000000000000000000000000000000000005"),
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-blockhash-simple",
			"gets blockhash of previous block (included in original chain)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code: blockHashCallerByteCode(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("ee82ac5e0000000000000000000000000000000000000000000000000000000000000001"),
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if err := checkBlockNumber(res[0].Number, 10); err != nil {
					return err
				}
				if len(res[0].Calls) != 1 {
					return fmt.Errorf("unexpected number of call results (have: %d, want: %d)", len(res[0].Calls), 1)
				}
				if err := checkBlockHash(common.BytesToHash(res[0].Calls[0].ReturnData), t.chain.GetHeaderByNumber(1).Hash()); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-blockhash-complex",
			"gets blockhash of simulated block",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc2}: OverrideAccount{
								Code: blockHashCallerByteCode(),
							},
						},
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(15)),
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("ee82ac5e0000000000000000000000000000000000000000000000000000000000000001"),
						}},
					}, {
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(20)),
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("ee82ac5e000000000000000000000000000000000000000000000000000000000000000f"),
						}},
					}, {
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(30)),
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("ee82ac5e000000000000000000000000000000000000000000000000000000000000001d"),
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}

				for i := 0; i < len(res); i++ {
					if len(res[i].Calls) != 1 {
						return fmt.Errorf("unexpected number of call results (have: %d, want: %d)", len(res[i].Calls), 1)
					}
					if res[i].Calls[0].Status != 0x1 {
						return fmt.Errorf("unexpected status value(have: %d, want: %d)", res[i].Calls[0].Status, 0x1)
					}
				}
				if err := checkBlockNumber(res[0].Number, 15); err != nil {
					return err
				}
				if err := checkBlockNumber(res[1].Number, 20); err != nil {
					return err
				}
				if err := checkBlockNumber(res[2].Number, 30); err != nil {
					return err
				}

				// should equal to block number ones hash
				if err := checkBlockHash(common.BytesToHash(res[0].Calls[0].ReturnData), t.chain.GetHeaderByNumber(1).Hash()); err != nil {
					return err
				}
				// should equal first generated BlockStateCalls hash
				if err := checkBlockHash(common.BytesToHash(res[1].Calls[0].ReturnData), res[0].Hash); err != nil {
					return err
				}
				// should equal keccack256(rlp([blockhash_20, 29]))
				rlp, rlpError := rlp.EncodeToBytes([][]byte{res[1].Hash.Bytes(), big.NewInt(int64(29)).Bytes()})
				if rlpError != nil {
					return rlpError
				}
				if err := checkBlockHash(common.BytesToHash(res[2].Calls[0].ReturnData), crypto.Keccak256Hash(rlp)); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-blockhash-start-before-head",
			"gets blockhash of simulated block",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc2}: OverrideAccount{
								Code: blockHashCallerByteCode(),
							},
						},
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(15)),
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("ee82ac5e0000000000000000000000000000000000000000000000000000000000000001"),
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("ee82ac5e0000000000000000000000000000000000000000000000000000000000000002"),
							},
						},
					}, {
						BlockOverrides: &BlockOverrides{
							Number: (*hexutil.Big)(big.NewInt(20)),
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("ee82ac5e0000000000000000000000000000000000000000000000000000000000000013"),
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, (*hexutil.Big)(big.NewInt(1))); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}

				if err := checkBlockNumber(res[0].Number, 15); err != nil {
					return err
				}
				if err := checkBlockNumber(res[1].Number, 20); err != nil {
					return err
				}

				rlp_1, rlpError := rlp.EncodeToBytes([][]byte{res[0].Calls[0].ReturnData, big.NewInt(int64(2)).Bytes()})
				if rlpError != nil {
					return rlpError
				}
				//keccack256(rlp([blockhash_1, 2])
				if err := checkBlockHash(common.BytesToHash(res[0].Calls[1].ReturnData), crypto.Keccak256Hash(rlp_1)); err != nil {
					return err
				}

				rlp_10, rlpError := rlp.EncodeToBytes([][]byte{res[0].Hash.Bytes(), big.NewInt(int64(19)).Bytes()})
				if rlpError != nil {
					return rlpError
				}
				//keccack256(rlp([blockhash_10, 19])
				if err := checkBlockHash(common.BytesToHash(res[1].Calls[0].ReturnData), crypto.Keccak256Hash(rlp_10)); err != nil {
					return err
				}

				return nil
			},
		},
		{
			"ethSimulate-self-destructing-state-override",
			"when selfdestructing a state override, the state override should go away",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code: selfDestructor(),
							},
							common.Address{0xc3}: OverrideAccount{
								Code: getCode(),
							},
						},
					}, {
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc3},
							Input: hex2Bytes("dce4a447000000000000000000000000c200000000000000000000000000000000000000"), //at(0xc2)
						}},
					}, {
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("83197ef0"), //destroy()
						}},
					}, {
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc3},
							Input: hex2Bytes("dce4a447000000000000000000000000c200000000000000000000000000000000000000"), //at(0xc2)
						}},
					}, {
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code: selfDestructor(),
							},
						},
					}, {
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc3},
							Input: hex2Bytes("dce4a447000000000000000000000000c200000000000000000000000000000000000000"), //at(0xc2)
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, (*hexutil.Big)(big.NewInt(1))); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				noCode := "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"
				if res[1].Calls[0].ReturnData.String() == noCode {
					return fmt.Errorf("res 1 overrided contract does not have contract code: %s", res[1].Calls[0].ReturnData.String())
				}
				if res[3].Calls[0].ReturnData.String() != noCode {
					return fmt.Errorf("res 3 self destructed code does have contract code: %s", res[3].Calls[0].ReturnData.String())
				}
				if res[5].Calls[0].ReturnData.String() == noCode {
					return fmt.Errorf("res 5 overrided contract does not have contract code: %s", res[5].Calls[0].ReturnData.String())
				}
				return nil
			},
		},
		{
			"ethSimulate-run-out-of-gas-in-block-38015",
			"we should get out of gas error if a block consumes too much gas (-38015)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc2}: OverrideAccount{
								Code: gasSpender(),
							},
						},
						BlockOverrides: &BlockOverrides{
							GasLimit: getUint64Ptr(1500000),
						},
					}, {
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("815b8ab400000000000000000000000000000000000000000000000000000000000f4240"), //spendGas(1000000)
							},
							{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc2},
								Input: hex2Bytes("815b8ab400000000000000000000000000000000000000000000000000000000000f4240"), //spendGas(1000000)
							},
						}},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-run-gas-spending",
			"spend a lot gas in separate blocks",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Balance: newRPCBalance(2000000),
								},
								common.Address{0xc2}: OverrideAccount{
									Code: gasSpender(),
								},
							},
							BlockOverrides: &BlockOverrides{
								GasLimit: getUint64Ptr(1500000),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc2},
									Input: hex2Bytes("815b8ab40000000000000000000000000000000000000000000000000000000000000000"), //spendGas(0)
								},
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc2},
									Input: hex2Bytes("815b8ab40000000000000000000000000000000000000000000000000000000000000000"), //spendGas(0)
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc2},
									Input: hex2Bytes("815b8ab400000000000000000000000000000000000000000000000000000000000f4240"), //spendGas(1000000)
								},
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc2},
									Input: hex2Bytes("815b8ab40000000000000000000000000000000000000000000000000000000000000000"), //spendGas(0)
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc2},
									Input: hex2Bytes("815b8ab400000000000000000000000000000000000000000000000000000000000f4240"), //spendGas(1000000)
								},
							},
						},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-eth-send-should-produce-logs",
			"when sending eth we should get ETH logs when traceTransfers is set",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls[0].Logs) != 1 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 1)
				}
				if res[0].Calls[0].Logs[0].Address.String() != "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE" {
					return fmt.Errorf("unexpected log address (have: %s, want: %s)", res[0].Calls[0].Logs[0].Address.String(), "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
				}
				return nil
			},
		},
		{
			"ethSimulate-override-address-twice",
			"override address twice",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
							common.Address{0xc0}: OverrideAccount{Code: getRevertingContract()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-empty-ethSimulate",
			"ethSimulate without parameters",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-empty-calls-and-overrides-ethSimulate",
			"ethSimulate with state overrides and calls but they are empty",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{},
							Calls:          []TransactionArgs{{}},
						},
						{
							StateOverrides: &StateOverride{},
							Calls:          []TransactionArgs{{}},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-override-address-twice-in-separate-BlockStateCalls",
			"override address twice in separate BlockStateCalls",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
							},
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							}},
						},
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
							},
							Calls: []TransactionArgs{{
								From:  &common.Address{0xc0},
								To:    &common.Address{0xc1},
								Value: *newRPCBalance(1000),
							}},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-eth-send-should-not-produce-logs-on-revert",
			"we should not be producing eth logs if the transaction reverts and ETH is not sent",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
							common.Address{0xc1}: OverrideAccount{Code: getRevertingContract()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls[0].Logs) != 0 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 0)
				}
				return nil
			},
		},
		{
			"ethSimulate-eth-send-should-produce-more-logs-on-forward",
			"we should be getting more logs if eth is forwarded",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
							common.Address{0xc1}: OverrideAccount{Code: getEthForwarder()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
							Input: hex2Bytes("4b64e4920000000000000000000000000000000000000000000000000000000000000100"),
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls[0].Logs) != 2 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 2)
				}
				return nil
			},
		},
		{
			"ethSimulate-eth-send-should-produce-no-logs-on-forward-revert",
			"we should be getting no logs if eth is forwarded but then the tx reverts",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
							common.Address{0xc1}: OverrideAccount{Code: getEthForwarder()},
							common.Address{0xc2}: OverrideAccount{Code: getRevertingContract()},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
							Input: hex2Bytes("4b64e492c200000000000000000000000000000000000000000000000000000000000000"), //foward(0xc2)
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls[0].Logs) != 0 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 0)
				}
				return nil
			},
		},
		{
			"ethSimulate-eth-send-should-not-produce-logs-by-default",
			"when sending eth we should not get ETH logs by default",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls[0].Logs) != 0 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 0)
				}
				return nil
			},
		},
		{
			"ethSimulate-transaction-too-low-nonce-38010",
			"Error: Nonce too low (-38010)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Nonce: getUint64Ptr(10)},
						},
						Calls: []TransactionArgs{{
							Nonce: getUint64Ptr(0),
							From:  &common.Address{0xc1},
							To:    &common.Address{0xc1},
						}},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-transaction-too-high-nonce",
			"Error: Nonce too high",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							Nonce: getUint64Ptr(100),
							From:  &common.Address{0xc1},
							To:    &common.Address{0xc1},
						}},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-basefee-too-low-with-validation-38012",
			"Error: BaseFee too low with validation (-38012)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
						},
						BlockOverrides: &BlockOverrides{
							BaseFee: (*hexutil.Big)(big.NewInt(10)),
						},
						Calls: []TransactionArgs{{
							From:                 &common.Address{0xc1},
							To:                   &common.Address{0xc1},
							MaxFeePerGas:         (*hexutil.Big)(big.NewInt(0)),
							MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(0)),
						}},
					}},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-basefee-too-low-without-validation-38012",
			"Error: BaseFee too low with no validation (-38012)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(2000)},
						},
						BlockOverrides: &BlockOverrides{
							BaseFee: (*hexutil.Big)(big.NewInt(10)),
						},
						Calls: []TransactionArgs{{
							From:                 &common.Address{0xc1},
							To:                   &common.Address{0xc1},
							MaxFeePerGas:         (*hexutil.Big)(big.NewInt(0)),
							MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(0)),
						}},
					}},
					Validation: false,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-basefee-too-low-without-validation-38012-without-basefee-override",
			"tries to send transaction with zero basefee",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							From:                 &common.Address{0xc1},
							To:                   &common.Address{0xc1},
							MaxFeePerGas:         (*hexutil.Big)(big.NewInt(0)),
							MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(0)),
						}},
					}},
					Validation: false,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-instrict-gas-38013",
			"Error: Not enough gas provided to pay for intrinsic gas (-38013)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							From: &common.Address{0xc1},
							To:   &common.Address{0xc1},
							Gas:  getUint64Ptr(0),
						}},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-gas-fees-and-value-error-38014",
			"Error: Insufficient funds to pay for gas fees and value (-38014)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-gas-fees-and-value-error-38014-with-validation",
			"Error: Insufficient funds to pay for gas fees and value (-38014) with validation",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1000),
						}},
					}},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-move-to-address-itself-reference-38022",
			"Error: MovePrecompileToAddress referenced itself in replacement (-38022)",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(200000)},
							common.Address{0xc1}: OverrideAccount{MovePrecompileToAddress: &common.Address{0xc1}},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Value: *newRPCBalance(1),
						}},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-move-two-non-precompiles-accounts-to-same",
			"Move two non-precompiles to same adddress",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0x1}: OverrideAccount{
								MovePrecompileToAddress: &common.Address{0xc2},
							},
							common.Address{0x2}: OverrideAccount{
								MovePrecompileToAddress: &common.Address{0xc2},
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-move-two-accounts-to-same-38023",
			"Move two accounts to the same destination (-38023)",
			func(ctx context.Context, t *T) error {
				ecRecoverAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000001"))
				keccakAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000002"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							ecRecoverAddress: OverrideAccount{
								MovePrecompileToAddress: &common.Address{0xc2},
							},
							keccakAddress: OverrideAccount{
								MovePrecompileToAddress: &common.Address{0xc2},
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-try-to-move-non-precompile",
			"try to move non-precompile",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Nonce: getUint64Ptr(5)},
							},
						}, {
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{MovePrecompileToAddress: &common.Address{0xc1}},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(0),
								},
								{
									From:  &common.Address{0xc1},
									To:    &common.Address{0xc1},
									Nonce: getUint64Ptr(5),
								},
							},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-make-call-with-future-block",
			"start ethSimulate with future block",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							Calls: []TransactionArgs{{
								From: &common.Address{0xc0},
								To:   &common.Address{0xc0},
							}},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "0x111")
				return nil
			},
		},
		{
			"ethSimulate-check-that-nonce-increases",
			"check that nonce increases",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(20000)},
							},
						}, {
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(0),
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(1),
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(2),
								},
							},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-check-invalid-nonce",
			"check that nonce cannot decrease",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{Balance: newRPCBalance(20000)},
							},
						}, {
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(0),
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(1),
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc0},
									Nonce: getUint64Ptr(0),
								},
							},
						},
					},
					Validation: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-override-all-in-BlockStateCalls",
			"override all values in block and see that they are set in return value",
			func(ctx context.Context, t *T) error {
				feeRecipient := common.Address{0xc2}
				randDao := common.Hash{0xc3}
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						BlockOverrides: &BlockOverrides{
							Number:       (*hexutil.Big)(big.NewInt(1001)),
							Time:         getUint64Ptr(1003),
							GasLimit:     getUint64Ptr(1004),
							FeeRecipient: &feeRecipient,
							PrevRandao:   &randDao,
							BaseFee:      (*hexutil.Big)(big.NewInt(1007)),
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if res[0].Number != 1001 {
					return fmt.Errorf("unexpected Number (have: %d, want: %d)", res[0].Number, 1001)
				}
				if res[0].Time != 1003 {
					return fmt.Errorf("unexpectedTime (have: %d, want: %d)", res[0].Time, 1003)
				}
				if res[0].GasLimit != 1004 {
					return fmt.Errorf("unexpected GasLimit (have: %d, want: %d)", res[0].GasLimit, 1004)
				}
				if res[0].FeeRecipient != feeRecipient {
					return fmt.Errorf("unexpected FeeRecipient (have: %d, want: %d)", res[0].FeeRecipient, feeRecipient)
				}
				if *res[0].PrevRandao != randDao {
					return fmt.Errorf("unexpected PrevRandao (have: %d, want: %d)", res[0].PrevRandao, randDao)
				}
				if res[0].BaseFeePerGas.ToInt().Cmp(big.NewInt(1007)) != 0 {
					return fmt.Errorf("unexpected BaseFeePerGas (have: %d, want: %d)", res[0].BaseFeePerGas.ToInt(), big.NewInt(1007))
				}
				return nil
			},
		},
		{
			"ethSimulate-move-ecrecover-and-call",
			"move ecrecover and try calling it",
			func(ctx context.Context, t *T) error {
				ecRecoverAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000001"))
				ecRecoverMovedToAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123456"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{ // just call ecrecover normally
							{ // call with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
						},
					}, {
						StateOverrides: &StateOverride{ // move ecRecover and call it in new address
							ecRecoverAddress: OverrideAccount{
								MovePrecompileToAddress: &ecRecoverMovedToAddress,
							},
						},
						Calls: []TransactionArgs{
							{ // call with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // call with valid params, the old address, should fail as it was moved
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls) != len(params.BlockStateCalls[0].Calls) {
					return fmt.Errorf("unexpected number of call results (have: %d, want: %d)", len(res[0].Calls), len(params.BlockStateCalls[0].Calls))
				}
				return nil
			},
		},
		{
			"ethSimulate-move-ecrecover-twice-and-call",
			"move ecrecover and try calling it, then move it again and call it",
			func(ctx context.Context, t *T) error {
				ecRecoverAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000001"))
				ecRecoverMovedToAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123456"))
				ecRecoverMovedToAddress2 := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123457"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{ // just call ecrecover normally
							{ // call with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
						},
					}, {
						StateOverrides: &StateOverride{ // move ecRecover and call it in new address
							ecRecoverAddress: OverrideAccount{
								MovePrecompileToAddress: &ecRecoverMovedToAddress,
							},
						},
						Calls: []TransactionArgs{
							{ // call with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // call with valid params, the old address, should fail as it was moved
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
						},
					}, {
						StateOverrides: &StateOverride{ // move ecRecover and call it in new address
							ecRecoverAddress: OverrideAccount{
								MovePrecompileToAddress: &ecRecoverMovedToAddress2,
							},
						},
						Calls: []TransactionArgs{
							{ // call with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // call with valid params, the old address, should fail as it was moved
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress2,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-override-ecrecover",
			"override ecrecover",
			func(ctx context.Context, t *T) error {
				ecRecoverAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000001"))
				ecRecoverMovedToAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123456"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							ecRecoverAddress: OverrideAccount{
								Code:                    getEcRecoverOverride(),
								MovePrecompileToAddress: &ecRecoverMovedToAddress,
							},
							common.Address{0xc1}: OverrideAccount{Balance: newRPCBalance(200000)},
						},
						Calls: []TransactionArgs{
							{ // call with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // add override
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("c00692604554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"),
							},
							{ // now it should resolve to 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // call with new invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554490000000000000000000000000000000000000000000000000000000000"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls) != len(params.BlockStateCalls[0].Calls) {
					return fmt.Errorf("unexpected number of call results (have: %d, want: %d)", len(res[0].Calls), len(params.BlockStateCalls[0].Calls))
				}
				zeroAddr := common.Address{0x0}
				if common.BytesToAddress(res[0].Calls[0].ReturnData) != zeroAddr {
					return fmt.Errorf("unexpected ReturnData (have: %d, want: %d)", common.BytesToAddress(res[0].Calls[0].ReturnData), zeroAddr)
				}
				successReturn := common.BytesToAddress(*hex2Bytes("b11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a"))
				if common.BytesToAddress(res[0].Calls[1].ReturnData) != successReturn {
					return fmt.Errorf("unexpected calls 1 ReturnData (have: %d, want: %d)", common.BytesToAddress(res[0].Calls[1].ReturnData), successReturn)
				}
				vitalikReturn := common.BytesToAddress(*hex2Bytes("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
				if common.BytesToAddress(res[0].Calls[3].ReturnData) != vitalikReturn {
					return fmt.Errorf("unexpected calls 3 ReturnData (have: %d, want: %d)", common.BytesToAddress(res[0].Calls[3].ReturnData), vitalikReturn)
				}
				if common.BytesToAddress(res[0].Calls[4].ReturnData) != successReturn {
					return fmt.Errorf("unexpected calls 4 ReturnData (have: %d, want: %d)", common.BytesToAddress(res[0].Calls[4].ReturnData), successReturn)
				}
				if common.BytesToAddress(res[0].Calls[5].ReturnData) != zeroAddr {
					return fmt.Errorf("unexpected calls 5 ReturnData (have: %d, want: %d)", common.BytesToAddress(res[0].Calls[5].ReturnData), zeroAddr)
				}
				return nil
			},
		},
		{
			"ethSimulate-override-sha256",
			"override sha256 precompile",
			func(ctx context.Context, t *T) error {
				sha256Address := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000002"))
				sha256MovedToAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123456"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							sha256Address: OverrideAccount{
								Code:                    hex2Bytes(""),
								MovePrecompileToAddress: &sha256MovedToAddress,
							},
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &sha256MovedToAddress,
								Input: hex2Bytes("1234"),
							},
							{
								From:  &common.Address{0xc0},
								To:    &sha256Address,
								Input: hex2Bytes("1234"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-override-identity",
			"override identity precompile",
			func(ctx context.Context, t *T) error {
				identityAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000004"))
				identityMovedToAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123456"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							identityAddress: OverrideAccount{
								Code:                    hex2Bytes(""),
								MovePrecompileToAddress: &identityMovedToAddress,
							},
						},
						Calls: []TransactionArgs{
							{
								From:  &common.Address{0xc0},
								To:    &identityMovedToAddress,
								Input: hex2Bytes("1234"),
							},
							{
								From:  &common.Address{0xc0},
								To:    &identityAddress,
								Input: hex2Bytes("1234"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-precompile-is-sending-transaction",
			"send transaction from a precompile",
			func(ctx context.Context, t *T) error {
				identityAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000004"))
				sha256Address := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000002"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{
							{
								From:  &identityAddress,
								To:    &sha256Address,
								Input: hex2Bytes("1234"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-simple-state-diff",
			"override one state variable with statediff",
			func(ctx context.Context, t *T) error {
				stateChanges := make(map[common.Hash]common.Hash)
				stateChanges[common.BytesToHash(*hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))] = common.Hash{0x12} //slot 0 -> 0x12
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Balance: newRPCBalance(2000),
								},
								common.Address{0xc1}: OverrideAccount{
									Code: getStorageTester(),
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("7b8d56e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"), // set storage slot 0 -> 1
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("7b8d56e300000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"), // set storage slot 1 -> 2
								},
							},
						},
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									StateDiff: &stateChanges, // state diff override
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000000"), // gets storage slot 0, should be 0x12 as overrided
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000001"), // gets storage slot 1, should be 2
								},
							},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-simple-state-diff",
			"override one state variable with state",
			func(ctx context.Context, t *T) error {
				stateChanges := make(map[common.Hash]common.Hash)
				stateChanges[common.BytesToHash(*hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))] = common.Hash{0x12} //slot 0 -> 0x12
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Balance: newRPCBalance(2000),
								},
								common.Address{0xc1}: OverrideAccount{
									Code: getStorageTester(),
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("7b8d56e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"), // set storage slot 0 -> 1
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("7b8d56e300000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"), // set storage slot 1 -> 2
								},
							},
						},
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									State: &stateChanges, // state diff override
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000000"), // gets storage slot 0, should be 0x12 as overrided
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000001"), // gets storage slot 1, should be 0
								},
							},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-override-storage-slots",
			"override storage slots",
			func(ctx context.Context, t *T) error {
				stateChanges := make(map[common.Hash]common.Hash)
				stateChanges[common.BytesToHash(*hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))] = common.Hash{0x12} //slot 0 -> 0x12
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Balance: newRPCBalance(2000),
								},
								common.Address{0xc1}: OverrideAccount{
									Code: getStorageTester(),
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("7b8d56e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"), // set storage slot 0 -> 1
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("7b8d56e300000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"), // set storage slot 1 -> 2
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000000"), // gets storage slot 0, should be 1
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000001"), // gets storage slot 1, should be 2
								},
							},
						},
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									StateDiff: &stateChanges, // state diff override
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000000"), // gets storage slot 0, should be 0x12 as overrided
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000001"), // gets storage slot 1, should be 2
								},
							},
						},
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									State: &stateChanges, // whole state override
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000000"), // gets storage slot 0, should be 0x12 as overrided
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("0ff4c9160000000000000000000000000000000000000000000000000000000000000001"), // gets storage slot 1, should be 0 as the whole storage was replaced
								},
							},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if res[0].Calls[2].ReturnData.String() != "0x0000000000000000000000000000000000000000000000000000000000000001" {
					return fmt.Errorf("unexpected call result (res[0].Calls[2]) (have: %s, want: %s)", res[0].Calls[2].ReturnData.String(), "0x0000000000000000000000000000000000000000000000000000000000000001")
				}
				if res[0].Calls[3].ReturnData.String() != "0x0000000000000000000000000000000000000000000000000000000000000002" {
					return fmt.Errorf("unexpected call result (res[0].Calls[3]) (have: %s, want: %s)", res[0].Calls[3].ReturnData.String(), "0x0000000000000000000000000000000000000000000000000000000000000002")
				}

				if res[1].Calls[0].ReturnData.String() != "0x1200000000000000000000000000000000000000000000000000000000000000" {
					return fmt.Errorf("unexpected call result (res[1].Calls[0]) (have: %s, want: %s)", res[1].Calls[0].ReturnData.String(), "0x1200000000000000000000000000000000000000000000000000000000000000")
				}
				if res[1].Calls[1].ReturnData.String() != "0x0000000000000000000000000000000000000000000000000000000000000002" {
					return fmt.Errorf("unexpected call result (res[1].Calls[1]) (have: %s, want: %s)", res[1].Calls[1].ReturnData.String(), "0x0000000000000000000000000000000000000000000000000000000000000002")
				}

				if res[2].Calls[0].ReturnData.String() != "0x1200000000000000000000000000000000000000000000000000000000000000" {
					return fmt.Errorf("unexpected call result (res[2].Calls[0]) (have: %s, want: %s)", res[2].Calls[0].ReturnData.String(), "0x1200000000000000000000000000000000000000000000000000000000000000")
				}
				if res[2].Calls[1].ReturnData.String() != "0x0000000000000000000000000000000000000000000000000000000000000000" {
					return fmt.Errorf("unexpected call result (res[2].Calls[1]) (have: %s, want: %s)", res[2].Calls[1].ReturnData.String(), "0x0000000000000000000000000000000000000000000000000000000000000000")
				}
				return nil
			},
		},
		{
			"ethSimulate-block-override-reflected-in-contract-simple",
			"Checks that block overrides are true in contract for block number and time",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(15)),
								Time:   getUint64Ptr(100),
							},
						},
						{
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(20)),
								Time:   getUint64Ptr(101),
							},
						},
						{
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(21)),
								Time:   getUint64Ptr(200),
							},
						},
					},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-get-block-properties",
			"gets various block properties from chain",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									Code: getBlockProperties(),
								},
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
					},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-block-override-reflected-in-contract",
			"Checks that block overrides are true in contract",
			func(ctx context.Context, t *T) error {
				prevRandDao1 := common.BytesToHash(*hex2Bytes("123"))
				prevRandDao2 := common.BytesToHash(*hex2Bytes("1234"))
				prevRandDao3 := common.BytesToHash(*hex2Bytes("12345"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									Code: getBlockProperties(),
								},
							},
							BlockOverrides: &BlockOverrides{
								Number:       (*hexutil.Big)(big.NewInt(15)),
								Time:         getUint64Ptr(100),
								GasLimit:     getUint64Ptr(190000),
								FeeRecipient: &common.Address{0xc0},
								PrevRandao:   &prevRandDao1,
								BaseFee:      (*hexutil.Big)(big.NewInt(10)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							BlockOverrides: &BlockOverrides{
								Number:       (*hexutil.Big)(big.NewInt(20)),
								Time:         getUint64Ptr(2000),
								GasLimit:     getUint64Ptr(300000),
								FeeRecipient: &common.Address{0xc1},
								PrevRandao:   &prevRandDao2,
								BaseFee:      (*hexutil.Big)(big.NewInt(20)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							BlockOverrides: &BlockOverrides{
								Number:       (*hexutil.Big)(big.NewInt(21)),
								Time:         getUint64Ptr(30000),
								GasLimit:     getUint64Ptr(190002),
								FeeRecipient: &common.Address{0xc2},
								PrevRandao:   &prevRandDao3,
								BaseFee:      (*hexutil.Big)(big.NewInt(30)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
					},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-add-more-non-defined-BlockStateCalls-than-fit",
			"Add more BlockStateCalls between two BlockStateCalls than it actually fits there",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									Code: getBlockProperties(),
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(15)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(16)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
					},
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-add-more-non-defined-BlockStateCalls-than-fit-but-now-with-fit",
			"Not all block numbers are defined",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc1}: OverrideAccount{
									Code: getBlockProperties(),
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(15)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(20)),
							},
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes(""),
								},
							},
						},
					},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-fee-recipient-receiving-funds",
			"Check that fee recipient gets funds",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Balance: newRPCBalance(200000000),
								},
								common.Address{0xc1}: OverrideAccount{
									Code: getBalanceGetter(),
								},
							},
							BlockOverrides: &BlockOverrides{
								Number:       (*hexutil.Big)(big.NewInt(15)),
								FeeRecipient: &common.Address{0xc2},
								BaseFee:      (*hexutil.Big)(big.NewInt(10)),
							},
							Calls: []TransactionArgs{
								{
									From:                 &common.Address{0xc0},
									To:                   &common.Address{0xc1},
									MaxFeePerGas:         (*hexutil.Big)(big.NewInt(10)),
									MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(10)),
									Input:                hex2Bytes(""),
									Nonce:                getUint64Ptr(0),
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("f8b2cb4f000000000000000000000000c000000000000000000000000000000000000000"), // gets balance of c0
									Nonce: getUint64Ptr(1),
								},
								{
									From:  &common.Address{0xc0},
									To:    &common.Address{0xc1},
									Input: hex2Bytes("f8b2cb4f000000000000000000000000c200000000000000000000000000000000000000"), // gets balance of c2
									Nonce: getUint64Ptr(2),
								},
							},
						},
					},
					Validation:     true,
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				return nil
			},
		},
		{
			"ethSimulate-contract-calls-itself",
			"contract calls itself",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Code: getBlockProperties(),
								},
							},
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc0},
									To:   &common.Address{0xc0},
								},
							},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-long-block-distances",
			"check that parameters adjust the same way when there's big distances between block numbers",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{
						{
							StateOverrides: &StateOverride{
								common.Address{0xc0}: OverrideAccount{
									Code: getBlockProperties(),
								},
							},
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(15)),
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(100)),
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(101)),
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(1000)),
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(10000)),
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(10001)),
							},
						},
						{
							Calls: []TransactionArgs{
								{
									From: &common.Address{0xc1},
									To:   &common.Address{0xc0},
								},
							},
							BlockOverrides: &BlockOverrides{
								Number: (*hexutil.Big)(big.NewInt(100000)),
							},
						},
					},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-send-eth-and-delegate-call",
			"sending eth and delegate calling should only produce one log",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc1}: OverrideAccount{
								Code: delegateCaller(),
							},
							common.Address{0xc2}: OverrideAccount{
								Code: getBlockProperties(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("5c19a95c000000000000000000000000c200000000000000000000000000000000000000"),
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if res[0].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if len(res[0].Calls[0].Logs) != 1 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 1)
				}
				return nil
			},
		},
		{
			"ethSimulate-send-eth-and-delegate-call-to-payble-contract",
			"sending eth and delegate calling a payable contract should only produce one log",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc1}: OverrideAccount{
								Code: delegateCaller2(),
							},
							common.Address{0xc2}: OverrideAccount{
								Code: payableFallBack(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes(""),
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if res[0].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if len(res[0].Calls[0].Logs) != 1 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 1)
				}
				return nil
			},
		},
		{
			"ethSimulate-send-eth-and-delegate-call-to-eoa",
			"sending eth and delegate calling a eoa should only produce one log",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc1}: OverrideAccount{
								Code: delegateCaller2(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes(""),
							Value: *newRPCBalance(1000),
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if res[0].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if len(res[0].Calls[0].Logs) != 1 {
					return fmt.Errorf("unexpected number of logs (have: %d, want: %d)", len(res[0].Calls[0].Logs), 1)
				}
				return nil
			},
		},
		{
			"ethSimulate-extcodehash-override",
			"test extcodehash getting of overriden contract",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc0}: OverrideAccount{
								Balance: newRPCBalance(2000000),
							},
							common.Address{0xc1}: OverrideAccount{
								Code: extCodeHashContract(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("b9724d63000000000000000000000000c200000000000000000000000000000000000000"), // getExtCodeHash(0xc2)
						}},
					}, {
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code: getBlockProperties(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("b9724d63000000000000000000000000c200000000000000000000000000000000000000"), // getExtCodeHash(0xc2)
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if res[0].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if res[1].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if res[0].Calls[0].ReturnData.String() == res[1].Calls[0].ReturnData.String() {
					return fmt.Errorf("returndata did not change (have: %s, want: %s)", res[0].Calls[0].ReturnData.String(), res[1].Calls[0].ReturnData.String())
				}
				return nil
			},
		},
		{
			"ethSimulate-extcodehash-existing-contract",
			"test extcodehash getting of existing contract and then overriding it",
			func(ctx context.Context, t *T) error {
				contractAddr := common.HexToAddress("0000000000000000000000000000000000031ec7")
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc1}: OverrideAccount{
								Code: extCodeHashContract(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("b9724d630000000000000000000000000000000000000000000000000000000000031ec7"), // getExtCodeHash(0000000000000000000000000000000000031ec7)
						}},
					}, {
						StateOverrides: &StateOverride{
							contractAddr: OverrideAccount{
								Code: getBlockProperties(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("b9724d630000000000000000000000000000000000000000000000000000000000031ec7"), // getExtCodeHash(0000000000000000000000000000000000031ec7)
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if res[0].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if res[1].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if res[0].Calls[0].ReturnData.String() == res[1].Calls[0].ReturnData.String() {
					return fmt.Errorf("returndata did not change (have: %s, want: %s)", res[0].Calls[0].ReturnData.String(), res[1].Calls[0].ReturnData.String())
				}
				return nil
			},
		},
		{
			"ethSimulate-extcodehash-precompile",
			"test extcodehash getting of precompile and then again after override",
			func(ctx context.Context, t *T) error {
				ecRecoverAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000001"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc1}: OverrideAccount{
								Code: extCodeHashContract(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("b9724d630000000000000000000000000000000000000000000000000000000000000001"), // getExtCodeHash(0x1)
						}},
					}, {
						StateOverrides: &StateOverride{
							ecRecoverAddress: OverrideAccount{
								Code: getBlockProperties(),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc1},
							Input: hex2Bytes("b9724d630000000000000000000000000000000000000000000000000000000000000001"), // getExtCodeHash(0x1)
						}},
					}},
					TraceTransfers: true,
					Validation:     false,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if res[0].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if res[1].Calls[0].Status != 1 {
					return fmt.Errorf("unexpected call status (have: %d, want: %d)", res[0].Calls[0].Status, 1)
				}
				if res[0].Calls[0].ReturnData.String() == res[1].Calls[0].ReturnData.String() {
					return fmt.Errorf("returndata did not change (have: %s, want: %s)", res[0].Calls[0].ReturnData.String(), res[1].Calls[0].ReturnData.String())
				}
				return nil
			},
		},
		{
			"ethSimulate-self-destructive-contract-produces-logs",
			"self destructive contract produces logs",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{
							common.Address{0xc2}: OverrideAccount{
								Code:    selfDestructor(),
								Balance: newRPCBalance(2000000),
							},
						},
						Calls: []TransactionArgs{{
							From:  &common.Address{0xc0},
							To:    &common.Address{0xc2},
							Input: hex2Bytes("83197ef0"), //destroy()
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-no-fields-call",
			"make a call with no fields",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-only-from-transaction",
			"make a call with only from field",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							From: &common.Address{0xc0},
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-only-from-to-transaction",
			"make a call with only from and to fields",
			func(ctx context.Context, t *T) error {
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						Calls: []TransactionArgs{{
							From: &common.Address{0xc0},
							To:   &common.Address{0xc1},
						}},
					}},
					TraceTransfers: true,
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"ethSimulate-big-block-state-calls-array",
			"Have a block state calls with 300 blocks",
			func(ctx context.Context, t *T) error {
				calls := make([]CallBatch, 300)
				params := ethSimulateOpts{BlockStateCalls: calls}
				res := make([]blockResult, 0)
				t.rpc.Call(&res, "eth_simulateV1", params, "latest")
				return nil
			},
		},
		{
			"ethSimulate-move-ecrecover-and-call-old-and-new",
			"move ecrecover and try calling the moved and non-moved version",
			func(ctx context.Context, t *T) error {
				ecRecoverAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000000001"))
				ecRecoverMovedToAddress := common.BytesToAddress(*hex2Bytes("0000000000000000000000000000000000123456"))
				params := ethSimulateOpts{
					BlockStateCalls: []CallBatch{{
						StateOverrides: &StateOverride{ // move ecRecover and call it in new address
							ecRecoverAddress: OverrideAccount{
								MovePrecompileToAddress: &ecRecoverMovedToAddress,
							},
						},
						Calls: []TransactionArgs{
							{ // call new address with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call new address with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverMovedToAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
							{ // call old address with invalid params, should fail (resolve to 0x0)
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("4554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b45544800000000000000000000000000000000000000000000000000000000004554480000000000000000000000000000000000000000000000000000000000"),
							},
							{ // call old address with valid params, should resolve to 0xb11CaD98Ad3F8114E0b3A1F6E7228bc8424dF48a
								From:  &common.Address{0xc1},
								To:    &ecRecoverAddress,
								Input: hex2Bytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8000000000000000000000000000000000000000000000000000000000000001cb7cf302145348387b9e69fde82d8e634a0f8761e78da3bfa059efced97cbed0d2a66b69167cafe0ccfc726aec6ee393fea3cf0e4f3f9c394705e0f56d9bfe1c9"),
							},
						},
					}},
				}
				res := make([]blockResult, 0)
				if err := t.rpc.Call(&res, "eth_simulateV1", params, "latest"); err != nil {
					return err
				}
				if len(res) != len(params.BlockStateCalls) {
					return fmt.Errorf("unexpected number of results (have: %d, want: %d)", len(res), len(params.BlockStateCalls))
				}
				if len(res[0].Calls) != len(params.BlockStateCalls[0].Calls) {
					return fmt.Errorf("unexpected number of call results (have: %d, want: %d)", len(res[0].Calls), len(params.BlockStateCalls[0].Calls))
				}
				return nil
			},
		},
	},
}

// EthEstimateGas stores a list of all tests against the method.
var EthEstimateGas = MethodTests{
	"eth_estimateGas",
	[]Test{
		{
			"estimate-simple-transfer",
			"estimates a simple transfer",
			func(ctx context.Context, t *T) error {
				msg := ethereum.CallMsg{From: common.Address{0xaa}, To: &common.Address{0x01}}
				got, err := t.eth.EstimateGas(ctx, msg)
				if err != nil {
					return err
				}
				if got != params.TxGas {
					return fmt.Errorf("unexpected return value (got: %d, want: %d)", got, params.TxGas)
				}
				return nil
			},
		},
		{
			"estimate-simple-contract",
			"estimates a simple contract call with no return",
			func(ctx context.Context, t *T) error {
				aa := common.Address{0xaa}
				msg := ethereum.CallMsg{From: aa, To: &aa}
				got, err := t.eth.EstimateGas(ctx, msg)
				if err != nil {
					return err
				}
				want := params.TxGas + 3
				if got != want {
					return fmt.Errorf("unexpected return value (got: %d, want: %d)", got, want)
				}
				return nil
			},
		},
	},
}

// EthEstimateGas stores a list of all tests against the method.
var EthCreateAccessList = MethodTests{
	"eth_createAccessList",
	[]Test{
		{
			"create-al-simple-transfer",
			"estimates a simple transfer",
			func(ctx context.Context, t *T) error {
				msg := make(map[string]interface{})
				msg["from"] = addr
				msg["to"] = common.Address{0x01}

				got := make(map[string]interface{})
				err := t.rpc.CallContext(ctx, &got, "eth_createAccessList", msg, "latest")
				if err != nil {
					return err
				}
				return nil
			},
		},
		{
			"create-al-simple-contract",
			"estimates a simple contract call with no return",
			func(ctx context.Context, t *T) error {
				msg := make(map[string]interface{})
				msg["from"] = addr
				msg["to"] = common.Address{0xaa}

				got := make(map[string]interface{})
				err := t.rpc.CallContext(ctx, &got, "eth_createAccessList", msg, "latest")
				if err != nil {
					return err
				}
				return nil
			},
		},
		{
			"create-al-multiple-reads",
			"estimates a simple contract call with no return",
			func(ctx context.Context, t *T) error {
				msg := make(map[string]interface{})
				msg["from"] = addr
				msg["to"] = common.Address{0xbb}

				got := make(map[string]interface{})
				err := t.rpc.CallContext(ctx, &got, "eth_createAccessList", msg, "latest")
				if err != nil {
					return err
				}
				return nil
			},
		},
	},
}

// EthGetBlockTransactionCountByNumber stores a list of all tests against the method.
var EthGetBlockTransactionCountByNumber = MethodTests{
	"eth_getBlockTransactionCountByNumber",
	[]Test{
		{
			"get-genesis",
			"gets tx count in block 0",
			func(ctx context.Context, t *T) error {
				var got hexutil.Uint
				err := t.rpc.CallContext(ctx, &got, "eth_getBlockTransactionCountByNumber", hexutil.Uint(0))
				if err != nil {
					return err
				}
				want := len(t.chain.GetBlockByNumber(0).Transactions())
				if int(got) != want {
					return fmt.Errorf("tx counts don't match (got: %d, want: %d)", int(got), want)
				}
				return nil
			},
		},
		{
			"get-block-n",
			"gets tx count in block 2",
			func(ctx context.Context, t *T) error {
				var got hexutil.Uint
				err := t.rpc.CallContext(ctx, &got, "eth_getBlockTransactionCountByNumber", hexutil.Uint(2))
				if err != nil {
					return err
				}
				want := len(t.chain.GetBlockByNumber(2).Transactions())
				if int(got) != want {
					return fmt.Errorf("tx counts don't match (got: %d, want: %d)", int(got), want)
				}
				return nil
			},
		},
	},
}

// EthGetBlockTransactionCountByHash stores a list of all tests against the method.
var EthGetBlockTransactionCountByHash = MethodTests{
	"eth_getBlockTransactionCountByHash",
	[]Test{
		{
			"get-genesis",
			"gets tx count in block 0",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(0)
				var got hexutil.Uint
				err := t.rpc.CallContext(ctx, &got, "eth_getBlockTransactionCountByHash", block.Hash())
				if err != nil {
					return err
				}
				want := len(t.chain.GetBlockByNumber(0).Transactions())
				if int(got) != want {
					return fmt.Errorf("tx counts don't match (got: %d, want: %d)", int(got), want)
				}
				return nil
			},
		},
		{
			"get-block-n",
			"gets tx count in block 2",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(2)
				var got hexutil.Uint
				err := t.rpc.CallContext(ctx, &got, "eth_getBlockTransactionCountByHash", block.Hash())
				if err != nil {
					return err
				}
				want := len(t.chain.GetBlockByNumber(2).Transactions())
				if int(got) != want {
					return fmt.Errorf("tx counts don't match (got: %d, want: %d)", int(got), want)
				}
				return nil
			},
		},
	},
}

// EthGetTransactionByBlockHashAndIndex stores a list of all tests against the method.
var EthGetTransactionByBlockHashAndIndex = MethodTests{
	"eth_getTransactionByBlockNumberAndIndex",
	[]Test{
		{
			"get-block-n",
			"gets tx 0 in block 2",
			func(ctx context.Context, t *T) error {
				var got types.Transaction
				err := t.rpc.CallContext(ctx, &got, "eth_getTransactionByBlockNumberAndIndex", hexutil.Uint(2), hexutil.Uint(0))
				if err != nil {
					return err
				}
				want := t.chain.GetBlockByNumber(2).Transactions()[0]
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx don't match (got: %d, want: %d)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
	},
}

// EthGetTransactionByBlockNumberAndIndex stores a list of all tests against the method.
var EthGetTransactionByBlockNumberAndIndex = MethodTests{
	"eth_getTransactionByBlockHashAndIndex",
	[]Test{
		{
			"get-block-n",
			"gets tx 0 in block 2",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(2)
				var got types.Transaction
				err := t.rpc.CallContext(ctx, &got, "eth_getTransactionByBlockHashAndIndex", block.Hash(), hexutil.Uint(0))
				if err != nil {
					return err
				}
				want := t.chain.GetBlockByNumber(2).Transactions()[0]
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx don't match (got: %d, want: %d)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
	},
}

// EthGetTransactionCount stores a list of all tests against the method.
var EthGetTransactionCount = MethodTests{
	"eth_getTransactionCount",
	[]Test{
		{
			"get-account-nonce",
			"gets nonce for a certain account",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				got, err := t.eth.NonceAt(ctx, addr, nil)
				if err != nil {
					return err
				}
				state, _ := t.chain.State()
				want := state.GetNonce(addr)
				if got != want {
					return fmt.Errorf("unexpected nonce (got: %d, want: %d)", got, want)
				}
				return nil
			},
		},
	},
}

// EthGetTransactionByHash stores a list of all tests against the method.
var EthGetTransactionByHash = MethodTests{
	"eth_getTransactionByHash",
	[]Test{
		{
			"get-legacy-tx",
			"gets a legacy transaction",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetBlockByNumber(2).Transactions()[0]
				got, _, err := t.eth.TransactionByHash(ctx, want.Hash())
				if err != nil {
					return err
				}
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx mismatch (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
		{
			"get-legacy-create",
			"gets a legacy contract create transaction",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetBlockByNumber(3).Transactions()[0]
				got, _, err := t.eth.TransactionByHash(ctx, want.Hash())
				if err != nil {
					return err
				}
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx mismatch (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
		{
			"get-legacy-input",
			"gets a legacy transaction with input data",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetBlockByNumber(4).Transactions()[0]
				got, _, err := t.eth.TransactionByHash(ctx, want.Hash())
				if err != nil {
					return err
				}
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx mismatch (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
		{
			"get-dynamic-fee",
			"gets a dynamic fee transaction",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetBlockByNumber(5).Transactions()[0]
				got, _, err := t.eth.TransactionByHash(ctx, want.Hash())
				if err != nil {
					return err
				}
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx mismatch (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
		{
			"get-access-list",
			"gets an access list transaction",
			func(ctx context.Context, t *T) error {
				want := t.chain.GetBlockByNumber(6).Transactions()[0]
				got, _, err := t.eth.TransactionByHash(ctx, want.Hash())
				if err != nil {
					return err
				}
				if got.Hash() != want.Hash() {
					return fmt.Errorf("tx mismatch (got: %s, want: %s)", got.Hash(), want.Hash())
				}
				return nil
			},
		},
		{
			"get-empty-tx",
			"gets an empty transaction",
			func(ctx context.Context, t *T) error {
				_, _, err := t.eth.TransactionByHash(ctx, common.Hash{})
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("expected not found error")
				}
				return nil
			},
		},
		{
			"get-notfound-tx",
			"gets a not exist transaction",
			func(ctx context.Context, t *T) error {
				_, _, err := t.eth.TransactionByHash(ctx, common.HexToHash("deadbeef"))
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("expected not found error")
				}
				return nil
			},
		},
	},
}

// EthGetTransactionReceipt stores a list of all tests against the method.
var EthGetTransactionReceipt = MethodTests{
	"eth_getTransactionReceipt",
	[]Test{
		{
			"get-legacy-receipt",
			"gets a receipt for a legacy transaction",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(2)
				receipt, err := t.eth.TransactionReceipt(ctx, block.Transactions()[0].Hash())
				if err != nil {
					return err
				}
				got, _ := receipt.MarshalBinary()
				want, _ := t.chain.GetReceiptsByHash(block.Hash())[0].MarshalBinary()
				if !bytes.Equal(got, want) {
					return fmt.Errorf("receipt mismatch (got: %s, want: %s)", hexutil.Bytes(got), hexutil.Bytes(want))
				}
				return nil
			},
		},
		{
			"get-legacy-contract",
			"gets a legacy contract create transaction",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(3)
				receipt, err := t.eth.TransactionReceipt(ctx, block.Transactions()[0].Hash())
				if err != nil {
					return err
				}
				got, _ := receipt.MarshalBinary()
				want, _ := t.chain.GetReceiptsByHash(block.Hash())[0].MarshalBinary()
				if !bytes.Equal(got, want) {
					return fmt.Errorf("receipt mismatch (got: %s, want: %s)", hexutil.Bytes(got), hexutil.Bytes(want))
				}
				return nil
			},
		},
		{
			"get-legacy-input",
			"gets a legacy transaction with input data",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(4)
				receipt, err := t.eth.TransactionReceipt(ctx, block.Transactions()[0].Hash())
				if err != nil {
					return err
				}
				got, _ := receipt.MarshalBinary()
				want, _ := t.chain.GetReceiptsByHash(block.Hash())[0].MarshalBinary()
				if !bytes.Equal(got, want) {
					return fmt.Errorf("receipt mismatch (got: %s, want: %s)", hexutil.Bytes(got), hexutil.Bytes(want))
				}
				return nil
			},
		},
		{
			"get-dynamic-fee",
			"gets a dynamic fee transaction",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(5)
				receipt, err := t.eth.TransactionReceipt(ctx, block.Transactions()[0].Hash())
				if err != nil {
					return err
				}
				got, _ := receipt.MarshalBinary()
				want, _ := t.chain.GetReceiptsByHash(block.Hash())[0].MarshalBinary()
				if !bytes.Equal(got, want) {
					return fmt.Errorf("receipt mismatch (got: %s, want: %s)", hexutil.Bytes(got), hexutil.Bytes(want))
				}
				return nil
			},
		},
		{
			"get-access-list",
			"gets an access list transaction",
			func(ctx context.Context, t *T) error {
				block := t.chain.GetBlockByNumber(6)
				receipt, err := t.eth.TransactionReceipt(ctx, block.Transactions()[0].Hash())
				if err != nil {
					return err
				}
				got, _ := receipt.MarshalBinary()
				want, _ := t.chain.GetReceiptsByHash(block.Hash())[0].MarshalBinary()
				if !bytes.Equal(got, want) {
					return fmt.Errorf("receipt mismatch (got: %s, want: %s)", hexutil.Bytes(got), hexutil.Bytes(want))
				}
				return nil
			},
		},
		{
			"get-empty-tx",
			"gets an empty transaction",
			func(ctx context.Context, t *T) error {
				_, err := t.eth.TransactionReceipt(ctx, common.Hash{})
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("expected not found error")
				}
				return nil
			},
		},
		{
			"get-notfound-tx",
			"gets a not exist transaction",
			func(ctx context.Context, t *T) error {
				_, err := t.eth.TransactionReceipt(ctx, common.HexToHash("deadbeef"))
				if !errors.Is(err, ethereum.NotFound) {
					return errors.New("expected not found error")
				}
				return nil
			},
		},
	},
}

var EthGetBlockReceipts = MethodTests{
	"eth_getBlockReceipts",
	[]Test{
		{
			"get-block-receipts-0",
			"gets receipts for block 0",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", hexutil.Uint64(0)); err != nil {
					return err
				}
				return checkBlockReceipts(t, 0, receipts)
			},
		},
		{
			"get-block-receipts-n",
			"gets receipts non-zero block",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", hexutil.Uint64(3)); err != nil {
					return err
				}
				return checkBlockReceipts(t, 3, receipts)
			},
		},
		{
			"get-block-receipts-future",
			"gets receipts of future block",
			func(ctx context.Context, t *T) error {
				var (
					receipts []*types.Receipt
					future   = t.chain.CurrentHeader().Number.Uint64() + 1
				)
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", hexutil.Uint64(future)); err != nil {
					return err
				}
				if len(receipts) != 0 {
					return fmt.Errorf("expected not found, got: %d receipts)", len(receipts))
				}
				return nil
			},
		},
		{
			"get-block-receipts-earliest",
			"gets receipts for block earliest",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", "earliest"); err != nil {
					return err
				}
				return checkBlockReceipts(t, 0, receipts)
			},
		},
		{
			"get-block-receipts-latest",
			"gets receipts for block latest",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", "latest"); err != nil {
					return err
				}
				return checkBlockReceipts(t, t.chain.CurrentHeader().Number.Uint64(), receipts)
			},
		},
		{
			"get-block-receipts-empty",
			"gets receipts for empty block hash",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", common.Hash{}); err != nil {
					return err
				}
				if len(receipts) != 0 {
					return fmt.Errorf("expected not found, got: %d receipts)", len(receipts))
				}
				return nil
			},
		},
		{
			"get-block-receipts-not-found",
			"gets receipts for notfound hash",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", common.HexToHash("deadbeef")); err != nil {
					return err
				}
				if len(receipts) != 0 {
					return fmt.Errorf("expected not found, got: %d receipts)", len(receipts))
				}
				return nil
			},
		},
		{
			"get-block-receipts-by-hash",
			"gets receipts for normal block hash",
			func(ctx context.Context, t *T) error {
				var receipts []*types.Receipt
				if err := t.rpc.CallContext(ctx, &receipts, "eth_getBlockReceipts", t.chain.GetCanonicalHash(5)); err != nil {
					return err
				}
				return checkBlockReceipts(t, 5, receipts)
			},
		},
	},
}

// EthSendRawTransaction stores a list of all tests against the method.
var EthSendRawTransaction = MethodTests{
	"eth_sendRawTransaction",
	[]Test{
		{
			"send-legacy-transaction",
			"sends a raw legacy transaction",
			func(ctx context.Context, t *T) error {
				genesis := t.chain.Genesis()
				state, _ := t.chain.State()
				txdata := &types.LegacyTx{
					Nonce:    state.GetNonce(addr),
					To:       &common.Address{0xaa},
					Value:    big.NewInt(10),
					Gas:      25000,
					GasPrice: new(big.Int).Add(genesis.BaseFee(), big.NewInt(1)),
					Data:     common.FromHex("5544"),
				}
				s := types.LatestSigner(t.chain.Config())
				tx, _ := types.SignNewTx(pk, s, txdata)
				if err := t.eth.SendTransaction(ctx, tx); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"send-dynamic-fee-transaction",
			"sends a transaction with dynamic fee",
			func(ctx context.Context, t *T) error {
				genesis := t.chain.Genesis()
				state, _ := t.chain.State()
				fee := big.NewInt(500)
				fee.Add(fee, genesis.BaseFee())
				txdata := &types.DynamicFeeTx{
					Nonce:     state.GetNonce(addr) + 1,
					To:        nil,
					Gas:       60000,
					Value:     big.NewInt(42),
					GasTipCap: big.NewInt(500),
					GasFeeCap: fee,
					Data:      common.FromHex("0x3d602d80600a3d3981f3363d3d373d3d3d363d734d11c446473105a02b5c1ab9ebe9b03f33902a295af43d82803e903d91602b57fd5bf3"), // eip1167.minimal.proxy
				}
				s := types.LatestSigner(t.chain.Config())
				tx, _ := types.SignNewTx(pk, s, txdata)
				if err := t.eth.SendTransaction(ctx, tx); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"send-access-list-transaction",
			"sends a transaction with access list",
			func(ctx context.Context, t *T) error {
				genesis := t.chain.Genesis()
				state, _ := t.chain.State()
				txdata := &types.AccessListTx{
					Nonce:    state.GetNonce(addr) + 2,
					To:       &contract,
					Gas:      90000,
					GasPrice: genesis.BaseFee(),
					Data:     common.FromHex("0xa9059cbb000000000000000000000000cff33720980c026cc155dcb366861477e988fd870000000000000000000000000000000000000000000000000000000002fd6892"), // transfer(address to, uint256 value)
					AccessList: types.AccessList{
						{Address: contract, StorageKeys: []common.Hash{{0}, {1}}},
					},
				}
				s := types.LatestSigner(t.chain.Config())
				tx, _ := types.SignNewTx(pk, s, txdata)
				if err := t.eth.SendTransaction(ctx, tx); err != nil {
					return err
				}
				return nil
			},
		},
		{
			"send-dynamic-fee-access-list-transaction",
			"sends a transaction with dynamic fee and access list",
			func(ctx context.Context, t *T) error {
				genesis := t.chain.Genesis()
				state, _ := t.chain.State()
				fee := big.NewInt(500)
				fee.Add(fee, genesis.BaseFee())
				txdata := &types.DynamicFeeTx{
					Nonce:     state.GetNonce(addr) + 3,
					To:        &contract,
					Gas:       80000,
					GasTipCap: big.NewInt(500),
					GasFeeCap: fee,
					Data:      common.FromHex("0xa9059cbb000000000000000000000000cff33720980c026cc155dcb366861477e988fd870000000000000000000000000000000000000000000000000000000002fd6892"), // transfer(address to, uint256 value)
					AccessList: types.AccessList{
						{Address: contract, StorageKeys: []common.Hash{{0}, {1}}},
					},
				}
				s := types.LatestSigner(t.chain.Config())
				tx, _ := types.SignNewTx(pk, s, txdata)
				if err := t.eth.SendTransaction(ctx, tx); err != nil {
					return err
				}
				return nil
			},
		},
	},
}

// EthGasPrice stores a list of all tests against the method.
var EthGasPrice = MethodTests{
	"eth_gasPrice",
	[]Test{
		{
			"get-current-gas-price",
			"gets the current gas price in wei",
			func(ctx context.Context, t *T) error {
				if _, err := t.eth.SuggestGasPrice(ctx); err != nil {
					return err
				}
				return nil
			},
		},
	},
}

// EthMaxPriorityFeePerGas stores a list of all tests against the method.
var EthMaxPriorityFeePerGas = MethodTests{
	"eth_maxPriorityFeePerGas",
	[]Test{
		{
			"get-current-tip",
			"gets the current maxPriorityFeePerGas in wei",
			func(ctx context.Context, t *T) error {
				if _, err := t.eth.SuggestGasTipCap(ctx); err != nil {
					return err
				}
				return nil
			},
		},
	},
}

// EthFeeHistory stores a list of all tests against the method.
var EthFeeHistory = MethodTests{
	"eth_feeHistory",
	[]Test{
		{
			"fee-history",
			"gets fee history information",
			func(ctx context.Context, t *T) error {
				got, err := t.eth.FeeHistory(ctx, 1, big.NewInt(2), []float64{95, 99})
				if err != nil {
					return err
				}
				block := t.chain.GetBlockByNumber(2)
				tip, err := block.Transactions()[0].EffectiveGasTip(block.BaseFee())
				if err != nil {
					return fmt.Errorf("unable to get effective tip: %w", err)
				}

				if len(got.Reward) != 1 {
					return fmt.Errorf("mismatch number of rewards (got: %d, want: 1", len(got.Reward))
				}
				if got.Reward[0][0].Cmp(tip) != 0 {
					return fmt.Errorf("mismatch reward value (got: %d, want: %d)", got.Reward[0][0], tip)
				}
				return nil
			},
		},
	},
}

// EthSyncing stores a list of all tests against the method.
var EthSyncing = MethodTests{
	"eth_syncing",
	[]Test{
		{
			"check-syncing",
			"checks client syncing status",
			func(ctx context.Context, t *T) error {
				_, err := t.eth.SyncProgress(ctx)
				if err != nil {
					return err
				}
				return nil
			},
		},
	},
}

// EthGetUncleByBlockNumberAndIndex stores a list of all tests against the method.
var EthGetUncleByBlockNumberAndIndex = MethodTests{
	"eth_getUncleByBlockNumberAndIndex",
	[]Test{
		{
			"get-uncle",
			"gets uncle header",
			func(ctx context.Context, t *T) error {
				var got *types.Header
				t.rpc.CallContext(ctx, got, "eth_getUncleByBlockNumberAndIndex", hexutil.Uint(2), hexutil.Uint(0))
				want := t.chain.GetBlockByNumber(2).Uncles()[0]
				if got.Hash() != want.Hash() {
					return fmt.Errorf("mismatch uncle hash (got: %s, want: %s", got.Hash(), want.Hash())
				}
				return nil
			},
		},
	},
}

// EthGetProof stores a list of all tests against the method.
var EthGetProof = MethodTests{
	"eth_getProof",
	[]Test{
		{
			"get-account-proof",
			"gets proof for a certain account",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				result, err := t.geth.GetProof(ctx, addr, []string{}, big.NewInt(3))
				if err != nil {
					return err
				}
				state, _ := t.chain.State()
				balance := state.GetBalance(addr)
				if result.Balance.Cmp(balance) != 0 {
					return fmt.Errorf("unexpected balance (got: %s, want: %s)", result.Balance, balance)
				}
				return nil
			},
		},
		{
			"get-account-proof-blockhash",
			"gets proof for a certain account at the specified blockhash",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				type accountResult struct {
					Balance *hexutil.Big `json:"balance"`
				}
				var result accountResult
				if err := t.rpc.CallContext(ctx, &result, "eth_getProof", addr, []string{}, t.chain.CurrentHeader().Hash()); err != nil {
					return err
				}
				state, _ := t.chain.State()
				balance := state.GetBalance(addr)
				if result.Balance.ToInt().Cmp(balance) != 0 {
					return fmt.Errorf("unexpected balance (got: %s, want: %s)", result.Balance, balance)
				}
				return nil
			},
		},
		{
			"get-account-proof-with-storage",
			"gets proof for a certain account",
			func(ctx context.Context, t *T) error {
				addr := common.Address{0xaa}
				result, err := t.geth.GetProof(ctx, addr, []string{"0x01"}, big.NewInt(3))
				if err != nil {
					return err
				}
				state, _ := t.chain.State()
				balance := state.GetBalance(addr)
				if result.Balance.Cmp(balance) != 0 {
					return fmt.Errorf("unexpected balance (got: %s, want: %s)", result.Balance, balance)
				}
				if len(result.StorageProof) == 0 || len(result.StorageProof[0].Proof) == 0 {
					return fmt.Errorf("expected storage proof")
				}
				return nil
			},
		},
	},
}

var DebugGetRawHeader = MethodTests{
	"debug_getRawHeader",
	[]Test{
		{
			"get-genesis",
			"gets block 0",
			func(ctx context.Context, t *T) error {
				var got hexutil.Bytes
				if err := t.rpc.CallContext(ctx, &got, "debug_getRawHeader", "0x0"); err != nil {
					return err
				}
				return checkHeaderRLP(t, 0, got)
			},
		},
		{
			"get-block-n",
			"gets non-zero block",
			func(ctx context.Context, t *T) error {
				var got hexutil.Bytes
				if err := t.rpc.CallContext(ctx, &got, "debug_getRawHeader", "0x3"); err != nil {
					return err
				}
				return checkHeaderRLP(t, 3, got)
			},
		},
		{
			"get-invalid-number",
			"gets block with invalid number formatting",
			func(ctx context.Context, t *T) error {
				err := t.rpc.CallContext(ctx, nil, "debug_getRawHeader", "2")
				if !strings.HasPrefix(err.Error(), "invalid argument 0") {
					return err
				}
				return nil
			},
		},
	},
}

var DebugGetRawBlock = MethodTests{
	"debug_getRawBlock",
	[]Test{
		{
			"get-genesis",
			"gets block 0",
			func(ctx context.Context, t *T) error {
				var got hexutil.Bytes
				if err := t.rpc.CallContext(ctx, &got, "debug_getRawBlock", "0x0"); err != nil {
					return err
				}
				return checkBlockRLP(t, 0, got)
			},
		},
		{
			"get-block-n",
			"gets non-zero block",
			func(ctx context.Context, t *T) error {
				var got hexutil.Bytes
				if err := t.rpc.CallContext(ctx, &got, "debug_getRawBlock", "0x3"); err != nil {
					return err
				}
				return checkBlockRLP(t, 3, got)
			},
		},
		{
			"get-invalid-number",
			"gets block with invalid number formatting",
			func(ctx context.Context, t *T) error {
				err := t.rpc.CallContext(ctx, nil, "debug_getRawBlock", "2")
				if !strings.HasPrefix(err.Error(), "invalid argument 0") {
					return err
				}
				return nil
			},
		},
	},
}

var DebugGetRawReceipts = MethodTests{
	"debug_getRawReceipts",
	[]Test{
		{
			"get-genesis",
			"gets receipts for block 0",
			func(ctx context.Context, t *T) error {
				return t.rpc.CallContext(ctx, nil, "debug_getRawReceipts", "0x0")
			},
		},
		{
			"get-block-n",
			"gets receipts non-zero block",
			func(ctx context.Context, t *T) error {
				return t.rpc.CallContext(ctx, nil, "debug_getRawReceipts", "0x3")
			},
		},
		{
			"get-invalid-number",
			"gets receipts with invalid number formatting",
			func(ctx context.Context, t *T) error {
				err := t.rpc.CallContext(ctx, nil, "debug_getRawReceipts", "2")
				if !strings.HasPrefix(err.Error(), "invalid argument 0") {
					return err
				}
				return nil
			},
		},
	},
}

var DebugGetRawTransaction = MethodTests{
	"debug_getRawTransaction",
	[]Test{
		{
			"get-tx",
			"gets tx rlp by hash",
			func(ctx context.Context, t *T) error {
				tx := t.chain.GetBlockByNumber(1).Transactions()[0]
				var got hexutil.Bytes
				if err := t.rpc.CallContext(ctx, &got, "debug_getRawTransaction", tx.Hash().Hex()); err != nil {
					return err
				}
				want, err := tx.MarshalBinary()
				if err != nil {
					return err
				}
				if !bytes.Equal(got, want) {
					return fmt.Errorf("mismatching raw tx (got: %s, want: %s)", hexutil.Bytes(got), hexutil.Bytes(want))
				}
				return nil
			},
		},
		{
			"get-invalid-hash",
			"gets tx with hash missing 0x prefix",
			func(ctx context.Context, t *T) error {
				var got hexutil.Bytes
				err := t.rpc.CallContext(ctx, &got, "debug_getRawTransaction", "1000000000000000000000000000000000000000000000000000000000000001")
				if !strings.HasPrefix(err.Error(), "invalid argument 0") {
					return err
				}
				return nil
			},
		},
	},
}

// TransactionArgs represents the arguments to construct a new transaction
// or a message call.
type TransactionArgs struct {
	From                 *common.Address `json:"from,omitempty"`
	To                   *common.Address `json:"to,omitempty"`
	Gas                  *hexutil.Uint64 `json:"gas,omitempty"`
	GasPrice             *hexutil.Big    `json:"gasPrice,omitempty"`
	MaxFeePerGas         *hexutil.Big    `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *hexutil.Big    `json:"maxPriorityFeePerGas,omitempty"`
	Value                *hexutil.Big    `json:"value,omitempty"`
	Nonce                *hexutil.Uint64 `json:"nonce,omitempty"`

	// We accept "data" and "input" for backwards-compatibility reasons.
	// "input" is the newer name and should be preferred by clients.
	// Issue detail: https://github.com/ethereum/go-ethereum/issues/15628
	Data  *hexutil.Bytes `json:"data,omitempty"`
	Input *hexutil.Bytes `json:"input,omitempty"`

	// Introduced by AccessListTxType transaction.
	AccessList *types.AccessList `json:"accessList,omitempty"`
	ChainID    *hexutil.Big      `json:"chainId,omitempty"`
}

// BlockOverrides is a set of header fields to override.
type BlockOverrides struct {
	Number       *hexutil.Big    `json:"number,omitempty"`
	Time         *hexutil.Uint64 `json:"time,omitempty"`
	GasLimit     *hexutil.Uint64 `json:"gasLimit,omitempty"`
	FeeRecipient *common.Address `json:"feeRecipient,omitempty"`
	PrevRandao   *common.Hash    `json:"prevRandao,omitempty"`
	BaseFee      *hexutil.Big    `json:"baseFeePerGas,omitempty"`
}

// OverrideAccount indicates the overriding fields of account during the execution
// of a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if statDiff is set, all diff will be applied first and then execute the call
// message.
type OverrideAccount struct {
	Nonce                   *hexutil.Uint64              `json:"nonce,omitempty"`
	Code                    *hexutil.Bytes               `json:"code,omitempty"`
	Balance                 **hexutil.Big                `json:"balance,omitempty"`
	State                   *map[common.Hash]common.Hash `json:"state,omitempty"`
	StateDiff               *map[common.Hash]common.Hash `json:"stateDiff,omitempty"`
	MovePrecompileToAddress *common.Address              `json:"MovePrecompileToAddress,omitempty"`
}

// StateOverride is the collection of overridden accounts.
type StateOverride map[common.Address]OverrideAccount

// ethSimulateOpts is the wrapper for ethSimulate parameters.
type ethSimulateOpts struct {
	BlockStateCalls []CallBatch `json:"blockStateCalls,omitempty"`
	TraceTransfers  bool        `json:"traceTransfers,omitempty"`
	Validation      bool        `json:"validation,omitempty"`
}

// CallBatch is a batch of calls to be simulated sequentially.
type CallBatch struct {
	BlockOverrides *BlockOverrides   `json:"blockOverrides,omitempty"`
	StateOverrides *StateOverride    `json:"stateOverrides,omitempty"`
	Calls          []TransactionArgs `json:"calls,omitempty"`
}

type blockResult struct {
	Number        hexutil.Uint64 `json:"number"`
	Hash          common.Hash    `json:"hash"`
	Time          hexutil.Uint64 `json:"timestamp"`
	GasLimit      hexutil.Uint64 `json:"gasLimit"`
	GasUsed       hexutil.Uint64 `json:"gasUsed"`
	FeeRecipient  common.Address `json:"feeRecipient"`
	BaseFeePerGas *hexutil.Big   `json:"baseFeePerGas"`
	PrevRandao    *common.Hash   `json:"prevRandao,omitempty"`
	Calls         []callResult   `json:"calls"`
}

type callResult struct {
	ReturnData hexutil.Bytes  `json:"ReturnData"`
	Logs       []*types.Log   `json:"logs"`
	Transfers  []transfer     `json:"transfers,omitempty"`
	GasUsed    hexutil.Uint64 `json:"gasUsed"`
	Status     hexutil.Uint64 `json:"status"`
	Error      errorResult    `json:"error,omitempty"`
}

type errorResult struct {
	Code    *big.Int `json:"code"`
	Message *string  `json:"message"`
}

type transfer struct {
	From  common.Address `json:"from"`
	To    common.Address `json:"to"`
	Value *big.Int       `json:"value"`
}

func newRPCBalance(balance int) **hexutil.Big {
	rpcBalance := (*hexutil.Big)(big.NewInt(int64(balance)))
	return &rpcBalance
}

func hex2Bytes(str string) *hexutil.Bytes {
	rpcBytes := hexutil.Bytes(common.Hex2Bytes(str))
	return &rpcBytes
}
