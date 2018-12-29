// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	// -- by btc   00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	// （64位数 - 8个零 ）= 56 × 4 = 224
	//mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)
	
	// -- by eac   00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	// （64位数 - 5个零 ）= 59 × 4 = 236
	// EarthCoin: starting difficulty is 1 / 2^12
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 236), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	// regressionPowLimit是比特币块可用于回归测试网络的最高工作价值证明。
	// 它的值是2 ^ 255  -  1。
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// BitNumber defines the specific bit number within the block version
	// this particular soft-fork deployment refers to.
	BitNumber uint8

	// StartTime is the median block time after which voting on the
	// deployment starts.
	StartTime uint64

	// ExpireTime is the median block time after which the attempted
	// deployment expires.
	ExpireTime uint64
}

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.  This is useful to be able to get the details
// of a specific deployment by name.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package. The segwit package
	// includes the deployment of BIPS 141, 142, 144, 145, 147 and 173.
	DeploymentSegwit

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// These fields define the block heights at which the specified softfork
	// BIP became active.
	BIP0034Height int32
	BIP0065Height int32
	BIP0066Height int32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// These fields are related to voting on consensus rule changes as
	// defined by BIP0009.
	//
	// RuleChangeActivationThreshold is the number of blocks in a threshold
	// state retarget window for which a positive vote for a rule change
	// must be cast in order to lock in a rule change. It should typically
	// be 95% for the main network and 75% for test networks.
	//
	// MinerConfirmationWindow is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on.
	RuleChangeActivationThreshold uint32
	MinerConfirmationWindow       uint32
	Deployments                   [DefinedDeployments]ConsensusDeployment

	// Mempool parameters
	RelayNonStdTxs bool

	// Human-readable part for Bech32 encoded segwit addresses, as defined
	// in BIP 173.
	Bech32HRPSegwit string

	// Address encoding magics
	PubKeyHashAddrID        byte // First byte of a P2PKH address
	ScriptHashAddrID        byte // First byte of a P2SH address
	PrivateKeyID            byte // First byte of a WIF private key
	WitnessPubKeyHashAddrID byte // First byte of a P2WPKH address
	WitnessScriptHashAddrID byte // First byte of a P2WSH address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
}

// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	//DefaultPort: "8333",		//--by btc
	DefaultPort: "35677",		//--by eac
	//--by btc
	// DNSSeeds: []DNSSeed{	
		// {"seed.bitcoin.sipa.be", true},
		// {"dnsseed.bluematt.me", true},
		// {"dnsseed.bitcoin.dashjr.org", false},
		// {"seed.bitcoinstats.com", true},
		// {"seed.bitnodes.io", false},
		// {"seed.bitcoin.jonasschnelli.ch", true},
	// },
	
	//--by eac
	DNSSeeds: []DNSSeed{	
		{"148.163.168.167", true},
	},

	// {"106.14.222.124", true},
	// {"120.79.171.136",true},
	// {"212.237.21.74",true},
	// {"144.34.129.66",true},
	// {"193.112.55.242",true},
	// {"47.88.57.196",true},
	// {"118.24.119.155",true},
	// {"182.151.14.132",true},
	// {"111.230.5.182",true},
	// {"122.224.233.77",true},

	// Chain parameters
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1d00ffff,
	BIP0034Height:            227931, // 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8
	BIP0065Height:            388381, // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
	BIP0066Height:            363725, // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	// -- by btc
	// Checkpoints: []Checkpoint{
	// 	{11111, newHashFromStr("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
	// 	{33333, newHashFromStr("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
	// 	{74000, newHashFromStr("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
	// 	{105000, newHashFromStr("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
	// 	{134444, newHashFromStr("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
	// 	{168000, newHashFromStr("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
	// 	{193000, newHashFromStr("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
	// 	{210000, newHashFromStr("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
	// 	{216116, newHashFromStr("00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
	// 	{225430, newHashFromStr("00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
	// 	{250000, newHashFromStr("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
	// 	{267300, newHashFromStr("000000000000000a83fbd660e918f218bf37edd92b748ad940483c7c116179ac")},
	// 	{279000, newHashFromStr("0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
	// 	{300255, newHashFromStr("0000000000000000162804527c6e9b9f0563a280525f9d08c12041def0a0f3b2")},
	// 	{319400, newHashFromStr("000000000000000021c6052e9becade189495d1c539aa37c58917305fd15f13b")},
	// 	{343185, newHashFromStr("0000000000000000072b8bf361d01a6ba7d445dd024203fafc78768ed4368554")},
	// 	{352940, newHashFromStr("000000000000000010755df42dba556bb72be6a32f3ce0b6941ce4430152c9ff")},
	// 	{382320, newHashFromStr("00000000000000000a8dc6ed5b133d0eb2fd6af56203e4159789b092defd8ab2")},
	// },

	// -- by eac
	Checkpoints: []Checkpoint{
		{100, newHashFromStr("c3d91cb4726610d422f8652a5a7cc21bd42e1b8009c00462081c81316d9abad6")},
        {10000, newHashFromStr("7b50ea3b42e613e65ec2aca6797a5780e1c545a617e4a610577fb4b040f0035b")},
        {30000, newHashFromStr("43e2fe7c700191ddfabe2cd09dfd3fc9eb6331f3c19e59b3e4a87cfa88cac543")},
        {50000, newHashFromStr("6a4f705b7a34de7dc1b6573b3595fde05c7b4303b35ede20a3b945244adc6c70")},
        {69500, newHashFromStr("8387b49853928fc67d8b8421fd9214184db590eeecd90a200c9d902d8b42e11f")},
        {80000, newHashFromStr("a7d7ac0b4b1f5eb56b50ad0693c47f47863b8df81f17514bcb5e59c0a4074eba")},
        {91000, newHashFromStr("3f135e0e06ae032de5437ae2b981e3ab84c7d22310224a6e53c6e6e769e8f8f0")},
        {101000, newHashFromStr("ba5948ef9fce38887df24c54366121437d336bd67a4332508248def0032c5d6e")},
        {111000, newHashFromStr("bb9cc6e2d9da343774dc4b49be417731991b90ef53a7fa7eb669cce237223c37")},
        {121000, newHashFromStr("1d286956120cf256bed13bcc1f5fe79a98347c80f2225ded92bbbdfc1147b5f5")},
        {136000, newHashFromStr("b7c7416c40425bc7976c7b6b87734e2fb84855eecd30e3e9673caf8c7f599b5c")},
        {153000, newHashFromStr("9f31abd27721e7eb2b58c0a61a117c324a3a6b8f45c82e8963b1bd14166f6510")},
        {161000, newHashFromStr("f7a9069c705516f60878bf6da9bac02c12d0d8984cb90bce03fe34842ba7eb3d")},
        {170000, newHashFromStr("827d5ce5ed69153deacab9a2d3c35a7b33cdaa397a6a4a540d538b765182f234")},
        {181000, newHashFromStr("69fa48e8b9231f101df79c5b3174feb70bf6da11d88a4ce879a7c9ecb799f46d")},
        {191000, newHashFromStr("80a9ea6b375312c376de880b6958459973a95be1dcbf28db1731452a59ef9750")},
        {200000, newHashFromStr("003a4cb3bf206cfc23b9477e1c433280ae1b3393a21aa858aa322e8402204cd0")},
        {220000, newHashFromStr("bed97c09983d1ee14d5f925c31dc4245b6c9d66af4fdadcf973465cb265b52c3")},
        {240000, newHashFromStr("d4e782aae21f551d4a8d7756eb92dfa2cb23d1ede58162382b3bbced4fbee518")},
        {260000, newHashFromStr("dfaef016341fab642190a6656b6c52efbdb43ce8a590bace86793f3c1b1276be")},
        {280000, newHashFromStr("6b836125e431d3fd31ef55f5fbbdfdadc4d9b98b11db5ee0b7ac8f1f8c3ede32")},
        {301000, newHashFromStr("c557d7363393148a630a3fda46ca380a202fe82fa594c5e57f88fbece755bb05")},
        {324000, newHashFromStr("8f6cb33fd75e327eb1a1d90b13ba2124e077b4cc5240bc7ec8039aee8a345e85")},
        {347000, newHashFromStr("f4bd9894306981ca4c20cdbf0bbd9e9832696701f5b3d3a840d026b893db7337")},
        {383000, newHashFromStr("d902cf21480851c35844b0744ea72c1bc2d9318e87a7de63a5e3e3854331a39c")},
        {401000, newHashFromStr("e43417eb3b583fd28dfbfb38c65763d990b4c370066ac615a08c4c5c3910ebc9")},
        {420000, newHashFromStr("76e0de5adb117e12e85beb264c45e768e47d1720d72a49a24daab57493e07a04")},
        {440000, newHashFromStr("bbc6051554e936d0a18adddb95064b16a001ce164d061fb399f26416ce7860f9")},
        {461000, newHashFromStr("a60d67991b4963efee5b102c281755afde28803b9bc0b647f0cbc2120b35185b")},
        {480000, newHashFromStr("d88e6f5e77a8cb4bcb883168f357a94db31203f1977a15d90b6f6d4c2edebbbb")},
        {500000, newHashFromStr("a2989da9f8e785f7040c2e2dfc0177babbf736cfad9f2b401656fea4c3c7c9db")},
        {510000, newHashFromStr("7646ee1a99843f1e303d85e14c58dbf2bd65b393b273b379de14534743111b72")},
        {520000, newHashFromStr("114f6c2065ad5e668b901dd5ed5e9d302d6153f8e38381fbfd44485d7d499e10")},
        {540000, newHashFromStr("d7480699ff87574bfad0038b8697f9bc4df5f0cba31058a637eefbc94e402761")},
        {600000, newHashFromStr("85ac8dbbba7a870a45740677be5f35114cb3b70f56d1c93cc2aaf415629037e7")},
        {700000, newHashFromStr("450af2f828cdfb29be40d644d39a0858b29fe05b556946db31a7c365cffed705")},
        {800001, newHashFromStr("a6d915a25e905d1329e482aac91228b168de6e6efb3838df16c21c3ac3a82ea2")},
        {900000, newHashFromStr("7854a46edbdc4311006a9fd27ae601bb1ebd22fc5e8d6f1757e15237080a545b")},
        {1000000, newHashFromStr("ec070022a4fe9b450e02edd08c6ed355047bc8e65ef05e881b51c212d7c0fe95")},
        {1010001, newHashFromStr("a2cb82b4ae04854108b18c502f1b33e18c6f69b9d4407e8aa205a23242cd4daf")},
        {1050000, newHashFromStr("3369fa16394aa222736793fd3fd50d7f7a34d5b1ff67b344eaba269daab28a68")},
        {1060000, newHashFromStr("44e3b2bfbfb9eef5ef34df447c9ea4c4912b8a3819c2c56dfd0dc02db8a84347")},
        {1100000, newHashFromStr("4173031420285636eeecfab94e4e62e3a3cf6e144b97b2cc3622c683e09102f0")},
        {1394462, newHashFromStr("ef308b7f477903acd8f300e6f0684c4888ce28c491fc32c1c469bfba6abf091b")},
        {1400000, newHashFromStr("4bc57c3a57cc977db9f3bd6a095f51c0c7cc9c30fa8554505fa8f8e33d9f2b80")},
        {1410000, newHashFromStr("7512574ec717d46a90b8c36fd923ef819fdc298b8e4be57be631519662f0db59")},
        {1573741, newHashFromStr("6e4dacfd1684e71a178f29f3e9c714d264e6d385f64c31cdbe532b3204ce4e1d")},
        {1574000, newHashFromStr("cef389868efd7785b977eb86527e8049a2a5ea472a6ed9bfc0741c6d6b39234b")},
        {1579000, newHashFromStr("12cb8ae28107d99f4ba24465b9abf21f98fe855d9b09449cf5c8ed98120829c1")},
        {1589000, newHashFromStr("479746c27e323e233e58af6024bb7b9727a26bc0114c26ff537469e6ada105e1")},
        {1600000, newHashFromStr("f44cbdcb21fc7716947f763ccca5de5b02ffff7f14beafef0a7486067f6777fa")},
        {1650000, newHashFromStr("70caabb0720c95f67a02eabfde27253eaa8698dc6ea5716631890876b9df421a")},        
        {1700000, newHashFromStr("691eb62d25a0961e81f1a8427b8c21e01ade5befe4a94be5826f49cfecc070a0")},
        {1750000, newHashFromStr("8971f1790e58c6de0ea2854872c6ad03752b65567ab8e5c8458ae4a6eb9fb783")},
        {1766666, newHashFromStr("ffb7d30ec4d20cae926af05252dc39dbc433b068a0807a8f0dfa63521caca6f0")},
        {1888888, newHashFromStr("89530dba778db5a540aac6b7b8659cee8909ba445fa5a54ba3023e98e045692d")},
        {1892222, newHashFromStr("685a23cfa75e4e084f32b6a4ae09b3113c9509d84ce0559813627d462df6db88")},
        {2227008, newHashFromStr("23eb6ca0fc87c887485a1417364dae6c3ae5cc4801c6eef8fc2b6bb83cdf9013")},
        {2242222, newHashFromStr("98b01e772f0ca3b3ac875857e4f3b6571f8f18b8b896d0cb2feefeca90b69583")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1916, // 95% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016, //
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  1462060800, // May 1st, 2016
			ExpireTime: 1493596800, // May 1st, 2017
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  1479168000, // November 15, 2016 UTC
			ExpireTime: 1510704000, // November 15, 2017 UTC.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "bc", // always bc for main net

	// Address encoding magics
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "18444",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	BIP0034Height:            100000000, // Not active - Permit ver 1 blocks
	BIP0065Height:            1351,      // Used by regression tests
	BIP0066Height:            1251,      // Used by regression tests
	SubsidyReductionInterval: 150,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 108, // 75%  of MinerConfirmationWindow
	MinerConfirmationWindow:       144,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "bcrt", // always bcrt for reg test net

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// TestNet3Params defines the network parameters for the test Bitcoin network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var TestNet3Params = Params{
	Name:        "testnet3",
	Net:         wire.TestNet3,
	//DefaultPort: "18333",	//-- by btc
	DefaultPort: "25677",	//-- by eac
	//-- by btc
	// DNSSeeds: []DNSSeed{
		// {"testnet-seed.bitcoin.jonasschnelli.ch", true},
		// {"testnet-seed.bitcoin.schildbach.de", false},
		// {"seed.tbtc.petertodd.org", true},
		// {"testnet-seed.bluematt.me", false},
	// },
	//-- by eac
	DNSSeeds: []DNSSeed{	
		{"testnet-seed.earthcointools.org", true},
	},

	// Chain parameters
	GenesisBlock:             &testNet3GenesisBlock,
	GenesisHash:              &testNet3GenesisHash,
	PowLimit:                 testNet3PowLimit,
	PowLimitBits:             0x1d00ffff,
	BIP0034Height:            21111,  // 0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8
	BIP0065Height:            581885, // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
	BIP0066Height:            330776, // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{546, newHashFromStr("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
		{100000, newHashFromStr("00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")},
		{200000, newHashFromStr("0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2")},
		{300001, newHashFromStr("0000000000004829474748f3d1bc8fcf893c88be255e6d7f571c548aff57abf4")},
		{400002, newHashFromStr("0000000005e2c73b8ecb82ae2dbc2e8274614ebad7172b53528aba7501f5a089")},
		{500011, newHashFromStr("00000000000929f63977fbac92ff570a9bd9e7715401ee96f2848f7b07750b02")},
		{600002, newHashFromStr("000000000001f471389afd6ee94dcace5ccc44adc18e8bff402443f034b07240")},
		{700000, newHashFromStr("000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1")},
		{800010, newHashFromStr("000000000017ed35296433190b6829db01e657d80631d43f5983fa403bfdb4c1")},
		{900000, newHashFromStr("0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b")},
		{1000007, newHashFromStr("00000000001ccb893d8a1f25b70ad173ce955e5f50124261bbbc50379a612ddf")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1512, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  1199145601, // January 1, 2008 UTC
			ExpireTime: 1230767999, // December 31, 2008 UTC
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  1456790400, // March 1st, 2016
			ExpireTime: 1493596800, // May 1st, 2017
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  1462060800, // May 1, 2016 UTC
			ExpireTime: 1493596800, // May 1, 2017 UTC.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tb", // always tb for test net

	// Address encoding magics
	PubKeyHashAddrID:        0x6f, // starts with m or n
	ScriptHashAddrID:        0xc4, // starts with 2
	WitnessPubKeyHashAddrID: 0x03, // starts with QW
	WitnessScriptHashAddrID: 0x28, // starts with T7n
	PrivateKeyID:            0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// SimNetParams defines the network parameters for the simulation test Bitcoin
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "18555",
	DNSSeeds:    []DNSSeed{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
	PowLimit:                 simNetPowLimit,
	PowLimitBits:             0x207fffff,
	BIP0034Height:            0, // Always active on simnet
	BIP0065Height:            0, // Always active on simnet
	BIP0066Height:            0, // Always active on simnet
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 75, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       100,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentCSV: {
			BitNumber:  0,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
		DeploymentSegwit: {
			BitNumber:  1,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires.
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "sb", // always sb for sim net

	// Address encoding magics
	PubKeyHashAddrID:        0x3f, // starts with S
	ScriptHashAddrID:        0x7b, // starts with s
	PrivateKeyID:            0x64, // starts with 4 (uncompressed) or F (compressed)
	WitnessPubKeyHashAddrID: 0x19, // starts with Gg
	WitnessScriptHashAddrID: 0x28, // starts with ?

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
	HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 115, // ASCII for s
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")
)

var (
	registeredNets       = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs    = make(map[byte]struct{})
	scriptHashAddrIDs    = make(map[byte]struct{})
	bech32SegwitPrefixes = make(map[string]struct{})
	hdPrivToPubKeyIDs    = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}
	hdPrivToPubKeyIDs[params.HDPrivateKeyID] = params.HDPublicKeyID[:]

	// A valid Bech32 encoded segwit address always has as prefix the
	// human-readable part for the given net followed by '1'.
	bech32SegwitPrefixes[params.Bech32HRPSegwit+"1"] = struct{}{}
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for segwit
// addresses on any default or registered network.  This is used when decoding
// an address string into a specific address type.
func IsBech32SegwitPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32SegwitPrefixes[prefix]
	return ok
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNet3Params)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
}
