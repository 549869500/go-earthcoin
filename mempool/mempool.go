// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"container/list"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/blockchain/indexers"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mining"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// DefaultBlockPrioritySize is the default size in bytes for high-
	// priority / low-fee transactions.  It is used to help determine which
	// are allowed into the mempool and consequently affects their relay and
	// inclusion when generating block templates.
	// DefaultBlockPrioritySize是高优先级/低费用交易的默认大小（以字节为单位）。
	// 它用于帮助确定哪些允许进入mempool，从而在生成块模板时影响它们的继电器和包含。
	DefaultBlockPrioritySize = 50000

	// orphanTTL is the maximum amount of time an orphan is allowed to
	// stay in the orphan pool before it expires and is evicted during the
	// next scan.
	orphanTTL = time.Minute * 15

	// orphanExpireScanInterval is the minimum amount of time in between
	// scans of the orphan pool to evict expired transactions.
	// orphanTTL是孤立交易池在到期之前被允许留在孤立池中的最长时间，
	// 并且在下一次扫描期间被驱逐。
	orphanExpireScanInterval = time.Minute * 5
)

// Tag represents an identifier to use for tagging orphan transactions.  The
// caller may choose any scheme it desires, however it is common to use peer IDs
// so that orphans can be identified by which peer first relayed them.
// Tag表示用于标记孤立交易的标识符。 呼叫者可以选择它想要的任何方案，但是通常使用节点ID，
// 以便可以通过哪个节点首先中继它们来识别孤立交易。
type Tag uint64

// Config is a descriptor containing the memory pool configuration.
// Config是包含内存池配置的描述符。
type Config struct {
	// Policy defines the various mempool configuration options related
	// to policy.
	// Policy定义了与策略相关的各种mempool配置选项。
	Policy Policy

	// ChainParams identifies which chain parameters the txpool is
	// associated with.
	// ChainParams识别txpool与哪些链参数相关联。
	ChainParams *chaincfg.Params

	// FetchUtxoView defines the function to use to fetch unspent
	// transaction output information.
	// FetchUtxoView定义用于获取未使用的交易输出信息的函数。
	FetchUtxoView func(*btcutil.Tx) (*blockchain.UtxoViewpoint, error)

	// BestHeight defines the function to use to access the block height of
	// the current best chain.
	// BestHeight定义用于访问当前最佳链的块高度的函数。
	BestHeight func() int32

	// MedianTimePast defines the function to use in order to access the
	// median time past calculated from the point-of-view of the current
	// chain tip within the best chain.
	// MedianTimePast定义要使用的函数，以便访问从最佳链中当前链尖的视点计算的过去的
	// 中值时间。
	MedianTimePast func() time.Time

	// CalcSequenceLock defines the function to use in order to generate
	// the current sequence lock for the given transaction using the passed
	// utxo view.
	// CalcSequenceLock定义要使用的函数，以便使用传递的utxo视图为给定的交易生成当前
	// 序列锁。
	CalcSequenceLock func(*btcutil.Tx, *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error)

	// IsDeploymentActive returns true if the target deploymentID is
	// active, and false otherwise. The mempool uses this function to gauge
	// if transactions using new to be soft-forked rules should be allowed
	// into the mempool or not.
	//如果目标deploymentID处于活动状态，则IsDeploymentActive返回true，否则返回false。
	//mempool使用此函数来判断是否应允许使用new作为软分叉规则的交易进入mempool。
	IsDeploymentActive func(deploymentID uint32) (bool, error)

	// SigCache defines a signature cache to use.
	// SigCache定义要使用的签名缓存。
	SigCache *txscript.SigCache

	// HashCache defines the transaction hash mid-state cache to use.
	// HashCache定义要使用的交易哈希中间状态缓存。
	HashCache *txscript.HashCache

	// AddrIndex defines the optional address index instance to use for
	// indexing the unconfirmed transactions in the memory pool.
	// This can be nil if the address index is not enabled.
	// AddrIndex定义可选的地址索引实例，用于索引内存池中未确认的交易。
	//如果未启用地址索引，则此值可以为nil。
	AddrIndex *indexers.AddrIndex

	// FeeEstimatator provides a feeEstimator. If it is not nil, the mempool
	// records all new transactions it observes into the feeEstimator.
	// FeeEstimatator提供费用估算器。
	// 如果它不是零，则mempool将它观察到的所有新交易记录到feeEstimator中。
	FeeEstimator *FeeEstimator
}

// Policy houses the policy (configuration parameters) which is used to
// control the mempool.
// 策略包含用于控制mempool的策略（配置参数）。
type Policy struct {
	// MaxTxVersion is the transaction version that the mempool should
	// accept.  All transactions above this version are rejected as
	// non-standard.
	// MaxTxVersion是mempool应该接受的交易版本。
	// 此版本以上的所有交易均被拒绝为非标准交易。
	MaxTxVersion int32

	// DisableRelayPriority defines whether to relay free or low-fee
	// transactions that do not have enough priority to be relayed.
	// DisableRelayPriority定义是否中继没有足够优先级的免费或低费用交易。
	DisableRelayPriority bool

	// AcceptNonStd defines whether to accept non-standard transactions. If
	// true, non-standard transactions will be accepted into the mempool.
	// Otherwise, all non-standard transactions will be rejected.
	// AcceptNonStd定义是否接受非标准交易。
	// 如果为true，则非标准交易将被接受到mempool中。
	// 否则，所有非标准交易都将被拒绝。
	AcceptNonStd bool

	// FreeTxRelayLimit defines the given amount in thousands of bytes
	// per minute that transactions with no fee are rate limited to.
	// FreeTxRelayLimit定义了每分钟数千字节的给定数量，交易不收取任何费用。
	FreeTxRelayLimit float64

	// MaxOrphanTxs is the maximum number of orphan transactions
	// that can be queued.
	// MaxOrphanTxs是可以排队的最大孤立交易数。
	MaxOrphanTxs int

	// MaxOrphanTxSize is the maximum size allowed for orphan transactions.
	// This helps prevent memory exhaustion attacks from sending a lot of
	// of big orphans.
	// MaxOrphanTxSize是孤立交易允许的最大大小。
	//这有助于防止内存耗尽攻击发送大量孤立交易。
	MaxOrphanTxSize int

	// MaxSigOpCostPerTx is the cumulative maximum cost of all the signature
	// operations in a single transaction we will relay or mine.  It is a
	// fraction of the max signature operations for a block.
	// MaxSigOpCostPerTx是我们将中继或挖掘的单个交易中所有签名操作的累积最大成本。
	// 它是块的最大签名操作的一部分。
	MaxSigOpCostPerTx int

	// MinRelayTxFee defines the minimum transaction fee in BTC/kB to be
	// considered a non-zero fee.
	// MinRelayTxFee定义BTC / kB中的最低交易费用被视为非零费用。
	MinRelayTxFee btcutil.Amount
}

// TxDesc is a descriptor containing a transaction in the mempool along with
// additional metadata.
// TxDesc是一个描述符，包含mempool中的交易以及其他元数据。
type TxDesc struct {
	mining.TxDesc

	// StartingPriority is the priority of the transaction when it was added
	// to the pool.
	// StartingPriority是将交易添加到池中时的优先级。
	StartingPriority float64
}

// orphanTx is normal transaction that references an ancestor transaction
// that is not yet available.  It also contains additional information related
// to it such as an expiration time to help prevent caching the orphan forever.
// orphanTx是引用尚不可用的祖先交易的普通交易。
// 它还包含与其相关的其他信息，例如过期时间，以帮助防止永久缓存孤立交易。
type orphanTx struct {
	tx         *btcutil.Tx
	tag        Tag
	expiration time.Time
}

// TxPool is used as a source of transactions that need to be mined into blocks
// and relayed to other peers.  It is safe for concurrent access from multiple
// peers.
// 定义交易池结构, 交易池TxPool是用来管理所有接收到的交易Tx。
// 交易池用作需要挖掘成块并转发给其他节点的交易源。 来自多个节点的并发访问是安全的。
type TxPool struct {
	// The following variables must only be used atomically.
	//以下变量只能以原子方式使用。
	lastUpdated int64 // 最后一次更新内存池时间 last time pool was updated

	mtx     sync.RWMutex
	cfg     Config
	pool    map[chainhash.Hash]*TxDesc   //交易池
	orphans map[chainhash.Hash]*orphanTx //孤立交易池
	//后向指针，指向子节点
	orphansByPrev map[wire.OutPoint]map[chainhash.Hash]*btcutil.Tx
	outpoints     map[wire.OutPoint]*btcutil.Tx
	//小钱的指数衰减总计。
	pennyTotal float64 // exponentially decaying total for penny spends.
	//UNIX时间/最后一分钱花费
	lastPennyUnix int64 // unix time of last ``penny spend''

	// nextExpireScan is the time after which the orphan pool will be
	// scanned in order to evict orphans.  This is NOT a hard deadline as
	// the scan will only run when an orphan is added to the pool as opposed
	// to on an unconditional timer.
	//nextExpireScan是对孤立交易池进行扫描以驱逐孤立交易的时间。这不是一个严格的最后期限，
	//因为只有当孤立交易被添加到池中时，扫描才会运行，而不是在无条件计时器上。
	nextExpireScan time.Time
}

// Ensure the TxPool type implements the mining.TxSource interface.
//确保TxPool类型实现了mining.TxSource接口。
var _ mining.TxSource = (*TxPool)(nil)

// 下面是交易的结构，位置在/github.com/btcsuite/btcutil/tx.go
// // Tx defines a bitcoin transaction that provides easier and more efficient
// // manipulation of raw transactions.  It also memoizes the hash for the
// // transaction on its first access so subsequent accesses don't have to repeat
// // the relatively expensive hashing operations.
// // Tx定义了一个比特币交易，可以更简单，更有效地处理原始交易。
// // 它还在第一次访问时记忆交易的哈希值，因此后续访问不必重复相对昂贵的哈希操作。
// type Tx struct {
// // MsgTx的基础
// 	msgTx         *wire.MsgTx     // Underlying MsgTx
// //缓存交易哈希
// 	txHash        *chainhash.Hash // Cached transaction hash
// 	// 缓存交易见证哈希
// 	txHashWitness *chainhash.Hash // Cached transaction witness hash
// 	//如果交易有见证数据
// 	txHasWitness  *bool           // If the transaction has witness data
//  //块内的位置或交易索引未知
// 	txIndex       int             // Position within a block or TxIndexUnknown
// }

// removeOrphan is the internal function which implements the public
// RemoveOrphan.  See the comment for RemoveOrphan for more details.
//
// RemoveOrphan:删除孤立交易
// removeOrphan是实现公共RemoveOrphan的内部函数。
// 有关详细信息，请参阅RemoveOrphan的注释。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) removeOrphan(tx *btcutil.Tx, removeRedeemers bool) {
	// Nothing to do if passed tx is not an orphan.
	//如果传递tx没有什么可以做的不是孤立交易。
	txHash := tx.Hash()
	otx, exists := mp.orphans[*txHash]
	if !exists {
		return
	}

	// Remove the reference from the previous orphan index.
	//从先前的孤立索引中删除引用。
	for _, txIn := range otx.tx.MsgTx().TxIn {
		orphans, exists := mp.orphansByPrev[txIn.PreviousOutPoint]
		if exists {
			delete(orphans, *txHash)

			// Remove the map entry altogether if there are no
			// longer any orphans which depend on it.
			//如果不再有依赖它的孤立交易，则完全删除地图条目。
			if len(orphans) == 0 {
				delete(mp.orphansByPrev, txIn.PreviousOutPoint)
			}
		}
	}

	// Remove any orphans that redeem outputs from this one if requested.
	//如果请求，删除任何从此一个兑换输出的孤立交易。
	if removeRedeemers {
		prevOut := wire.OutPoint{Hash: *txHash}
		for txOutIdx := range tx.MsgTx().TxOut {
			prevOut.Index = uint32(txOutIdx)
			for _, orphan := range mp.orphansByPrev[prevOut] {
				mp.removeOrphan(orphan, true)
			}
		}
	}

	// Remove the transaction from the orphan pool.
	//从孤立池中删除交易。
	delete(mp.orphans, *txHash)
}

// RemoveOrphan removes the passed orphan transaction from the orphan pool and
// previous orphan index.
//
// This function is safe for concurrent access.
// RemoveOrphan:删除孤立交易
// RemoveOrphan从孤立池和先前的孤立索引中删除传递的孤立交易。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) RemoveOrphan(tx *btcutil.Tx) {
	mp.mtx.Lock()
	mp.removeOrphan(tx, false)
	mp.mtx.Unlock()
}

// RemoveOrphansByTag removes all orphan transactions tagged with the provided
// identifier.
//
// This function is safe for concurrent access.
// RemoveOrphansByTag删除所有使用提供的标识符标记的孤立交易。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) RemoveOrphansByTag(tag Tag) uint64 {
	var numEvicted uint64
	mp.mtx.Lock()
	for _, otx := range mp.orphans {
		if otx.tag == tag {
			mp.removeOrphan(otx.tx, true)
			numEvicted++
		}
	}
	mp.mtx.Unlock()
	return numEvicted
}

// limitNumOrphans limits the number of orphan transactions by evicting a random
// orphan if adding a new one would cause it to overflow the max allowed.
//
// This function MUST be called with the mempool lock held (for writes).
// 限制孤立交易的数量
// limitNumOrphans通过驱逐随机孤立来限制孤立交易的数量，
// 如果添加新的孤立交易将导致它溢出允许的最大值。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) limitNumOrphans() error {
	// Scan through the orphan pool and remove any expired orphans when it's
	// time.  This is done for efficiency so the scan only happens
	// periodically instead of on every orphan added to the pool.
	if now := time.Now(); now.After(mp.nextExpireScan) {
		origNumOrphans := len(mp.orphans)
		for _, otx := range mp.orphans {
			if now.After(otx.expiration) {
				// Remove redeemers too because the missing
				// parents are very unlikely to ever materialize
				// since the orphan has already been around more
				// than long enough for them to be delivered.
				mp.removeOrphan(otx.tx, true)
			}
		}

		// Set next expiration scan to occur after the scan interval.
		mp.nextExpireScan = now.Add(orphanExpireScanInterval)

		numOrphans := len(mp.orphans)
		if numExpired := origNumOrphans - numOrphans; numExpired > 0 {
			log.Debugf("Expired %d %s (remaining: %d)", numExpired,
				pickNoun(numExpired, "orphan", "orphans"),
				numOrphans)
		}
	}

	// Nothing to do if adding another orphan will not cause the pool to
	// exceed the limit.
	if len(mp.orphans)+1 <= mp.cfg.Policy.MaxOrphanTxs {
		return nil
	}

	// Remove a random entry from the map.  For most compilers, Go's
	// range statement iterates starting at a random item although
	// that is not 100% guaranteed by the spec.  The iteration order
	// is not important here because an adversary would have to be
	// able to pull off preimage attacks on the hashing function in
	// order to target eviction of specific entries anyways.
	for _, otx := range mp.orphans {
		// Don't remove redeemers in the case of a random eviction since
		// it is quite possible it might be needed again shortly.
		mp.removeOrphan(otx.tx, false)
		break
	}

	return nil
}

// addOrphan adds an orphan transaction to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
// addOrphan:添加孤立交易
// addOrphan将一个孤立交易添加到孤立池中。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) addOrphan(tx *btcutil.Tx, tag Tag) {
	// Nothing to do if no orphans are allowed.
	if mp.cfg.Policy.MaxOrphanTxs <= 0 {
		return
	}

	// Limit the number orphan transactions to prevent memory exhaustion.
	// This will periodically remove any expired orphans and evict a random
	// orphan if space is still needed.
	mp.limitNumOrphans()

	mp.orphans[*tx.Hash()] = &orphanTx{
		tx:         tx,
		tag:        tag,
		expiration: time.Now().Add(orphanTTL),
	}
	for _, txIn := range tx.MsgTx().TxIn {
		if _, exists := mp.orphansByPrev[txIn.PreviousOutPoint]; !exists {
			mp.orphansByPrev[txIn.PreviousOutPoint] =
				make(map[chainhash.Hash]*btcutil.Tx)
		}
		mp.orphansByPrev[txIn.PreviousOutPoint][*tx.Hash()] = tx
	}

	log.Debugf("Stored orphan transaction %v (total: %d)", tx.Hash(),
		len(mp.orphans))
}

// maybeAddOrphan potentially adds an orphan to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
// maybeAddOrphan:或许能添加孤立交易
// maybeAddOrphan可能会为孤立交易池添加一个孤立交易。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) maybeAddOrphan(tx *btcutil.Tx, tag Tag) error {
	// Ignore orphan transactions that are too large.  This helps avoid
	// a memory exhaustion attack based on sending a lot of really large
	// orphans.  In the case there is a valid transaction larger than this,
	// it will ultimtely be rebroadcast after the parent transactions
	// have been mined or otherwise received.
	//
	// Note that the number of orphan transactions in the orphan pool is
	// also limited, so this equates to a maximum memory used of
	// mp.cfg.Policy.MaxOrphanTxSize * mp.cfg.Policy.MaxOrphanTxs (which is ~5MB
	// using the default values at the time this comment was written).
	serializedLen := tx.MsgTx().SerializeSize()
	if serializedLen > mp.cfg.Policy.MaxOrphanTxSize {
		str := fmt.Sprintf("orphan transaction size of %d bytes is "+
			"larger than max allowed size of %d bytes",
			serializedLen, mp.cfg.Policy.MaxOrphanTxSize)
		return txRuleError(wire.RejectNonstandard, str)
	}

	// Add the orphan if the none of the above disqualified it.
	mp.addOrphan(tx, tag)

	return nil
}

// removeOrphanDoubleSpends removes all orphans which spend outputs spent by the
// passed transaction from the orphan pool.  Removing those orphans then leads
// to removing all orphans which rely on them, recursively.  This is necessary
// when a transaction is added to the main pool because it may spend outputs
// that orphans also spend.
//
// This function MUST be called with the mempool lock held (for writes).
// removeOrphanDoubleSpends：删除孤立交易双倍花费
// removeOrphanDoubleSpends删除所有孤立交易，
// 这些孤立交易花费来自孤立池的传递交易所花费的输出。
// 移除那些孤立交易，然后导致以递归方式移除所有依赖它们的孤立交易。
// 当交易被添加到主池时，这是必要的，因为它可能花费孤立交易也花费的输出。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) removeOrphanDoubleSpends(tx *btcutil.Tx) {
	msgTx := tx.MsgTx()
	for _, txIn := range msgTx.TxIn {
		for _, orphan := range mp.orphansByPrev[txIn.PreviousOutPoint] {
			mp.removeOrphan(orphan, true)
		}
	}
}

// isTransactionInPool returns whether or not the passed transaction already
// exists in the main pool.
//
// This function MUST be called with the mempool lock held (for reads).
// isTransactionInPool:是交易池中的交易
// isTransactionInPool返回传递的交易是否已存在于主池中。
//
//必须在保持mempool锁（用于读取）的情况下调用此函数。
func (mp *TxPool) isTransactionInPool(hash *chainhash.Hash) bool {
	if _, exists := mp.pool[*hash]; exists {
		return true
	}

	return false
}

// IsTransactionInPool returns whether or not the passed transaction already
// exists in the main pool.
//
// This function is safe for concurrent access.
// isTransactionInPool:是交易池中的交易
// IsTransactionInPool返回传递的交易是否已存在于主池中。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) IsTransactionInPool(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	inPool := mp.isTransactionInPool(hash)
	mp.mtx.RUnlock()

	return inPool
}

// isOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
// isOrphanInPool:是孤立交易池中的孤立交易
// isOrphanInPool返回传递的交易是否已存在于孤立池中。
//
//必须在保持mempool锁（用于读取）的情况下调用此函数。
func (mp *TxPool) isOrphanInPool(hash *chainhash.Hash) bool {
	if _, exists := mp.orphans[*hash]; exists {
		return true
	}

	return false
}

// IsOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function is safe for concurrent access.
// isOrphanInPool:是孤立交易池中的孤立交易
// IsOrphanInPool返回传递的交易是否已存在于孤立池中。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) IsOrphanInPool(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	inPool := mp.isOrphanInPool(hash)
	mp.mtx.RUnlock()

	return inPool
}

// haveTransaction returns whether or not the passed transaction already exists
// in the main pool or in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
// haveTransaction:有交易
// haveTransaction返回传递的交易是否已存在于主池或孤立交易池中。
//
//必须在保持mempool锁（用于读取）的情况下调用此函数。
func (mp *TxPool) haveTransaction(hash *chainhash.Hash) bool {
	return mp.isTransactionInPool(hash) || mp.isOrphanInPool(hash)
}

// HaveTransaction returns whether or not the passed transaction already exists
// in the main pool or in the orphan pool.
//
// This function is safe for concurrent access.
// haveTransaction:有交易
// HaveTransaction返回传递的交易是否已存在于主池或孤立池中。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) HaveTransaction(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	haveTx := mp.haveTransaction(hash)
	mp.mtx.RUnlock()

	return haveTx
}

// removeTransaction is the internal function which implements the public
// RemoveTransaction.  See the comment for RemoveTransaction for more details.
//
// This function MUST be called with the mempool lock held (for writes).
// removeTransaction:删除交易
// removeTransaction是实现公共RemoveTransaction的内部函数。
// 有关详细信息，请参阅RemoveTransaction的注释。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) removeTransaction(tx *btcutil.Tx, removeRedeemers bool) {
	txHash := tx.Hash()
	if removeRedeemers {
		// Remove any transactions which rely on this one.
		for i := uint32(0); i < uint32(len(tx.MsgTx().TxOut)); i++ {
			prevOut := wire.OutPoint{Hash: *txHash, Index: i}
			if txRedeemer, exists := mp.outpoints[prevOut]; exists {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}

	// Remove the transaction if needed.
	if txDesc, exists := mp.pool[*txHash]; exists {
		// Remove unconfirmed address index entries associated with the
		// transaction if enabled.
		if mp.cfg.AddrIndex != nil {
			mp.cfg.AddrIndex.RemoveUnconfirmedTx(txHash)
		}

		// Mark the referenced outpoints as unspent by the pool.
		for _, txIn := range txDesc.Tx.MsgTx().TxIn {
			delete(mp.outpoints, txIn.PreviousOutPoint)
		}
		delete(mp.pool, *txHash)
		atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
	}
}

// RemoveTransaction removes the passed transaction from the mempool. When the
// removeRedeemers flag is set, any transactions that redeem outputs from the
// removed transaction will also be removed recursively from the mempool, as
// they would otherwise become orphans.
//
// This function is safe for concurrent access.
// removeTransaction:删除交易
// RemoveTransaction从mempool中删除传递的交易。 当设置了removeRedeemers标志时，
// 任何从被删除的交易中兑换输出的交易也将从mempool中递归删除，否则它们将成为孤立交易。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) RemoveTransaction(tx *btcutil.Tx, removeRedeemers bool) {
	// Protect concurrent access.
	//保护并发访问。
	mp.mtx.Lock()
	mp.removeTransaction(tx, removeRedeemers)
	mp.mtx.Unlock()
}

// RemoveDoubleSpends removes all transactions which spend outputs spent by the
// passed transaction from the memory pool.  Removing those transactions then
// leads to removing all transactions which rely on them, recursively.  This is
// necessary when a block is connected to the main chain because the block may
// contain transactions which were previously unknown to the memory pool.
//
// This function is safe for concurrent access.
// RemoveDoubleSpends:删除双倍花费
// RemoveDoubleSpends删除所有从内存池中消耗传递的交易所花费的交易的交易。
// 删除这些交易然后导致以递归方式删除依赖它们的所有交易。
// 当块连接到主链时，这是必需的，因为块可能包含以前内存池未知的交易。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) RemoveDoubleSpends(tx *btcutil.Tx) {
	// Protect concurrent access.
	//保护并发访问。
	mp.mtx.Lock()
	for _, txIn := range tx.MsgTx().TxIn {
		if txRedeemer, ok := mp.outpoints[txIn.PreviousOutPoint]; ok {
			if !txRedeemer.Hash().IsEqual(tx.Hash()) {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}
	mp.mtx.Unlock()
}

// addTransaction adds the passed transaction to the memory pool.  It should
// not be called directly as it doesn't perform any validation.  This is a
// helper for maybeAcceptTransaction.
//
// This function MUST be called with the mempool lock held (for writes).
// addTransaction:添加交易
// addTransaction将传递的交易添加到内存池。
// 它不应该直接调用，因为它不执行任何验证。 这是maybeAcceptTransaction的帮手。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) addTransaction(utxoView *blockchain.UtxoViewpoint, tx *btcutil.Tx, height int32, fee int64) *TxDesc {
	// Add the transaction to the pool and mark the referenced outpoints
	// as spent by the pool.
	txD := &TxDesc{
		TxDesc: mining.TxDesc{
			Tx:       tx,
			Added:    time.Now(),
			Height:   height,
			Fee:      fee,
			FeePerKB: fee * 1000 / GetTxVirtualSize(tx),
		},
		StartingPriority: mining.CalcPriority(tx.MsgTx(), utxoView, height),
	}

	mp.pool[*tx.Hash()] = txD
	for _, txIn := range tx.MsgTx().TxIn {
		mp.outpoints[txIn.PreviousOutPoint] = tx
	}
	atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())

	// Add unconfirmed address index entries associated with the transaction
	// if enabled.
	if mp.cfg.AddrIndex != nil {
		mp.cfg.AddrIndex.AddUnconfirmedTx(tx, utxoView)
	}

	// Record this tx for fee estimation if enabled.
	if mp.cfg.FeeEstimator != nil {
		mp.cfg.FeeEstimator.ObserveTransaction(txD)
	}

	return txD
}

// checkPoolDoubleSpend checks whether or not the passed transaction is
// attempting to spend coins already spent by other transactions in the pool.
// Note it does not check for double spends against transactions already in the
// main chain.
//
// This function MUST be called with the mempool lock held (for reads).
// checkPoolDoubleSpend:检查交易池双倍花费
// checkPoolDoubleSpend检查传递的交易是否正在尝试花费池中其他交易已经花费的硬币。
//请注意，它不会检查主链中已有交易的双倍花费。
//
//必须在保持mempool锁（用于读取）的情况下调用此函数。
func (mp *TxPool) checkPoolDoubleSpend(tx *btcutil.Tx) error {
	for _, txIn := range tx.MsgTx().TxIn {
		if txR, exists := mp.outpoints[txIn.PreviousOutPoint]; exists {
			str := fmt.Sprintf("output %v already spent by "+
				"transaction %v in the memory pool",
				txIn.PreviousOutPoint, txR.Hash())
			return txRuleError(wire.RejectDuplicate, str)
		}
	}

	return nil
}

// CheckSpend checks whether the passed outpoint is already spent by a
// transaction in the mempool. If that's the case the spending transaction will
// be returned, if not nil will be returned.
// CheckSpend：检查花费
// CheckSpend检查传递的outpoint是否已被mempool中的交易占用。
// 如果是这种情况，将返回支出交易，如果不是，则返回nil。
func (mp *TxPool) CheckSpend(op wire.OutPoint) *btcutil.Tx {
	mp.mtx.RLock()
	txR := mp.outpoints[op]
	mp.mtx.RUnlock()

	return txR
}

// fetchInputUtxos loads utxo details about the input transactions referenced by
// the passed transaction.  First, it loads the details form the viewpoint of
// the main chain, then it adjusts them based upon the contents of the
// transaction pool.
//
// This function MUST be called with the mempool lock held (for reads).
// fetchInputUtxos:获取输入Utxos
// fetchInputUtxos加载有关传递的交易引用的输入交易的utxo详细信息。
// 首先，它从主链的角度加载细节，然后根据交易池的内容调整它们。
//
//必须在保持mempool锁（用于读取）的情况下调用此函数。
func (mp *TxPool) fetchInputUtxos(tx *btcutil.Tx) (*blockchain.UtxoViewpoint, error) {
	utxoView, err := mp.cfg.FetchUtxoView(tx)
	if err != nil {
		return nil, err
	}

	// Attempt to populate any missing inputs from the transaction pool.
	for _, txIn := range tx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		entry := utxoView.LookupEntry(*prevOut)
		if entry != nil && !entry.IsSpent() {
			continue
		}

		if poolTxDesc, exists := mp.pool[prevOut.Hash]; exists {
			// AddTxOut ignores out of range index values, so it is
			// safe to call without bounds checking here.
			utxoView.AddTxOut(poolTxDesc.Tx, prevOut.Index,
				mining.UnminedHeight)
		}
	}

	return utxoView, nil
}

// FetchTransaction returns the requested transaction from the transaction pool.
// This only fetches from the main transaction pool and does not include
// orphans.
//
// This function is safe for concurrent access.
// FetchTransaction:获取交易
// FetchTransaction从交易池返回请求的交易。
// 这只从主交易池中提取，不包括孤立交易。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) FetchTransaction(txHash *chainhash.Hash) (*btcutil.Tx, error) {
	// Protect concurrent access.
	mp.mtx.RLock()
	txDesc, exists := mp.pool[*txHash]
	mp.mtx.RUnlock()

	if exists {
		return txDesc.Tx, nil
	}

	return nil, fmt.Errorf("transaction is not in the pool")
}

// maybeAcceptTransaction is the internal function which implements the public
// MaybeAcceptTransaction.  See the comment for MaybeAcceptTransaction for
// more details.
//
// This function MUST be called with the mempool lock held (for writes).
// MaybeAcceptTransaction:也许接受交易
// maybeAcceptTransaction是实现公共MaybeAcceptTransaction的内部函数。
// 有关详细信息，请参阅MaybeAcceptTransaction的注释。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) maybeAcceptTransaction(tx *btcutil.Tx, isNew, rateLimit, rejectDupOrphans bool) ([]*chainhash.Hash, *TxDesc, error) {
	txHash := tx.Hash()

	// If a transaction has iwtness data, and segwit isn't active yet, If
	// segwit isn't active yet, then we won't accept it into the mempool as
	// it can't be mined yet.
	//如果一个交易有iwtness数据，并且segwit还没有激活，如果segwit尚未激活，
	//那么我们不会接受它进入mempool，因为它还无法被挖掘。
	if tx.MsgTx().HasWitness() {
		segwitActive, err := mp.cfg.IsDeploymentActive(chaincfg.DeploymentSegwit)
		if err != nil {
			return nil, nil, err
		}

		if !segwitActive {
			str := fmt.Sprintf("transaction %v has witness data, "+
				"but segwit isn't active yet", txHash)
			return nil, nil, txRuleError(wire.RejectNonstandard, str)
		}
	}

	// Don't accept the transaction if it already exists in the pool.  This
	// applies to orphan transactions as well when the reject duplicate
	// orphans flag is set.  This check is intended to be a quick check to
	// weed out duplicates.
	if mp.isTransactionInPool(txHash) || (rejectDupOrphans &&
		mp.isOrphanInPool(txHash)) {

		str := fmt.Sprintf("already have transaction %v", txHash)
		return nil, nil, txRuleError(wire.RejectDuplicate, str)
	}

	// Perform preliminary sanity checks on the transaction.  This makes
	// use of blockchain which contains the invariant rules for what
	// transactions are allowed into blocks.
	err := blockchain.CheckTransactionSanity(tx)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, nil, chainRuleError(cerr)
		}
		return nil, nil, err
	}

	// A standalone transaction must not be a coinbase transaction.
	if blockchain.IsCoinBase(tx) {
		str := fmt.Sprintf("transaction %v is an individual coinbase",
			txHash)
		return nil, nil, txRuleError(wire.RejectInvalid, str)
	}

	// Get the current height of the main chain.  A standalone transaction
	// will be mined into the next block at best, so its height is at least
	// one more than the current height.
	bestHeight := mp.cfg.BestHeight()
	nextBlockHeight := bestHeight + 1

	medianTimePast := mp.cfg.MedianTimePast()

	// Don't allow non-standard transactions if the network parameters
	// forbid their acceptance.
	if !mp.cfg.Policy.AcceptNonStd {
		err = checkTransactionStandard(tx, nextBlockHeight,
			medianTimePast, mp.cfg.Policy.MinRelayTxFee,
			mp.cfg.Policy.MaxTxVersion)
		if err != nil {
			// Attempt to extract a reject code from the error so
			// it can be retained.  When not possible, fall back to
			// a non standard error.
			rejectCode, found := extractRejectCode(err)
			if !found {
				rejectCode = wire.RejectNonstandard
			}
			str := fmt.Sprintf("transaction %v is not standard: %v",
				txHash, err)
			return nil, nil, txRuleError(rejectCode, str)
		}
	}

	// The transaction may not use any of the same outputs as other
	// transactions already in the pool as that would ultimately result in a
	// double spend.  This check is intended to be quick and therefore only
	// detects double spends within the transaction pool itself.  The
	// transaction could still be double spending coins from the main chain
	// at this point.  There is a more in-depth check that happens later
	// after fetching the referenced transaction inputs from the main chain
	// which examines the actual spend data and prevents double spends.
	//交易可能不会使用与池中已有的其他交易相同的任何输出，因为这最终会导致双重花费。
	//此检查旨在快速进行，因此仅检测交易池本身的双重花费。 此时交易仍可能是主链的双重花费。
	//  在从主链获取引用的交易输入之后会进行更深入的检查，
	// 该主链检查实际的支出数据并防止双重花费。
	err = mp.checkPoolDoubleSpend(tx)
	if err != nil {
		return nil, nil, err
	}

	// Fetch all of the unspent transaction outputs referenced by the inputs
	// to this transaction.  This function also attempts to fetch the
	// transaction itself to be used for detecting a duplicate transaction
	// without needing to do a separate lookup.
	// 获取此交易输入引用的所有未使用的交易输出。
	// 此函数还尝试获取交易本身以用于检测重复交易，而无需进行单独查找。
	utxoView, err := mp.fetchInputUtxos(tx)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, nil, chainRuleError(cerr)
		}
		return nil, nil, err
	}

	// Don't allow the transaction if it exists in the main chain and is not
	// not already fully spent.
	prevOut := wire.OutPoint{Hash: *txHash}
	for txOutIdx := range tx.MsgTx().TxOut {
		prevOut.Index = uint32(txOutIdx)
		entry := utxoView.LookupEntry(prevOut)
		if entry != nil && !entry.IsSpent() {
			return nil, nil, txRuleError(wire.RejectDuplicate,
				"transaction already exists")
		}
		utxoView.RemoveEntry(prevOut)
	}

	// Transaction is an orphan if any of the referenced transaction outputs
	// don't exist or are already spent.  Adding orphans to the orphan pool
	// is not handled by this function, and the caller should use
	// maybeAddOrphan if this behavior is desired.
	var missingParents []*chainhash.Hash
	for outpoint, entry := range utxoView.Entries() {
		if entry == nil || entry.IsSpent() {
			// Must make a copy of the hash here since the iterator
			// is replaced and taking its address directly would
			// result in all of the entries pointing to the same
			// memory location and thus all be the final hash.
			hashCopy := outpoint.Hash
			missingParents = append(missingParents, &hashCopy)
		}
	}
	if len(missingParents) > 0 {
		return missingParents, nil, nil
	}

	// Don't allow the transaction into the mempool unless its sequence
	// lock is active, meaning that it'll be allowed into the next block
	// with respect to its defined relative lock times.
	sequenceLock, err := mp.cfg.CalcSequenceLock(tx, utxoView)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, nil, chainRuleError(cerr)
		}
		return nil, nil, err
	}
	if !blockchain.SequenceLockActive(sequenceLock, nextBlockHeight,
		medianTimePast) {
		return nil, nil, txRuleError(wire.RejectNonstandard,
			"transaction's sequence locks on inputs not met")
	}

	// Perform several checks on the transaction inputs using the invariant
	// rules in blockchain for what transactions are allowed into blocks.
	// Also returns the fees associated with the transaction which will be
	// used later.
	txFee, err := blockchain.CheckTransactionInputs(tx, nextBlockHeight,
		utxoView, mp.cfg.ChainParams)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, nil, chainRuleError(cerr)
		}
		return nil, nil, err
	}

	// Don't allow transactions with non-standard inputs if the network
	// parameters forbid their acceptance.
	if !mp.cfg.Policy.AcceptNonStd {
		err := checkInputsStandard(tx, utxoView)
		if err != nil {
			// Attempt to extract a reject code from the error so
			// it can be retained.  When not possible, fall back to
			// a non standard error.
			rejectCode, found := extractRejectCode(err)
			if !found {
				rejectCode = wire.RejectNonstandard
			}
			str := fmt.Sprintf("transaction %v has a non-standard "+
				"input: %v", txHash, err)
			return nil, nil, txRuleError(rejectCode, str)
		}
	}

	// NOTE: if you modify this code to accept non-standard transactions,
	// you should add code here to check that the transaction does a
	// reasonable number of ECDSA signature verifications.

	// Don't allow transactions with an excessive number of signature
	// operations which would result in making it impossible to mine.  Since
	// the coinbase address itself can contain signature operations, the
	// maximum allowed signature operations per transaction is less than
	// the maximum allowed signature operations per block.
	// TODO(roasbeef): last bool should be conditional on segwit activation
	//注意：如果您修改此代码以接受非标准交易，则应在此处添加代码以检查交易是否执行了
	// 合理数量的ECDSA签名验证。

	//不允许具有过多签名操作的交易导致无法挖掘。 由于coinbase地址本身可以包含签名操作，
	//因此每个交易允许的最大签名操作数小于每个块允许的最大签名操作数。
	// TODO（roasbeef）：最后一个bool应该以segwit激活为条件
	sigOpCost, err := blockchain.GetSigOpCost(tx, false, utxoView, true, true)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, nil, chainRuleError(cerr)
		}
		return nil, nil, err
	}
	if sigOpCost > mp.cfg.Policy.MaxSigOpCostPerTx {
		str := fmt.Sprintf("transaction %v sigop cost is too high: %d > %d",
			txHash, sigOpCost, mp.cfg.Policy.MaxSigOpCostPerTx)
		return nil, nil, txRuleError(wire.RejectNonstandard, str)
	}

	// Don't allow transactions with fees too low to get into a mined block.
	//
	// Most miners allow a free transaction area in blocks they mine to go
	// alongside the area used for high-priority transactions as well as
	// transactions with fees.  A transaction size of up to 1000 bytes is
	// considered safe to go into this section.  Further, the minimum fee
	// calculated below on its own would encourage several small
	// transactions to avoid fees rather than one single larger transaction
	// which is more desirable.  Therefore, as long as the size of the
	// transaction does not exceeed 1000 less than the reserved space for
	// high-priority transactions, don't require a fee for it.
	//不允许费用过低的交易进入开采区块。
	//
	//大多数矿工允许他们开采的区块中的免费交易区域与用于高优先级交易的区域以及带有
	//费用的交易并排。 对于本节，最多1000字节的交易大小被认为是安全的。
	//此外，下面计算的最低费用将鼓励几笔小额交易以避免费用，而不是一笔更大的交易，
	//这是更理想的。 因此，只要交易的规模不超过高优先级交易的预留空间1000，就不需要收费。
	serializedSize := GetTxVirtualSize(tx)
	minFee := calcMinRequiredTxRelayFee(serializedSize,
		mp.cfg.Policy.MinRelayTxFee)
	if serializedSize >= (DefaultBlockPrioritySize-1000) && txFee < minFee {
		str := fmt.Sprintf("transaction %v has %d fees which is under "+
			"the required amount of %d", txHash, txFee,
			minFee)
		return nil, nil, txRuleError(wire.RejectInsufficientFee, str)
	}

	// Require that free transactions have sufficient priority to be mined
	// in the next block.  Transactions which are being added back to the
	// memory pool from blocks that have been disconnected during a reorg
	// are exempted.
	if isNew && !mp.cfg.Policy.DisableRelayPriority && txFee < minFee {
		currentPriority := mining.CalcPriority(tx.MsgTx(), utxoView,
			nextBlockHeight)
		if currentPriority <= mining.MinHighPriority {
			str := fmt.Sprintf("transaction %v has insufficient "+
				"priority (%g <= %g)", txHash,
				currentPriority, mining.MinHighPriority)
			return nil, nil, txRuleError(wire.RejectInsufficientFee, str)
		}
	}

	// Free-to-relay transactions are rate limited here to prevent
	// penny-flooding with tiny transactions as a form of attack.
	if rateLimit && txFee < minFee {
		nowUnix := time.Now().Unix()
		// Decay passed data with an exponentially decaying ~10 minute
		// window - matches bitcoind handling.
		mp.pennyTotal *= math.Pow(1.0-1.0/600.0,
			float64(nowUnix-mp.lastPennyUnix))
		mp.lastPennyUnix = nowUnix

		// Are we still over the limit?
		if mp.pennyTotal >= mp.cfg.Policy.FreeTxRelayLimit*10*1000 {
			str := fmt.Sprintf("transaction %v has been rejected "+
				"by the rate limiter due to low fees", txHash)
			return nil, nil, txRuleError(wire.RejectInsufficientFee, str)
		}
		oldTotal := mp.pennyTotal

		mp.pennyTotal += float64(serializedSize)
		log.Tracef("rate limit: curTotal %v, nextTotal: %v, "+
			"limit %v", oldTotal, mp.pennyTotal,
			mp.cfg.Policy.FreeTxRelayLimit*10*1000)
	}

	// Verify crypto signatures for each input and reject the transaction if
	// any don't verify.
	err = blockchain.ValidateTransactionScripts(tx, utxoView,
		txscript.StandardVerifyFlags, mp.cfg.SigCache,
		mp.cfg.HashCache)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, nil, chainRuleError(cerr)
		}
		return nil, nil, err
	}

	// Add to transaction pool.
	txD := mp.addTransaction(utxoView, tx, bestHeight, txFee)

	log.Debugf("Accepted transaction %v (pool size: %v)", txHash,
		len(mp.pool))

	return nil, txD, nil
}

// MaybeAcceptTransaction is the main workhorse for handling insertion of new
// free-standing transactions into a memory pool.  It includes functionality
// such as rejecting duplicate transactions, ensuring transactions follow all
// rules, detecting orphan transactions, and insertion into the memory pool.
//
// If the transaction is an orphan (missing parent transactions), the
// transaction is NOT added to the orphan pool, but each unknown referenced
// parent is returned.  Use ProcessTransaction instead if new orphans should
// be added to the orphan pool.
//
// This function is safe for concurrent access.
// MaybeAcceptTransaction:也许接受交易
// MaybeAcceptTransaction是处理将新的独立交易插入内存池的主要工具。
// 它包括诸如拒绝重复交易，确保交易遵循所有的功能
//规则，检测孤立交易，以及插入内存池。
//
//如果交易是孤立的（缺少父交易），则交易不会添加到孤立池中，但会返回每个未知的引用父项。
// 如果应将新的孤儿添加到孤立池中，请使用ProcessTransaction。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) MaybeAcceptTransaction(tx *btcutil.Tx, isNew, rateLimit bool) ([]*chainhash.Hash, *TxDesc, error) {
	// Protect concurrent access.
	mp.mtx.Lock()
	hashes, txD, err := mp.maybeAcceptTransaction(tx, isNew, rateLimit, true)
	mp.mtx.Unlock()

	return hashes, txD, err
}

// processOrphans is the internal function which implements the public
// ProcessOrphans.  See the comment for ProcessOrphans for more details.
//
// This function MUST be called with the mempool lock held (for writes).
// processOrphans：处理孤立交易
// processOrphans是实现公共ProcessOrphans的内部函数。
// 有关更多详细信息，请参阅ProcessOrphans的注释。
//
//必须在保持mempool锁（用于写入）的情况下调用此函数。
func (mp *TxPool) processOrphans(acceptedTx *btcutil.Tx) []*TxDesc {
	var acceptedTxns []*TxDesc

	// Start with processing at least the passed transaction.
	processList := list.New()
	processList.PushBack(acceptedTx)
	for processList.Len() > 0 {
		// Pop the transaction to process from the front of the list.
		firstElement := processList.Remove(processList.Front())
		processItem := firstElement.(*btcutil.Tx)

		prevOut := wire.OutPoint{Hash: *processItem.Hash()}
		for txOutIdx := range processItem.MsgTx().TxOut {
			// Look up all orphans that redeem the output that is
			// now available.  This will typically only be one, but
			// it could be multiple if the orphan pool contains
			// double spends.  While it may seem odd that the orphan
			// pool would allow this since there can only possibly
			// ultimately be a single redeemer, it's important to
			// track it this way to prevent malicious actors from
			// being able to purposely constructing orphans that
			// would otherwise make outputs unspendable.
			//
			// Skip to the next available output if there are none.
			prevOut.Index = uint32(txOutIdx)
			orphans, exists := mp.orphansByPrev[prevOut]
			if !exists {
				continue
			}

			// Potentially accept an orphan into the tx pool.
			for _, tx := range orphans {
				missing, txD, err := mp.maybeAcceptTransaction(
					tx, true, true, false)
				if err != nil {
					// The orphan is now invalid, so there
					// is no way any other orphans which
					// redeem any of its outputs can be
					// accepted.  Remove them.
					mp.removeOrphan(tx, true)
					break
				}

				// Transaction is still an orphan.  Try the next
				// orphan which redeems this output.
				if len(missing) > 0 {
					continue
				}

				// Transaction was accepted into the main pool.
				//
				// Add it to the list of accepted transactions
				// that are no longer orphans, remove it from
				// the orphan pool, and add it to the list of
				// transactions to process so any orphans that
				// depend on it are handled too.
				acceptedTxns = append(acceptedTxns, txD)
				mp.removeOrphan(tx, false)
				processList.PushBack(tx)

				// Only one transaction for this outpoint can be
				// accepted, so the rest are now double spends
				// and are removed later.
				break
			}
		}
	}

	// Recursively remove any orphans that also redeem any outputs redeemed
	// by the accepted transactions since those are now definitive double
	// spends.
	mp.removeOrphanDoubleSpends(acceptedTx)
	for _, txD := range acceptedTxns {
		mp.removeOrphanDoubleSpends(txD.Tx)
	}

	return acceptedTxns
}

// ProcessOrphans determines if there are any orphans which depend on the passed
// transaction hash (it is possible that they are no longer orphans) and
// potentially accepts them to the memory pool.  It repeats the process for the
// newly accepted transactions (to detect further orphans which may no longer be
// orphans) until there are no more.
//
// It returns a slice of transactions added to the mempool.  A nil slice means
// no transactions were moved from the orphan pool to the mempool.
//
// This function is safe for concurrent access.
// ProcessOrphans确定是否有任何孤立依赖于传递的交易哈希（它们可能不再是孤立的）
// 并且可能将它们接受到内存池。
// 它重复了新接受的交易的过程（以检测可能不再是孤儿的其他孤儿），直到不再有。
//
//它返回添加到mempool的一小部分交易。 nil slice表示没有交易从孤立池移动到mempool。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) ProcessOrphans(acceptedTx *btcutil.Tx) []*TxDesc {
	mp.mtx.Lock()
	acceptedTxns := mp.processOrphans(acceptedTx)
	mp.mtx.Unlock()

	return acceptedTxns
}

// ProcessTransaction is the main workhorse for handling insertion of new
// free-standing transactions into the memory pool.  It includes functionality
// such as rejecting duplicate transactions, ensuring transactions follow all
// rules, orphan transaction handling, and insertion into the memory pool.
//
// It returns a slice of transactions added to the mempool.  When the
// error is nil, the list will include the passed transaction itself along
// with any additional orphan transaactions that were added as a result of
// the passed one being accepted.
//
// This function is safe for concurrent access.
// ProcessTransaction流程交易
// ProcessTransaction是处理将新的独立交易插入内存池的主要工具。
// 它包括拒绝重复交易，确保交易遵循所有规则，孤立交易处理以及插入内存池等功能。
//
//它返回添加到mempool的一小部分交易。
//当错误为nil时，列表将包括传递的交易本身以及由于接受传递的事件而添加的任何其他孤立交易。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) ProcessTransaction(tx *btcutil.Tx, allowOrphan, rateLimit bool, tag Tag) ([]*TxDesc, error) {
	log.Tracef("Processing transaction %v", tx.Hash())

	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	// Potentially accept the transaction to the memory pool.
	missingParents, txD, err := mp.maybeAcceptTransaction(tx, true, rateLimit,
		true)
	if err != nil {
		return nil, err
	}

	if len(missingParents) == 0 {
		// Accept any orphan transactions that depend on this
		// transaction (they may no longer be orphans if all inputs
		// are now available) and repeat for those accepted
		// transactions until there are no more.
		newTxs := mp.processOrphans(tx)
		acceptedTxs := make([]*TxDesc, len(newTxs)+1)

		// Add the parent transaction first so remote nodes
		// do not add orphans.
		acceptedTxs[0] = txD
		copy(acceptedTxs[1:], newTxs)

		return acceptedTxs, nil
	}

	// The transaction is an orphan (has inputs missing).  Reject
	// it if the flag to allow orphans is not set.
	if !allowOrphan {
		// Only use the first missing parent transaction in
		// the error message.
		//
		// NOTE: RejectDuplicate is really not an accurate
		// reject code here, but it matches the reference
		// implementation and there isn't a better choice due
		// to the limited number of reject codes.  Missing
		// inputs is assumed to mean they are already spent
		// which is not really always the case.
		str := fmt.Sprintf("orphan transaction %v references "+
			"outputs of unknown or fully-spent "+
			"transaction %v", tx.Hash(), missingParents[0])
		return nil, txRuleError(wire.RejectDuplicate, str)
	}

	// Potentially add the orphan transaction to the orphan pool.
	err = mp.maybeAddOrphan(tx, tag)
	return nil, err
}

// Count returns the number of transactions in the main pool.  It does not
// include the orphan pool.
//
// This function is safe for concurrent access.
// Count返回主池中的交易数。 它不包括孤立交易池。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) Count() int {
	mp.mtx.RLock()
	count := len(mp.pool)
	mp.mtx.RUnlock()

	return count
}

// TxHashes returns a slice of hashes for all of the transactions in the memory
// pool.
//
// This function is safe for concurrent access.
// TxHashes为内存池中的所有交易返回一片哈希值。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) TxHashes() []*chainhash.Hash {
	mp.mtx.RLock()
	hashes := make([]*chainhash.Hash, len(mp.pool))
	i := 0
	for hash := range mp.pool {
		hashCopy := hash
		hashes[i] = &hashCopy
		i++
	}
	mp.mtx.RUnlock()

	return hashes
}

// TxDescs returns a slice of descriptors for all the transactions in the pool.
// The descriptors are to be treated as read only.
//
// This function is safe for concurrent access.
// TxDescs为池中的所有交易返回一片描述符。
//描述符将被视为只读。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) TxDescs() []*TxDesc {
	mp.mtx.RLock()
	descs := make([]*TxDesc, len(mp.pool))
	i := 0
	for _, desc := range mp.pool {
		descs[i] = desc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

// MiningDescs returns a slice of mining descriptors for all the transactions
// in the pool.
//
// This is part of the mining.TxSource interface implementation and is safe for
// concurrent access as required by the interface contract.
// MiningDescs为池中的所有交易返回一片挖掘描述符。
//
//这是mining.TxSource接口实现的一部分，是安全的
//接口契约要求的并发访问。
func (mp *TxPool) MiningDescs() []*mining.TxDesc {
	mp.mtx.RLock()
	descs := make([]*mining.TxDesc, len(mp.pool))
	i := 0
	for _, desc := range mp.pool {
		descs[i] = &desc.TxDesc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

// RawMempoolVerbose returns all of the entries in the mempool as a fully
// populated btcjson result.
//
// This function is safe for concurrent access.
// RawMempoolVerbose返回mempool中的所有条目，作为完全填充的btcjson结果。
//
//此函数对于并发访问是安全的
func (mp *TxPool) RawMempoolVerbose() map[string]*btcjson.GetRawMempoolVerboseResult {
	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	result := make(map[string]*btcjson.GetRawMempoolVerboseResult,
		len(mp.pool))
	bestHeight := mp.cfg.BestHeight()

	for _, desc := range mp.pool {
		// Calculate the current priority based on the inputs to
		// the transaction.  Use zero if one or more of the
		// input transactions can't be found for some reason.
		tx := desc.Tx
		var currentPriority float64
		utxos, err := mp.fetchInputUtxos(tx)
		if err == nil {
			currentPriority = mining.CalcPriority(tx.MsgTx(), utxos,
				bestHeight+1)
		}

		mpd := &btcjson.GetRawMempoolVerboseResult{
			Size:             int32(tx.MsgTx().SerializeSize()),
			Vsize:            int32(GetTxVirtualSize(tx)),
			Fee:              btcutil.Amount(desc.Fee).ToBTC(),
			Time:             desc.Added.Unix(),
			Height:           int64(desc.Height),
			StartingPriority: desc.StartingPriority,
			CurrentPriority:  currentPriority,
			Depends:          make([]string, 0),
		}
		for _, txIn := range tx.MsgTx().TxIn {
			hash := &txIn.PreviousOutPoint.Hash
			if mp.haveTransaction(hash) {
				mpd.Depends = append(mpd.Depends,
					hash.String())
			}
		}

		result[tx.Hash().String()] = mpd
	}

	return result
}

// LastUpdated returns the last time a transaction was added to or removed from
// the main pool.  It does not include the orphan pool.
//
// This function is safe for concurrent access.
// LastUpdated返回上次向主池添加或删除交易的时间。 它不包括孤立交易池。
//
//此函数对于并发访问是安全的。
func (mp *TxPool) LastUpdated() time.Time {
	return time.Unix(atomic.LoadInt64(&mp.lastUpdated), 0)
}

// New returns a new memory pool for validating and storing standalone
// transactions until they are mined into a block.
// New返回一个新的内存池，用于验证和存储独立交易，直到它们被挖掘到一个块中。
func New(cfg *Config) *TxPool {
	return &TxPool{
		cfg:            *cfg,
		pool:           make(map[chainhash.Hash]*TxDesc),
		orphans:        make(map[chainhash.Hash]*orphanTx),
		orphansByPrev:  make(map[wire.OutPoint]map[chainhash.Hash]*btcutil.Tx),
		nextExpireScan: time.Now().Add(orphanExpireScanInterval),
		outpoints:      make(map[wire.OutPoint]*btcutil.Tx),
	}
}
