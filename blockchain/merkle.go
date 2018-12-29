// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
)

const (
	// CoinbaseWitnessDataLen is the required length of the only element within
	// the coinbase's witness data if the coinbase transaction contains a
	// witness commitment.
	CoinbaseWitnessDataLen = 32

	// CoinbaseWitnessPkScriptLength is the length of the public key script
	// containing an OP_RETURN, the WitnessMagicBytes, and the witness
	// commitment itself. In order to be a valid candidate for the output
	// containing the witness commitment
	CoinbaseWitnessPkScriptLength = 38
)

var (
	// WitnessMagicBytes is the prefix marker within the public key script
	// of a coinbase output to indicate that this output holds the witness
	// commitment for a block.
	WitnessMagicBytes = []byte{
		txscript.OP_RETURN,
		txscript.OP_DATA_36,
		0xaa,
		0x21,
		0xa9,
		0xed,
	}
)

// nextPowerOfTwo returns the next highest power of two from a given number if
// it is not already a power of two.  This is a helper function used during the
// calculation of a merkle tree.
func nextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}

	// Figure out and return the next power of two.
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}

// HashMerkleBranches takes two hashes, treated as the left and right tree
// nodes, and returns the hash of their concatenation.  This is a helper
// function used to aid in the generation of a merkle tree.
func HashMerkleBranches(left *chainhash.Hash, right *chainhash.Hash) *chainhash.Hash {
	// Concatenate the left and right nodes.
	var hash [chainhash.HashSize * 2]byte
	copy(hash[:chainhash.HashSize], left[:])
	copy(hash[chainhash.HashSize:], right[:])

	newHash := chainhash.DoubleHashH(hash[:])
	return &newHash
}

// // BuildMerkleTreeStore creates a merkle tree from a slice of transactions,
// // stores it using a linear array, and returns a slice of the backing array.  A
// // linear array was chosen as opposed to an actual tree structure since it uses
// // about half as much memory.  The following describes a merkle tree and how it
// // is stored in a linear array.
// //
// // A merkle tree is a tree in which every non-leaf node is the hash of its
// // children nodes.  A diagram depicting how this works for bitcoin transactions
// // where h(x) is a double sha256 follows:
// //
// //	         root = h1234 = h(h12 + h34)
// //	        /                           \
// //	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
// //	   /            \              /            \
// //	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
// //
// // The above stored as a linear array is as follows:
// //
// // 	[h1 h2 h3 h4 h12 h34 root]
// //
// // As the above shows, the merkle root is always the last element in the array.
// //
// // The number of inputs is not always a power of two which results in a
// // balanced tree structure as above.  In that case, parent nodes with no
// // children are also zero and parent nodes with only a single left node
// // are calculated by concatenating the left node with itself before hashing.
// // Since this function uses nodes that are pointers to the hashes, empty nodes
// // will be nil.
// //
// // The additional bool parameter indicates if we are generating the merkle tree
// // using witness transaction id's rather than regular transaction id's. This
// // also presents an additional case wherein the wtxid of the coinbase transaction
// // is the zeroHash.
// // BuildMerkleTreeStore从一片事务中创建一个merkle树，使用线性数组存储它，并返回一个支持数组的切片。选择线性阵列而不是实际树结构，因为它使用大约一半的内存。以下描述了merkle树以及它如何存储在线性阵列中。
// //
// // merkle树是一棵树，其中每个非叶节点都是其子节点的哈希值。
// // 描述如何在比特币交易中使用h（x）是双sha256的图表如下：
// //
// //	         root = h1234 = h(h12 + h34)
// //	        /                           \
// //	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
// //	   /            \              /            \
// //	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
// //
// // 以上存储为线性数组如下：
// //
// // [h1 h2 h3 h4 h12 h34 root]
// //
// // 如上所示，merkle根始终是数组中的最后一个元素。
// //
// // 输入的数量并不总是2的幂，这导致如上所述的平衡树结构。
// // 在这种情况下，没有子节点的父节点也为零，
// // 并且通过在散列之前将左节点与其自身连接来计算仅具有单个左节点的父节点。
// // 由于此函数使用指向散列指针的节点，因此空节点将为零。
// //
// // 附加的bool参数指示我们是否使用见证事务id而不是常规事务id生成merkle树。
// // 这还提供了另一种情况，其中coinbase事务的wtxid是zeroHash。
// // -- by btc
// func BuildMerkleTreeStore2(transactions []*btcutil.Tx, witness bool) []*chainhash.Hash {
// 	// Calculate how many entries are required to hold the binary merkle
// 	// tree as a linear array and create an array of that size.
// 	nextPoT := nextPowerOfTwo(len(transactions))
// 	arraySize := nextPoT*2 - 1
// 	merkles := make([]*chainhash.Hash, arraySize)

// 	// Create the base transaction hashes and populate the array with them.
// 	//创建基本事务哈希并用它们填充数组。
// 	for i, tx := range transactions {
// 		// If we're computing a witness merkle root, instead of the
// 		// regular txid, we use the modified wtxid which includes a
// 		// transaction's witness data within the digest. Additionally,
// 		// the coinbase's wtxid is all zeroes.
// 		// 如果我们计算的是见证merkle root，而不是常规的txid，
// 		// 我们使用修改后的wtxid，其中包含摘要中的事务见证数据。 此外，coinbase的wtxid全部为零。
// 		// -- by btc
// 		switch {
// 		case witness && i == 0:
// 			var zeroHash chainhash.Hash
// 			merkles[i] = &zeroHash
// 		case witness:
// 			wSha := tx.MsgTx().WitnessHash()
// 			merkles[i] = &wSha
// 		default:
// 			merkles[i] = tx.Hash()
// 		}
// 		// -- by eac 
// 		//merkles[i] = tx.Hash()

// 	}

// 	// Start the array offset after the last transaction and adjusted to the
// 	// next power of two.
// 	//在最后一次交易后开始数组偏移，并调整到下一个2的幂。
// 	offset := nextPoT
// 	for i := 0; i < arraySize-1; i += 2 {
// 		switch {
// 		// When there is no left child node, the parent is nil too.
// 		//当没有左子节点时，父节点也是零。
// 		case merkles[i] == nil:
// 			merkles[offset] = nil

// 		// When there is no right child, the parent is generated by
// 		// hashing the concatenation of the left child with itself.
// 		//当没有正确的子节点时，通过散列左子节点与其自身的串联来生成父节点。
// 		case merkles[i+1] == nil:
// 			newHash := HashMerkleBranches(merkles[i], merkles[i])
// 			merkles[offset] = newHash

// 		// The normal case sets the parent node to the double sha256
// 		// of the concatentation of the left and right children.
// 		//正常情况将父节点设置为左右子节点串联的double sha256。
// 		default:
// 			newHash := HashMerkleBranches(merkles[i], merkles[i+1])
// 			merkles[offset] = newHash
// 		}
// 		offset++
// 	}

// 	return merkles
// }

// BuildMerkleTreeStore creates a merkle tree from a slice of transactions,
// stores it using a linear array, and returns a slice of the backing array.  A
// linear array was chosen as opposed to an actual tree structure since it uses
// about half as much memory.  The following describes a merkle tree and how it
// is stored in a linear array.
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// children nodes.  A diagram depicting how this works for bitcoin transactions
// where h(x) is a double sha256 follows:
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// The above stored as a linear array is as follows:
//
// 	[h1 h2 h3 h4 h12 h34 root]
//
// As the above shows, the merkle root is always the last element in the array.
//
// The number of inputs is not always a power of two which results in a
// balanced tree structure as above.  In that case, parent nodes with no
// children are also zero and parent nodes with only a single left node
// are calculated by concatenating the left node with itself before hashing.
// Since this function uses nodes that are pointers to the hashes, empty nodes
// will be nil.
//
// The additional bool parameter indicates if we are generating the merkle tree
// using witness transaction id's rather than regular transaction id's. This
// also presents an additional case wherein the wtxid of the coinbase transaction
// is the zeroHash.
// BuildMerkleTreeStore从一片事务中创建一个merkle树，使用线性数组存储它，并返回一个支持数组的切片。选择线性阵列而不是实际树结构，因为它使用大约一半的内存。以下描述了merkle树以及它如何存储在线性阵列中。
//
// merkle树是一棵树，其中每个非叶节点都是其子节点的哈希值。
// 描述如何在比特币交易中使用h（x）是双sha256的图表如下：
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// 以上存储为线性数组如下：
//
// [h1 h2 h3 h4 h12 h34 root]
//
// 如上所示，merkle根始终是数组中的最后一个元素。
//
// 输入的数量并不总是2的幂，这导致如上所述的平衡树结构。
// 在这种情况下，没有子节点的父节点也为零，
// 并且通过在散列之前将左节点与其自身连接来计算仅具有单个左节点的父节点。
// 由于此函数使用指向散列指针的节点，因此空节点将为零。
//
// 附加的bool参数指示我们是否使用见证事务id而不是常规事务id生成merkle树。
// 这还提供了另一种情况，其中coinbase事务的wtxid是zeroHash。
// -- by eac 重写桶树函数
func BuildMerkleTreeStore(transactions []*btcutil.Tx, witness bool) []*chainhash.Hash {

	// vMerkleTree.clear();
	// BOOST_FOREACH(const CTransaction& tx, vtx)
	// 	vMerkleTree.push_back(tx.GetHash());
	// int j = 0;
	// for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
	// {
	// 	for (int i = 0; i < nSize; i += 2)
	// 	{
	// 		 //因为循环步骤是2，取一个最小值防止数组越界
	// 		int i2 = std::min(i+1, nSize-1);
	// 		//hash计算2个字符串拼接的hash256
	// 		//从前到后，每次取相邻2个节点计算hash,并放入数组尾部
	// 		vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
	// 								   BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
	// 	}
	// 	j += nSize;
	// }
	// return (vMerkleTree.empty() ? 0 : vMerkleTree.back());

	merkles := []*chainhash.Hash{}
	arraySize := len(transactions)-1

	for i := 0; i < arraySize ; i += 1 {
		tx := transactions[i]
		merkles = append(merkles,tx.Hash())
	}

	j := 0
	for nSize := len(transactions); nSize > 1; nSize = (nSize + 1) / 2{
		for i := 0; i < nSize; i += 2 {
			//因为循环步骤是2，取一个最小值防止数组越界
			i2 := i+1 
			if i2 > nSize-1 {
				i2 = nSize-1
			}
			//hash计算2个字符串拼接的hash256
			//从前到后，每次取相邻2个节点计算hash,并放入数组尾部
			newHash := HashMerkleBranches(merkles[j+i], merkles[j+i2])
			merkles = append(merkles,newHash)

		}
		j += nSize
	}


	return merkles
	

	// // Calculate how many entries are required to hold the binary merkle
	// // tree as a linear array and create an array of that size.
	// nextPoT := nextPowerOfTwo(len(transactions))
	// arraySize := nextPoT*2 - 1
	// merkles := make([]*chainhash.Hash, arraySize)

	// // Create the base transaction hashes and populate the array with them.
	// //创建基本事务哈希并用它们填充数组。
	// for i, tx := range transactions {
	// 	// If we're computing a witness merkle root, instead of the
	// 	// regular txid, we use the modified wtxid which includes a
	// 	// transaction's witness data within the digest. Additionally,
	// 	// the coinbase's wtxid is all zeroes.
	// 	// 如果我们计算的是见证merkle root，而不是常规的txid，
	// 	// 我们使用修改后的wtxid，其中包含摘要中的事务见证数据。 此外，coinbase的wtxid全部为零。
	// 	// -- by btc
	// 	switch {
	// 	case witness && i == 0:
	// 		var zeroHash chainhash.Hash
	// 		merkles[i] = &zeroHash
	// 	case witness:
	// 		wSha := tx.MsgTx().WitnessHash()
	// 		merkles[i] = &wSha
	// 	default:
	// 		merkles[i] = tx.Hash()
	// 	}
	// 	// -- by eac 
	// 	//merkles[i] = tx.Hash()

	// }

	// // Start the array offset after the last transaction and adjusted to the
	// // next power of two.
	// //在最后一次交易后开始数组偏移，并调整到下一个2的幂。
	// offset := nextPoT
	// for i := 0; i < arraySize-1; i += 2 {
	// 	switch {
	// 	// When there is no left child node, the parent is nil too.
	// 	//当没有左子节点时，父节点也是零。
	// 	case merkles[i] == nil:
	// 		merkles[offset] = nil

	// 	// When there is no right child, the parent is generated by
	// 	// hashing the concatenation of the left child with itself.
	// 	//当没有正确的子节点时，通过散列左子节点与其自身的串联来生成父节点。
	// 	case merkles[i+1] == nil:
	// 		newHash := HashMerkleBranches(merkles[i], merkles[i])
	// 		merkles[offset] = newHash

	// 	// The normal case sets the parent node to the double sha256
	// 	// of the concatentation of the left and right children.
	// 	//正常情况将父节点设置为左右子节点串联的double sha256。
	// 	default:
	// 		newHash := HashMerkleBranches(merkles[i], merkles[i+1])
	// 		merkles[offset] = newHash
	// 	}
	// 	offset++
	// }

	// return merkles
}

// ExtractWitnessCommitment attempts to locate, and return the witness
// commitment for a block. The witness commitment is of the form:
// SHA256(witness root || witness nonce). The function additionally returns a
// boolean indicating if the witness root was located within any of the txOut's
// in the passed transaction. The witness commitment is stored as the data push
// for an OP_RETURN with special magic bytes to aide in location.
func ExtractWitnessCommitment(tx *btcutil.Tx) ([]byte, bool) {
	// The witness commitment *must* be located within one of the coinbase
	// transaction's outputs.
	if !IsCoinBase(tx) {
		return nil, false
	}

	msgTx := tx.MsgTx()
	for i := len(msgTx.TxOut) - 1; i >= 0; i-- {
		// The public key script that contains the witness commitment
		// must shared a prefix with the WitnessMagicBytes, and be at
		// least 38 bytes.
		pkScript := msgTx.TxOut[i].PkScript
		if len(pkScript) >= CoinbaseWitnessPkScriptLength &&
			bytes.HasPrefix(pkScript, WitnessMagicBytes) {

			// The witness commitment itself is a 32-byte hash
			// directly after the WitnessMagicBytes. The remaining
			// bytes beyond the 38th byte currently have no consensus
			// meaning.
			start := len(WitnessMagicBytes)
			end := CoinbaseWitnessPkScriptLength
			return msgTx.TxOut[i].PkScript[start:end], true
		}
	}

	return nil, false
}

// ValidateWitnessCommitment validates the witness commitment (if any) found
// within the coinbase transaction of the passed block.
func ValidateWitnessCommitment(blk *btcutil.Block) error {
	// If the block doesn't have any transactions at all, then we won't be
	// able to extract a commitment from the non-existent coinbase
	// transaction. So we exit early here.
	if len(blk.Transactions()) == 0 {
		str := "cannot validate witness commitment of block without " +
			"transactions"
		return ruleError(ErrNoTransactions, str)
	}

	coinbaseTx := blk.Transactions()[0]
	if len(coinbaseTx.MsgTx().TxIn) == 0 {
		return ruleError(ErrNoTxInputs, "transaction has no inputs")
	}

	witnessCommitment, witnessFound := ExtractWitnessCommitment(coinbaseTx)

	// If we can't find a witness commitment in any of the coinbase's
	// outputs, then the block MUST NOT contain any transactions with
	// witness data.
	if !witnessFound {
		for _, tx := range blk.Transactions() {
			msgTx := tx.MsgTx()
			if msgTx.HasWitness() {
				str := fmt.Sprintf("block contains transaction with witness" +
					" data, yet no witness commitment present")
				return ruleError(ErrUnexpectedWitness, str)
			}
		}
		return nil
	}

	// At this point the block contains a witness commitment, so the
	// coinbase transaction MUST have exactly one witness element within
	// its witness data and that element must be exactly
	// CoinbaseWitnessDataLen bytes.
	coinbaseWitness := coinbaseTx.MsgTx().TxIn[0].Witness
	if len(coinbaseWitness) != 1 {
		str := fmt.Sprintf("the coinbase transaction has %d items in "+
			"its witness stack when only one is allowed",
			len(coinbaseWitness))
		return ruleError(ErrInvalidWitnessCommitment, str)
	}
	witnessNonce := coinbaseWitness[0]
	if len(witnessNonce) != CoinbaseWitnessDataLen {
		str := fmt.Sprintf("the coinbase transaction witness nonce "+
			"has %d bytes when it must be %d bytes",
			len(witnessNonce), CoinbaseWitnessDataLen)
		return ruleError(ErrInvalidWitnessCommitment, str)
	}

	// Finally, with the preliminary checks out of the way, we can check if
	// the extracted witnessCommitment is equal to:
	// SHA256(witnessMerkleRoot || witnessNonce). Where witnessNonce is the
	// coinbase transaction's only witness item.
	witnessMerkleTree := BuildMerkleTreeStore(blk.Transactions(), true)
	witnessMerkleRoot := witnessMerkleTree[len(witnessMerkleTree)-1]

	var witnessPreimage [chainhash.HashSize * 2]byte
	copy(witnessPreimage[:], witnessMerkleRoot[:])
	copy(witnessPreimage[chainhash.HashSize:], witnessNonce)

	computedCommitment := chainhash.DoubleHashB(witnessPreimage[:])
	if !bytes.Equal(computedCommitment, witnessCommitment) {
		str := fmt.Sprintf("witness commitment does not match: "+
			"computed %v, coinbase includes %v", computedCommitment,
			witnessCommitment)
		return ruleError(ErrWitnessCommitmentMismatch, str)
	}

	return nil
}
