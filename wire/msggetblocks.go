// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// MaxBlockLocatorsPerMsg is the maximum number of block locator hashes allowed
// per message.
const MaxBlockLocatorsPerMsg = 500

// MsgGetBlocks implements the Message interface and represents a bitcoin
// getblocks message.  It is used to request a list of blocks starting after the
// last known hash in the slice of block locator hashes.  The list is returned
// via an inv message (MsgInv) and is limited by a specific hash to stop at or
// the maximum number of blocks per message, which is currently 500.
//
// Set the HashStop field to the hash at which to stop and use
// AddBlockLocatorHash to build up the list of block locator hashes.
//
// The algorithm for building the block locator hashes should be to add the
// hashes in reverse order until you reach the genesis block.  In order to keep
// the list of locator hashes to a reasonable number of entries, first add the
// most recent 10 block hashes, then double the step each loop iteration to
// exponentially decrease the number of hashes the further away from head and
// closer to the genesis block you get.
// MsgGetBlocks实现Message接口并表示比特币getblocks消息。
// 它用于请求块块定位器哈希值中最后一个已知哈希之后开始的块列表。
// 该列表通过inv消息（MsgInv）返回，并受到停止的特定散列或每个消息的最大块数（当前为500）的限制。
//
// 将HashStop字段设置为要停止的哈希值，并使用AddBlockLocatorHash构建块定位符哈希值列表。
//
// 构建块定位器哈希的算法应该是以相反的顺序添加哈希值，直到到达创世块。
// 为了将定位符哈希列表保持为合理数量的条目，首先添加最近的10个块哈希值，
// 然后将每个循环迭代的步骤加倍，以指数方式减少哈希值，使其距离头部越远，越接近生成块 你得到。
//
// getblocks请求的区块位于BlockLocator指向的区块和HashStop指向的区块之间，
// 不包括BlockLocator指向的区块；如果HashStop为零，则返回BlockLocator指向的区块之后的500个区块。
type MsgGetBlocks struct {
	//协议的版本号;
	ProtocolVersion    uint32				

	// 记录一个BlockLocator，BlockLocator用于定位列表中第一个block元素在区块链中的位置;
	BlockLocatorHashes []*chainhash.Hash	

	//HashStop: getblocks请求的block区间的结束位置;
	HashStop           chainhash.Hash
}

// AddBlockLocatorHash adds a new block locator hash to the message.
func (msg *MsgGetBlocks) AddBlockLocatorHash(hash *chainhash.Hash) error {
	if len(msg.BlockLocatorHashes)+1 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message [max %v]",
			MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.AddBlockLocatorHash", str)
	}

	msg.BlockLocatorHashes = append(msg.BlockLocatorHashes, hash)
	return nil
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetBlocks) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readElement(r, &msg.ProtocolVersion)
	if err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.BtcDecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into in order to
	// reduce the number of allocations.
	locatorHashes := make([]chainhash.Hash, count)
	msg.BlockLocatorHashes = make([]*chainhash.Hash, 0, count)
	for i := uint64(0); i < count; i++ {
		hash := &locatorHashes[i]
		err := readElement(r, hash)
		if err != nil {
			return err
		}
		msg.AddBlockLocatorHash(hash)
	}

	return readElement(r, &msg.HashStop)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// BtcEncode使用比特币协议编码将接收器编码并保存到w。
//这是Message接口实现的一部分。
func (msg *MsgGetBlocks) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	count := len(msg.BlockLocatorHashes)
	//MsgGetBlocks序列化时按顺序写入协议版本号、BlockLocator中hash个数、
	//BlockLocator中hash列表及截止hash值，这就是getblocks消息体的格式。
	if count > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.BtcEncode", str)
	}

	err := writeElement(w, msg.ProtocolVersion)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, hash := range msg.BlockLocatorHashes {
		err = writeElement(w, hash)
		if err != nil {
			return err
		}
	}

	return writeElement(w, &msg.HashStop)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetBlocks) Command() string {
	return CmdGetBlocks
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetBlocks) MaxPayloadLength(pver uint32) uint32 {
	// Protocol version 4 bytes + num hashes (varInt) + max block locator
	// hashes + hash stop.
	return 4 + MaxVarIntPayload + (MaxBlockLocatorsPerMsg * chainhash.HashSize) + chainhash.HashSize
}

// NewMsgGetBlocks returns a new bitcoin getblocks message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewMsgGetBlocks(hashStop *chainhash.Hash) *MsgGetBlocks {
	return &MsgGetBlocks{
		ProtocolVersion:    ProtocolVersion,
		BlockLocatorHashes: make([]*chainhash.Hash, 0, MaxBlockLocatorsPerMsg),
		HashStop:           *hashStop,
	}
}
