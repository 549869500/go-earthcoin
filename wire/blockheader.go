// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// MaxBlockHeaderPayload is the maximum number of bytes a block header can be.
// Version 4 bytes + Timestamp 4 bytes + Bits 4 bytes + Nonce 4 bytes +
// PrevBlock and MerkleRoot hashes.
// MaxBlockHeaderPayload是块头可以的最大字节数。
//版本4字节+时间戳4字节+位4字节+现时4字节+
// PrevBlock和MerkleRoot哈希。
const MaxBlockHeaderPayload = 16 + (chainhash.HashSize * 2)

// BlockHeader defines information about a block and is used in the bitcoin
// block (MsgBlock) and headers (MsgHeaders) messages.
//定义区块头（block header）结构
// BlockHeader定义有关块的信息，用于比特币块（MsgBlock）和头（MsgHeaders）消息。
//一个区块包括区块头和交易信息（数据）两个部分，这里定义的是区块头
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	//区块的版本。这与协议版本不一样。
	Version int32

	// Hash of the previous block header in the block chain.
	//区块链中前一个块头的哈希值。
	PrevBlock chainhash.Hash

	// Merkle tree reference to hash of all transactions for the block.
	//Merkle树引用块的所有事务的哈希(当前块的哈希)。
	MerkleRoot chainhash.Hash

	// Time the block was created.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.
	//块创建的时间。 不幸的是，这在线上被编码为uint32，因此限于2106。
	Timestamp time.Time

	// Difficulty target for the block.
	//块的难度目标。
	Bits uint32

	// Nonce used to generate the block.
	//Nonce用于生成块。
	Nonce uint32
}

// blockHeaderLen is a constant that represents the number of bytes for a block
// header.
//blockHeaderLen是一个常量，表示块头的字节数。
const blockHeaderLen = 80

// BlockHash computes the block identifier hash for the given block header.
//BlockHash计算给定块头的块标识符哈希。
func (h *BlockHeader) BlockHash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	//在事务数量之前对头部进行编码并对sha256进行双重处理。
	//忽略错误返回，因为编码可能无法失败，除非内存不足会导致运行时出现紧急情况。
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockHeader(buf, 0, h)

	return chainhash.DoubleHashH(buf.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
//BtcDecode使用比特币协议编码将r解码到接收器中。
//这是Message接口实现的一部分。
//请参阅反序列化以解码存储到磁盘的块头，例如在数据库中，而不是从线路解码块头。
func (h *BlockHeader) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readBlockHeader(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
// BtcEncode使用比特币协议编码将接收器编码为w。
//这是Message接口实现的一部分。
//请参阅序列化以编码要存储到磁盘的块头，例如在数据库，而不是编码线的块头。
func (h *BlockHeader) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeBlockHeader(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
//反序列化使用适合长期存储的格式（例如数据库）将块头从r解码到接收器中，同时尊重Version字段。
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	//目前，协议版本0的线路编码与稳定的长期存储格式没有区别。 因此，请使用readBlockHeader。
	return readBlockHeader(r, 0, h)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
// Serialize使用适合长期存储的格式（例如数据库）将块头从r编码到接收器中，同时尊重Version字段。
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	//目前，协议版本0的线路编码与稳定的长期存储格式没有区别。 因此，请使用writeBlockHeader。
	return writeBlockHeader(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
// 生成新的区块头，NewBlockHeader使用提供的版本，先前的块哈希，merkle根哈希，
// 难度位和用于生成具有剩余字段的默认值的块的随机数返回新的BlockHeader。
func NewBlockHeader(version int32, prevHash, merkleRootHash *chainhash.Hash,
	bits uint32, nonce uint32) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	//将时间戳限制为一秒精度，因为协议不支持更好。
	return &BlockHeader{
		Version:    version,
		PrevBlock:  *prevHash,
		MerkleRoot: *merkleRootHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		Bits:       bits,
		Nonce:      nonce,
	}
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
//readBlockHeader从r读取比特币块头。 请参阅反序列化以解码存储到磁盘的块头，例如在数据库中，
//而不是从线路解码。
func readBlockHeader(r io.Reader, pver uint32, bh *BlockHeader) error {
	return readElements(r, &bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		(*uint32Time)(&bh.Timestamp), &bh.Bits, &bh.Nonce)
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
//writeBlockHeader将比特币块头写入w。 有关要编码存储在磁盘上的块头的序列化，例如在数据库中，
//而不是对线路进行编码。
func writeBlockHeader(w io.Writer, pver uint32, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		sec, bh.Bits, bh.Nonce)
}
