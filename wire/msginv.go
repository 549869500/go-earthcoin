// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// defaultInvListAlloc is the default size used for the backing array for an
// inventory list.  The array will dynamically grow as needed, but this
// figure is intended to provide enough space for the max number of inventory
// vectors in a *typical* inventory message without needing to grow the backing
// array multiple times.  Technically, the list can grow to MaxInvPerMsg, but
// rather than using that large figure, this figure more accurately reflects the
// typical case.
const defaultInvListAlloc = 1000

// MsgInv implements the Message interface and represents a bitcoin inv message.
// It is used to advertise a peer's known data such as blocks and transactions
// through inventory vectors.  It may be sent unsolicited to inform other peers
// of the data or in response to a getblocks message (MsgGetBlocks).  Each
// message is limited to a maximum number of inventory vectors, which is
// currently 50,000.
//
// Use the AddInvVect function to build up the list of inventory vectors when
// sending an inv message to another peer.
// MsgInv实现Message接口并表示比特币inv消息。
// 它用于通过清单向量通告对等方的已知数据，例如块和事务。
// 可以不主要地发送它以通知其他对等方数据或响应getblocks消息（MsgGetBlocks）。
// 每条消息都限制为最大数量的库存向量，目前为50,000。
//
//在向另一个对等方发送inv消息时，使用AddInvVect函数构建清单向量列表。
//
//inv主要用来向Peer通告区块或者交易数据，它是getblocks消息的响应消息，也可以主动发送。
//inv消息体包含一个InvVect列表和表示InvVect个数的可变长度整数Count值。
type MsgInv struct {
	InvList []*InvVect
}

// AddInvVect adds an inventory vector to the message.
func (msg *MsgInv) AddInvVect(iv *InvVect) error {
	if len(msg.InvList)+1 > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [max %v]",
			MaxInvPerMsg)
		return messageError("MsgInv.AddInvVect", str)
	}

	msg.InvList = append(msg.InvList, iv)
	return nil
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgInv) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Limit to max inventory vectors per message.
	if count > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcDecode", str)
	}

	// Create a contiguous slice of inventory vectors to deserialize into in
	// order to reduce the number of allocations.
	invList := make([]InvVect, count)
	msg.InvList = make([]*InvVect, 0, count)
	for i := uint64(0); i < count; i++ {
		iv := &invList[i]
		err := readInvVect(r, pver, iv)
		if err != nil {
			return err
		}
		msg.AddInvVect(iv)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgInv) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Limit to max inventory vectors per message.
	count := len(msg.InvList)
	if count > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcEncode", str)
	}

	err := WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, iv := range msg.InvList {
		err := writeInvVect(w, pver, iv)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgInv) Command() string {
	return CmdInv
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgInv) MaxPayloadLength(pver uint32) uint32 {
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	return MaxVarIntPayload + (MaxInvPerMsg * maxInvVectPayload)
}

// NewMsgInv returns a new bitcoin inv message that conforms to the Message
// interface.  See MsgInv for details.
func NewMsgInv() *MsgInv {
	return &MsgInv{
		InvList: make([]*InvVect, 0, defaultInvListAlloc),
	}
}

// NewMsgInvSizeHint returns a new bitcoin inv message that conforms to the
// Message interface.  See MsgInv for details.  This function differs from
// NewMsgInv in that it allows a default allocation size for the backing array
// which houses the inventory vector list.  This allows callers who know in
// advance how large the inventory list will grow to avoid the overhead of
// growing the internal backing array several times when appending large amounts
// of inventory vectors with AddInvVect.  Note that the specified hint is just
// that - a hint that is used for the default allocation size.  Adding more
// (or less) inventory vectors will still work properly.  The size hint is
// limited to MaxInvPerMsg.
func NewMsgInvSizeHint(sizeHint uint) *MsgInv {
	// Limit the specified hint to the maximum allow per message.
	if sizeHint > MaxInvPerMsg {
		sizeHint = MaxInvPerMsg
	}

	return &MsgInv{
		InvList: make([]*InvVect, 0, sizeHint),
	}
}
