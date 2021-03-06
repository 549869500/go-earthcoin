// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

// MaxUserAgentLen is the maximum allowed length for the user agent field in a
// version message (MsgVersion).
const MaxUserAgentLen = 256

// DefaultUserAgent for wire in the stack
// -- by btc
// const DefaultUserAgent = "/btcwire:0.5.0/"
// -- by eac
const DefaultUserAgent = "/Satoshi:1.5.5.1/"

// MsgVersion implements the Message interface and represents a bitcoin version
// message.  It is used for a peer to advertise itself as soon as an outbound
// connection is made.  The remote peer then uses this information along with
// its own to negotiate.  The remote peer must then respond with a version
// message of its own containing the negotiated values followed by a verack
// message (MsgVerAck).  This exchange must take place before any further
// communication is allowed to proceed.
// MsgVersion实现Message接口并表示比特币版本消息。
// 一旦建立了出站连接，它就用于对等体自我通告。
// 然后，远程对等方使用此信息与其自己进行协商。
// 然后，远程对等体必须使用其自己的版本消息进行响应，该消息包含协商的值，
// 然后是verack消息（MsgVerAck）。 必须在允许进一步通信之前进行此交换。
type MsgVersion struct {
	// Version of the protocol the node is using.
	ProtocolVersion int32

	// Bitfield which identifies the enabled services.
	// Services ServiceFlag

	// -- by eac 
	LocalServices int64

	// Time the message was generated.  This is encoded as an int64 on the wire.
	// -- by eac 
	//Timestamp time.Time

	// -- by eac 
	nTime int64

	// -- by eac
	 sAddrYou string

	 sAddrMe string
	// Address of the remote peer.
	//AddrYou NetAddress

	// Address of the local peer.
	//AddrMe NetAddress

	// Unique value associated with message that is used to detect self
	// connections.
	//与用于检测自连接的消息关联的唯一值。
	//Nonce是为了防止自己给自己发送version消息
	Nonce uint64

	// The user agent that generated messsage.  This is a encoded as a varString
	// on the wire.  This has a max length of MaxUserAgentLen.
	//UserAgent会被编码为可变长度字符串，它可以用来区别不同的客户端实现；
	//当前默认的UserAgent是"/btcwire:0.5.0/"，
	//可以通过AddUserAgent()方法来附加，如当前btcd实现的UserAgent为“/btcwire:0.5.0/0.12.0”
	UserAgent string

	// Last block seen by the generator of the version message.
	LastBlock int32

	// Don't announce transactions to peer.
	// -- by eac remove DisableRelayTx
	//DisableRelayTx bool

	// Bitfield which identifies the enabled services.
	Services ServiceFlag

	// -- by eac
	 //sAddrYou string

	 //sAddrMe string

	// Address of the remote peer.
	AddrYou NetAddress

	// Address of the local peer.
	// 在较新版本(Satoshi:0.14.1及以上)Bitcoin客户端实现中，
	// AddrMe不再包含本地的IP和Port，因为节点可能通过Proxy上网，填入本地的地址没有意义。
	AddrMe NetAddress

	Timestamp time.Time
}

// HasService returns whether the specified service is supported by the peer
// that generated the message.
func (msg *MsgVersion) HasService(service ServiceFlag) bool {
	return msg.Services&service == service
}

// AddService adds service as a supported service by the peer generating the
// message.
func (msg *MsgVersion) AddService(service ServiceFlag) {
	msg.Services |= service
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// The version message is special in that the protocol version hasn't been
// negotiated yet.  As a result, the pver field is ignored and any fields which
// are added in new versions are optional.  This also mean that r must be a
// *bytes.Buffer so the number of remaining bytes can be ascertained.
//
// This is part of the Message interface implementation.
// 对版本信息进行解码
// BtcDecode使用比特币协议编码将r解码到接收器中。
// 版本消息的特殊之处在于协议版本尚未协商。
// 因此，将忽略pver字段，并且在新版本中添加的任何字段都是可选的。
// 这也意味着r必须是* bytes.Buffer，因此可以确定剩余字节数。
//
//这是Message接口实现的一部分。
//
// 熟悉了version的格式定义后，理解BtcEncode()和BtcDecode()变得非常简单，
// 它们就是调用writeElement()或readElement等方法对不同的数据类型进行读写。
func (msg *MsgVersion) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	buf, ok := r.(*bytes.Buffer)
	if !ok {
		return fmt.Errorf("MsgVersion.BtcDecode reader is not a " +
			"*bytes.Buffer")
	}

	err := readElements(buf, &msg.ProtocolVersion, &msg.Services,
		&msg.nTime)
		//(*int64Time)(&msg.Timestamp))
	if err != nil {
		return err
	}

	err = readNetAddress(buf, pver, &msg.AddrYou, false)
	if err != nil {
		return err
	}

	// Protocol versions >= 106 added a from address, nonce, and user agent
	// field and they are only considered present if there are bytes
	// remaining in the message.
	if buf.Len() > 0 {
		err = readNetAddress(buf, pver, &msg.AddrMe, false)
		if err != nil {
			return err
		}
	}
	if buf.Len() > 0 {
		err = readElement(buf, &msg.Nonce)
		if err != nil {
			return err
		}
	}
	if buf.Len() > 0 {
		userAgent, err := ReadVarString(buf, pver)
		if err != nil {
			return err
		}
		err = validateUserAgent(userAgent)
		if err != nil {
			return err
		}
		msg.UserAgent = userAgent
	}

	// Protocol versions >= 209 added a last known block field.  It is only
	// considered present if there are bytes remaining in the message.
	if buf.Len() > 0 {
		err = readElement(buf, &msg.LastBlock)
		if err != nil {
			return err
		}
	}

	// There was no relay transactions field before BIP0037Version, but
	// the default behavior prior to the addition of the field was to always
	// relay transactions.
	if buf.Len() > 0 {
		// It's safe to ignore the error here since the buffer has at
		// least one byte and that byte will result in a boolean value
		// regardless of its value.  Also, the wire encoding for the
		// field is true when transactions should be relayed, so reverse
		// it for the DisableRelayTx field.
		var relayTx bool
		readElement(r, &relayTx)
		// -- by eac remove DisableRelayTx
		// msg.DisableRelayTx = !relayTx
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// 对版本信息进行编码
// BtcEncode使用比特币协议编码将接收器编码为w。
// 这是Message接口实现的一部分。
func (msg *MsgVersion) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := validateUserAgent(msg.UserAgent)
	if err != nil {
		return err
	}

	err = writeElements(w, msg.ProtocolVersion, msg.Services,
		msg.nTime)
		//msg.Timestamp.Unix())
	if err != nil {
		return err
	}

	err = writeNetAddress(w, pver, &msg.AddrYou, false)
	if err != nil {
		return err
	}

	err = writeNetAddress(w, pver, &msg.AddrMe, false)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Nonce)
	if err != nil {
		return err
	}

	err = WriteVarString(w, pver, msg.UserAgent)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.LastBlock)
	if err != nil {
		return err
	}

	// There was no relay transactions field before BIP0037Version.  Also,
	// the wire encoding for the field is true when transactions should be
	// relayed, so reverse it from the DisableRelayTx field.
	if pver >= BIP0037Version {
		// -- by eac remove DisableRelayTx
		// err = writeElement(w, !msg.DisableRelayTx)
		// if err != nil {
		// 	return err
		// }
	}
	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgVersion) Command() string {
	return CmdVersion
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgVersion) MaxPayloadLength(pver uint32) uint32 {
	// XXX: <= 106 different

	// Protocol version 4 bytes + services 8 bytes + timestamp 8 bytes +
	// remote and local net addresses + nonce 8 bytes + length of user
	// agent (varInt) + max allowed useragent length + last block 4 bytes +
	// relay transactions flag 1 byte.
	return 33 + (maxNetAddressPayload(pver) * 2) + MaxVarIntPayload +
		MaxUserAgentLen
}

// NewMsgVersion returns a new bitcoin version message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
// NewMsgVersion使用传递的参数和其余字段的默认值返回符合Message接口的新比特币版本消息。
func NewMsgVersion(me *NetAddress, you *NetAddress, nonce uint64,
	lastBlock int32) *MsgVersion {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &MsgVersion{
		ProtocolVersion: int32(ProtocolVersion),
		// -- by eac
		//Services:        0,
		LocalServices:	 3,
		// -- by eac
		//Timestamp:       time.Unix(time.Now().Unix(), 0),
		nTime:			 time.Now().Unix(),
		AddrYou:         *you,
		AddrMe:          *me,
		sAddrYou:		 "148.163.168.167/35677",
		sAddrMe:		 "0.0.0.0/0",
		Nonce:           nonce,
		UserAgent:       DefaultUserAgent,	// DefaultUserAgent = "/btcwire:0.5.0/"
		LastBlock:       lastBlock,
		// -- by eac remove DisableRelayTx
		//DisableRelayTx:  false,
	}
}

// validateUserAgent checks userAgent length against MaxUserAgentLen
func validateUserAgent(userAgent string) error {
	if len(userAgent) > MaxUserAgentLen {
		str := fmt.Sprintf("user agent too long [len %v, max %v]",
			len(userAgent), MaxUserAgentLen)
		return messageError("MsgVersion", str)
	}
	return nil
}

// AddUserAgent adds a user agent to the user agent string for the version
// message.  The version string is not defined to any strict format, although
// it is recommended to use the form "major.minor.revision" e.g. "2.6.41".
func (msg *MsgVersion) AddUserAgent(name string, version string,
	comments ...string) error {

	// -- by eac do not add UserAgent
	return nil

	newUserAgent := fmt.Sprintf("%s:%s", name, version)
	if len(comments) != 0 {
		newUserAgent = fmt.Sprintf("%s(%s)", newUserAgent,
			strings.Join(comments, "; "))
	}
	newUserAgent = fmt.Sprintf("%s%s/", msg.UserAgent, newUserAgent)
	err := validateUserAgent(newUserAgent)
	if err != nil {
		return err
	}
	msg.UserAgent = newUserAgent
	return nil
}
