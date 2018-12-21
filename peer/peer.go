// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/davecgh/go-spew/spew"
)

const (
	// MaxProtocolVersion is the max protocol version the peer supports.
	// MaxProtocolVersion是节点支持的最大协议版本。
	MaxProtocolVersion = wire.FeeFilterVersion

	// DefaultTrickleInterval is the min time between attempts to send an
	// inv message to a peer.
	// DefaultTrickleInterval是尝试向节点发送inv消息之间的最短时间。
	DefaultTrickleInterval = 10 * time.Second

	// MinAcceptableProtocolVersion is the lowest protocol version that a
	// connected peer may support.
	// MinAcceptableProtocolVersion是连接节点可能支持的最低协议版本。
	MinAcceptableProtocolVersion = wire.MultipleAddressVersion

	// outputBufferSize is the number of elements the output channels use.
	// outputBufferSize是输出通道使用的元素数。
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	// invTrickleSize是将库存流向远程节点时在单个消息中发送的最大库存量。
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	// maxKnownInventory是已知库存缓存中要保留的最大项目数。
	maxKnownInventory = 1000

	// pingInterval is the interval of time to wait in between sending ping
	// messages.
	// pingInterval是发送ping消息之间等待的时间间隔。
	pingInterval = 2 * time.Minute

	// negotiateTimeout is the duration of inactivity before we timeout a
	// peer that hasn't completed the initial version negotiation.
	// negotiateTimeout：协商超时，是在我们超时未完成初始版本协商的节点之前的不活动持续时间。
	negotiateTimeout = 30 * time.Second

	// idleTimeout is the duration of inactivity before we time out a peer.
	// idleTimeout：空闲超时，是我们超时之前不活动的持续时间。
	idleTimeout = 5 * time.Minute

	// stallTickInterval is the interval of time between each check for
	// stalled peers.
	// stallTickInterval是每次检查停顿的节点之间的时间间隔。
	stallTickInterval = 15 * time.Second

	// stallResponseTimeout is the base maximum amount of time messages that
	// expect a response will wait before disconnecting the peer for
	// stalling.  The deadlines are adjusted for callback running times and
	// only checked on each stall tick interval.
	// stallResponseTimeout:停止响应超时
	// stallResponseTimeout是在断开节点停止之前，响应将等待的消息的基本最大时间量。
	// 最后期限根据回调运行时间进行调整，并且仅在每个停顿时间间隔进行检查。
	stallResponseTimeout = 30 * time.Second
)

var (
	// nodeCount is the total number of peer connections made since startup
	// and is used to assign an id to a peer.
	// nodeCount是自启动以来所做的节点连接总数，用于为节点分配id。
	nodeCount int32

	// zeroHash is the zero value hash (all zeros).  It is defined as a
	// convenience.
	// zeroHash是零值哈希（全为零）。 它被定义为一种便利。
	zeroHash chainhash.Hash

	// sentNonces houses the unique nonces that are generated when pushing
	// version messages that are used to detect self connections.
	// sentNonces包含推送用于检测自连接的版本消息时生成的唯一nonce。
	sentNonces = newMruNonceMap(50)

	// allowSelfConns is only used to allow the tests to bypass the self
	// connection detecting and disconnect logic since they intentionally
	// do so for testing purposes.
	// allowSelfConns：允许自我链接
	// allowSelfConns仅用于允许测试绕过自连接检测和断开逻辑，因为它们故意这样做是为了测试目的。
	allowSelfConns bool
)

// MessageListeners defines callback function pointers to invoke with message
// listeners for a peer. Any listener which is not set to a concrete callback
// during peer initialization is ignored. Execution of multiple message
// listeners occurs serially, so one callback blocks the execution of the next.
//
// NOTE: Unless otherwise documented, these listeners must NOT directly call any
// blocking calls (such as WaitForShutdown) on the peer instance since the input
// handler goroutine blocks until the callback has completed.  Doing so will
// result in a deadlock.
// MessageListeners定义了使用节点方的消息侦听器调用的回调函数指针。
// 在节点初始化期间未设置为具体回调的任何侦听器都将被忽略。
// 多个消息侦听器的执行是串行发生的，因此一个回调会阻止下一个执行。
//
// 注意：除非另有说明，否则这些侦听器不得直接调用节点实例上的任何阻塞调用（如WaitForShutdown），
// 因为输入处理程序goroutine会阻塞，直到回调完成。 这样做会导致死锁。
type MessageListeners struct {
	// OnGetAddr is invoked when a peer receives a getaddr bitcoin message.
	//当节点收到getaddr比特币消息时，调用OnGetAddr。
	OnGetAddr func(p *Peer, msg *wire.MsgGetAddr)

	// OnAddr is invoked when a peer receives an addr bitcoin message.
	//当节点收到addr比特币消息时，调用OnAddr。
	OnAddr func(p *Peer, msg *wire.MsgAddr)

	// OnPing is invoked when a peer receives a ping bitcoin message.
	//当节点收到ping比特币消息时调用OnPing。
	OnPing func(p *Peer, msg *wire.MsgPing)

	// OnPong is invoked when a peer receives a pong bitcoin message.
	//当节点收到pong比特币消息时调用OnPong。
	OnPong func(p *Peer, msg *wire.MsgPong)

	// OnAlert is invoked when a peer receives an alert bitcoin message.
	//当节点收到警报比特币消息时调用OnAlert。
	OnAlert func(p *Peer, msg *wire.MsgAlert)

	// OnMemPool is invoked when a peer receives a mempool bitcoin message.
	//当节点收到mempool比特币消息时调用OnMemPool。
	OnMemPool func(p *Peer, msg *wire.MsgMemPool)

	// OnTx is invoked when a peer receives a tx bitcoin message.
	//当节点收到tx比特币消息时调用OnTx。
	OnTx func(p *Peer, msg *wire.MsgTx)

	// OnBlock is invoked when a peer receives a block bitcoin message.
	//当节点收到块比特币消息时，调用OnBlock。
	OnBlock func(p *Peer, msg *wire.MsgBlock, buf []byte)

	// OnCFilter is invoked when a peer receives a cfilter bitcoin message.
	//当节点收到cfilter比特币消息时，调用OnCFilter。
	OnCFilter func(p *Peer, msg *wire.MsgCFilter)

	// OnCFHeaders is invoked when a peer receives a cfheaders bitcoin
	// message.
	//当节点收到cfheaders比特币消息时，调用OnCFHeaders。
	OnCFHeaders func(p *Peer, msg *wire.MsgCFHeaders)

	// OnCFCheckpt is invoked when a peer receives a cfcheckpt bitcoin
	// message.
	//当节点收到cfcheckpt比特币消息时，调用OnCFCheckpt。
	OnCFCheckpt func(p *Peer, msg *wire.MsgCFCheckpt)

	// OnInv is invoked when a peer receives an inv bitcoin message.
	//当节点收到inv比特币消息时调用OnInv。
	OnInv func(p *Peer, msg *wire.MsgInv)

	// OnHeaders is invoked when a peer receives a headers bitcoin message.
	//当节点收到头比特币消息时调用OnHeaders。
	OnHeaders func(p *Peer, msg *wire.MsgHeaders)

	// OnNotFound is invoked when a peer receives a notfound bitcoin
	// message.
	//当节点收到未发现的比特币消息时，会调用OnNotFound。
	OnNotFound func(p *Peer, msg *wire.MsgNotFound)

	// OnGetData is invoked when a peer receives a getdata bitcoin message.
	//当节点收到getdata比特币消息时，调用OnGetData。
	OnGetData func(p *Peer, msg *wire.MsgGetData)

	// OnGetBlocks is invoked when a peer receives a getblocks bitcoin
	// message.
	//当节点收到getblocks比特币消息时，调用OnGetBlocks。
	OnGetBlocks func(p *Peer, msg *wire.MsgGetBlocks)

	// OnGetHeaders is invoked when a peer receives a getheaders bitcoin
	// message.
	//当节点收到getheaders比特币消息时，调用OnGetHeaders。
	OnGetHeaders func(p *Peer, msg *wire.MsgGetHeaders)

	// OnGetCFilters is invoked when a peer receives a getcfilters bitcoin
	// message.
	//当节点收到getcfilters比特币消息时，将调用OnGetCFilters。
	OnGetCFilters func(p *Peer, msg *wire.MsgGetCFilters)

	// OnGetCFHeaders is invoked when a peer receives a getcfheaders
	// bitcoin message.
	//当节点收到getcfheaders比特币消息时，调用OnGetCFHeaders。
	OnGetCFHeaders func(p *Peer, msg *wire.MsgGetCFHeaders)

	// OnGetCFCheckpt is invoked when a peer receives a getcfcheckpt
	// bitcoin message.
	//当节点收到getcfcheckpt比特币消息时，调用OnGetCFCheckpt。
	OnGetCFCheckpt func(p *Peer, msg *wire.MsgGetCFCheckpt)

	// OnFeeFilter is invoked when a peer receives a feefilter bitcoin message.
	//当节点收到费用过滤器比特币消息时，调用OnFeeFilter。
	OnFeeFilter func(p *Peer, msg *wire.MsgFeeFilter)

	// OnFilterAdd is invoked when a peer receives a filteradd bitcoin message.
	//当节点收到filteradd比特币消息时，调用OnFilterAdd。
	OnFilterAdd func(p *Peer, msg *wire.MsgFilterAdd)

	// OnFilterClear is invoked when a peer receives a filterclear bitcoin
	// message.
	//当节点收到filterclear比特币消息时，调用OnFilterClear。
	OnFilterClear func(p *Peer, msg *wire.MsgFilterClear)

	// OnFilterLoad is invoked when a peer receives a filterload bitcoin
	// message.
	//当节点收到filterload比特币消息时，调用OnFilterLoad。
	OnFilterLoad func(p *Peer, msg *wire.MsgFilterLoad)

	// OnMerkleBlock  is invoked when a peer receives a merkleblock bitcoin
	// message.
	//当节点收到merkleblock比特币消息时调用OnMerkleBlock。
	OnMerkleBlock func(p *Peer, msg *wire.MsgMerkleBlock)

	// OnVersion is invoked when a peer receives a version bitcoin message.
	// The caller may return a reject message in which case the message will
	// be sent to the peer and the peer will be disconnected.
	//当节点收到版本比特币消息时，调用COnVersion。
	//调用者可能会返回拒绝消息，在这种情况下，消息将被发送到节点，并且节点将被断开。
	OnVersion func(p *Peer, msg *wire.MsgVersion) *wire.MsgReject

	// OnVerAck is invoked when a peer receives a verack bitcoin message.
	//当节点收到verack比特币消息时，调用OnVerAck。
	OnVerAck func(p *Peer, msg *wire.MsgVerAck)

	// OnReject is invoked when a peer receives a reject bitcoin message.
	//当节点收到拒绝比特币消息时，调用OnReject。
	OnReject func(p *Peer, msg *wire.MsgReject)

	// OnSendHeaders is invoked when a peer receives a sendheaders bitcoin
	// message.
	//当节点收到sendheaders比特币消息时，调用OnSendHeaders。
	OnSendHeaders func(p *Peer, msg *wire.MsgSendHeaders)

	// OnRead is invoked when a peer receives a bitcoin message.  It
	// consists of the number of bytes read, the message, and whether or not
	// an error in the read occurred.  Typically, callers will opt to use
	// the callbacks for the specific message types, however this can be
	// useful for circumstances such as keeping track of server-wide byte
	// counts or working with custom message types for which the peer does
	// not directly provide a callback.
	// 当节点收到比特币消息时调用OnRead。 它由读取的字节数，消息以及是否发生读取错误组成。
	// 通常，调用者将选择使用特定消息类型的回调，
	// 但这对于跟踪服务器范围的字节计数或使用节点不直接提供回调的自定义消息类型等情况非常有用。
	OnRead func(p *Peer, bytesRead int, msg wire.Message, err error)

	// OnWrite is invoked when we write a bitcoin message to a peer.  It
	// consists of the number of bytes written, the message, and whether or
	// not an error in the write occurred.  This can be useful for
	// circumstances such as keeping track of server-wide byte counts.
	// 当我们向节点写入比特币消息时调用OnWrite。
	// 它由写入的字节数，消息以及是否发生写入错误组成。
	// 这对于跟踪服务器范围的字节计数等情况非常有用。
	OnWrite func(p *Peer, bytesWritten int, msg wire.Message, err error)
}

// Config is the struct to hold configuration options useful to Peer.
// Config是保存对节点有用的配置选项的结构。
type Config struct {
	// NewestBlock specifies a callback which provides the newest block
	// details to the peer as needed.  This can be nil in which case the
	// peer will report a block height of 0, however it is good practice for
	// peers to specify this so their currently best known is accurately
	// reported.
	// NewestBlock指定一个回调，根据需要向节点提供最新的块详细信息。
	// 这可以是nil，在这种情况下，节点将报告块高度为0，但是节点指定此值是一种好习惯，
	// 因此可以准确地报告它们当前最为人知的情况。
	NewestBlock HashFunc

	// HostToNetAddress returns the netaddress for the given host. This can be
	// nil in  which case the host will be parsed as an IP address.
	// HostToNetAddress返回给定主机的netaddress。
	// 这可以是零，在这种情况下，主机将被解析为IP地址。
	HostToNetAddress HostToNetAddrFunc

	// Proxy indicates a proxy is being used for connections.  The only
	// effect this has is to prevent leaking the tor proxy address, so it
	// only needs to specified if using a tor proxy.
	//代理表示正在使用代理进行连接。
	// 唯一的影响是防止泄漏代理地址，因此只需要指定是否使用tor代理。
	Proxy string

	// UserAgentName specifies the user agent name to advertise.  It is
	// highly recommended to specify this value.
	// UserAgentName指定要通告的用户代理名称。 强烈建议指定此值。
	UserAgentName string

	// UserAgentVersion specifies the user agent version to advertise.  It
	// is highly recommended to specify this value and that it follows the
	// form "major.minor.revision" e.g. "2.6.41".
	// UserAgentVersion指定要通告的用户代理版本。
	// 强烈建议指定此值，并且它遵循“major.minor.revision”形式，例如“2.6.41”。
	UserAgentVersion string

	// UserAgentComments specify the user agent comments to advertise.  These
	// values must not contain the illegal characters specified in BIP 14:
	// '/', ':', '(', ')'.
	// UserAgentComments指定要广告的用户代理注释。 这些值不得包含BIP 14中指定的非法字符：
	//'/'，'：'，'（'，'）'。
	UserAgentComments []string

	// ChainParams identifies which chain parameters the peer is associated
	// with.  It is highly recommended to specify this field, however it can
	// be omitted in which case the test network will be used.
	// ChainParams识别节点与哪些链参数相关联。
	// 强烈建议指定此字段，但在这种情况下可以省略测试网络。
	ChainParams *chaincfg.Params

	// Services specifies which services to advertise as supported by the
	// local peer.  This field can be omitted in which case it will be 0
	// and therefore advertise no supported services.
	// Services指定本地节点支持的通告哪些服务。
	// 该字段可以省略，在这种情况下它将为0，因此不通告任何支持的服务。
	Services wire.ServiceFlag

	// ProtocolVersion specifies the maximum protocol version to use and
	// advertise.  This field can be omitted in which case
	// peer.MaxProtocolVersion will be used.
	// ProtocolVersion指定要使用和通告的最大协议版本。
	// 可以省略该字段，在这种情况下将使用peer.MaxProtocolVersion。
	ProtocolVersion uint32

	// DisableRelayTx specifies if the remote peer should be informed to
	// not send inv messages for transactions.
	// DisableRelayTx指定是否应通知远程节点不发送事务的inv消息。
	// -- by eac remove DisableRelayTx
	//DisableRelayTx bool

	// Listeners houses callback functions to be invoked on receiving peer
	// messages.
	//监听器包含在接收节点消息时调用的回调函数。
	Listeners MessageListeners

	// TrickleInterval is the duration of the ticker which trickles down the
	// inventory to a peer.
	// TrickleInterval是股票代码的持续时间，它将库存细化到同行。
	TrickleInterval time.Duration
}

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
// minUint32是一个辅助函数，用于返回两个uint32里面最小的一个。
//这可以避免数学导入以及转换为浮点数的需要。
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// newNetAddress attempts to extract the IP address and port from the passed
// net.Addr interface and create a bitcoin NetAddress structure using that
// information.
// newNetAddress尝试从传递的net.Addr接口中提取IP地址和端口，
// 并使用该信息创建比特币NetAddress结构。
func newNetAddress(addr net.Addr, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// addr will be a net.TCPAddr when not using a proxy.
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip := tcpAddr.IP
		port := uint16(tcpAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// addr will be a socks.ProxiedAddr when using a proxy.
	if proxiedAddr, ok := addr.(*socks.ProxiedAddr); ok {
		ip := net.ParseIP(proxiedAddr.Host)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		port := uint16(proxiedAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// For the most part, addr should be one of the two above cases, but
	// to be safe, fall back to trying to parse the information from the
	// address string as a last resort.
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), services)
	return na, nil
}

// outMsg is used to house a message to be sent along with a channel to signal
// when the message has been sent (or won't be sent due to things such as
// shutdown)
// outMsg用于存储要与频道一起发送的消息，
// 以便在消息发送时发出信号（或由于关机之类的事情而不会发送）
type outMsg struct {
	msg      wire.Message
	doneChan chan<- struct{}
	encoding wire.MessageEncoding
}

// stallControlCmd represents the command of a stall control message.
// stallControlCmd表示停顿控制消息的命令。
type stallControlCmd uint8

// Constants for the command of a stall control message.
//停顿控制消息命令的常量。
const (
	// sccSendMessage indicates a message is being sent to the remote peer.
	// sccSendMessage表示正在向远程节点发送消息。
	sccSendMessage stallControlCmd = iota

	// sccReceiveMessage indicates a message has been received from the
	// remote peer.
	// sccReceiveMessage表示已从远程节点收到消息。
	sccReceiveMessage

	// sccHandlerStart indicates a callback handler is about to be invoked.
	// sccHandlerStart表示即将调用回调处理程序。
	sccHandlerStart

	// sccHandlerStart indicates a callback handler has completed.
	// sccHandlerStart表示回调处理程序已完成。
	sccHandlerDone
)

// stallControlMsg is used to signal the stall handler about specific events
// so it can properly detect and handle stalled remote peers.
// stallControlMsg用于向停止处理程序发出有关特定事件的信号，
// 以便它可以正确检测和处理停滞的远程节点。
type stallControlMsg struct {
	command stallControlCmd
	message wire.Message
}

// StatsSnap is a snapshot of peer stats at a point in time.
// StatsSnap是某个时间点的节点统计信息的快照。
type StatsSnap struct {
	ID             int32
	Addr           string
	Services       wire.ServiceFlag
	LastSend       time.Time
	LastRecv       time.Time
	BytesSent      uint64
	BytesRecv      uint64
	ConnTime       time.Time
	TimeOffset     int64
	Version        uint32
	UserAgent      string
	Inbound        bool
	StartingHeight int32
	LastBlock      int32
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64
}

// HashFunc is a function which returns a block hash, height and error
// It is used as a callback to get newest block details.
// HashFunc是一个返回块哈希，高度和错误的函数
//它用作回调以获取最新的块详细信息。
type HashFunc func() (hash *chainhash.Hash, height int32, err error)

// AddrFunc is a func which takes an address and returns a related address.
// AddrFunc是一个func，它接收一个地址并返回一个相关的地址。
type AddrFunc func(remoteAddr *wire.NetAddress) *wire.NetAddress

// HostToNetAddrFunc is a func which takes a host, port, services and returns
// the netaddress.
// HostToNetAddrFunc是一个func，它接受主机，端口，服务并返回netaddress。
type HostToNetAddrFunc func(host string, port uint16,
	services wire.ServiceFlag) (*wire.NetAddress, error)

// NOTE: The overall data flow of a peer is split into 3 goroutines.  Inbound
// messages are read via the inHandler goroutine and generally dispatched to
// their own handler.  For inbound data-related messages such as blocks,
// transactions, and inventory, the data is handled by the corresponding
// message handlers.  The data flow for outbound messages is split into 2
// goroutines, queueHandler and outHandler.  The first, queueHandler, is used
// as a way for external entities to queue messages, by way of the QueueMessage
// function, quickly regardless of whether the peer is currently sending or not.
// It acts as the traffic cop between the external world and the actual
// goroutine which writes to the network socket.

// Peer provides a basic concurrent safe bitcoin peer for handling bitcoin
// communications via the peer-to-peer protocol.  It provides full duplex
// reading and writing, automatic handling of the initial handshake process,
// querying of usage statistics and other information about the remote peer such
// as its address, user agent, and protocol version, output message queuing,
// inventory trickling, and the ability to dynamically register and unregister
// callbacks for handling bitcoin protocol messages.
//
// Outbound messages are typically queued via QueueMessage or QueueInventory.
// QueueMessage is intended for all messages, including responses to data such
// as blocks and transactions.  QueueInventory, on the other hand, is only
// intended for relaying inventory as it employs a trickling mechanism to batch
// the inventory together.  However, some helper functions for pushing messages
// of specific types that typically require common special handling are
// provided as a convenience.

// 注意：节点的整体数据流分为3个goroutines。入站消息通过inHandler goroutine读取，
// 通常分派给自己的处理程序。对于与数据相关的入站消息，例如块，事务和库存，
// 数据由相应的消息处理程序处理。出站消息的数据流分为2个goroutine，queueHandler和outHandler。
// 第一个是queueHandler，用于外部实体通过QueueMessage函数快速排队消息，
// 无论节点方当前是否正在发送。
//它充当外部世界和写入网络套接字的实际goroutine之间的交通警察。

// Peer提供了一个基本的并发安全比特币节点，用于通过节点协议处理比特币通信。
// 它提供全双工读写，初始握手过程的自动处理，使用统计和其他信息有关远端节点，
// 例如它的地址，用户代理，和协议版本，输出消息排队，库存滴滤，
// 并且能够的查询动态注册和取消注册回调以处理比特币协议消息。
//
// 出站邮件通常通过QueueMessage或QueueInventory排队。
// QueueMessage适用于所有消息，包括对块和事务等数据的响应。
// 另一方面，QueueInventory仅用于中继库存，因为它采用滴流机制将库存一起批处理。
// 但是，为方便起见，提供了一些辅助功能，用于推送通常需要通用特殊处理的特定类型的消息。
type Peer struct {
	// The following variables must only be used atomically.
	//以下变量只能以原子方式使用。
	bytesReceived uint64
	bytesSent     uint64
	lastRecv      int64
	lastSend      int64
	connected     int32
	disconnect    int32

	conn net.Conn

	// These fields are set at creation time and never modified, so they are
	// safe to read from concurrently without a mutex.
	//这些字段在创建时设置，从不修改，因此可以安全地在没有互斥锁的情况下同时读取。
	addr    string
	cfg     Config
	inbound bool

	//保护下面的节点标志
	flagsMtx     sync.Mutex // protects the peer flags below
	na           *wire.NetAddress
	id           int32
	userAgent    string
	services     wire.ServiceFlag
	versionKnown bool
	//远程通告的协议版本
	advertisedProtoVer uint32 // protocol version advertised by remote
	//协商协议版本
	protocolVersion uint32 // negotiated protocol version
	// peer发送了sendheaders消息
	sendHeadersPreferred bool // peer sent a sendheaders message
	verAckReceived       bool
	witnessEnabled       bool

	wireEncoding wire.MessageEncoding

	knownInventory     *mruInventoryMap
	prevGetBlocksMtx   sync.Mutex
	prevGetBlocksBegin *chainhash.Hash
	prevGetBlocksStop  *chainhash.Hash
	prevGetHdrsMtx     sync.Mutex
	prevGetHdrsBegin   *chainhash.Hash
	prevGetHdrsStop    *chainhash.Hash

	// These fields keep track of statistics for the peer and are protected
	// by the statsMtx mutex.
	//这些字段跟踪节点的统计信息，并受statsMtx互斥锁保护。
	statsMtx           sync.RWMutex
	timeOffset         int64
	timeConnected      time.Time
	startingHeight     int32
	lastBlock          int32
	lastAnnouncedBlock *chainhash.Hash
	//如果我们有一个挂起的ping，则设置为nonce。
	lastPingNonce uint64 // Set to nonce if we have a pending ping.
	//我们发送最后一次ping的时间。
	lastPingTime time.Time // Time we sent last ping.
	//上次ping返回的时间。
	lastPingMicros int64 // Time for last ping to return.

	stallControl  chan stallControlMsg
	outputQueue   chan outMsg
	sendQueue     chan outMsg
	sendDoneQueue chan struct{}
	outputInvChan chan *wire.InvVect
	inQuit        chan struct{}
	queueQuit     chan struct{}
	outQuit       chan struct{}
	quit          chan struct{}
}

// String returns the peer's address and directionality as a human-readable
// string.
//
// This function is safe for concurrent access.
// String将节点的地址和方向性作为人类可读的字符串返回。
//
//此函数对于并发访问是安全的。
func (p *Peer) String() string {
	return fmt.Sprintf("%s (%s)", p.addr, directionString(p.inbound))
}

// UpdateLastBlockHeight updates the last known block for the peer.
//
// This function is safe for concurrent access.
// UpdateLastBlockHeight更新节点的最后一个已知块。
//
//此函数对于并发访问是安全的。
func (p *Peer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.addr, p.lastBlock, newHeight)
	p.lastBlock = newHeight
	p.statsMtx.Unlock()
}

// UpdateLastAnnouncedBlock updates meta-data about the last block hash this
// peer is known to have announced.
//
// This function is safe for concurrent access.
// UpdateLastAnnouncedBlock更新已知此节点已宣布的最后一个块哈希的元数据。
//
//此函数对于并发访问是安全的。
func (p *Peer) UpdateLastAnnouncedBlock(blkHash *chainhash.Hash) {
	log.Tracef("Updating last blk for peer %v, %v", p.addr, blkHash)

	p.statsMtx.Lock()
	p.lastAnnouncedBlock = blkHash
	p.statsMtx.Unlock()
}

// AddKnownInventory adds the passed inventory to the cache of known inventory
// for the peer.
//
// This function is safe for concurrent access.
// AddKnownInventory将传递的库存添加到节点的已知库存缓存中。
//
//此函数对于并发访问是安全的。
func (p *Peer) AddKnownInventory(invVect *wire.InvVect) {
	p.knownInventory.Add(invVect)
}

// StatsSnapshot returns a snapshot of the current peer flags and statistics.
//
// This function is safe for concurrent access.
// StatsSnapshot返回当前节点标志和统计信息的快照。
//
//此函数对于并发访问是安全的。
func (p *Peer) StatsSnapshot() *StatsSnap {
	p.statsMtx.RLock()

	p.flagsMtx.Lock()
	id := p.id
	addr := p.addr
	userAgent := p.userAgent
	services := p.services
	protocolVersion := p.advertisedProtoVer
	p.flagsMtx.Unlock()

	// Get a copy of all relevant flags and stats.
	//获取所有相关标志和统计信息的副本。
	statsSnap := &StatsSnap{
		ID:             id,
		Addr:           addr,
		UserAgent:      userAgent,
		Services:       services,
		LastSend:       p.LastSend(),
		LastRecv:       p.LastRecv(),
		BytesSent:      p.BytesSent(),
		BytesRecv:      p.BytesReceived(),
		ConnTime:       p.timeConnected,
		TimeOffset:     p.timeOffset,
		Version:        protocolVersion,
		Inbound:        p.inbound,
		StartingHeight: p.startingHeight,
		LastBlock:      p.lastBlock,
		LastPingNonce:  p.lastPingNonce,
		LastPingMicros: p.lastPingMicros,
		LastPingTime:   p.lastPingTime,
	}

	p.statsMtx.RUnlock()
	return statsSnap
}

// ID returns the peer id.
//
// This function is safe for concurrent access.
// ID返回节点ID。
//
//此函数对于并发访问是安全的。
func (p *Peer) ID() int32 {
	p.flagsMtx.Lock()
	id := p.id
	p.flagsMtx.Unlock()

	return id
}

// NA returns the peer network address.
//
// This function is safe for concurrent access.
// NA返回节点网络地址。
//
//此函数对于并发访问是安全的。
func (p *Peer) NA() *wire.NetAddress {
	p.flagsMtx.Lock()
	na := p.na
	p.flagsMtx.Unlock()

	return na
}

// Addr returns the peer address.
//
// This function is safe for concurrent access.
// Addr返回节点地址。
//
//此函数对于并发访问是安全的。
func (p *Peer) Addr() string {
	// The address doesn't change after initialization, therefore it is not
	// protected by a mutex.
	//初始化后地址不会更改，因此它不受互斥锁保护。
	return p.addr
}

// Inbound returns whether the peer is inbound.
//
// This function is safe for concurrent access.
//Inbound 返回节点是否入站。
//
//此函数对于并发访问是安全的。
func (p *Peer) Inbound() bool {
	return p.inbound
}

// Services returns the services flag of the remote peer.
//
// This function is safe for concurrent access.
// Services返回远程节点的服务标志。
//
//此函数对于并发访问是安全的。
func (p *Peer) Services() wire.ServiceFlag {
	p.flagsMtx.Lock()
	services := p.services
	p.flagsMtx.Unlock()

	return services
}

// UserAgent returns the user agent of the remote peer.
//
// This function is safe for concurrent access.
// UserAgent返回远程节点的用户代理。
//
//此函数对于并发访问是安全的。
func (p *Peer) UserAgent() string {
	p.flagsMtx.Lock()
	userAgent := p.userAgent
	p.flagsMtx.Unlock()

	return userAgent
}

// LastAnnouncedBlock returns the last announced block of the remote peer.
//
// This function is safe for concurrent access.
// LastAnnouncedBlock返回最后公布的远程节点块。
//
//此函数对于并发访问是安全的。
func (p *Peer) LastAnnouncedBlock() *chainhash.Hash {
	p.statsMtx.RLock()
	lastAnnouncedBlock := p.lastAnnouncedBlock
	p.statsMtx.RUnlock()

	return lastAnnouncedBlock
}

// LastPingNonce returns the last ping nonce of the remote peer.
//
// This function is safe for concurrent access.
// LastPingNonce返回远程节点的最后一个ping nonce。
//
//此函数对于并发访问是安全的。
func (p *Peer) LastPingNonce() uint64 {
	p.statsMtx.RLock()
	lastPingNonce := p.lastPingNonce
	p.statsMtx.RUnlock()

	return lastPingNonce
}

// LastPingTime returns the last ping time of the remote peer.
//
// This function is safe for concurrent access.
// LastPingTime返回远程节点的最后一次ping时间。
//
//此函数对于并发访问是安全的。
func (p *Peer) LastPingTime() time.Time {
	p.statsMtx.RLock()
	lastPingTime := p.lastPingTime
	p.statsMtx.RUnlock()

	return lastPingTime
}

// LastPingMicros returns the last ping micros of the remote peer.
//
// This function is safe for concurrent access.
// LastPingMicros返回远程节点的最后一个ping微控制器。
//
//此函数对于并发访问是安全的。
func (p *Peer) LastPingMicros() int64 {
	p.statsMtx.RLock()
	lastPingMicros := p.lastPingMicros
	p.statsMtx.RUnlock()

	return lastPingMicros
}

// VersionKnown returns the whether or not the version of a peer is known
// locally.
//
// This function is safe for concurrent access.
// VersionKnown返回节点的版本是否在本地已知。
//
//此函数对于并发访问是安全的。
func (p *Peer) VersionKnown() bool {
	p.flagsMtx.Lock()
	versionKnown := p.versionKnown
	p.flagsMtx.Unlock()

	return versionKnown
}

// VerAckReceived returns whether or not a verack message was received by the
// peer.
//
// This function is safe for concurrent access.
// VerAckReceived返回节点是否收到verack消息。
//
//此函数对于并发访问是安全的。
func (p *Peer) VerAckReceived() bool {
	p.flagsMtx.Lock()
	verAckReceived := p.verAckReceived
	p.flagsMtx.Unlock()

	return verAckReceived
}

// ProtocolVersion returns the negotiated peer protocol version.
//
// This function is safe for concurrent access.
// ProtocolVersion返回协商的节点协议版本。
//
//此函数对于并发访问是安全的。
func (p *Peer) ProtocolVersion() uint32 {
	p.flagsMtx.Lock()
	protocolVersion := p.protocolVersion
	p.flagsMtx.Unlock()

	return protocolVersion
}

// LastBlock returns the last block of the peer.
//
// This function is safe for concurrent access.
// LastBlock返回节点的最后一个块。
//
//此函数对于并发访问是安全的。

func (p *Peer) LastBlock() int32 {
	p.statsMtx.RLock()
	lastBlock := p.lastBlock
	p.statsMtx.RUnlock()

	return lastBlock
}

// LastSend returns the last send time of the peer.
//
// This function is safe for concurrent access.
// LastSend返回节点的最后发送时间。
//
//此函数对于并发访问是安全的。
func (p *Peer) LastSend() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastSend), 0)
}

// LastRecv returns the last recv time of the peer.
//
// This function is safe for concurrent access.
// LastRecv返回节点的最后一次recv时间。
//
//此函数对于并发访问是安全的。
func (p *Peer) LastRecv() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastRecv), 0)
}

// LocalAddr returns the local address of the connection.
//
// This function is safe fo concurrent access.
// LocalAddr返回连接的本地地址。
//
//此函数对于并发访问是安全的。
func (p *Peer) LocalAddr() net.Addr {
	var localAddr net.Addr
	if atomic.LoadInt32(&p.connected) != 0 {
		localAddr = p.conn.LocalAddr()
	}
	return localAddr
}

// BytesSent returns the total number of bytes sent by the peer.
//
// This function is safe for concurrent access.
// BytesSent返回节点发送的总字节数。
//
//此函数对于并发访问是安全的。
func (p *Peer) BytesSent() uint64 {
	return atomic.LoadUint64(&p.bytesSent)
}

// BytesReceived returns the total number of bytes received by the peer.
//
// This function is safe for concurrent access.
// BytesReceived返回节点接收的总字节数。
//
//此函数对于并发访问是安全的。
func (p *Peer) BytesReceived() uint64 {
	return atomic.LoadUint64(&p.bytesReceived)
}

// TimeConnected returns the time at which the peer connected.
//
// This function is safe for concurrent access.
// TimeConnected返回节点连接的时间。
//
//此函数对于并发访问是安全的。
func (p *Peer) TimeConnected() time.Time {
	p.statsMtx.RLock()
	timeConnected := p.timeConnected
	p.statsMtx.RUnlock()

	return timeConnected
}

// TimeOffset returns the number of seconds the local time was offset from the
// time the peer reported during the initial negotiation phase.  Negative values
// indicate the remote peer's time is before the local time.
//
// This function is safe for concurrent access.
// TimeOffset返回本地时间偏离节点在初始协商阶段报告的时间的秒数。
// 负值表示远程节点的时间早于本地时间。
//
//此函数对于并发访问是安全的。

func (p *Peer) TimeOffset() int64 {
	p.statsMtx.RLock()
	timeOffset := p.timeOffset
	p.statsMtx.RUnlock()

	return timeOffset
}

// StartingHeight returns the last known height the peer reported during the
// initial negotiation phase.
//
// This function is safe for concurrent access.
// StartingHeight返回节点在初始协商阶段报告的最后已知高度。
//
//此函数对于并发访问是安全的。
func (p *Peer) StartingHeight() int32 {
	p.statsMtx.RLock()
	startingHeight := p.startingHeight
	p.statsMtx.RUnlock()

	return startingHeight
}

// WantsHeaders returns if the peer wants header messages instead of
// inventory vectors for blocks.
//
// This function is safe for concurrent access.
//如果节点想要标题消息而不是块的库存向量，则WantsHeaders返回。
//
//此函数对于并发访问是安全的。
func (p *Peer) WantsHeaders() bool {
	p.flagsMtx.Lock()
	sendHeadersPreferred := p.sendHeadersPreferred
	p.flagsMtx.Unlock()

	return sendHeadersPreferred
}

// IsWitnessEnabled returns true if the peer has signalled that it supports
// segregated witness.
//
// This function is safe for concurrent access.
//如果节点发出信号表明它支持隔离的见证，则IsWitnessEnabled返回true。
//
//此函数对于并发访问是安全的。
func (p *Peer) IsWitnessEnabled() bool {
	p.flagsMtx.Lock()
	witnessEnabled := p.witnessEnabled
	p.flagsMtx.Unlock()

	return witnessEnabled
}

// PushAddrMsg sends an addr message to the connected peer using the provided
// addresses.  This function is useful over manually sending the message via
// QueueMessage since it automatically limits the addresses to the maximum
// number allowed by the message and randomizes the chosen addresses when there
// are too many.  It returns the addresses that were actually sent and no
// message will be sent if there are no entries in the provided addresses slice.
//
// This function is safe for concurrent access.
// PushAddrMsg使用提供的地址向连接的节点发送addr消息。
// 此功能比通过QueueMessage手动发送消息更有用，因为它会自动将地址限制为消息允许的最大数量，
// 并在有太多时将所选地址随机化。
// 它返回实际发送的地址，如果提供的地址片中没有条目，则不会发送任何消息。
//
//此函数对于并发访问是安全的。
func (p *Peer) PushAddrMsg(addresses []*wire.NetAddress) ([]*wire.NetAddress, error) {
	addressCount := len(addresses)

	// Nothing to send.
	if addressCount == 0 {
		return nil, nil
	}

	msg := wire.NewMsgAddr()
	msg.AddrList = make([]*wire.NetAddress, addressCount)
	copy(msg.AddrList, addresses)

	// Randomize the addresses sent if there are more than the maximum allowed.
	if addressCount > wire.MaxAddrPerMsg {
		// Shuffle the address list.
		for i := 0; i < wire.MaxAddrPerMsg; i++ {
			j := i + rand.Intn(addressCount-i)
			msg.AddrList[i], msg.AddrList[j] = msg.AddrList[j], msg.AddrList[i]
		}

		// Truncate it to the maximum size.
		msg.AddrList = msg.AddrList[:wire.MaxAddrPerMsg]
	}

	p.QueueMessage(msg, nil)
	return msg.AddrList, nil
}

// PushGetBlocksMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
//
// This function is safe for concurrent access.
// PushGetBlocksMsg为提供的块定位器发送getblocks消息并停止哈希。 它将忽略背对背的重复请求。
//
//此函数对于并发访问是安全的。
func (p *Peer) PushGetBlocksMsg(locator blockchain.BlockLocator, stopHash *chainhash.Hash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getblocks requests.
	//从块定位器中提取begin哈希，如果指定了一个，
	//用于过滤重复的getblocks请求。
	var beginHash *chainhash.Hash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getblocks requests.
	p.prevGetBlocksMtx.Lock()
	isDuplicate := p.prevGetBlocksStop != nil && p.prevGetBlocksBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetBlocksStop) &&
		beginHash.IsEqual(p.prevGetBlocksBegin)
	p.prevGetBlocksMtx.Unlock()

	if isDuplicate {
		log.Tracef("Filtering duplicate [getblocks] with begin "+
			"hash %v, stop hash %v", beginHash, stopHash)
		return nil
	}

	// Construct the getblocks request and queue it to be sent.
	msg := wire.NewMsgGetBlocks(stopHash)
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	p.QueueMessage(msg, nil)

	// Update the previous getblocks request information for filtering
	// duplicates.
	p.prevGetBlocksMtx.Lock()
	p.prevGetBlocksBegin = beginHash
	p.prevGetBlocksStop = stopHash
	p.prevGetBlocksMtx.Unlock()
	return nil
}

// PushGetHeadersMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
//
// This function is safe for concurrent access.
// PushGetHeadersMsg为提供的块定位器发送getblocks消息并停止哈希。 它将忽略背对背的重复请求。
//
//此函数对于并发访问是安全的。
func (p *Peer) PushGetHeadersMsg(locator blockchain.BlockLocator, stopHash *chainhash.Hash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getheaders requests.
	//从块定位器中提取begin哈希，如果指定了一个，
	//用于过滤重复的getheaders请求。
	var beginHash *chainhash.Hash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getheaders requests.
	p.prevGetHdrsMtx.Lock()
	isDuplicate := p.prevGetHdrsStop != nil && p.prevGetHdrsBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetHdrsStop) &&
		beginHash.IsEqual(p.prevGetHdrsBegin)
	p.prevGetHdrsMtx.Unlock()

	if isDuplicate {
		log.Tracef("Filtering duplicate [getheaders] with begin hash %v",
			beginHash)
		return nil
	}

	// Construct the getheaders request and queue it to be sent.
	msg := wire.NewMsgGetHeaders()
	msg.HashStop = *stopHash
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	p.QueueMessage(msg, nil)

	// Update the previous getheaders request information for filtering
	// duplicates.
	p.prevGetHdrsMtx.Lock()
	p.prevGetHdrsBegin = beginHash
	p.prevGetHdrsStop = stopHash
	p.prevGetHdrsMtx.Unlock()
	return nil
}

// PushRejectMsg sends a reject message for the provided command, reject code,
// reject reason, and hash.  The hash will only be used when the command is a tx
// or block and should be nil in other cases.  The wait parameter will cause the
// function to block until the reject message has actually been sent.
//
// This function is safe for concurrent access.
// PushRejectMsg为提供的命令发送拒绝消息，拒绝代码，拒绝原因和哈希。
// 仅当命令是tx或块时才使用哈希，而在其他情况下应该为nil。
// wait参数将导致函数阻塞，直到实际发送了拒绝消息。
//
//此函数对于并发访问是安全的。
func (p *Peer) PushRejectMsg(command string, code wire.RejectCode, reason string, hash *chainhash.Hash, wait bool) {
	// Don't bother sending the reject message if the protocol version
	// is too low.
	//如果协议版本太低，请不要打扰发送拒绝消息。
	if p.VersionKnown() && p.ProtocolVersion() < wire.RejectVersion {
		return
	}

	msg := wire.NewMsgReject(command, code, reason)
	if command == wire.CmdTx || command == wire.CmdBlock {
		if hash == nil {
			log.Warnf("Sending a reject message for command "+
				"type %v which should have specified a hash "+
				"but does not", command)
			hash = &zeroHash
		}
		msg.Hash = *hash
	}

	// Send the message without waiting if the caller has not requested it.
	if !wait {
		p.QueueMessage(msg, nil)
		return
	}

	// Send the message and block until it has been sent before returning.
	doneChan := make(chan struct{}, 1)
	p.QueueMessage(msg, doneChan)
	<-doneChan
}

// handlePingMsg is invoked when a peer receives a ping bitcoin message.  For
// recent clients (protocol version > BIP0031Version), it replies with a pong
// message.  For older clients, it does nothing and anything other than failure
// is considered a successful ping.
//当节点收到ping比特币消息时，调用handlePingMsg。
// 对于最近的客户端（协议版本> BIP0031版本），它会回复一条pong消息。
// 对于较旧的客户端，它什么都不做，除了失败之外的任何事情都被视为成功的ping。
func (p *Peer) handlePingMsg(msg *wire.MsgPing) {
	// Only reply with pong if the message is from a new enough client.
	//如果消息来自足够新的客户端，则仅使用pong进行回复。

	if p.ProtocolVersion() > wire.BIP0031Version {
		// Include nonce from ping so pong can be identified.
		p.QueueMessage(wire.NewMsgPong(msg.Nonce), nil)
	}
}

// handlePongMsg is invoked when a peer receives a pong bitcoin message.  It
// updates the ping statistics as required for recent clients (protocol
// version > BIP0031Version).  There is no effect for older clients or when a
// ping was not previously sent.
//当节点收到pong比特币消息时，调用handlePongMsg。
// 它根据最近客户端的需要更新ping统计信息（协议版本> BIP0031Version）。
// 对于较旧的客户端或之前未发送ping的情况没有任何影响。
func (p *Peer) handlePongMsg(msg *wire.MsgPong) {
	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping rpc call since we ping infrequently
	// enough that if they overlap we would have timed out the peer.
	// 我们可以使用缓冲通道，每当我们发送ping时，都会以fifo方式发送数据，
	// 或者跟踪每次ping的时间。 现在我们只是尽力而为，只记录最后发送的ping的统计数据。
	// 任何先前和重叠的ping都将被忽略。
	// 如果没有大量使用ping rpc调用，就不太可能发生这种情况，因为我们不经常ping通，
	// 如果它们重叠，我们就会超时。
	if p.ProtocolVersion() > wire.BIP0031Version {
		p.statsMtx.Lock()
		if p.lastPingNonce != 0 && msg.Nonce == p.lastPingNonce {
			p.lastPingMicros = time.Since(p.lastPingTime).Nanoseconds()
			p.lastPingMicros /= 1000 // convert to usec.
			p.lastPingNonce = 0
		}
		p.statsMtx.Unlock()
	}
}

// readMessage reads the next bitcoin message from the peer with logging.
// readMessage使用日志记录从节点读取下一个比特币消息。
func (p *Peer) readMessage(encoding wire.MessageEncoding) (wire.Message, []byte, error) {
	n, msg, buf, err := wire.ReadMessageWithEncodingN(p.conn,
		p.ProtocolVersion(), p.cfg.ChainParams.Net, encoding)
	atomic.AddUint64(&p.bytesReceived, uint64(n))
	if p.cfg.Listeners.OnRead != nil {
		p.cfg.Listeners.OnRead(p, n, msg, err)
	}
	if err != nil {
		log.Infof("readMessage nil err %s ", p)
		log.Infof("err : %s ", err)
		return nil, nil, err
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	//使用闭包记录昂贵的操作，以便它们仅在日志记录级别需要时运行。
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Received %v%s from %s",
			msg.Command(), summary, p)
	}))

	log.Infof("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Received %v%s from %s",
			msg.Command(), summary, p)
	}))

	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(buf)
	}))

	return msg, buf, nil
}

// writeMessage sends a bitcoin message to the peer with logging.
// writeMessage通过日志记录向节点发送比特币消息。
func (p *Peer) writeMessage(msg wire.Message, enc wire.MessageEncoding) error {
	// Don't do anything if we're disconnecting.
	//如果我们断开连接，不要做任何事情。
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return nil
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Sending %v%s to %s", msg.Command(),
			summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		var buf bytes.Buffer
		_, err := wire.WriteMessageWithEncodingN(&buf, msg, p.ProtocolVersion(),
			p.cfg.ChainParams.Net, enc)
		if err != nil {
			return err.Error()
		}
		return spew.Sdump(buf.Bytes())
	}))

	// Write the message to the peer.
	n, err := wire.WriteMessageWithEncodingN(p.conn, msg,
		p.ProtocolVersion(), p.cfg.ChainParams.Net, enc)
	atomic.AddUint64(&p.bytesSent, uint64(n))
	if p.cfg.Listeners.OnWrite != nil {
		p.cfg.Listeners.OnWrite(p, n, msg, err)
	}
	return err
}

// isAllowedReadError returns whether or not the passed error is allowed without
// disconnecting the peer.  In particular, regression tests need to be allowed
// to send malformed messages without the peer being disconnected.
// isAllowedReadError返回是否允许传递错误而不断开节点。
// 特别是，需要允许回归测试发送格式错误的消息，而不会断开节点的连接。
func (p *Peer) isAllowedReadError(err error) bool {
	// Only allow read errors in regression test mode.
	//仅允许在回归测试模式下读取错误。
	if p.cfg.ChainParams.Net != wire.TestNet {
		return false
	}

	// Don't allow the error if it's not specifically a malformed message error.
	if _, ok := err.(*wire.MessageError); !ok {
		return false
	}

	// Don't allow the error if it's not coming from localhost or the
	// hostname can't be determined for some reason.
	host, _, err := net.SplitHostPort(p.addr)
	if err != nil {
		return false
	}

	if host != "127.0.0.1" && host != "localhost" {
		return false
	}

	// Allowed if all checks passed.
	return true
}

// shouldHandleReadError returns whether or not the passed error, which is
// expected to have come from reading from the remote peer in the inHandler,
// should be logged and responded to with a reject message.
// shouldHandleReadError返回是否应该记录传递的错误，
// 该错误是预期来自inHandler中远程节点的读取，并且应该使用拒绝消息进行响应。
func (p *Peer) shouldHandleReadError(err error) bool {
	// No logging or reject message when the peer is being forcibly
	// disconnected.
	//强制断开节点时没有记录或拒绝消息。
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging or reject message when the remote peer has been
	// disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// maybeAddDeadline potentially adds a deadline for the appropriate expected
// response for the passed wire protocol command to the pending responses map.
// maybeAddDeadline可能会将传递的有线协议命令的相应预期响应的截止时间添加到待处理的响应映射中。
func (p *Peer) maybeAddDeadline(pendingResponses map[string]time.Time, msgCmd string) {
	// Setup a deadline for each message being sent that expects a response.
	//
	// NOTE: Pings are intentionally ignored here since they are typically
	// sent asynchronously and as a result of a long backlock of messages,
	// such as is typical in the case of initial block download, the
	// response won't be received in time.
	//为每个要发送响应的消息设置截止日期。
	//
	//注意：这里有意忽略Ping，因为它们通常是异步发送的，并且由于长时间的消息后锁，
	//例如在初始块下载的情况下通常不会及时收到响应。
	deadline := time.Now().Add(stallResponseTimeout)
	switch msgCmd {
	case wire.CmdVersion:
		// Expects a verack message.
		pendingResponses[wire.CmdVerAck] = deadline

	case wire.CmdMemPool:
		// Expects an inv message.
		pendingResponses[wire.CmdInv] = deadline

	case wire.CmdGetBlocks:
		// Expects an inv message.
		pendingResponses[wire.CmdInv] = deadline

	case wire.CmdGetData:
		// Expects a block, merkleblock, tx, or notfound message.
		pendingResponses[wire.CmdBlock] = deadline
		pendingResponses[wire.CmdMerkleBlock] = deadline
		pendingResponses[wire.CmdTx] = deadline
		pendingResponses[wire.CmdNotFound] = deadline

	case wire.CmdGetHeaders:
		// Expects a headers message.  Use a longer deadline since it
		// can take a while for the remote peer to load all of the
		// headers.
		//期待标题消息。 使用更长的截止日期，因为远程节点可能需要一段时间才能加载所有标头。
		deadline = time.Now().Add(stallResponseTimeout * 3)
		pendingResponses[wire.CmdHeaders] = deadline
	}
}

// stallHandler handles stall detection for the peer.  This entails keeping
// track of expected responses and assigning them deadlines while accounting for
// the time spent in callbacks.  It must be run as a goroutine.
// stallHandler处理节点的失速检测。 这需要跟踪预期的响应并指定它们的最后期限，
// 同时考虑回调所花费的时间。 它必须作为协程运行。
func (p *Peer) stallHandler() {
	// These variables are used to adjust the deadline times forward by the
	// time it takes callbacks to execute.  This is done because new
	// messages aren't read until the previous one is finished processing
	// (which includes callbacks), so the deadline for receiving a response
	// for a given message must account for the processing time as well.
	// 这些变量用于在执行回调时调整截止时间。 这样做是因为在前一个消息完成处理（包括回调）
	// 之前不会读取新消息，因此接收给定消息的响应的截止时间也必须考虑处理时间。
	var handlerActive bool
	var handlersStartTime time.Time
	var deadlineOffset time.Duration

	// pendingResponses tracks the expected response deadline times.
	pendingResponses := make(map[string]time.Time)

	// stallTicker is used to periodically check pending responses that have
	// exceeded the expected deadline and disconnect the peer due to
	// stalling.
	stallTicker := time.NewTicker(stallTickInterval)
	defer stallTicker.Stop()

	// ioStopped is used to detect when both the input and output handler
	// goroutines are done.
	var ioStopped bool
out:
	for {
		select {
		case msg := <-p.stallControl:
			switch msg.command {
			case sccSendMessage:
				// Add a deadline for the expected response
				// message if needed.
				//如果需要，为预期的响应消息添加截止日期。
				p.maybeAddDeadline(pendingResponses,
					msg.message.Command())

			case sccReceiveMessage:
				// Remove received messages from the expected
				// response map.  Since certain commands expect
				// one of a group of responses, remove
				// everything in the expected group accordingly.
				//从预期的响应映射中删除收到的消息。
				// 由于某些命令需要一组响应中的一个，因此相应地删除预期组中的所有内容。
				switch msgCmd := msg.message.Command(); msgCmd {
				case wire.CmdBlock:
					fallthrough
				case wire.CmdMerkleBlock:
					fallthrough
				case wire.CmdTx:
					fallthrough
				case wire.CmdNotFound:
					delete(pendingResponses, wire.CmdBlock)
					delete(pendingResponses, wire.CmdMerkleBlock)
					delete(pendingResponses, wire.CmdTx)
					delete(pendingResponses, wire.CmdNotFound)

				default:
					delete(pendingResponses, msgCmd)
				}

			case sccHandlerStart:
				// Warn on unbalanced callback signalling.
				if handlerActive {
					log.Warn("Received handler start " +
						"control command while a " +
						"handler is already active")
					continue
				}

				handlerActive = true
				handlersStartTime = time.Now()

			case sccHandlerDone:
				// Warn on unbalanced callback signalling.
				if !handlerActive {
					log.Warn("Received handler done " +
						"control command when a " +
						"handler is not already active")
					continue
				}

				// Extend active deadlines by the time it took
				// to execute the callback.
				duration := time.Since(handlersStartTime)
				deadlineOffset += duration
				handlerActive = false

			default:
				log.Warnf("Unsupported message command %v",
					msg.command)
			}

		case <-stallTicker.C:
			// Calculate the offset to apply to the deadline based
			// on how long the handlers have taken to execute since
			// the last tick.
			//根据处理程序自上次打勾后执行的时间长度，计算应用于截止时间的偏移量。
			now := time.Now()
			offset := deadlineOffset
			if handlerActive {
				offset += now.Sub(handlersStartTime)
			}

			// Disconnect the peer if any of the pending responses
			// don't arrive by their adjusted deadline.
			//如果任何待处理的响应未按调整的截止日期到达，请断开节点的连接。
			for command, deadline := range pendingResponses {
				if now.Before(deadline.Add(offset)) {
					continue
				}

				log.Debugf("Peer %s appears to be stalled or "+
					"misbehaving, %s timeout -- "+
					"disconnecting", p, command)
				p.Disconnect()
				break
			}

			// Reset the deadline offset for the next tick.
			deadlineOffset = 0

		case <-p.inQuit:
			// The stall handler can exit once both the input and
			// output handler goroutines are done.
			//一旦输入和输出处理程序goroutine完成，停顿处理程序就可以退出。
			if ioStopped {
				break out
			}
			ioStopped = true

		case <-p.outQuit:
			// The stall handler can exit once both the input and
			// output handler goroutines are done.
			//一旦输入和输出处理程序goroutine完成，停顿处理程序就可以退出。
			if ioStopped {
				break out
			}
			ioStopped = true
		}
	}

	// Drain any wait channels before going away so there is nothing left
	// waiting on this goroutine.
	//在离开之前排空任何等待通道，这样就没有什么可以等待这个goroutine了。
cleanup:
	for {
		select {
		case <-p.stallControl:
		default:
			break cleanup
		}
	}
	log.Tracef("Peer stall handler done for %s", p)
}

// inHandler handles all incoming messages for the peer.  It must be run as a
// goroutine.
//通过tcp协议连接外部节点，打开自己的tcp服务器；同时用于接收比特币协议数据
// inHandler处理节点的所有传入消息。 它必须作为goroutine运行。
func (p *Peer) inHandler() {
	// The timer is stopped when a new message is received and reset after it
	// is processed.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		log.Warnf("Peer %s no answer for %s -- disconnecting", p, idleTimeout)
		p.Disconnect()
	})

out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		// Read a message and stop the idle timer as soon as the read
		// is done.  The timer is reset below for the next iteration if
		// needed.
		//读取完成后立即读取消息并停止空闲计时器。 如果需要，定时器将在下面重置以进行下一次迭代。
		rmsg, buf, err := p.readMessage(p.wireEncoding)
		idleTimer.Stop()
		if err != nil {
			// In order to allow regression tests with malformed messages, don't
			// disconnect the peer when we're in regression test mode and the
			// error is one of the allowed errors.
			//为了允许使用格式错误的消息进行回归测试，
			//请不要在我们处于回归测试模式时断开节点，并且错误是允许的错误之一。
			if p.isAllowedReadError(err) {
				log.Errorf("Allowed test error from %s: %v", p, err)
				idleTimer.Reset(idleTimeout)
				continue
			}

			// Only log the error and send reject message if the
			// local peer is not forcibly disconnecting and the
			// remote peer has not disconnected.
			//如果本地节点未强制断开连接且远程节点未断开连接，则仅记录错误并发送拒绝消息。
			if p.shouldHandleReadError(err) {
				errMsg := fmt.Sprintf("Can't read message from %s: %v", p, err)
				if err != io.ErrUnexpectedEOF {
					log.Errorf(errMsg)
				}

				// Push a reject message for the malformed message and wait for
				// the message to be sent before disconnecting.
				//
				// NOTE: Ideally this would include the command in the header if
				// at least that much of the message was valid, but that is not
				// currently exposed by wire, so just used malformed for the
				// command.
				//针对格式错误的消息推送拒绝消息，并在断开连接之前等待消息发送。
				//
				//注意：理想情况下，如果至少消息的大部分是有效的，那么这将包括头部中的命令，
				//但是当前没有通过线路暴露，因此只是对命令使用了格式错误。
				p.PushRejectMsg("malformed", wire.RejectMalformed, errMsg, nil,
					true)
			}
			break out
		}
		atomic.StoreInt64(&p.lastRecv, time.Now().Unix())
		p.stallControl <- stallControlMsg{sccReceiveMessage, rmsg}

		// Handle each supported message type.
		p.stallControl <- stallControlMsg{sccHandlerStart, rmsg}
		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			// Limit to one version message per peer.
			p.PushRejectMsg(msg.Command(), wire.RejectDuplicate,
				"duplicate version message", nil, true)
			break out

		case *wire.MsgVerAck:

			// No read lock is necessary because verAckReceived is not written
			// to in any other goroutine.
			//不需要读取锁定，因为verAckReceived不会写入任何其他goroutine。
			if p.verAckReceived {
				log.Infof("Already received 'verack' from peer %v -- "+
					"disconnecting", p)
				break out
			}
			p.flagsMtx.Lock()
			p.verAckReceived = true
			p.flagsMtx.Unlock()
			if p.cfg.Listeners.OnVerAck != nil {
				p.cfg.Listeners.OnVerAck(p, msg)
			}

		case *wire.MsgGetAddr:
			if p.cfg.Listeners.OnGetAddr != nil {
				p.cfg.Listeners.OnGetAddr(p, msg)
			}

		case *wire.MsgAddr:
			if p.cfg.Listeners.OnAddr != nil {
				p.cfg.Listeners.OnAddr(p, msg)
			}

		case *wire.MsgPing:
			p.handlePingMsg(msg)
			if p.cfg.Listeners.OnPing != nil {
				p.cfg.Listeners.OnPing(p, msg)
			}

		case *wire.MsgPong:
			p.handlePongMsg(msg)
			if p.cfg.Listeners.OnPong != nil {
				p.cfg.Listeners.OnPong(p, msg)
			}

		case *wire.MsgAlert:
			if p.cfg.Listeners.OnAlert != nil {
				p.cfg.Listeners.OnAlert(p, msg)
			}

		case *wire.MsgMemPool:
			if p.cfg.Listeners.OnMemPool != nil {
				p.cfg.Listeners.OnMemPool(p, msg)
			}

		case *wire.MsgTx:
			if p.cfg.Listeners.OnTx != nil {
				p.cfg.Listeners.OnTx(p, msg)
			}

		case *wire.MsgBlock:
			if p.cfg.Listeners.OnBlock != nil {
				p.cfg.Listeners.OnBlock(p, msg, buf)
			}

		case *wire.MsgInv:
			if p.cfg.Listeners.OnInv != nil {
				p.cfg.Listeners.OnInv(p, msg)
			}

		case *wire.MsgHeaders:
			if p.cfg.Listeners.OnHeaders != nil {
				p.cfg.Listeners.OnHeaders(p, msg)
			}

		case *wire.MsgNotFound:
			if p.cfg.Listeners.OnNotFound != nil {
				p.cfg.Listeners.OnNotFound(p, msg)
			}

		case *wire.MsgGetData:
			if p.cfg.Listeners.OnGetData != nil {
				p.cfg.Listeners.OnGetData(p, msg)
			}

		case *wire.MsgGetBlocks:
			if p.cfg.Listeners.OnGetBlocks != nil {
				p.cfg.Listeners.OnGetBlocks(p, msg)
			}

		case *wire.MsgGetHeaders:
			if p.cfg.Listeners.OnGetHeaders != nil {
				p.cfg.Listeners.OnGetHeaders(p, msg)
			}

		case *wire.MsgGetCFilters:
			if p.cfg.Listeners.OnGetCFilters != nil {
				p.cfg.Listeners.OnGetCFilters(p, msg)
			}

		case *wire.MsgGetCFHeaders:
			if p.cfg.Listeners.OnGetCFHeaders != nil {
				p.cfg.Listeners.OnGetCFHeaders(p, msg)
			}

		case *wire.MsgGetCFCheckpt:
			if p.cfg.Listeners.OnGetCFCheckpt != nil {
				p.cfg.Listeners.OnGetCFCheckpt(p, msg)
			}

		case *wire.MsgCFilter:
			if p.cfg.Listeners.OnCFilter != nil {
				p.cfg.Listeners.OnCFilter(p, msg)
			}

		case *wire.MsgCFHeaders:
			if p.cfg.Listeners.OnCFHeaders != nil {
				p.cfg.Listeners.OnCFHeaders(p, msg)
			}

		case *wire.MsgFeeFilter:
			if p.cfg.Listeners.OnFeeFilter != nil {
				p.cfg.Listeners.OnFeeFilter(p, msg)
			}

		case *wire.MsgFilterAdd:
			if p.cfg.Listeners.OnFilterAdd != nil {
				p.cfg.Listeners.OnFilterAdd(p, msg)
			}

		case *wire.MsgFilterClear:
			if p.cfg.Listeners.OnFilterClear != nil {
				p.cfg.Listeners.OnFilterClear(p, msg)
			}

		case *wire.MsgFilterLoad:
			if p.cfg.Listeners.OnFilterLoad != nil {
				p.cfg.Listeners.OnFilterLoad(p, msg)
			}

		case *wire.MsgMerkleBlock:
			if p.cfg.Listeners.OnMerkleBlock != nil {
				p.cfg.Listeners.OnMerkleBlock(p, msg)
			}

		case *wire.MsgReject:
			if p.cfg.Listeners.OnReject != nil {
				p.cfg.Listeners.OnReject(p, msg)
			}

		case *wire.MsgSendHeaders:
			p.flagsMtx.Lock()
			p.sendHeadersPreferred = true
			p.flagsMtx.Unlock()

			if p.cfg.Listeners.OnSendHeaders != nil {
				p.cfg.Listeners.OnSendHeaders(p, msg)
			}

		default:
			log.Debugf("Received unhandled message of type %v "+
				"from %v", rmsg.Command(), p)
		}
		p.stallControl <- stallControlMsg{sccHandlerDone, rmsg}

		// A message was received so reset the idle timer.
		idleTimer.Reset(idleTimeout)
	}

	// Ensure the idle timer is stopped to avoid leaking the resource.
	idleTimer.Stop()

	// Ensure connection is closed.
	p.Disconnect()

	close(p.inQuit)
	log.Tracef("Peer input handler done for %s", p)
}

// queueHandler handles the queuing of outgoing data for the peer. This runs as
// a muxer for various sources of input so we can ensure that server and peer
// handlers will not block on us sending a message.  That data is then passed on
// to outHandler to be actually written.
// queueHandler处理节点的传出数据的排队。 它作为各种输入源的复用器运行，
// 因此我们可以确保服务器和节点处理程序不会阻止我们发送消息。
// 然后将该数据传递给outHandler以实际写入。

// 需要发送的报文需由queueHandler处理后发送至其他节点
func (p *Peer) queueHandler() {
	pendingMsgs := list.New()
	invSendQueue := list.New()
	trickleTicker := time.NewTicker(p.cfg.TrickleInterval)
	defer trickleTicker.Stop()

	// We keep the waiting flag so that we know if we have a message queued
	// to the outHandler or not.  We could use the presence of a head of
	// the list for this but then we have rather racy concerns about whether
	// it has gotten it at cleanup time - and thus who sends on the
	// message's done channel.  To avoid such confusion we keep a different
	// flag and pendingMsgs only contains messages that we have not yet
	// passed to outHandler.
	//我们保留等待标志，以便我们知道是否有一个排队到outHandler的消息。
	// 我们可以使用列表头部的存在，但后来我们对它是否已经在清理时间得到它有相当的关注
	// - 因此谁发送了消息的完成通道。
	// 为了避免这种混淆，我们保留一个不同的标志，
	// pendingMsgs只包含我们尚未传递给outHandler的消息。
	waiting := false

	// To avoid duplication below.
	queuePacket := func(msg outMsg, list *list.List, waiting bool) bool {
		if !waiting {
			p.sendQueue <- msg
		} else {
			list.PushBack(msg)
		}
		// we are always waiting now.
		return true
	}
out:
	for {
		select {
		case msg := <-p.outputQueue:
			waiting = queuePacket(msg, pendingMsgs, waiting)

		// This channel is notified when a message has been sent across
		// the network socket.
		case <-p.sendDoneQueue:
			// No longer waiting if there are no more messages
			// in the pending messages queue.
			next := pendingMsgs.Front()
			if next == nil {
				waiting = false
				continue
			}

			// Notify the outHandler about the next item to
			// asynchronously send.
			val := pendingMsgs.Remove(next)
			p.sendQueue <- val.(outMsg)

		case iv := <-p.outputInvChan:
			// No handshake?  They'll find out soon enough.
			if p.VersionKnown() {
				// If this is a new block, then we'll blast it
				// out immediately, sipping the inv trickle
				// queue.
				if iv.Type == wire.InvTypeBlock ||
					iv.Type == wire.InvTypeWitnessBlock {

					invMsg := wire.NewMsgInvSizeHint(1)
					invMsg.AddInvVect(iv)
					waiting = queuePacket(outMsg{msg: invMsg},
						pendingMsgs, waiting)
				} else {
					invSendQueue.PushBack(iv)
				}
			}

		case <-trickleTicker.C:
			// Don't send anything if we're disconnecting or there
			// is no queued inventory.
			// version is known if send queue has any entries.
			if atomic.LoadInt32(&p.disconnect) != 0 ||
				invSendQueue.Len() == 0 {
				continue
			}

			// Create and send as many inv messages as needed to
			// drain the inventory send queue.
			invMsg := wire.NewMsgInvSizeHint(uint(invSendQueue.Len()))
			for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
				iv := invSendQueue.Remove(e).(*wire.InvVect)

				// Don't send inventory that became known after
				// the initial check.
				if p.knownInventory.Exists(iv) {
					continue
				}

				invMsg.AddInvVect(iv)
				if len(invMsg.InvList) >= maxInvTrickleSize {
					waiting = queuePacket(
						outMsg{msg: invMsg},
						pendingMsgs, waiting)
					invMsg = wire.NewMsgInvSizeHint(uint(invSendQueue.Len()))
				}

				// Add the inventory that is being relayed to
				// the known inventory for the peer.
				p.AddKnownInventory(iv)
			}
			if len(invMsg.InvList) > 0 {
				waiting = queuePacket(outMsg{msg: invMsg},
					pendingMsgs, waiting)
			}

		case <-p.quit:
			break out
		}
	}

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us.
	for e := pendingMsgs.Front(); e != nil; e = pendingMsgs.Front() {
		val := pendingMsgs.Remove(e)
		msg := val.(outMsg)
		if msg.doneChan != nil {
			msg.doneChan <- struct{}{}
		}
	}
cleanup:
	for {
		select {
		case msg := <-p.outputQueue:
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
		case <-p.outputInvChan:
			// Just drain channel
		// sendDoneQueue is buffered so doesn't need draining.
		default:
			break cleanup
		}
	}
	close(p.queueQuit)
	log.Tracef("Peer queue handler done for %s", p)
}

// shouldLogWriteError returns whether or not the passed error, which is
// expected to have come from writing to the remote peer in the outHandler,
// should be logged.
// shouldLogWriteError返回是否应记录传递的错误，
// 该错误应该是从写入outHandler中的远程节点获得的。
func (p *Peer) shouldLogWriteError(err error) bool {
	// No logging when the peer is being forcibly disconnected.
	//强制断开节点时没有记录。
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging when the remote peer has been disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// outHandler handles all outgoing messages for the peer.  It must be run as a
// goroutine.  It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
// outHandler处理节点的所有传出消息。 它必须作为协程运行。
// 它使用缓冲通道来序列化输出消息，同时允许发送器以异步方式继续运行。

//发送报文
func (p *Peer) outHandler() {
out:
	for {
		select {
		case msg := <-p.sendQueue:
			switch m := msg.msg.(type) {
			case *wire.MsgPing:
				// Only expects a pong message in later protocol
				// versions.  Also set up statistics.
				if p.ProtocolVersion() > wire.BIP0031Version {
					p.statsMtx.Lock()
					p.lastPingNonce = m.Nonce
					p.lastPingTime = time.Now()
					p.statsMtx.Unlock()
				}
			}

			p.stallControl <- stallControlMsg{sccSendMessage, msg.msg}

			err := p.writeMessage(msg.msg, msg.encoding)
			if err != nil {
				p.Disconnect()
				if p.shouldLogWriteError(err) {
					log.Errorf("Failed to send message to "+
						"%s: %v", p, err)
				}
				if msg.doneChan != nil {
					msg.doneChan <- struct{}{}
				}
				continue
			}

			// At this point, the message was successfully sent, so
			// update the last send time, signal the sender of the
			// message that it has been sent (if requested), and
			// signal the send queue to the deliver the next queued
			// message.
			atomic.StoreInt64(&p.lastSend, time.Now().Unix())
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			p.sendDoneQueue <- struct{}{}

		case <-p.quit:
			break out
		}
	}

	<-p.queueQuit

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us. We have waited on queueQuit and thus we can be sure
	// that we will not miss anything sent on sendQueue.
cleanup:
	for {
		select {
		case msg := <-p.sendQueue:
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			// no need to send on sendDoneQueue since queueHandler
			// has been waited on and already exited.
		default:
			break cleanup
		}
	}
	close(p.outQuit)
	log.Tracef("Peer output handler done for %s", p)
}

// pingHandler periodically pings the peer.  It must be run as a goroutine.
// pingHandler定期ping节点。 它必须作为协程运行。
// 心跳检测
func (p *Peer) pingHandler() {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

out:
	for {
		select {
		case <-pingTicker.C:
			nonce, err := wire.RandomUint64()
			if err != nil {
				log.Errorf("Not sending ping to %s: %v", p, err)
				continue
			}
			p.QueueMessage(wire.NewMsgPing(nonce), nil)

		case <-p.quit:
			break out
		}
	}
}

// QueueMessage adds the passed bitcoin message to the peer send queue.
//
// This function is safe for concurrent access.
// QueueMessage将传递的比特币消息添加到节点发送队列。
//
//此函数对于并发访问是安全的。
func (p *Peer) QueueMessage(msg wire.Message, doneChan chan<- struct{}) {
	p.QueueMessageWithEncoding(msg, doneChan, wire.BaseEncoding)
}

// QueueMessageWithEncoding adds the passed bitcoin message to the peer send
// queue. This function is identical to QueueMessage, however it allows the
// caller to specify the wire encoding type that should be used when
// encoding/decoding blocks and transactions.
//
// This function is safe for concurrent access.
// QueueMessageWithEncoding将传递的比特币消息添加到节点发送队列。
// 此函数与QueueMessage相同，但它允许调用者指定在编码/解码块和事务时应使用的线编码类型。
//
//此函数对于并发访问是安全的。
func (p *Peer) QueueMessageWithEncoding(msg wire.Message, doneChan chan<- struct{},
	encoding wire.MessageEncoding) {

	// Avoid risk of deadlock if goroutine already exited.  The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected and *then* it drains the channels.
	//如果goroutine已经退出，请避免死锁的风险。 我们将发送的goroutine挂起，
	//直到它知道它被标记为断开连接然后*然后*它消耗通道。
	if !p.Connected() {
		if doneChan != nil {
			go func() {
				doneChan <- struct{}{}
			}()
		}
		return
	}
	p.outputQueue <- outMsg{msg: msg, encoding: encoding, doneChan: doneChan}
}

// QueueInventory adds the passed inventory to the inventory send queue which
// might not be sent right away, rather it is trickled to the peer in batches.
// Inventory that the peer is already known to have is ignored.
//
// This function is safe for concurrent access.
// QueueInventory将传递的库存添加到库存发送队列中，该库存可能不会立即发送，而是分批流向同级。
//忽略节点已知的库存。
//
//此函数对于并发访问是安全的。
func (p *Peer) QueueInventory(invVect *wire.InvVect) {
	// Don't add the inventory to the send queue if the peer is already
	// known to have it.
	//如果节点已经存在，请不要将库存添加到发送队列
	//知道拥有它
	if p.knownInventory.Exists(invVect) {
		return
	}

	// Avoid risk of deadlock if goroutine already exited.  The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected and *then* it drains the channels.
	if !p.Connected() {
		return
	}

	p.outputInvChan <- invVect
}

// Connected returns whether or not the peer is currently connected.
//
// This function is safe for concurrent access.
// Connected返回节点当前是否已连接。
//
//此函数对于并发访问是安全的。
func (p *Peer) Connected() bool {
	return atomic.LoadInt32(&p.connected) != 0 &&
		atomic.LoadInt32(&p.disconnect) == 0
}

// Disconnect disconnects the peer by closing the connection.  Calling this
// function when the peer is already disconnected or in the process of
// disconnecting will have no effect.
// Disconnect通过关闭连接来断开节点的连接。 在节点已经断开连接或正在进行的过程中调用此函数
//断开连接将无效。
func (p *Peer) Disconnect() {
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	log.Tracef("Disconnecting %s", p)
	if atomic.LoadInt32(&p.connected) != 0 {
		p.conn.Close()
	}
	close(p.quit)
}

// readRemoteVersionMsg waits for the next message to arrive from the remote
// peer.  If the next message is not a version message or the version is not
// acceptable then return an error.
// readRemoteVersionMsg等待从远程节点到达的下一条消息。
// 如果下一条消息不是版本消息或版本不可接受，则返回错误。
func (p *Peer) readRemoteVersionMsg() error {
	
	log.Infof("start readRemoteVersionMsg  %s", p)

	// Read their version message.
	remoteMsg, _, err := p.readMessage(wire.LatestEncoding)
	if err != nil {
		log.Infof("remoteMsg err %s", p)

		return err
	}

	// Notify and disconnect clients if the first message is not a version
	// message.
	msg, ok := remoteMsg.(*wire.MsgVersion)
	if !ok {
		reason := "a version message must precede all others"
		rejectMsg := wire.NewMsgReject(msg.Command(), wire.RejectMalformed,
			reason)
		_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
		return errors.New(reason)
	}
	log.Infof("start readRemoteVersionMsg a %s", p)
	// Detect self connections.
	if !allowSelfConns && sentNonces.Exists(msg.Nonce) {
		return errors.New("disconnecting peer connected to self")
	}

	// Negotiate the protocol version and set the services to what the remote
	// peer advertised.
	p.flagsMtx.Lock()
	p.advertisedProtoVer = uint32(msg.ProtocolVersion)
	p.protocolVersion = minUint32(p.protocolVersion, p.advertisedProtoVer)
	p.versionKnown = true
	p.services = msg.Services
	p.flagsMtx.Unlock()
	log.Debugf("Negotiated protocol version %d for peer %s",
		p.protocolVersion, p)

	log.Infof("start readRemoteVersionMsg b %s", p)

	// Updating a bunch of stats including block based stats, and the
	// peer's time offset.
	p.statsMtx.Lock()
	p.lastBlock = msg.LastBlock
	p.startingHeight = msg.LastBlock
	p.timeOffset = msg.Timestamp.Unix() - time.Now().Unix()
	p.statsMtx.Unlock()

	// Set the peer's ID, user agent, and potentially the flag which
	// specifies the witness support is enabled.
	p.flagsMtx.Lock()
	p.id = atomic.AddInt32(&nodeCount, 1)
	p.userAgent = msg.UserAgent

	// Determine if the peer would like to receive witness data with
	// transactions, or not.
	if p.services&wire.SFNodeWitness == wire.SFNodeWitness {
		p.witnessEnabled = true
	}
	p.flagsMtx.Unlock()

	// Once the version message has been exchanged, we're able to determine
	// if this peer knows how to encode witness data over the wire
	// protocol. If so, then we'll switch to a decoding mode which is
	// prepared for the new transaction format introduced as part of
	// BIP0144.
	if p.services&wire.SFNodeWitness == wire.SFNodeWitness {
		p.wireEncoding = wire.WitnessEncoding
	}

	// Invoke the callback if specified.
	if p.cfg.Listeners.OnVersion != nil {
		rejectMsg := p.cfg.Listeners.OnVersion(p, msg)
		if rejectMsg != nil {
			_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
			return errors.New(rejectMsg.Reason)
		}
	}

	log.Infof("start readRemoteVersionMsg c %s", p)

	// Notify and disconnect clients that have a protocol version that is
	// too old.
	//
	// NOTE: If minAcceptableProtocolVersion is raised to be higher than
	// wire.RejectVersion, this should send a reject packet before
	// disconnecting.
	if uint32(msg.ProtocolVersion) < MinAcceptableProtocolVersion {
		// Send a reject message indicating the protocol version is
		// obsolete and wait for the message to be sent before
		// disconnecting.
		reason := fmt.Sprintf("protocol version must be %d or greater",
			MinAcceptableProtocolVersion)
		rejectMsg := wire.NewMsgReject(msg.Command(), wire.RejectObsolete,
			reason)
		_ = p.writeMessage(rejectMsg, wire.LatestEncoding)
		return errors.New(reason)
	}

	return nil
}

// localVersionMsg creates a version message that can be used to send to the
// remote peer.
// localVersionMsg创建可用于发送到远程节点的版本消息。
func (p *Peer) localVersionMsg() (*wire.MsgVersion, error) {
	var blockNum int32
	if p.cfg.NewestBlock != nil {
		var err error
		_, blockNum, err = p.cfg.NewestBlock()
		if err != nil {
			return nil, err
		}
	}

	theirNA := p.na

	// If we are behind a proxy and the connection comes from the proxy then
	// we return an unroutable address as their address. This is to prevent
	// leaking the tor proxy address.
	//如果我们在代理后面并且连接来自代理，那么我们返回一个不可路由的地址作为他们的地址。
	// 这是为了防止泄漏代理地址。
	if p.cfg.Proxy != "" {
		proxyaddress, _, err := net.SplitHostPort(p.cfg.Proxy)
		// invalid proxy means poorly configured, be on the safe side.
		//无效的代理意味着配置不当，是安全的。
		if err != nil || p.na.IP.String() == proxyaddress {
			theirNA = wire.NewNetAddressIPPort(net.IP([]byte{0, 0, 0, 0}), 0,
				theirNA.Services)
		}
	}

	// Create a wire.NetAddress with only the services set to use as the
	// "addrme" in the version message.
	//
	// Older nodes previously added the IP and port information to the
	// address manager which proved to be unreliable as an inbound
	// connection from a peer didn't necessarily mean the peer itself
	// accepted inbound connections.
	//
	// Also, the timestamp is unused in the version message.
	//创建一个wire.NetAddress，只设置用作版本消息中“addrme”的服务。
	//
	//较旧的节点先前已将IP和端口信息添加到地址管理器，这被证明是不可靠的，
	//因为来自节点的入站连接并不一定意味着节点本身接受入站连接。
	//
	//此外，版本消息中未使用时间戳。
	ourNA := &wire.NetAddress{
		Services: p.cfg.Services,
	}

	// Generate a unique nonce for this peer so self connections can be
	// detected.  This is accomplished by adding it to a size-limited map of
	// recently seen nonces.
	// 为此节点生成唯一的随机数，以便可以检测到自身连接。
	// 这是通过将其添加到最近看到的随机数的大小有限的地图来实现的。
	nonce := uint64(rand.Int63())
	sentNonces.Add(nonce)

	//&{%!s(int32=70016) SFNodeNetwork|SFNodeBloom|SFNodeWitness|SFNodeCF 2018-12-21 14:50:15 +0800 CST {2018-12-21 14:50:15 +0800 CST 0x0 106.14.222.124 %!s(uint16=35677)} {0001-01-01 00:00:00 +0000 UTC SFNodeNetwork|SFNodeBloom|SFNodeWitness|SFNodeCF <nil> %!s(uint16=0)} %!s(uint64=4582433502102686919) /btcwire:0.5.0/btcd:0.12.0/ %!s(int32=0) %!s(bool=false)}
	// Version message.
	//版本消息
	msg := wire.NewMsgVersion(ourNA, theirNA, nonce, blockNum)
	msg.AddUserAgent(p.cfg.UserAgentName, p.cfg.UserAgentVersion,
		p.cfg.UserAgentComments...)

	// Advertise local services.
	//宣传本地服务
	//msg.Services = p.cfg.Services
	msg.LocalServices = 1

	// Advertise our max supported protocol version.
	//宣传我们最大支持的协议版本。
	msg.ProtocolVersion = int32(p.cfg.ProtocolVersion)

	// Advertise if inv messages for transactions are desired.
	//如果需要用于事务的inv消息，则发布广告。
	// -- by eac remove DisableRelayTx
	//msg.DisableRelayTx = p.cfg.DisableRelayTx

	return msg, nil
}

// writeLocalVersionMsg writes our version message to the remote peer.
// writeLocalVersionMsg将我们的版本消息写入远程节点。
func (p *Peer) writeLocalVersionMsg() error {
	localVerMsg, err := p.localVersionMsg()
	if err != nil {
		return err
	}

	log.Infof("start writeLocalVersionMsg %s", p)
	log.Infof("Msg %s", localVerMsg)

	return p.writeMessage(localVerMsg, wire.LatestEncoding)
}

// negotiateInboundProtocol waits to receive a version message from the peer
// then sends our version message. If the events do not occur in that order then
// it returns an error.
// negotiateInboundProtocol等待从节点接收版本消息然后发送我们的版本消息。
// 如果事件不按该顺序发生，则返回错误。
func (p *Peer) negotiateInboundProtocol() error {
	log.Infof("Starting negotiateInboundProtocol %s", p)
	if err := p.readRemoteVersionMsg(); err != nil {
		return err
	}

	return p.writeLocalVersionMsg()
}

// negotiateOutboundProtocol sends our version message then waits to receive a
// version message from the peer.  If the events do not occur in that order then
// it returns an error.
// negotiateOutboundProtocol发送我们的版本消息，然后等待从节点接收版本消息。
// 如果事件不按该顺序发生，则返回错误。
func (p *Peer) negotiateOutboundProtocol() error {
	log.Infof("Starting negotiateOutboundProtocol %s", p)
	if err := p.writeLocalVersionMsg(); err != nil {
		return err
	}

	return p.readRemoteVersionMsg()
}

// start begins processing input and output messages.
//start 处理输入和输出消息。
func (p *Peer) start() error {
	log.Tracef("Starting peer %s", p)

	log.Infof("Starting peer %s", p)

	negotiateErr := make(chan error, 1)
	go func() {
		if p.inbound {
			negotiateErr <- p.negotiateInboundProtocol()
		} else {
			negotiateErr <- p.negotiateOutboundProtocol()
		}
	}()

	// Negotiate the protocol within the specified negotiateTimeout.
	select {
	case err := <-negotiateErr:
		if err != nil {
			p.Disconnect()
			return err
		}
	case <-time.After(negotiateTimeout):
		p.Disconnect()
		return errors.New("protocol negotiation timeout")
	}
	log.Debugf("Connected to %s", p.Addr())

	// The protocol has been negotiated successfully so start processing input
	// and output messages.
	//协议已成功协商，因此开始处理输入和输出消息。

	go p.stallHandler()
	//接受其他节点发送的报文
	go p.inHandler()
	// 需要发送的报文需由queueHandler处理后发送至其他节点
	go p.queueHandler()
	//发送报文
	go p.outHandler()
	// 心跳检测
	go p.pingHandler()

	// Send our verack message now that the IO processing machinery has started.
	p.QueueMessage(wire.NewMsgVerAck(), nil)
	return nil
}

// AssociateConnection associates the given conn to the peer.   Calling this
// function when the peer is already connected will have no effect.
// AssociateConnection将给定的conn与节点关联。 当节点已经连接时调用此功能将不起作用。
func (p *Peer) AssociateConnection(conn net.Conn) {
	// Already connected?

	if !atomic.CompareAndSwapInt32(&p.connected, 0, 1) {
		return
	}

	p.conn = conn
	p.timeConnected = time.Now()

	if p.inbound {
		p.addr = p.conn.RemoteAddr().String()

		// Set up a NetAddress for the peer to be used with AddrManager.  We
		// only do this inbound because outbound set this up at connection time
		// and no point recomputing.
		na, err := newNetAddress(p.conn.RemoteAddr(), p.services)
		if err != nil {
			log.Errorf("Cannot create remote net address: %v", err)
			p.Disconnect()
			return
		}
		p.na = na
	}

	go func() {
		if err := p.start(); err != nil {
			log.Debugf("Cannot start peer %v: %v", p, err)
			p.Disconnect()
		}
	}()
}

// WaitForDisconnect waits until the peer has completely disconnected and all
// resources are cleaned up.  This will happen if either the local or remote
// side has been disconnected or the peer is forcibly disconnected via
// Disconnect.
// WaitForDisconnect等待，直到节点完全断开连接并清除所有资源。
// 如果本地或远程端已断开连接或通过断开连接强制断开节点端，则会发生这种情况。
func (p *Peer) WaitForDisconnect() {
	<-p.quit
}

// newPeerBase returns a new base bitcoin peer based on the inbound flag.  This
// is used by the NewInboundPeer and NewOutboundPeer functions to perform base
// setup needed by both types of peers.
// newPeerBase根据入站标志返回一个新的基本比特币节点。
// NewInboundPeer和NewOutboundPeer函数使用它来执行两种类型的节点所需的基本设置。
func newPeerBase(origCfg *Config, inbound bool) *Peer {
	// Default to the max supported protocol version if not specified by the
	// caller.
	//如果调用者未指定，则默认为支持的最大协议版本。
	cfg := *origCfg // Copy to avoid mutating caller.
	if cfg.ProtocolVersion == 0 {
		cfg.ProtocolVersion = MaxProtocolVersion
	}

	// Set the chain parameters to testnet if the caller did not specify any.
	if cfg.ChainParams == nil {
		cfg.ChainParams = &chaincfg.TestNet3Params
	}

	// Set the trickle interval if a non-positive value is specified.
	if cfg.TrickleInterval <= 0 {
		cfg.TrickleInterval = DefaultTrickleInterval
	}

	p := Peer{
		inbound:         inbound,
		wireEncoding:    wire.BaseEncoding,
		knownInventory:  newMruInventoryMap(maxKnownInventory),
		stallControl:    make(chan stallControlMsg, 1), // nonblocking sync
		outputQueue:     make(chan outMsg, outputBufferSize),
		sendQueue:       make(chan outMsg, 1),   // nonblocking sync
		sendDoneQueue:   make(chan struct{}, 1), // nonblocking sync
		outputInvChan:   make(chan *wire.InvVect, outputBufferSize),
		inQuit:          make(chan struct{}),
		queueQuit:       make(chan struct{}),
		outQuit:         make(chan struct{}),
		quit:            make(chan struct{}),
		cfg:             cfg, // Copy so caller can't mutate.
		services:        cfg.Services,
		protocolVersion: cfg.ProtocolVersion,
	}
	return &p
}

// NewInboundPeer returns a new inbound bitcoin peer. Use Start to begin
// processing incoming and outgoing messages.
// NewInboundPeer返回一个新的入站比特币节点。 使用“开始”开始处理传入和传出消息。
func NewInboundPeer(cfg *Config) *Peer {
	return newPeerBase(cfg, true)
}

// NewOutboundPeer returns a new outbound bitcoin peer.
// NewOutboundPeer返回一个新的出站比特币节点。
func NewOutboundPeer(cfg *Config, addr string) (*Peer, error) {
	p := newPeerBase(cfg, false)
	p.addr = addr

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	if cfg.HostToNetAddress != nil {
		na, err := cfg.HostToNetAddress(host, uint16(port), 0)
		if err != nil {
			return nil, err
		}
		p.na = na
	} else {
		p.na = wire.NewNetAddressIPPort(net.ParseIP(host), uint16(port), 0)
	}

	return p, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
