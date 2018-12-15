// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxFailedAttempts is the maximum number of successive failed connection
// attempts after which network failure is assumed and new connections will
// be delayed by the configured retry duration.
// maxFailedAttempts是连续失败的连接尝试的最大次数，之后将假定网络故障，
// 并且新连接将按配置的重试持续时间延迟。
const maxFailedAttempts = 25

var (
	//ErrDialNil is used to indicate that Dial cannot be nil in the configuration.
	// ErrDialNil用于指示Dial在配置中不能为零。
	ErrDialNil = errors.New("Config: Dial cannot be nil")

	// maxRetryDuration is the max duration of time retrying of a persistent
	// connection is allowed to grow to.  This is necessary since the retry
	// logic uses a backoff mechanism which increases the interval base times
	// the number of retries that have been done.
	// maxRetryDuration:最大重试持续时间,是允许重试持久连接的最长持续时间。
	// 这是必要的，因为重试逻辑使用退避机制，该机制将间隔基数乘以已完成的重试次数。
	maxRetryDuration = time.Minute * 5

	// defaultRetryDuration is the default duration of time for retrying
	// persistent connections.
	// defaultRetryDuration:默认重试持续时间,是重试持久连接的默认持续时间。
	defaultRetryDuration = time.Second * 5

	// defaultTargetOutbound is the default number of outbound connections to
	// maintain.
	// defaultTargetOutbound:默认目标出站,是要维护的默认出站连接数。
	defaultTargetOutbound = uint32(8)
)

// ConnState represents the state of the requested connection.
// ConnState表示请求的连接的状态。
type ConnState uint8

// ConnState can be either pending, established, disconnected or failed.  When
// a new connection is requested, it is attempted and categorized as
// established or failed depending on the connection result.  An established
// connection which was disconnected is categorized as disconnected.
// ConnState可以是挂起，已建立，已断开连接或已失败。
// 请求新连接时，会尝试将其分类为已建立或失败，具体取决于连接结果。
// 已建立的连接断开链接后，被分类为已断开连接。
const (
	ConnPending ConnState = iota //挂起
	ConnFailing                  //已失败
	ConnCanceled
	ConnEstablished  //已建立
	ConnDisconnected //已断开连接
)

// ConnReq is the connection request to a network address. If permanent, the
// connection will be retried on disconnection.
// ConnReq是对网络地址的连接请求。 如果是永久性的，则断开连接时将重试连接。
type ConnReq struct {
	// The following variables must only be used atomically.
	id uint64

	Addr      net.Addr
	Permanent bool

	conn       net.Conn
	state      ConnState
	stateMtx   sync.RWMutex
	retryCount uint32
}

// updateState updates the state of the connection request.
// updateState更新连接请求的状态。
func (c *ConnReq) updateState(state ConnState) {
	c.stateMtx.Lock()
	c.state = state
	c.stateMtx.Unlock()
}

// ID returns a unique identifier for the connection request.
// ID返回连接请求的唯一标识符。
func (c *ConnReq) ID() uint64 {
	return atomic.LoadUint64(&c.id)
}

// State is the connection state of the requested connection.
// State是请求连接的连接状态。
func (c *ConnReq) State() ConnState {
	c.stateMtx.RLock()
	state := c.state
	c.stateMtx.RUnlock()
	return state
}

// String returns a human-readable string for the connection request.
// String返回连接请求的可读字符串。
func (c *ConnReq) String() string {
	if c.Addr == nil || c.Addr.String() == "" {
		return fmt.Sprintf("reqid %d", atomic.LoadUint64(&c.id))
	}
	return fmt.Sprintf("%s (reqid %d)", c.Addr, atomic.LoadUint64(&c.id))
}

// Config holds the configuration options related to the connection manager.
// Config保存与连接管理器相关的配置选项。
// 定义连接管理器
// 作用：开启监听handleConnected与handleDisconnected服务
type Config struct {
	// Listeners defines a slice of listeners for which the connection
	// manager will take ownership of and accept connections.  When a
	// connection is accepted, the OnAccept handler will be invoked with the
	// connection.  Since the connection manager takes ownership of these
	// listeners, they will be closed when the connection manager is
	// stopped.
	//
	// This field will not have any effect if the OnAccept field is not
	// also specified.  It may be nil if the caller does not wish to listen
	// for incoming connections.
	// 监听器定义了一段监听器，连接管理器将为其获取所有权并接受连接。
	// 接受连接时，将使用连接调用OnAccept处理程序。
	// 由于连接管理器获取这些侦听器的所有权，因此在连接管理器停止时它们将被关闭。
	//
	//如果未指定OnAccept字段，此字段将不起作用。 如果呼叫者不希望收听传入连接，则可能为零。
	Listeners []net.Listener

	// OnAccept is a callback that is fired when an inbound connection is
	// accepted.  It is the caller's responsibility to close the connection.
	// Failure to close the connection will result in the connection manager
	// believing the connection is still active and thus have undesirable
	// side effects such as still counting toward maximum connection limits.
	//
	// This field will not have any effect if the Listeners field is not
	// also specified since there couldn't possibly be any accepted
	// connections in that case.
	// OnAccept是接受入站连接时触发的回调。
	// 呼叫者有责任关闭连接。未能关闭连接将导致连接管理器认为连接仍处于活动状态，
	// 从而产生不良副作用，例如仍然计入最大连接限制。
	//
	// 如果未指定Listeners字段，则此字段不会产生任何影响，因为在这种情况下可能没有任何已接受的连接。
	OnAccept func(net.Conn)

	// TargetOutbound is the number of outbound network connections to
	// maintain. Defaults to 8.
	// TargetOutbound是要维护的出站网络连接数。 默认为8。
	TargetOutbound uint32

	// RetryDuration is the duration to wait before retrying connection
	// requests. Defaults to 5s.
	// RetryDuration是重试连接请求之前等待的持续时间。 默认为5秒。
	RetryDuration time.Duration

	// OnConnection is a callback that is fired when a new outbound
	// connection is established.
	// OnConnection是在建立新的出站连接时触发的回调。
	OnConnection func(*ConnReq, net.Conn)

	// OnDisconnection is a callback that is fired when an outbound
	// connection is disconnected.
	// OnDisconnection是在出站连接断开时触发的回调。
	OnDisconnection func(*ConnReq)

	// GetNewAddress is a way to get an address to make a network connection
	// to.  If nil, no new connections will be made automatically.
	// GetNewAddress是一种获取地址以建立网络连接的方法。 如果为nil，则不会自动建立新连接。
	GetNewAddress func() (net.Addr, error)

	// Dial connects to the address on the named network. It cannot be nil.
	//拨号连接到指定网络上的地址。 它不能是零。
	Dial func(net.Addr) (net.Conn, error)
}

// registerPending is used to register a pending connection attempt. By
// registering pending connection attempts we allow callers to cancel pending
// connection attempts before their successful or in the case they're not
// longer wanted.
// registerPending:注册待定,用于注册挂起的连接尝试。
// 通过注册挂起的连接尝试，我们允许呼叫者在成功之前取消挂起的连接尝试，或者在他们不再需要的情况下取消。
type registerPending struct {
	c    *ConnReq
	done chan struct{}
}

// handleConnected is used to queue a successful connection.
// handleConnected用于对成功连接进行排队。
type handleConnected struct {
	c    *ConnReq
	conn net.Conn
}

// handleDisconnected is used to remove a connection.
// handleDisconnected用于删除连接。
type handleDisconnected struct {
	id    uint64
	retry bool
}

// handleFailed is used to remove a pending connection.
// handleFailed用于删除挂起的连接。
type handleFailed struct {
	c   *ConnReq
	err error
}

// ConnManager provides a manager to handle network connections.
// ConnManager提供管理器来处理网络连接。
type ConnManager struct {
	// The following variables must only be used atomically.
	//以下变量只能以原子方式使用。
	connReqCount uint64
	start        int32
	stop         int32

	cfg            Config
	wg             sync.WaitGroup
	failedAttempts uint64
	requests       chan interface{}
	quit           chan struct{}
}

// handleFailedConn handles a connection failed due to a disconnect or any
// other failure. If permanent, it retries the connection after the configured
// retry duration. Otherwise, if required, it makes a new connection request.
// After maxFailedConnectionAttempts new connections will be retried after the
// configured retry duration.
// handleFailedConn:处理失败连接，处理因断开连接或任何其他故障而失败的连接。
// 如果是永久性的，则在配置的重试持续时间后重试连接。 否则，如果需要，它会发出新的连接请求。
// 在maxFailedConnectionAttempts之后，将在配置的重试持续时间后重试新连接。
func (cm *ConnManager) handleFailedConn(c *ConnReq) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}
	if c.Permanent {
		c.retryCount++
		d := time.Duration(c.retryCount) * cm.cfg.RetryDuration
		if d > maxRetryDuration {
			d = maxRetryDuration
		}
		log.Debugf("Retrying connection to %v in %v", c, d)
		time.AfterFunc(d, func() {
			cm.Connect(c)
		})
	} else if cm.cfg.GetNewAddress != nil {
		cm.failedAttempts++
		if cm.failedAttempts >= maxFailedAttempts {
			log.Debugf("Max failed connection attempts reached: [%d] "+
				"-- retrying connection in: %v", maxFailedAttempts,
				cm.cfg.RetryDuration)
			time.AfterFunc(cm.cfg.RetryDuration, func() {
				cm.NewConnReq()
			})
		} else {
			go cm.NewConnReq()
		}
	}
}

// connHandler handles all connection related requests.  It must be run as a
// goroutine.
//
// The connection handler makes sure that we maintain a pool of active outbound
// connections so that we remain connected to the network.  Connection requests
// are processed and mapped by their assigned ids.
// connHandler处理所有与连接相关的请求。 它必须作为协程运行。
//
// 连接处理程序确保我们维护一个活动的出站连接池，以便我们保持连接到网络。
// 连接请求由其分配的ID进行处理和映射。
func (cm *ConnManager) connHandler() {

	var (
		// pending holds all registered conn requests that have yet to
		// succeed.
		pending = make(map[uint64]*ConnReq)

		// conns represents the set of all actively connected peers.
		conns = make(map[uint64]*ConnReq, cm.cfg.TargetOutbound)
	)

out:
	for {
		select {
		case req := <-cm.requests:
			switch msg := req.(type) {

			case registerPending:
				connReq := msg.c
				connReq.updateState(ConnPending)
				pending[msg.c.id] = connReq
				close(msg.done)

			case handleConnected:
				connReq := msg.c

				if _, ok := pending[connReq.id]; !ok {
					if msg.conn != nil {
						msg.conn.Close()
					}
					log.Debugf("Ignoring connection for "+
						"canceled connreq=%v", connReq)
					continue
				}

				connReq.updateState(ConnEstablished)
				connReq.conn = msg.conn
				conns[connReq.id] = connReq
				log.Debugf("Connected to %v", connReq)
				connReq.retryCount = 0
				cm.failedAttempts = 0

				delete(pending, connReq.id)

				if cm.cfg.OnConnection != nil {
					go cm.cfg.OnConnection(connReq, msg.conn)
				}

			case handleDisconnected:
				connReq, ok := conns[msg.id]
				if !ok {
					connReq, ok = pending[msg.id]
					if !ok {
						log.Errorf("Unknown connid=%d",
							msg.id)
						continue
					}

					// Pending connection was found, remove
					// it from pending map if we should
					// ignore a later, successful
					// connection.
					connReq.updateState(ConnCanceled)
					log.Debugf("Canceling: %v", connReq)
					delete(pending, msg.id)
					continue

				}

				// An existing connection was located, mark as
				// disconnected and execute disconnection
				// callback.
				log.Debugf("Disconnected from %v", connReq)
				delete(conns, msg.id)

				if connReq.conn != nil {
					connReq.conn.Close()
				}

				if cm.cfg.OnDisconnection != nil {
					go cm.cfg.OnDisconnection(connReq)
				}

				// All internal state has been cleaned up, if
				// this connection is being removed, we will
				// make no further attempts with this request.
				if !msg.retry {
					connReq.updateState(ConnDisconnected)
					continue
				}

				// Otherwise, we will attempt a reconnection if
				// we do not have enough peers, or if this is a
				// persistent peer. The connection request is
				// re added to the pending map, so that
				// subsequent processing of connections and
				// failures do not ignore the request.
				if uint32(len(conns)) < cm.cfg.TargetOutbound ||
					connReq.Permanent {

					connReq.updateState(ConnPending)
					log.Debugf("Reconnecting to %v",
						connReq)
					pending[msg.id] = connReq
					cm.handleFailedConn(connReq)
				}

			case handleFailed:
				connReq := msg.c

				if _, ok := pending[connReq.id]; !ok {
					log.Debugf("Ignoring connection for "+
						"canceled conn req: %v", connReq)
					continue
				}

				connReq.updateState(ConnFailing)
				log.Debugf("Failed to connect to %v: %v",
					connReq, msg.err)
				cm.handleFailedConn(connReq)
			}

		case <-cm.quit:
			break out
		}
	}

	cm.wg.Done()
	log.Trace("Connection handler done")
}

// NewConnReq creates a new connection request and connects to the
// corresponding address.
// NewConnReq创建一个新的连接请求并连接到相应的地址。
// 调用地址管理获取一个ip，并连接。如果连接成功，调用  handleConnected服务；
// 如果连接失败，调用handleDisconnected服务。
func (cm *ConnManager) NewConnReq() {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}
	if cm.cfg.GetNewAddress == nil {
		return
	}

	c := &ConnReq{}
	atomic.StoreUint64(&c.id, atomic.AddUint64(&cm.connReqCount, 1))

	// Submit a request of a pending connection attempt to the connection
	// manager. By registering the id before the connection is even
	// established, we'll be able to later cancel the connection via the
	// Remove method.
	done := make(chan struct{})
	select {
	case cm.requests <- registerPending{c, done}:
	case <-cm.quit:
		return
	}

	// Wait for the registration to successfully add the pending conn req to
	// the conn manager's internal state.
	select {
	case <-done:
	case <-cm.quit:
		return
	}

	addr, err := cm.cfg.GetNewAddress()
	if err != nil {
		select {
		case cm.requests <- handleFailed{c, err}:
		case <-cm.quit:
		}
		return
	}

	c.Addr = addr

	cm.Connect(c)
}

// Connect assigns an id and dials a connection to the address of the
// connection request.
// Connect分配一个id并拨打连接到连接请求的地址。
// 根据链接结果调用handleConnected或handleDisconnected服务。
// 当调用handleConnected时，服务调用OnConnection函数，开辟协程处理Peer服务。
func (cm *ConnManager) Connect(c *ConnReq) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}
	if atomic.LoadUint64(&c.id) == 0 {
		atomic.StoreUint64(&c.id, atomic.AddUint64(&cm.connReqCount, 1))

		// Submit a request of a pending connection attempt to the
		// connection manager. By registering the id before the
		// connection is even established, we'll be able to later
		// cancel the connection via the Remove method.
		done := make(chan struct{})
		select {
		case cm.requests <- registerPending{c, done}:
		case <-cm.quit:
			return
		}

		// Wait for the registration to successfully add the pending
		// conn req to the conn manager's internal state.
		select {
		case <-done:
		case <-cm.quit:
			return
		}
	}

	log.Debugf("Attempting to connect to %v", c)

	conn, err := cm.cfg.Dial(c.Addr)
	if err != nil {
		select {
		case cm.requests <- handleFailed{c, err}:
		case <-cm.quit:
		}
		return
	}

	select {
	case cm.requests <- handleConnected{c, conn}:
	case <-cm.quit:
	}
}

// Disconnect disconnects the connection corresponding to the given connection
// id. If permanent, the connection will be retried with an increasing backoff
// duration.
// 断开连接断开与给定连接ID对应的连接。 如果是永久性的，则将以增加的退避持续时间重试连接。
// 调用handleDisconnected服务
func (cm *ConnManager) Disconnect(id uint64) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}

	select {
	case cm.requests <- handleDisconnected{id, true}:
	case <-cm.quit:
	}
}

// Remove removes the connection corresponding to the given connection id from
// known connections.
//
// NOTE: This method can also be used to cancel a lingering connection attempt
// that hasn't yet succeeded.
// Remove从已知连接中删除与给定连接ID对应的连接。
//
// 注意：此方法还可用于取消尚未成功的延迟连接尝试。
func (cm *ConnManager) Remove(id uint64) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}

	select {
	case cm.requests <- handleDisconnected{id, false}:
	case <-cm.quit:
	}
}

// listenHandler accepts incoming connections on a given listener.  It must be
// run as a goroutine.
// listenHandler接受给定侦听器上的传入连接。 它必须作为协程运行。
func (cm *ConnManager) listenHandler(listener net.Listener) {
	log.Infof("Server listening on %s", listener.Addr())
	for atomic.LoadInt32(&cm.stop) == 0 {
		conn, err := listener.Accept()
		if err != nil {
			// Only log the error if not forcibly shutting down.
			if atomic.LoadInt32(&cm.stop) == 0 {
				log.Errorf("Can't accept connection: %v", err)
			}
			continue
		}
		go cm.cfg.OnAccept(conn)
	}

	cm.wg.Done()
	log.Tracef("Listener handler done for %s", listener.Addr())
}

// Start launches the connection manager and begins connecting to the network.
//Start启动连接管理器并开始连接到网络。
func (cm *ConnManager) Start() {
	// Already started?
	if atomic.AddInt32(&cm.start, 1) != 1 {
		return
	}

	log.Trace("Connection manager started")
	cm.wg.Add(1)
	go cm.connHandler()

	// Start all the listeners so long as the caller requested them and
	// provided a callback to be invoked when connections are accepted.
	if cm.cfg.OnAccept != nil {
		for _, listner := range cm.cfg.Listeners {
			cm.wg.Add(1)
			go cm.listenHandler(listner)
		}
	}

	for i := atomic.LoadUint64(&cm.connReqCount); i < uint64(cm.cfg.TargetOutbound); i++ {
		go cm.NewConnReq()
	}
}

// Wait blocks until the connection manager halts gracefully.
//Wait：阻塞，直到连接管理器正常停止。
func (cm *ConnManager) Wait() {
	cm.wg.Wait()
}

// Stop gracefully shuts down the connection manager.
//Stop ： 正常地关闭连接管理器。
func (cm *ConnManager) Stop() {
	if atomic.AddInt32(&cm.stop, 1) != 1 {
		log.Warnf("Connection manager already stopped")
		return
	}

	// Stop all the listeners.  There will not be any listeners if
	// listening is disabled.
	for _, listener := range cm.cfg.Listeners {
		// Ignore the error since this is shutdown and there is no way
		// to recover anyways.
		_ = listener.Close()
	}

	close(cm.quit)
	log.Trace("Connection manager stopped")
}

// New returns a new connection manager.
// Use Start to start connecting to the network.
// New返回一个新的连接管理器。
// 使用“Start”开始连接到网络。
func New(cfg *Config) (*ConnManager, error) {
	if cfg.Dial == nil {
		return nil, ErrDialNil
	}
	// Default to sane values
	if cfg.RetryDuration <= 0 {
		cfg.RetryDuration = defaultRetryDuration
	}
	if cfg.TargetOutbound == 0 {
		cfg.TargetOutbound = defaultTargetOutbound
	}
	cm := ConnManager{
		cfg:      *cfg, // Copy so caller can't mutate
		requests: make(chan interface{}),
		quit:     make(chan struct{}),
	}
	return &cm, nil
}
