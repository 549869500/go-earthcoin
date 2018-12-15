// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"container/list"
	crand "crypto/rand" // for seeding
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// AddrManager provides a concurrency safe address manager for caching potential
// peers on the bitcoin network.
// 定义地址管理器
// AddrManager提供了一个并发安全地址管理器，用于缓存比特币网络上的潜在节点。
// 作用：定时将节点连接信息保存至文件
type AddrManager struct {
	mtx            sync.Mutex
	peersFile      string //保存在文件中的连接节点信息
	lookupFunc     func(string) ([]net.IP, error)
	rand           *rand.Rand
	key            [32]byte
	addrIndex      map[string]*KnownAddress                 // addrNew 与 addrTried地址集合 address key to ka for all addrs.
	addrNew        [newBucketCount]map[string]*KnownAddress //map[桶树编号][地址map集合]，未被确定可连接的集合
	addrTried      [triedBucketCount]*list.List             //连接成功集合
	started        int32
	shutdown       int32
	wg             sync.WaitGroup
	quit           chan struct{}
	nTried         int //addrTried大小
	nNew           int //addrNew大小
	lamtx          sync.Mutex
	localAddresses map[string]*localAddress
}

//定义序列化已知地址
type serializedKnownAddress struct {
	Addr        string
	Src         string
	Attempts    int //连接次数
	TimeStamp   int64
	LastAttempt int64 // 最后一次连接时间
	LastSuccess int64 // 最后一次成功连接时间
	// no refcount or tried, that is available from context.
	//没有引用或尝试，可以从上下文中获得。
}

type serializedAddrManager struct {
	Version      int
	Key          [32]byte
	Addresses    []*serializedKnownAddress
	NewBuckets   [newBucketCount][]string // string is NetAddressKey
	TriedBuckets [triedBucketCount][]string
}

type localAddress struct {
	na    *wire.NetAddress
	score AddressPriority
}

// AddressPriority type is used to describe the hierarchy of local address
// discovery methods.
// AddressPriority:地址优先级
// AddressPriority类型用于描述本地地址发现方法的层次结构。
type AddressPriority int

const (
	// InterfacePrio signifies the address is on a local interface
	// InterfacePrio：接口优先级，表示地址在本地接口上
	InterfacePrio AddressPriority = iota

	// BoundPrio signifies the address has been explicitly bounded to.
	// BoundPrio:绑定优先级，表示地址已明确限制。
	BoundPrio

	// UpnpPrio signifies the address was obtained from UPnP.
	// UpnpPrio：Upnp优先级，表示该地址是从UPnP获得的。
	UpnpPrio

	// HTTPPrio signifies the address was obtained from an external HTTP service.
	// HTTPPrio：HTTP优先级，表示该地址是从外部HTTP服务获取的。
	HTTPPrio

	// ManualPrio signifies the address was provided by --externalip.
	// ManualPrio：Manual优先级，表示地址由--externalip提供。
	ManualPrio
)

const (
	// needAddressThreshold is the number of addresses under which the
	// address manager will claim to need more addresses.
	// needAddressThreshold：需要地址阈值，是地址管理器声称需要更多地址的地址数。
	needAddressThreshold = 1000

	// dumpAddressInterval is the interval used to dump the address
	// cache to disk for future use.
	// dumpAddressInterval：转储地址间隔，是用于将地址缓存转储到磁盘以供将来使用的时间间隔。
	dumpAddressInterval = time.Minute * 10

	// triedBucketSize is the maximum number of addresses in each
	// tried address bucket.
	// triesBucketSize：尝试地址存储桶最大值，是每个尝试过的地址存储桶中的最大地址数。
	triedBucketSize = 256

	// triedBucketCount is the number of buckets we split tried
	// addresses over.
	// triesBucketCount：尝试地址存储桶统计，是我们拆分尝试地址的存储桶数量。
	triedBucketCount = 64

	// newBucketSize is the maximum number of addresses in each new address
	// bucket.
	// newBucketSize是每个新地址存储桶中的最大地址数。
	newBucketSize = 64

	// newBucketCount is the number of buckets that we spread new addresses
	// over.
	// newBucketCount是我们传播新地址的存储桶数量。
	newBucketCount = 1024

	// triedBucketsPerGroup is the number of tried buckets over which an
	// address group will be spread.
	// triesBucketsPerGroup是一个地址组将在其上传播的已尝试存储桶的数量。
	triedBucketsPerGroup = 8

	// newBucketsPerGroup is the number of new buckets over which an
	// source address group will be spread.
	// newBucketsPerGroup是源地址组将在其上传播的新存储桶的数量。
	newBucketsPerGroup = 64

	// newBucketsPerAddress is the number of buckets a frequently seen new
	// address may end up in.
	// newBucketsPerAddress是经常看到的新地址最终可能出现的存储桶数量。
	newBucketsPerAddress = 8

	// numMissingDays is the number of days before which we assume an
	// address has vanished if we have not seen it announced  in that long.
	// numMissingDays是我们假设地址已经消失的天数，如果我们在那么长时间内没有看到它被声明的话。
	numMissingDays = 30

	// numRetries is the number of tried without a single success before
	// we assume an address is bad.
	// numRetries是在我们假设地址无效之前尝试过没有一次成功的次数。
	numRetries = 3

	// maxFailures is the maximum number of failures we will accept without
	// a success before considering an address bad.
	// maxFailures是在考虑地址无效之前我们将接受但未成功的最大失败次数。
	maxFailures = 10

	// minBadDays is the number of days since the last success before we
	// will consider evicting an address.
	// minBadDays是我们考虑驱逐地址之前自上次成功以来的天数。
	minBadDays = 7

	// getAddrMax is the most addresses that we will send in response
	// to a getAddr (in practise the most addresses we will return from a
	// call to AddressCache()).
	// getAddrMax是我们将响应getAddr发送的最多地址
	// （实际上我们将通过调用AddressCache（）返回大多数地址）。
	getAddrMax = 2500

	// getAddrPercent is the percentage of total addresses known that we
	// will share with a call to AddressCache.
	// getAddrPercent是我们将通过调用AddressCache分享的已知总地址的百分比。
	getAddrPercent = 23

	// serialisationVersion is the current version of the on-disk format.
	serialisationVersion = 1
)

// updateAddress is a helper function to either update an address already known
// to the address manager, or to add the address if not already known.
// updateAddress是一个帮助函数，用于更新地址管理器已知的地址，或添加地址（如果尚未知道）。
func (a *AddrManager) updateAddress(netAddr, srcAddr *wire.NetAddress) {
	// Filter out non-routable addresses. Note that non-routable
	// also includes invalid and local addresses.
	if !IsRoutable(netAddr) {
		return
	}

	addr := NetAddressKey(netAddr)
	ka := a.find(netAddr)
	if ka != nil {
		// TODO: only update addresses periodically.
		// Update the last seen time and services.
		// note that to prevent causing excess garbage on getaddr
		// messages the netaddresses in addrmaanger are *immutable*,
		// if we need to change them then we replace the pointer with a
		// new copy so that we don't have to copy every na for getaddr.
		if netAddr.Timestamp.After(ka.na.Timestamp) ||
			(ka.na.Services&netAddr.Services) !=
				netAddr.Services {

			naCopy := *ka.na
			naCopy.Timestamp = netAddr.Timestamp
			naCopy.AddService(netAddr.Services)
			ka.na = &naCopy
		}

		// If already in tried, we have nothing to do here.
		if ka.tried {
			return
		}

		// Already at our max?
		if ka.refs == newBucketsPerAddress {
			return
		}

		// The more entries we have, the less likely we are to add more.
		// likelihood is 2N.
		factor := int32(2 * ka.refs)
		if a.rand.Int31n(factor) != 0 {
			return
		}
	} else {
		// Make a copy of the net address to avoid races since it is
		// updated elsewhere in the addrmanager code and would otherwise
		// change the actual netaddress on the peer.
		netAddrCopy := *netAddr
		ka = &KnownAddress{na: &netAddrCopy, srcAddr: srcAddr}
		a.addrIndex[addr] = ka
		a.nNew++
		// XXX time penalty?
	}

	bucket := a.getNewBucket(netAddr, srcAddr)

	// Already exists?
	if _, ok := a.addrNew[bucket][addr]; ok {
		return
	}

	// Enforce max addresses.
	if len(a.addrNew[bucket]) > newBucketSize {
		log.Tracef("new bucket is full, expiring old")
		a.expireNew(bucket)
	}

	// Add to new bucket.
	ka.refs++
	a.addrNew[bucket][addr] = ka

	log.Tracef("Added new address %s for a total of %d addresses", addr,
		a.nTried+a.nNew)
}

// expireNew makes space in the new buckets by expiring the really bad entries.
// If no bad entries are available we look at a few and remove the oldest.
//
// expireNew:到期新建 , expireNew通过使真正错误的条目到期来在新桶中创建空间。
// 如果没有可用的错误条目，我们会查看几个并删除最旧的条目。
func (a *AddrManager) expireNew(bucket int) {
	// First see if there are any entries that are so bad we can just throw
	// them away. otherwise we throw away the oldest entry in the cache.
	// Bitcoind here chooses four random and just throws the oldest of
	// those away, but we keep track of oldest in the initial traversal and
	// use that information instead.
	// 首先看看是否有任何条目如此糟糕我们可以扔掉它们。 否则我们会丢弃缓存中最旧的条目。
	// Bitcoind在这里选择四个随机并且只抛出最老的那些，
	// 但是我们在初始遍历中跟踪最旧的并且使用该信息。
	var oldest *KnownAddress
	for k, v := range a.addrNew[bucket] {
		if v.isBad() {
			log.Tracef("expiring bad address %v", k)
			delete(a.addrNew[bucket], k)
			v.refs--
			if v.refs == 0 {
				a.nNew--
				delete(a.addrIndex, k)
			}
			continue
		}
		if oldest == nil {
			oldest = v
		} else if !v.na.Timestamp.After(oldest.na.Timestamp) {
			oldest = v
		}
	}

	if oldest != nil {
		key := NetAddressKey(oldest.na)
		log.Tracef("expiring oldest address %v", key)

		delete(a.addrNew[bucket], key)
		oldest.refs--
		if oldest.refs == 0 {
			a.nNew--
			delete(a.addrIndex, key)
		}
	}
}

// pickTried selects an address from the tried bucket to be evicted.
// We just choose the eldest. Bitcoind selects 4 random entries and throws away
// the older of them.
// pickTried从被尝试的存储桶中选择一个地址进行驱逐。
// 我们只选择最年长的 Bitcoind选择4个随机条目并丢弃它们中较旧的条目。
// bitcoind：是比特币运行的核心程序俗称bitcoin core
func (a *AddrManager) pickTried(bucket int) *list.Element {
	var oldest *KnownAddress
	var oldestElem *list.Element
	for e := a.addrTried[bucket].Front(); e != nil; e = e.Next() {
		ka := e.Value.(*KnownAddress)
		if oldest == nil || oldest.na.Timestamp.After(ka.na.Timestamp) {
			oldestElem = e
			oldest = ka
		}

	}
	return oldestElem
}

//getNewBucket：获取新的存储桶
func (a *AddrManager) getNewBucket(netAddr, srcAddr *wire.NetAddress) int {
	// bitcoind:是比特币运行的核心程序俗称bitcoin core
	// doublesha256(key + sourcegroup + int64(doublesha256(key + group + sourcegroup))%bucket_per_source_group) % num_new_buckets

	data1 := []byte{}
	data1 = append(data1, a.key[:]...)
	data1 = append(data1, []byte(GroupKey(netAddr))...)
	data1 = append(data1, []byte(GroupKey(srcAddr))...)
	hash1 := chainhash.DoubleHashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= newBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, a.key[:]...)
	data2 = append(data2, GroupKey(srcAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.DoubleHashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % newBucketCount)
}

//getTriedBucket：获取尝试链接的地址存储桶
func (a *AddrManager) getTriedBucket(netAddr *wire.NetAddress) int {
	// bitcoind hashes this as:
	// doublesha256(key + group + truncate_to_64bits(doublesha256(key)) % buckets_per_group) % num_buckets
	data1 := []byte{}
	data1 = append(data1, a.key[:]...)
	data1 = append(data1, []byte(NetAddressKey(netAddr))...)
	hash1 := chainhash.DoubleHashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= triedBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, a.key[:]...)
	data2 = append(data2, GroupKey(netAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.DoubleHashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % triedBucketCount)
}

// addressHandler is the main handler for the address manager.  It must be run
// as a goroutine.
// addressHandler是地址管理器的主要处理程序。 它必须作为协程运行。
func (a *AddrManager) addressHandler() {
	dumpAddressTicker := time.NewTicker(dumpAddressInterval)
	defer dumpAddressTicker.Stop()
out:
	for {
		select {
		case <-dumpAddressTicker.C:
			a.savePeers()

		case <-a.quit:
			break out
		}
	}
	a.savePeers()
	a.wg.Done()
	log.Trace("Address handler done")
}

// savePeers saves all the known addresses to a file so they can be read back
// in at next run.
// savePeers将所有已知地址保存到文件中，以便在下次运行时可以回读它们。
func (a *AddrManager) savePeers() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// First we make a serialisable datastructure so we can encode it to
	// json.
	sam := new(serializedAddrManager)
	sam.Version = serialisationVersion
	copy(sam.Key[:], a.key[:])

	sam.Addresses = make([]*serializedKnownAddress, len(a.addrIndex))
	i := 0
	for k, v := range a.addrIndex {
		ska := new(serializedKnownAddress)
		ska.Addr = k
		ska.TimeStamp = v.na.Timestamp.Unix()
		ska.Src = NetAddressKey(v.srcAddr)
		ska.Attempts = v.attempts
		ska.LastAttempt = v.lastattempt.Unix()
		ska.LastSuccess = v.lastsuccess.Unix()
		// Tried and refs are implicit in the rest of the structure
		// and will be worked out from context on unserialisation.
		sam.Addresses[i] = ska
		i++
	}
	for i := range a.addrNew {
		sam.NewBuckets[i] = make([]string, len(a.addrNew[i]))
		j := 0
		for k := range a.addrNew[i] {
			sam.NewBuckets[i][j] = k
			j++
		}
	}
	for i := range a.addrTried {
		sam.TriedBuckets[i] = make([]string, a.addrTried[i].Len())
		j := 0
		for e := a.addrTried[i].Front(); e != nil; e = e.Next() {
			ka := e.Value.(*KnownAddress)
			sam.TriedBuckets[i][j] = NetAddressKey(ka.na)
			j++
		}
	}

	w, err := os.Create(a.peersFile)
	if err != nil {
		log.Errorf("Error opening file %s: %v", a.peersFile, err)
		return
	}
	enc := json.NewEncoder(w)
	defer w.Close()
	if err := enc.Encode(&sam); err != nil {
		log.Errorf("Failed to encode file %s: %v", a.peersFile, err)
		return
	}
}

// loadPeers loads the known address from the saved file.  If empty, missing, or
// malformed file, just don't load anything and start fresh
// loadPeers从保存的文件中加载已知地址。 如果文件为空，丢失或格式错误，
// 就不加载任何内容并重新开始
func (a *AddrManager) loadPeers() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	err := a.deserializePeers(a.peersFile)
	if err != nil {
		log.Errorf("Failed to parse file %s: %v", a.peersFile, err)
		// if it is invalid we nuke the old one unconditionally.
		err = os.Remove(a.peersFile)
		if err != nil {
			log.Warnf("Failed to remove corrupt peers file %s: %v",
				a.peersFile, err)
		}
		a.reset()
		return
	}
	log.Infof("Loaded %d addresses from file '%s'", a.numAddresses(), a.peersFile)
}

//deserializePeers：反序列化节点，解析节点
func (a *AddrManager) deserializePeers(filePath string) error {

	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil
	}
	r, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("%s error opening file: %v", filePath, err)
	}
	defer r.Close()

	var sam serializedAddrManager
	dec := json.NewDecoder(r)
	err = dec.Decode(&sam)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filePath, err)
	}

	if sam.Version != serialisationVersion {
		return fmt.Errorf("unknown version %v in serialized "+
			"addrmanager", sam.Version)
	}
	copy(a.key[:], sam.Key[:])

	for _, v := range sam.Addresses {
		ka := new(KnownAddress)
		ka.na, err = a.DeserializeNetAddress(v.Addr)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Addr, err)
		}
		ka.srcAddr, err = a.DeserializeNetAddress(v.Src)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Src, err)
		}
		ka.attempts = v.Attempts
		ka.lastattempt = time.Unix(v.LastAttempt, 0)
		ka.lastsuccess = time.Unix(v.LastSuccess, 0)
		a.addrIndex[NetAddressKey(ka.na)] = ka
	}

	for i := range sam.NewBuckets {
		for _, val := range sam.NewBuckets[i] {
			ka, ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("newbucket contains %s but "+
					"none in address list", val)
			}

			if ka.refs == 0 {
				a.nNew++
			}
			ka.refs++
			a.addrNew[i][val] = ka
		}
	}
	for i := range sam.TriedBuckets {
		for _, val := range sam.TriedBuckets[i] {
			ka, ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("Newbucket contains %s but "+
					"none in address list", val)
			}

			ka.tried = true
			a.nTried++
			a.addrTried[i].PushBack(ka)
		}
	}

	// Sanity checking.
	for k, v := range a.addrIndex {
		if v.refs == 0 && !v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"with no references", k)
		}

		if v.refs > 0 && v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"which is both new and tried!", k)
		}
	}

	return nil
}

// DeserializeNetAddress converts a given address string to a *wire.NetAddress
// DeserializeNetAddress：反序列化网址，将给定的地址字符串转换为* wire.NetAddress
func (a *AddrManager) DeserializeNetAddress(addr string) (*wire.NetAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	return a.HostToNetAddress(host, uint16(port), wire.SFNodeNetwork)
}

// Start begins the core address handler which manages a pool of known
// addresses, timeouts, and interval based writes.
// Start开始核心地址处理程序，该处理程序管理已知地址，超时和基于间隔的写入池。
func (a *AddrManager) Start() {
	// Already started?
	if atomic.AddInt32(&a.started, 1) != 1 {
		return
	}

	log.Trace("Starting address manager")

	// Load peers we already know about from file.
	a.loadPeers()

	// Start the address ticker to save addresses periodically.
	a.wg.Add(1)
	go a.addressHandler()
}

// Stop gracefully shuts down the address manager by stopping the main handler.
//通过停止主处理程序优雅地停止地址管理器。
func (a *AddrManager) Stop() error {
	if atomic.AddInt32(&a.shutdown, 1) != 1 {
		log.Warnf("Address manager is already in the process of " +
			"shutting down")
		return nil
	}

	log.Infof("Address manager shutting down")
	close(a.quit)
	a.wg.Wait()
	return nil
}

// AddAddresses adds new addresses to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.  It is
// safe for concurrent access.
// AddAddresses向地址管理器添加新地址。 它强制执行最大数量的地址，并静默忽略重复的地址。
// 并发访问是安全的。
// 1.如果地址不存在，将地址添加到addrNew
// 2. 如果地址存在，更新地址连接属性
func (a *AddrManager) AddAddresses(addrs []*wire.NetAddress, srcAddr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for _, na := range addrs {
		a.updateAddress(na, srcAddr)
	}
}

// AddAddress adds a new address to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.  It is
// safe for concurrent access.
// AddAddresses向地址管理器添加新地址。 它强制执行最大数量的地址，并静默忽略重复的地址。
// 并发访问是安全的。
// 1.如果地址不存在，将地址添加到addrNew
// 2. 如果地址存在，更新地址连接属性
func (a *AddrManager) AddAddress(addr, srcAddr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.updateAddress(addr, srcAddr)
}

// AddAddressByIP adds an address where we are given an ip:port and not a
// wire.NetAddress.
// AddAddressByIP添加一个地址，给出一个ip：port而不是一个wire.NetAddress。
func (a *AddrManager) AddAddressByIP(addrIP string) error {
	// Split IP and port
	addr, portStr, err := net.SplitHostPort(addrIP)
	if err != nil {
		return err
	}
	// Put it in wire.Netaddress
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid ip address %s", addr)
	}
	port, err := strconv.ParseUint(portStr, 10, 0)
	if err != nil {
		return fmt.Errorf("invalid port %s: %v", portStr, err)
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), 0)
	a.AddAddress(na, na) // XXX use correct src address
	return nil
}

// NumAddresses returns the number of addresses known to the address manager.
// NumAddresses返回地址管理器已知的地址数。
func (a *AddrManager) numAddresses() int {
	return a.nTried + a.nNew
}

// NumAddresses returns the number of addresses known to the address manager.
// NumAddresses返回地址管理器已知的地址数。
func (a *AddrManager) NumAddresses() int {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.numAddresses()
}

// NeedMoreAddresses returns whether or not the address manager needs more
// addresses.
// NeedMoreAddresses返回地址管理器是否需要更多地址。
func (a *AddrManager) NeedMoreAddresses() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.numAddresses() < needAddressThreshold
}

// AddressCache returns the current address cache.  It must be treated as
// read-only (but since it is a copy now, this is not as dangerous).
// AddressCache返回当前地址缓存。 它必须被视为只读（但由于它现在是一个副本，这不是那么危险）。
func (a *AddrManager) AddressCache() []*wire.NetAddress {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	addrIndexLen := len(a.addrIndex)
	if addrIndexLen == 0 {
		return nil
	}

	allAddr := make([]*wire.NetAddress, 0, addrIndexLen)
	// Iteration order is undefined here, but we randomise it anyway.
	for _, v := range a.addrIndex {
		allAddr = append(allAddr, v.na)
	}

	numAddresses := addrIndexLen * getAddrPercent / 100
	if numAddresses > getAddrMax {
		numAddresses = getAddrMax
	}

	// Fisher-Yates shuffle the array. We only need to do the first
	// `numAddresses' since we are throwing the rest.
	for i := 0; i < numAddresses; i++ {
		// pick a number between current index and the end
		j := rand.Intn(addrIndexLen-i) + i
		allAddr[i], allAddr[j] = allAddr[j], allAddr[i]
	}

	// slice off the limit we are willing to share.
	return allAddr[0:numAddresses]
}

// reset resets the address manager by reinitialising the random source
// and allocating fresh empty bucket storage.
// reset通过重新初始化随机源并分配新的空存储桶来重置地址管理器。
func (a *AddrManager) reset() {

	a.addrIndex = make(map[string]*KnownAddress)

	// fill key with bytes from a good random source.
	io.ReadFull(crand.Reader, a.key[:])
	for i := range a.addrNew {
		a.addrNew[i] = make(map[string]*KnownAddress)
	}
	for i := range a.addrTried {
		a.addrTried[i] = list.New()
	}
}

// HostToNetAddress returns a netaddress given a host address.  If the address
// is a Tor .onion address this will be taken care of.  Else if the host is
// not an IP address it will be resolved (via Tor if required).
// HostToNetAddress返回给定主机地址的netaddress。 如果地址是Tor .onion地址，那么这将被处理。
// 否则，如果主机不是IP地址，则将解析（如果需要，通过Tor）。
func (a *AddrManager) HostToNetAddress(host string, port uint16, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// Tor address is 16 char base32 + ".onion"
	var ip net.IP
	if len(host) == 22 && host[16:] == ".onion" {
		// go base32 encoding uses capitals (as does the rfc
		// but Tor and bitcoind tend to user lowercase, so we switch
		// case here.
		data, err := base32.StdEncoding.DecodeString(
			strings.ToUpper(host[:16]))
		if err != nil {
			return nil, err
		}
		prefix := []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}
		ip = net.IP(append(prefix, data...))
	} else if ip = net.ParseIP(host); ip == nil {
		ips, err := a.lookupFunc(host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", host)
		}
		ip = ips[0]
	}

	return wire.NewNetAddressIPPort(ip, port, services), nil
}

// ipString returns a string for the ip from the provided NetAddress. If the
// ip is in the range used for Tor addresses then it will be transformed into
// the relevant .onion address.
// ipString从提供的NetAddress返回ip的字符串。 如果ip在用于Tor地址的范围内，
// 则它将被转换为相关的.onion地址。
func ipString(na *wire.NetAddress) string {
	if IsOnionCatTor(na) {
		// We know now that na.IP is long enough.
		base32 := base32.StdEncoding.EncodeToString(na.IP[6:])
		return strings.ToLower(base32) + ".onion"
	}

	return na.IP.String()
}

// NetAddressKey returns a string key in the form of ip:port for IPv4 addresses
// or [ip]:port for IPv6 addresses.
// NetAddressKey以ip：port的形式返回IPv4地址的字符串密钥，或[ip]：IPv6地址的端口。
func NetAddressKey(na *wire.NetAddress) string {
	port := strconv.FormatUint(uint64(na.Port), 10)

	return net.JoinHostPort(ipString(na), port)
}

// GetAddress returns a single address that should be routable.  It picks a
// random one from the possible addresses with preference given to ones that
// have not been used recently and should not pick 'close' addresses
// consecutively.
// GetAddress返回一个应该可路由的地址。 它从可能的地址中选择一个随机的地址，
// 优先考虑最近没有使用的地址，不应连续选择“已关闭”地址。
// 1.从addrTried提供有效IP
// 2.从addrNew提供IP
func (a *AddrManager) GetAddress() *KnownAddress {
	// Protect concurrent access.
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.numAddresses() == 0 {
		return nil
	}

	// Use a 50% chance for choosing between tried and new table entries.
	if a.nTried > 0 && (a.nNew == 0 || a.rand.Intn(2) == 0) {
		// Tried entry.
		large := 1 << 30
		factor := 1.0
		for {
			// pick a random bucket.
			bucket := a.rand.Intn(len(a.addrTried))
			if a.addrTried[bucket].Len() == 0 {
				continue
			}

			// Pick a random entry in the list
			e := a.addrTried[bucket].Front()
			for i :=
				a.rand.Int63n(int64(a.addrTried[bucket].Len())); i > 0; i-- {
				e = e.Next()
			}
			ka := e.Value.(*KnownAddress)
			randval := a.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from tried bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	} else {
		// new node.
		// XXX use a closure/function to avoid repeating this.
		large := 1 << 30
		factor := 1.0
		for {
			// Pick a random bucket.
			bucket := a.rand.Intn(len(a.addrNew))
			if len(a.addrNew[bucket]) == 0 {
				continue
			}
			// Then, a random entry in it.
			var ka *KnownAddress
			nth := a.rand.Intn(len(a.addrNew[bucket]))
			for _, value := range a.addrNew[bucket] {
				if nth == 0 {
					ka = value
				}
				nth--
			}
			randval := a.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from new bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	}
}

func (a *AddrManager) find(addr *wire.NetAddress) *KnownAddress {
	return a.addrIndex[NetAddressKey(addr)]
}

// Attempt increases the given address' attempt counter and updates
// the last attempt time.
// Attempt增加给定地址的尝试计数器并更新上次尝试时间
func (a *AddrManager) Attempt(addr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// find address.
	// Surely address will be in tried by now?
	ka := a.find(addr)
	if ka == nil {
		return
	}
	// set last tried time to now
	ka.attempts++
	ka.lastattempt = time.Now()
}

// Connected Marks the given address as currently connected and working at the
// current time.  The address must already be known to AddrManager else it will
// be ignored.
// Connected函数将给定地址标记为当前连接并在当前时间工作。 该地址必须已为AddrManager所知，
// 否则将被忽略。
// 1.更新地址属性信息
func (a *AddrManager) Connected(addr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		return
	}

	// Update the time as long as it has been 20 minutes since last we did
	// so.
	now := time.Now()
	if now.After(ka.na.Timestamp.Add(time.Minute * 20)) {
		// ka.na is immutable, so replace it.
		naCopy := *ka.na
		naCopy.Timestamp = time.Now()
		ka.na = &naCopy
	}
}

// Good marks the given address as good.  To be called after a successful
// connection and version exchange.  If the address is unknown to the address
// manager it will be ignored.
// Good将给定的地址标记为好。 在成功连接和版本交换后调用。 如果地址管理器不知道该地址，
// 则将忽略该地址。
// 1. server通知地址管理哪个IP Addr为有效地址
// 2. 更新lastsuccess、lastattemp、attemps字段
// 3. 同时从addrNew中删除该IP地址
// 4. 该IP添加到addrTried桶树
func (a *AddrManager) Good(addr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		return
	}

	// ka.Timestamp is not updated here to avoid leaking information
	// about currently connected peers.
	now := time.Now()
	ka.lastsuccess = now
	ka.lastattempt = now
	ka.attempts = 0

	// move to tried set, optionally evicting other addresses if neeed.
	if ka.tried {
		return
	}

	// ok, need to move it to tried.

	// remove from all new buckets.
	// record one of the buckets in question and call it the `first'
	addrKey := NetAddressKey(addr)
	oldBucket := -1
	for i := range a.addrNew {
		// we check for existence so we can record the first one
		if _, ok := a.addrNew[i][addrKey]; ok {
			delete(a.addrNew[i], addrKey)
			ka.refs--
			if oldBucket == -1 {
				oldBucket = i
			}
		}
	}
	a.nNew--

	if oldBucket == -1 {
		// What? wasn't in a bucket after all.... Panic?
		return
	}

	bucket := a.getTriedBucket(ka.na)

	// Room in this tried bucket?
	if a.addrTried[bucket].Len() < triedBucketSize {
		ka.tried = true
		a.addrTried[bucket].PushBack(ka)
		a.nTried++
		return
	}

	// No room, we have to evict something else.
	entry := a.pickTried(bucket)
	rmka := entry.Value.(*KnownAddress)

	// First bucket it would have been put in.
	newBucket := a.getNewBucket(rmka.na, rmka.srcAddr)

	// If no room in the original bucket, we put it in a bucket we just
	// freed up a space in.
	if len(a.addrNew[newBucket]) >= newBucketSize {
		newBucket = oldBucket
	}

	// replace with ka in list.
	ka.tried = true
	entry.Value = ka

	rmka.tried = false
	rmka.refs++

	// We don't touch a.nTried here since the number of tried stays the same
	// but we decemented new above, raise it again since we're putting
	// something back.
	a.nNew++

	rmkey := NetAddressKey(rmka.na)
	log.Tracef("Replacing %s with %s in tried", rmkey, addrKey)

	// We made sure there is space here just above.
	a.addrNew[newBucket][rmkey] = rmka
}

// SetServices sets the services for the giiven address to the provided value.
// SetServices将giiven地址的服务设置为提供的值。
func (a *AddrManager) SetServices(addr *wire.NetAddress, services wire.ServiceFlag) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		return
	}

	// Update the services if needed.
	if ka.na.Services != services {
		// ka.na is immutable, so replace it.
		naCopy := *ka.na
		naCopy.Services = services
		ka.na = &naCopy
	}
}

// AddLocalAddress adds na to the list of known local addresses to advertise
// with the given priority.
// AddLocalAddress将网络地址添加到已知本地地址列表中以使用给定优先级进行通告。
func (a *AddrManager) AddLocalAddress(na *wire.NetAddress, priority AddressPriority) error {
	if !IsRoutable(na) {
		return fmt.Errorf("address %s is not routable", na.IP)
	}

	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	key := NetAddressKey(na)
	la, ok := a.localAddresses[key]
	if !ok || la.score < priority {
		if ok {
			la.score = priority + 1
		} else {
			a.localAddresses[key] = &localAddress{
				na:    na,
				score: priority,
			}
		}
	}
	return nil
}

// getReachabilityFrom returns the relative reachability of the provided local
// address to the provided remote address.
// getReachabilityFrom返回提供的本地地址与提供的远程地址的相对可达性。
func getReachabilityFrom(localAddr, remoteAddr *wire.NetAddress) int {
	const (
		Unreachable = 0
		Default     = iota
		Teredo
		Ipv6Weak
		Ipv4
		Ipv6Strong
		Private
	)

	if !IsRoutable(remoteAddr) {
		return Unreachable
	}

	if IsOnionCatTor(remoteAddr) {
		if IsOnionCatTor(localAddr) {
			return Private
		}

		if IsRoutable(localAddr) && IsIPv4(localAddr) {
			return Ipv4
		}

		return Default
	}

	if IsRFC4380(remoteAddr) {
		if !IsRoutable(localAddr) {
			return Default
		}

		if IsRFC4380(localAddr) {
			return Teredo
		}

		if IsIPv4(localAddr) {
			return Ipv4
		}

		return Ipv6Weak
	}

	if IsIPv4(remoteAddr) {
		if IsRoutable(localAddr) && IsIPv4(localAddr) {
			return Ipv4
		}
		return Unreachable
	}

	/* ipv6 */
	var tunnelled bool
	// Is our v6 is tunnelled?
	if IsRFC3964(localAddr) || IsRFC6052(localAddr) || IsRFC6145(localAddr) {
		tunnelled = true
	}

	if !IsRoutable(localAddr) {
		return Default
	}

	if IsRFC4380(localAddr) {
		return Teredo
	}

	if IsIPv4(localAddr) {
		return Ipv4
	}

	if tunnelled {
		// only prioritise ipv6 if we aren't tunnelling it.
		return Ipv6Weak
	}

	return Ipv6Strong
}

// GetBestLocalAddress returns the most appropriate local address to use
// for the given remote address.
// GetBestLocalAddress返回用于给定远程地址的最合适的本地地址。
func (a *AddrManager) GetBestLocalAddress(remoteAddr *wire.NetAddress) *wire.NetAddress {
	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	bestreach := 0
	var bestscore AddressPriority
	var bestAddress *wire.NetAddress
	for _, la := range a.localAddresses {
		reach := getReachabilityFrom(la.na, remoteAddr)
		if reach > bestreach ||
			(reach == bestreach && la.score > bestscore) {
			bestreach = reach
			bestscore = la.score
			bestAddress = la.na
		}
	}
	if bestAddress != nil {
		log.Debugf("Suggesting address %s:%d for %s:%d", bestAddress.IP,
			bestAddress.Port, remoteAddr.IP, remoteAddr.Port)
	} else {
		log.Debugf("No worthy address for %s:%d", remoteAddr.IP,
			remoteAddr.Port)

		// Send something unroutable if nothing suitable.
		var ip net.IP
		if !IsIPv4(remoteAddr) && !IsOnionCatTor(remoteAddr) {
			ip = net.IPv6zero
		} else {
			ip = net.IPv4zero
		}
		services := wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeBloom
		bestAddress = wire.NewNetAddressIPPort(ip, 0, services)
	}

	return bestAddress
}

// New returns a new bitcoin address manager.
// Use Start to begin processing asynchronous address updates.
// New返回一个新的比特币地址管理器。
// 使用“Start”开始处理异步地址更新。
func New(dataDir string, lookupFunc func(string) ([]net.IP, error)) *AddrManager {
	am := AddrManager{
		peersFile:      filepath.Join(dataDir, "peers.json"),
		lookupFunc:     lookupFunc,
		rand:           rand.New(rand.NewSource(time.Now().UnixNano())),
		quit:           make(chan struct{}),
		localAddresses: make(map[string]*localAddress),
	}
	am.reset()
	return &am
}
