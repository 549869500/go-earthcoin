// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"time"

	"github.com/btcsuite/btcd/wire"
)

// KnownAddress tracks information about a known network address that is used
// to determine how viable an address is.
// KnownAddress跟踪有关已知网络地址的信息，该网络地址用于确定地址的可行性。
type KnownAddress struct {
	na          *wire.NetAddress
	srcAddr     *wire.NetAddress
	attempts    int       //连接次数
	lastattempt time.Time //最后一次连接时间
	lastsuccess time.Time //最后一次成功连接时间
	tried       bool
	refs        int // 节点被连接次数  reference count of new buckets
}

// NetAddress returns the underlying wire.NetAddress associated with the
// known address.
// NetAddress返回与已知地址关联的基础wire.NetAddress。
func (ka *KnownAddress) NetAddress() *wire.NetAddress {
	return ka.na
}

// LastAttempt returns the last time the known address was attempted.
// LastAttempt返回上次尝试已知地址的时间。
func (ka *KnownAddress) LastAttempt() time.Time {
	return ka.lastattempt
}

// chance returns the selection probability for a known address.  The priority
// depends upon how recently the address has been seen, how recently it was last
// attempted and how often attempts to connect to it have failed.
// chance 返回已知地址的选择概率。
// 优先级取决于最近查看地址的时间，上次尝试的最近时间以及连接到该地址的尝试失败的频率。
func (ka *KnownAddress) chance() float64 {
	now := time.Now()
	lastAttempt := now.Sub(ka.lastattempt)

	if lastAttempt < 0 {
		lastAttempt = 0
	}

	c := 1.0

	// Very recent attempts are less likely to be retried.
	if lastAttempt < 10*time.Minute {
		c *= 0.01
	}

	// Failed attempts deprioritise.
	for i := ka.attempts; i > 0; i-- {
		c /= 1.5
	}

	return c
}

// isBad returns true if the address in question has not been tried in the last
// minute and meets one of the following criteria:
// 1) It claims to be from the future
// 2) It hasn't been seen in over a month
// 3) It has failed at least three times and never succeeded
// 4) It has failed ten times in the last week
// All addresses that meet these criteria are assumed to be worthless and not
// worth keeping hold of.
//如果在最后一分钟没有尝试过相关地址并且满足以下条件之一，则isBad返回true：
// 1）它声称来自未来
// 2）一个多月没见过了
// 3）它至少失败了三次并且从未成功过
// 4）上周失败了十次
//所有符合这些标准的地址都被认为是毫无价值的，不值得保留。
func (ka *KnownAddress) isBad() bool {
	if ka.lastattempt.After(time.Now().Add(-1 * time.Minute)) {
		return false
	}

	// From the future?
	if ka.na.Timestamp.After(time.Now().Add(10 * time.Minute)) {
		return true
	}

	// Over a month old?
	if ka.na.Timestamp.Before(time.Now().Add(-1 * numMissingDays * time.Hour * 24)) {
		return true
	}

	// Never succeeded?
	if ka.lastsuccess.IsZero() && ka.attempts >= numRetries {
		return true
	}

	// Hasn't succeeded in too long?
	if !ka.lastsuccess.After(time.Now().Add(-1*minBadDays*time.Hour*24)) &&
		ka.attempts >= maxFailures {
		return true
	}

	return false
}
