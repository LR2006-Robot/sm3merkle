// Package sm3merkle 实现基于 SM3（GB/T 32905-2016）的 RFC 6962 Merkle 树。
//
// 哈希策略与 RFC 6962 完全一致，只把 SHA-256 换成 SM3：
//
//	空树根     = SM3()
//	叶子节点   = SM3(0x00 || 数据)
//	内部节点   = SM3(0x01 || 左子哈希 || 右子哈希)
//
// 0x00 / 0x01 前缀是域分离标记，用来阻断第二原像攻击——没有它，
// 攻击者可以把一个内部节点的哈希冒充成某个叶子的哈希。
//
// 证明的生成与校验直接复用 github.com/transparency-dev/merkle
// （Certificate Transparency 的上游实现），本包只提供 SM3 哈希层和
// 一棵内存树，不重写任何 Merkle 数学。
package sm3merkle

import (
	"github.com/emmansun/gmsm/sm3"
	"github.com/transparency-dev/merkle"
)

// RFC 6962 域分离前缀。
const (
	LeafPrefix = 0x00
	NodePrefix = 0x01
)

// HashSize 是 SM3 摘要长度，32 字节。
const HashSize = sm3.Size

// Hasher 是 SM3 版本的 RFC 6962 哈希策略，实现 merkle.LogHasher。
type Hasher struct{}

// DefaultHasher 是本包各处默认使用的 SM3 哈希器。
var DefaultHasher = Hasher{}

// 编译期确认接口契约成立，接口变了这里会直接编译失败。
var _ merkle.LogHasher = DefaultHasher

// EmptyRoot 返回空树的根哈希，即 SM3 对空输入的摘要。
func (Hasher) EmptyRoot() []byte {
	sum := sm3.Sum(nil)
	return sum[:]
}

// HashLeaf 返回叶子哈希 SM3(0x00 || leaf)。
func (Hasher) HashLeaf(leaf []byte) []byte {
	h := sm3.New()
	h.Write([]byte{LeafPrefix})
	h.Write(leaf)
	return h.Sum(nil)
}

// HashChildren 返回内部节点哈希 SM3(0x01 || l || r)。
func (Hasher) HashChildren(l, r []byte) []byte {
	h := sm3.New()
	h.Write([]byte{NodePrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// Size 返回摘要字节数。
func (Hasher) Size() int { return HashSize }
