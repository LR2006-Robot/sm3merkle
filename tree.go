package sm3merkle

import (
	"bytes"
	"fmt"

	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
)

// Tree 是一棵仅追加（append-only）的内存 Merkle 树。
//
// 零值不可用，请用 New 或 NewWithHasher 构造。Tree 不是并发安全的，
// 多 goroutine 访问需自行加锁。
//
// ponytail: 全部节点哈希常驻内存，约 2*N 个哈希，每个连 []byte 切片头约 56 字节，
// 实测百万叶子约 114MB。
// 日志规模超出内存时，改用 compact.Range 配合外部节点存储（见 docs/USAGE.md
// “超出内存的日志”一节），本包的 Hasher 可以原样复用。
type Tree struct {
	hasher merkle.LogHasher
	size   uint64
	// hashes[level][index] —— 第一维是层号（0 为叶子层），第二维是层内下标。
	hashes [][][]byte
}

// New 返回一棵空的 SM3 Merkle 树。
func New() *Tree { return NewWithHasher(DefaultHasher) }

// NewWithHasher 用指定哈希策略构造空树。
//
// 正常使用国密场景请用 New。这个入口的存在是为了能塞入 RFC 6962 的
// SHA-256 哈希器，拿 CT 官方黄金向量验证树本身的逻辑（见 tree_test.go）。
func NewWithHasher(h merkle.LogHasher) *Tree { return &Tree{hasher: h} }

// Append 追加一条数据作为新叶子，返回它的下标。
func (t *Tree) Append(data []byte) uint64 {
	// HashLeaf 的输出长度天然正确，无须走带校验的那条路径。
	return t.appendHash(t.hasher.HashLeaf(data))
}

// AppendHash 追加一个已经算好的叶子哈希，返回它的下标。
//
// 用于从持久化存储重建整棵树：把库里存的叶子哈希按下标顺序喂进来即可，
// 不需要原始数据。
//
// 哈希长度必须等于 hasher 的 Size()，否则返回错误且树不被修改。这个检查
// 拦的是恢复路径上最坏的一类事故——存储里的字节被截断、或误把原始数据当
// 哈希传入时，树会静默地长出一个错误的根，所有证明随之失效却没有任何报错。
// 长度对但内容错仍然无法在这里发现，恢复后请比对树根与上次发布的值。
//
// leafHash 会被复制一份，调用方可以安全地复用传入的缓冲区。
func (t *Tree) AppendHash(leafHash []byte) (uint64, error) {
	if got, want := len(leafHash), t.hasher.Size(); got != want {
		return 0, fmt.Errorf("sm3merkle: 叶子哈希长度为 %d 字节, 应为 %d", got, want)
	}
	// 必须拷贝：否则调用方复用缓冲区会静默改写已经入树的叶子哈希。
	return t.appendHash(bytes.Clone(leafHash)), nil
}

// appendHash 是不做校验的内部追加，调用方须保证哈希长度正确。
func (t *Tree) appendHash(leafHash []byte) uint64 {
	index := t.size

	// 每当 size 的第 level 位是 1，说明该层右侧已有一个待合并的兄弟节点。
	// 把新哈希落到该层，再与左邻居合并向上进位——和二进制加法的进位同构。
	hash := leafHash
	level := 0
	for ; (t.size>>level)&1 == 1; level++ {
		row := append(t.hashes[level], hash)
		t.hashes[level] = row
		hash = t.hasher.HashChildren(row[len(row)-2], hash)
	}
	if level == len(t.hashes) {
		t.hashes = append(t.hashes, nil)
	}
	t.hashes[level] = append(t.hashes[level], hash)

	t.size++
	return index
}

// Size 返回当前叶子数量。
func (t *Tree) Size() uint64 { return t.size }

// Root 返回当前树根。空树返回 EmptyRoot。返回的是副本，可安全修改。
func (t *Tree) Root() []byte {
	root, err := t.RootAt(t.size)
	if err != nil {
		panic(err) // size 永远合法，走不到这里。
	}
	return root
}

// RootAt 返回树在历史大小 size 时的根哈希，要求 0 <= size <= Size()。
// 返回的是副本，可安全修改。
func (t *Tree) RootAt(size uint64) ([]byte, error) {
	if size > t.size {
		return nil, fmt.Errorf("sm3merkle: size %d 超出当前树大小 %d", size, t.size)
	}
	if size == 0 {
		return t.hasher.EmptyRoot(), nil
	}
	hashes, err := t.nodes(compact.RangeNodes(0, size, nil))
	if err != nil {
		return nil, err
	}
	// RangeNodes 从左到右给出覆盖 [0,size) 的完美子树，自右向左折叠成根。
	root := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		root = t.hasher.HashChildren(hashes[i], root)
	}
	// size 恰为 2 的幂时上面的循环不执行，root 直接指向内部节点，必须拷贝。
	return bytes.Clone(root), nil
}

// LeafHash 返回下标 index 处的叶子哈希，要求 0 <= index < Size()。
// 返回的是副本，可安全修改。
func (t *Tree) LeafHash(index uint64) ([]byte, error) {
	if index >= t.size {
		return nil, fmt.Errorf("sm3merkle: 叶子下标 %d 超出树大小 %d", index, t.size)
	}
	return bytes.Clone(t.hashes[0][index]), nil
}

// InclusionProof 返回「下标 index 的叶子确实在大小为 size 的树里」的包含证明，
// 要求 0 <= index < size <= Size()。
func (t *Tree) InclusionProof(index, size uint64) ([][]byte, error) {
	if size > t.size {
		return nil, fmt.Errorf("sm3merkle: size %d 超出当前树大小 %d", size, t.size)
	}
	nodes, err := proof.Inclusion(index, size)
	if err != nil {
		return nil, err
	}
	return t.rehash(nodes)
}

// ConsistencyProof 返回「大小 size1 的树是大小 size2 的树的前缀」的一致性证明，
// 要求 0 <= size1 <= size2 <= Size()。这是仅追加性质的证据：老根没被改写过。
func (t *Tree) ConsistencyProof(size1, size2 uint64) ([][]byte, error) {
	if size2 > t.size {
		return nil, fmt.Errorf("sm3merkle: size %d 超出当前树大小 %d", size2, t.size)
	}
	nodes, err := proof.Consistency(size1, size2)
	if err != nil {
		return nil, err
	}
	return t.rehash(nodes)
}

func (t *Tree) rehash(nodes proof.Nodes) ([][]byte, error) {
	hashes, err := t.nodes(nodes.IDs)
	if err != nil {
		return nil, err
	}
	pf, err := nodes.Rehash(hashes, t.hasher.HashChildren)
	if err != nil {
		return nil, err
	}
	// Rehash 对无需重算的节点会原样透传内部切片，同样要拷贝。
	for i := range pf {
		pf[i] = bytes.Clone(pf[i])
	}
	return pf, nil
}

// nodes 按节点地址取出哈希。上游算出的地址一定落在已有节点内，
// 这里仍然做一次边界检查，把可能的 panic 换成错误。
func (t *Tree) nodes(ids []compact.NodeID) ([][]byte, error) {
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		if int(id.Level) >= len(t.hashes) || id.Index >= uint64(len(t.hashes[id.Level])) {
			return nil, fmt.Errorf("sm3merkle: 节点 (level=%d, index=%d) 不存在", id.Level, id.Index)
		}
		hashes[i] = t.hashes[id.Level][id.Index]
	}
	return hashes, nil
}
