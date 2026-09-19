package sm3merkle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// 把 SHA-256 的 RFC 6962 哈希器塞进本包的 Tree，逐一对比 CT 官方黄金根哈希。
// 树的形状、进位、证明组装如果有任何偏差，这里必然失败——这条用例验的是
// 树本身的逻辑，与 SM3 无关。
func TestTreeMatchesRFC6962GoldenRoots(t *testing.T) {
	leaves := testonly.LeafInputs()
	want := testonly.RootHashes()

	tree := NewWithHasher(rfc6962.DefaultHasher)
	if got := tree.Root(); !bytes.Equal(got, want[0]) {
		t.Errorf("空树根 = %x, want %x", got, want[0])
	}
	for i, leaf := range leaves {
		if idx := tree.Append(leaf); idx != uint64(i) {
			t.Errorf("Append 返回下标 %d, want %d", idx, i)
		}
		if got := tree.Root(); !bytes.Equal(got, want[i+1]) {
			t.Errorf("size=%d 根 = %x, want %x", i+1, got, want[i+1])
		}
	}

	// 历史根也要对得上，这是一致性证明的基础。
	for size := range uint64(len(leaves) + 1) {
		got, err := tree.RootAt(size)
		if err != nil {
			t.Fatalf("RootAt(%d): %v", size, err)
		}
		if !bytes.Equal(got, want[size]) {
			t.Errorf("RootAt(%d) = %x, want %x", size, got, want[size])
		}
	}
}

// 叶子哈希也跟 CT 黄金向量对齐（NodeHashes 第 0 层即叶子层）。
func TestLeafHashesMatchGolden(t *testing.T) {
	want := testonly.NodeHashes()[0]
	tree := NewWithHasher(rfc6962.DefaultHasher)
	for _, leaf := range testonly.LeafInputs() {
		tree.Append(leaf)
	}
	for i, w := range want {
		got, err := tree.LeafHash(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, w) {
			t.Errorf("LeafHash(%d) = %x, want %x", i, got, w)
		}
	}
}

// SM3 哈希层：确认三条公式就是 RFC 6962 的域分离规则接 SM3。
func TestHasherFormulas(t *testing.T) {
	empty := sm3.Sum(nil)
	if got := DefaultHasher.EmptyRoot(); !bytes.Equal(got, empty[:]) {
		t.Errorf("EmptyRoot = %x, want SM3() = %x", got, empty)
	}

	leaf := sm3.Sum([]byte{LeafPrefix, 'a', 'b', 'c'})
	if got := DefaultHasher.HashLeaf([]byte("abc")); !bytes.Equal(got, leaf[:]) {
		t.Errorf("HashLeaf = %x, want SM3(0x00||abc) = %x", got, leaf)
	}

	l, r := DefaultHasher.HashLeaf([]byte("l")), DefaultHasher.HashLeaf([]byte("r"))
	node := sm3.Sum(append(append([]byte{NodePrefix}, l...), r...))
	if got := DefaultHasher.HashChildren(l, r); !bytes.Equal(got, node[:]) {
		t.Errorf("HashChildren = %x, want SM3(0x01||l||r) = %x", got, node)
	}

	if DefaultHasher.Size() != 32 {
		t.Errorf("Size = %d, want 32", DefaultHasher.Size())
	}
}

// 域分离前缀真的起作用：叶子哈希不可能与内部节点哈希碰撞。
func TestDomainSeparation(t *testing.T) {
	l, r := DefaultHasher.HashLeaf([]byte("l")), DefaultHasher.HashLeaf([]byte("r"))
	node := DefaultHasher.HashChildren(l, r)
	// 若无前缀，把 l||r 当作叶子数据提交就能伪造出同一个哈希。
	if forged := DefaultHasher.HashLeaf(append(append([]byte{}, l...), r...)); bytes.Equal(forged, node) {
		t.Error("叶子哈希与内部节点哈希发生碰撞，域分离失效")
	}
}

// SM3 树的包含证明：所有规模、所有下标全量验证，并确认篡改会被拒绝。
func TestInclusionProofAllSizes(t *testing.T) {
	const maxSize = 17
	leaves := make([][]byte, maxSize)
	tree := New()
	for i := range leaves {
		leaves[i] = fmt.Appendf(nil, "leaf-%d", i)
		tree.Append(leaves[i])
	}

	for size := uint64(1); size <= maxSize; size++ {
		root, err := tree.RootAt(size)
		if err != nil {
			t.Fatal(err)
		}
		for index := uint64(0); index < size; index++ {
			pf, err := tree.InclusionProof(index, size)
			if err != nil {
				t.Fatalf("InclusionProof(%d, %d): %v", index, size, err)
			}
			if err := VerifyInclusionData(index, size, leaves[index], pf, root); err != nil {
				t.Errorf("VerifyInclusionData(%d, %d): %v", index, size, err)
			}

			// 换一条数据必须验不过。
			if err := VerifyInclusionData(index, size, []byte("forged"), pf, root); err == nil {
				t.Errorf("伪造数据在 (%d, %d) 通过了校验", index, size)
			}
			// 证明里翻一个 bit 必须验不过。
			if len(pf) > 0 {
				bad := make([][]byte, len(pf))
				copy(bad, pf)
				bad[0] = append([]byte{}, pf[0]...)
				bad[0][0] ^= 1
				if err := VerifyInclusionData(index, size, leaves[index], bad, root); err == nil {
					t.Errorf("被篡改的证明在 (%d, %d) 通过了校验", index, size)
				}
			}
		}
	}
}

// SM3 树的一致性证明：任意 size1 <= size2 都应成立，并确认拿错根会被拒绝。
func TestConsistencyProofAllSizes(t *testing.T) {
	const maxSize = 17
	tree := New()
	for i := range maxSize {
		tree.Append(fmt.Appendf(nil, "leaf-%d", i))
	}

	for size1 := uint64(1); size1 <= maxSize; size1++ {
		root1, err := tree.RootAt(size1)
		if err != nil {
			t.Fatal(err)
		}
		for size2 := size1; size2 <= maxSize; size2++ {
			root2, err := tree.RootAt(size2)
			if err != nil {
				t.Fatal(err)
			}
			pf, err := tree.ConsistencyProof(size1, size2)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): %v", size1, size2, err)
			}
			if err := VerifyConsistency(size1, size2, pf, root1, root2); err != nil {
				t.Errorf("VerifyConsistency(%d, %d): %v", size1, size2, err)
			}

			// 老根对不上——等于日志被改写——必须验不过。
			if size1 > 1 {
				wrong, err := tree.RootAt(size1 - 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyConsistency(size1, size2, pf, wrong, root2); err == nil {
					t.Errorf("错误的 root1 在 (%d, %d) 通过了校验", size1, size2)
				}
			}
		}
	}
}

// AppendHash 重建的树必须与原树逐位一致——持久化恢复依赖这个性质。
func TestRebuildFromLeafHashes(t *testing.T) {
	orig := New()
	for i := range 20 {
		orig.Append(fmt.Appendf(nil, "leaf-%d", i))
	}

	rebuilt := New()
	for i := uint64(0); i < orig.Size(); i++ {
		lh, err := orig.LeafHash(i)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt.AppendHash(lh)
	}

	if rebuilt.Size() != orig.Size() {
		t.Fatalf("重建后大小 %d, want %d", rebuilt.Size(), orig.Size())
	}
	if !bytes.Equal(rebuilt.Root(), orig.Root()) {
		t.Errorf("重建后根 %x, want %x", rebuilt.Root(), orig.Root())
	}
}

// 越界应返回错误而不是 panic。
func TestOutOfRange(t *testing.T) {
	tree := New()
	tree.Append([]byte("only"))

	if _, err := tree.LeafHash(1); err == nil {
		t.Error("LeafHash 越界未报错")
	}
	if _, err := tree.RootAt(2); err == nil {
		t.Error("RootAt 越界未报错")
	}
	if _, err := tree.InclusionProof(0, 2); err == nil {
		t.Error("InclusionProof 越界未报错")
	}
	if _, err := tree.ConsistencyProof(1, 2); err == nil {
		t.Error("ConsistencyProof 越界未报错")
	}
}

// 手工按 RFC 6962 的结构算出 4 叶子树根，与 Tree 的输出比对。
// 这条路径完全不经过 Tree 的进位逻辑，是对它的独立交叉验证。
func TestFourLeafRootByHand(t *testing.T) {
	leaves := [][]byte{[]byte("leaf-0"), []byte("leaf-1"), []byte("leaf-2"), []byte("leaf-3")}

	h := func(prefix byte, parts ...[]byte) []byte {
		d := sm3.New()
		d.Write([]byte{prefix})
		for _, p := range parts {
			d.Write(p)
		}
		return d.Sum(nil)
	}
	l0, l1 := h(LeafPrefix, leaves[0]), h(LeafPrefix, leaves[1])
	l2, l3 := h(LeafPrefix, leaves[2]), h(LeafPrefix, leaves[3])
	want := h(NodePrefix, h(NodePrefix, l0, l1), h(NodePrefix, l2, l3))

	tree := New()
	for _, leaf := range leaves {
		tree.Append(leaf)
	}
	if got := tree.Root(); !bytes.Equal(got, want) {
		t.Errorf("4 叶子树根 = %x, want %x", got, want)
	}
}

// 固定回归向量：SM3 树在 1..8 个叶子（数据为 "leaf-0".."leaf-7"）时的根哈希。
// 这组值由本实现产生并经上面的交叉验证锁定，作用是防回归——
// 日后重构若改变任何一个根哈希，这里会立刻暴露。
func TestSM3GoldenRoots(t *testing.T) {
	want := []string{
		"25736362cb6acc70942a2b9454934f2c8a7d22547c279d420a71871efc236e61", // size=1
		"a58a500e4951e30b79294826f34fad5ecc6c1297e50f5f1ce28fe5bb6030b4ec", // size=2
		"bf3a93c66aecfa5210f0a6e79467bb17effa98a688bedb4693d23c1d1fe0f450", // size=3
		"aac6cd5aba5d079d386f4626c88ce077ad20cbf8b4bf0d58a3740910800cd800", // size=4
		"20a9c4953bd7e572e33f0df857fb79de989f5e290c4cb380a1c2887731603bf6", // size=5
		"bd3af22b534ac3754fe73b73e19e1dd36d64c4785d7eefd62cb4cc76def1e27f", // size=6
		"21f439e3829b7ef3d0ac7232075bce7f7ca35780b842b80231399b339e8549c9", // size=7
		"3133bc0ff0e3f131955962142d11db8ac22b29f8edd7f891514a263bed17fcc8", // size=8
	}
	tree := New()
	for i, w := range want {
		tree.Append(fmt.Appendf(nil, "leaf-%d", i))
		if got := hex.EncodeToString(tree.Root()); got != w {
			t.Errorf("size=%d 根 = %s, want %s", i+1, got, w)
		}
	}
}
