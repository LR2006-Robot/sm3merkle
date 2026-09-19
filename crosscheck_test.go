package sm3merkle

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/transparency-dev/merkle/testonly"
)

// 用上游的参考树实现 + 本包的 SM3 哈希器，逐项比对本包 Tree 的输出。
// 两套树代码彼此独立，若本包的进位或证明组装有错，这里必然分叉。
// 这条用例的作用是消除 TestSM3GoldenRoots 的循环论证——那组固定值
// 原本只由本实现自己产生。
func TestAgainstUpstreamReferenceTree(t *testing.T) {
	const maxSize = 64
	data := make([][]byte, maxSize)
	for i := range data {
		data[i] = fmt.Appendf(nil, "entry-%d", i)
	}

	mine := New()
	ref := testonly.New(DefaultHasher)
	for i, d := range data {
		mine.Append(d)
		ref.AppendData(d)

		size := uint64(i + 1)
		if !bytes.Equal(mine.Root(), ref.Hash()) {
			t.Fatalf("size=%d 根不一致: 本包 %x, 上游参考实现 %x", size, mine.Root(), ref.Hash())
		}
	}

	for size := uint64(0); size <= maxSize; size++ {
		got, err := mine.RootAt(size)
		if err != nil {
			t.Fatal(err)
		}
		if want := ref.HashAt(size); !bytes.Equal(got, want) {
			t.Errorf("RootAt(%d) 不一致: 本包 %x, 上游 %x", size, got, want)
		}
	}

	for size := uint64(1); size <= maxSize; size++ {
		for index := uint64(0); index < size; index++ {
			got, err := mine.InclusionProof(index, size)
			if err != nil {
				t.Fatalf("本包 InclusionProof(%d,%d): %v", index, size, err)
			}
			want, err := ref.InclusionProof(index, size)
			if err != nil {
				t.Fatalf("上游 InclusionProof(%d,%d): %v", index, size, err)
			}
			if !equalProof(got, want) {
				t.Errorf("InclusionProof(%d,%d) 不一致:\n本包 %x\n上游 %x", index, size, got, want)
			}
		}
	}

	for size2 := uint64(1); size2 <= maxSize; size2++ {
		for size1 := uint64(1); size1 <= size2; size1++ {
			got, err := mine.ConsistencyProof(size1, size2)
			if err != nil {
				t.Fatalf("本包 ConsistencyProof(%d,%d): %v", size1, size2, err)
			}
			want, err := ref.ConsistencyProof(size1, size2)
			if err != nil {
				t.Fatalf("上游 ConsistencyProof(%d,%d): %v", size1, size2, err)
			}
			if !equalProof(got, want) {
				t.Errorf("ConsistencyProof(%d,%d) 不一致", size1, size2)
			}
		}
	}

	// 叶子哈希也要逐个对上。
	for i := range data {
		got, err := mine.LeafHash(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if want := ref.LeafHash(uint64(i)); !bytes.Equal(got, want) {
			t.Errorf("LeafHash(%d) 不一致", i)
		}
	}
}

func equalProof(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// 大规模追加：确认进位逻辑在层数增长时不会越界 panic，且证明仍然成立。
// 2049 跨过 2^11，能触发一次新层分配。
func TestLargeTreeNoPanic(t *testing.T) {
	const size = 2049
	tree := New()
	for i := range size {
		tree.Append(fmt.Appendf(nil, "entry-%d", i))
	}
	if tree.Size() != size {
		t.Fatalf("Size = %d, want %d", tree.Size(), size)
	}

	root := tree.Root()
	for _, index := range []uint64{0, 1, 1023, 1024, 2047, 2048} {
		pf, err := tree.InclusionProof(index, size)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", index, err)
		}
		if err := VerifyInclusionData(index, size, fmt.Appendf(nil, "entry-%d", index), pf, root); err != nil {
			t.Errorf("VerifyInclusionData(%d): %v", index, err)
		}
	}

	// 与上游参考实现在这个规模上也要一致。
	ref := testonly.New(DefaultHasher)
	for i := range size {
		ref.AppendData(fmt.Appendf(nil, "entry-%d", i))
	}
	if !bytes.Equal(root, ref.Hash()) {
		t.Errorf("size=%d 根与上游不一致", size)
	}
}
