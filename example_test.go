package sm3merkle_test

import (
	"fmt"

	"github.com/LR2006-Robot/sm3merkle"
)

// 日志方追加数据、发布树根，审计方只凭树根和证明验证某条数据确实在日志里。
func Example_inclusion() {
	tree := sm3merkle.New()
	for _, entry := range []string{"cert-A", "cert-B", "cert-C", "cert-D"} {
		tree.Append([]byte(entry))
	}

	size := tree.Size()
	root := tree.Root() // 对外发布的树根（实际场景中由 SM2 签名背书）

	// 证明第 2 条数据在日志中。
	pf, err := tree.InclusionProof(2, size)
	if err != nil {
		panic(err)
	}

	// 审计方手里只有 root、size 和这份证明。
	err = sm3merkle.VerifyInclusionData(2, size, []byte("cert-C"), pf, root)
	fmt.Println("cert-C 校验:", err)

	err = sm3merkle.VerifyInclusionData(2, size, []byte("cert-X"), pf, root)
	fmt.Println("伪造数据校验通过:", err == nil)

	// Output:
	// cert-C 校验: <nil>
	// 伪造数据校验通过: false
}

// 一致性证明用来确认日志只做了追加，历史条目没有被悄悄改写。
func Example_consistency() {
	tree := sm3merkle.New()
	for _, entry := range []string{"v1", "v2", "v3"} {
		tree.Append([]byte(entry))
	}
	oldSize, oldRoot := tree.Size(), tree.Root()

	for _, entry := range []string{"v4", "v5"} {
		tree.Append([]byte(entry))
	}
	newSize, newRoot := tree.Size(), tree.Root()

	pf, err := tree.ConsistencyProof(oldSize, newSize)
	if err != nil {
		panic(err)
	}
	err = sm3merkle.VerifyConsistency(oldSize, newSize, pf, oldRoot, newRoot)
	fmt.Println("仅追加校验:", err)

	// Output:
	// 仅追加校验: <nil>
}
