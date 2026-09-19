// 把本包算出的树根与包含证明打印出来，供 verify.py 与独立实现比对。
// 由 verify/verify.py 自动调用，一般不需要手动运行。
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/LR2006-Robot/sm3merkle"
)

const maxSize = 9

func main() {
	tree := sm3merkle.New()
	for i := range maxSize {
		tree.Append(fmt.Appendf(nil, "leaf-%d", i))
		fmt.Printf("root %d %s\n", i+1, hex.EncodeToString(tree.Root()))
	}
	for size := uint64(1); size <= maxSize; size++ {
		for index := uint64(0); index < size; index++ {
			pf, err := tree.InclusionProof(index, size)
			if err != nil {
				panic(err)
			}
			fmt.Printf("proof %d %d", index, size)
			for _, h := range pf {
				fmt.Printf(" %s", hex.EncodeToString(h))
			}
			fmt.Println()
		}
	}
}
