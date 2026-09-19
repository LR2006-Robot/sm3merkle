package sm3merkle

import "github.com/transparency-dev/merkle/proof"

// 校验函数不需要整棵树，只要根哈希和证明——审计方、轻客户端用这组接口。

// VerifyInclusion 校验包含证明：leafHash 确实是大小为 size 的树中下标 index 的叶子，
// 且该树的根为 root。校验通过返回 nil。
func VerifyInclusion(index, size uint64, leafHash []byte, pf [][]byte, root []byte) error {
	return proof.VerifyInclusion(DefaultHasher, index, size, leafHash, pf, root)
}

// VerifyConsistency 校验一致性证明：根为 root1、大小为 size1 的树，
// 是根为 root2、大小为 size2 的树的前缀。校验通过返回 nil。
func VerifyConsistency(size1, size2 uint64, pf [][]byte, root1, root2 []byte) error {
	return proof.VerifyConsistency(DefaultHasher, size1, size2, pf, root1, root2)
}

// VerifyInclusionData 是 VerifyInclusion 的便利包装，直接收原始叶子数据。
func VerifyInclusionData(index, size uint64, data []byte, pf [][]byte, root []byte) error {
	return VerifyInclusion(index, size, DefaultHasher.HashLeaf(data), pf, root)
}
