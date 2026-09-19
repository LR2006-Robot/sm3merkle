# sm3merkle

基于 **SM3（GB/T 32905-2016）** 的 RFC 6962 Merkle 树，全国密场景可用。

哈希策略与 RFC 6962 逐字对齐，只把 SHA-256 换成 SM3：

| 用途 | 公式 |
| --- | --- |
| 空树根 | `SM3()` |
| 叶子节点 | `SM3(0x00 ‖ 数据)` |
| 内部节点 | `SM3(0x01 ‖ 左子哈希 ‖ 右子哈希)` |

`0x00` / `0x01` 是域分离前缀，用来阻断第二原像攻击 —— 没有它，攻击者可以把一个内部节点的哈希当作叶子数据提交，伪造出同样的树根。

## 为什么不是从零实现

Merkle 证明的下标数学（哪些节点进证明、怎么重算）是这类库最容易写错的部分。本项目**不重写**它，而是直接复用 [`transparency-dev/merkle`](https://github.com/transparency-dev/merkle) —— Certificate Transparency 的上游实现，经过多年生产验证和 fuzz。

本项目只提供两样东西：

1. **SM3 哈希层**（`hasher.go`，约 30 行）—— 实现上游的 `merkle.LogHasher` 接口
2. **一棵内存树**（`tree.go`）—— 上游刻意不提供存储，这里补上，并把越界 panic 换成错误返回

上游那个 `testonly` 包里确实有一棵可用的内存树，但它的名字就是契约：随时可能变、越界直接 panic。所以这部分自己写，底下调用的仍是上游的稳定 API（`proof.Inclusion` / `proof.Consistency` / `Nodes.Rehash` / `compact.RangeNodes`）。

## 安装

```bash
go get github.com/LR2006-Robot/sm3merkle
```

## 快速开始

```go
tree := sm3merkle.New()
for _, entry := range []string{"cert-A", "cert-B", "cert-C", "cert-D"} {
    tree.Append([]byte(entry))
}

size, root := tree.Size(), tree.Root()   // 对外发布的树根

// 日志方生成证明
pf, err := tree.InclusionProof(2, size)

// 审计方只凭 root / size / pf 校验，不需要整棵树
err = sm3merkle.VerifyInclusionData(2, size, []byte("cert-C"), pf, root)
```

完整用法见 [docs/USAGE.md](docs/USAGE.md)，含持久化恢复、SM2 签名树根、超出内存的日志三节。

## API

**哈希层**

| 名称 | 说明 |
| --- | --- |
| `Hasher` / `DefaultHasher` | SM3 版 RFC 6962 哈希策略，实现 `merkle.LogHasher` |
| `HashSize` | 32 |
| `LeafPrefix` / `NodePrefix` | `0x00` / `0x01` |

**树**（需要持有全部数据的一方使用）

| 方法 | 说明 |
| --- | --- |
| `New()` / `NewWithHasher(h)` | 构造空树 |
| `Append(data) uint64` | 追加数据，返回叶子下标 |
| `AppendHash(leafHash) uint64` | 追加已算好的叶子哈希，用于从存储重建 |
| `Size()` / `Root()` | 当前叶子数 / 当前树根 |
| `RootAt(size)` | 历史某个大小时的树根 |
| `LeafHash(index)` | 指定叶子的哈希 |
| `InclusionProof(index, size)` | 包含证明 |
| `ConsistencyProof(size1, size2)` | 一致性证明 |

**校验**（审计方 / 轻客户端使用，不需要树）

| 函数 | 说明 |
| --- | --- |
| `VerifyInclusion(index, size, leafHash, pf, root)` | 校验包含证明 |
| `VerifyInclusionData(index, size, data, pf, root)` | 同上，直接收原始数据 |
| `VerifyConsistency(size1, size2, pf, root1, root2)` | 校验仅追加性质 |

## 测试

```bash
go test ./...
```

验证分三层：

- **树逻辑** —— 把 SHA-256 哈希器塞进同一棵 `Tree`，逐一比对 CT 官方黄金根哈希（`testonly.RootHashes`）。树的形状、进位、证明组装有任何偏差都会暴露，这一层与 SM3 无关。
- **SM3 层** —— 三条哈希公式逐条对照 `sm3.Sum` 手算；另有一条 4 叶子树根完全手工按 RFC 6962 结构算出，不经过 `Tree` 的进位逻辑，作为独立交叉验证；并确认域分离前缀确实阻断了叶子与内部节点的碰撞。
- **证明** —— 1..17 全部规模 × 全部下标的包含证明与一致性证明，每条都附带反向用例（改数据、翻 bit、换错根必须验不过）；外加持久化重建一致性与越界返回错误。

## 已知边界

- `Tree` 全部节点常驻内存，约 `2N` 个 32 字节哈希 —— 百万叶子约 64MB。更大的日志见 USAGE 最后一节。
- `Tree` **非并发安全**，多 goroutine 访问请自行加锁。
- 树根本身不含签名。生产用法应由 SM2 对 `(size, root, 时间戳)` 签名后发布，否则日志方可以随意换根。见 USAGE。

## 许可

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
