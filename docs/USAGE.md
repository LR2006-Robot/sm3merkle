# 操作文档

- [1. 两种角色](#1-两种角色)
- [2. 日志方：追加与发布](#2-日志方追加与发布)
- [3. 审计方：校验](#3-审计方校验)
- [4. 持久化与重建（SQLite）](#4-持久化与重建sqlite)
- [5. 用 SM2 给树根签名](#5-用-sm2-给树根签名)
- [6. 叶子数据该放什么（JCS）](#6-叶子数据该放什么jcs)
- [7. 超出内存的日志](#7-超出内存的日志)
- [8. 错误与边界](#8-错误与边界)

## 1. 两种角色

这类日志系统里始终是两种角色，本库的 API 也按这条线切开：

| 角色 | 持有 | 用到的 API |
| --- | --- | --- |
| **日志方** | 全部数据 | `Tree` 的全部方法 |
| **审计方 / 客户端** | 只有树根和一份证明 | `VerifyInclusion*` / `VerifyConsistency` |

校验函数是包级函数、不依赖 `Tree`，就是为了让审计方那一侧可以完全不持有数据。

## 2. 日志方：追加与发布

```go
tree := sm3merkle.New()

index := tree.Append([]byte("entry-1"))   // 返回该条目的叶子下标
tree.Append([]byte("entry-2"))

size := tree.Size()
root := tree.Root()
```

`Append` 返回的下标要和数据一起存下来 —— 生成包含证明时必须提供它。

**`Root()` vs `RootAt(size)`**：前者是当前树根；后者是「树长到 size 时的根」，用于补发历史证明和一致性证明。两者在 `size == Size()` 时相等。

## 3. 审计方：校验

```go
// 包含证明：entry 确实是大小为 size 的树中下标 index 的叶子
err := sm3merkle.VerifyInclusionData(index, size, data, pf, root)

// 已经有叶子哈希时用这个，省掉一次哈希
err := sm3merkle.VerifyInclusion(index, size, leafHash, pf, root)

// 一致性证明：老树是新树的前缀，即日志只追加、没改写历史
err := sm3merkle.VerifyConsistency(oldSize, newSize, pf, oldRoot, newRoot)
```

`err == nil` 即通过。**证明的 size 必须与生成时一致** —— 同一个下标在不同 size 下的证明不同，拿 size=10 的证明去配 size=11 的根一定失败，这是正确行为而不是 bug。

## 4. 持久化与重建（SQLite）

`Tree` 是纯内存的，进程重启就没了。恢复不需要原始数据，只要按下标顺序存好**叶子哈希**。

建表：

```sql
CREATE TABLE leaves (
    idx  INTEGER PRIMARY KEY,   -- 叶子下标，必须连续且从 0 开始
    hash BLOB NOT NULL,         -- 32 字节 SM3 叶子哈希
    data BLOB NOT NULL          -- 原始数据，按需
);
```

写入：

```go
index := tree.Append(data)
leafHash, _ := tree.LeafHash(index)
_, err := db.Exec(`INSERT INTO leaves (idx, hash, data) VALUES (?, ?, ?)`,
    index, leafHash, data)
```

重建：

```go
rows, err := db.Query(`SELECT hash FROM leaves ORDER BY idx`)
if err != nil {
    return nil, err
}
defer rows.Close()

tree := sm3merkle.New()
for rows.Next() {
    var h []byte
    if err := rows.Scan(&h); err != nil {
        return nil, err
    }
    tree.AppendHash(h)   // 注意是 AppendHash，不是 Append
}
return tree, rows.Err()
```

三个坑：

- **`ORDER BY idx` 不能省。** SQLite 不保证返回顺序，顺序错了树根就错了，而且不会报错。
- **下标必须连续无缺口。** 这是仅追加日志，中间删一条会让后面所有证明失效。别对 `leaves` 做 `DELETE`。
- **喂 `AppendHash` 而不是 `Append`。** 传原始数据进 `AppendHash` 会把数据当成哈希用，树根静默错误。

重建后建议比对一下树根与上次发布的是否一致，作为数据完整性自检。

## 5. 用 SM2 给树根签名

裸树根没有任何约束力 —— 日志方可以换一个根、重算所有证明，审计方看不出来。生产用法是对 `(size, root)` 连同时间戳签名后发布：

```go
import (
    "crypto/rand"
    "encoding/binary"

    "github.com/emmansun/gmsm/sm2"
)

// 把 size 和 root 一起签，避免把某个根挪用到别的 size 上
func signRoot(key *sm2.PrivateKey, size uint64, root []byte) ([]byte, error) {
    msg := binary.BigEndian.AppendUint64(nil, size)
    msg = append(msg, root...)
    return key.Sign(rand.Reader, msg, nil)
}

func verifyRoot(pub *sm2.PublicKey, size uint64, root, sig []byte) bool {
    msg := binary.BigEndian.AppendUint64(nil, size)
    msg = append(msg, root...)
    return sm2.VerifyASN1(pub, msg, sig)
}
```

`size` 必须进签名内容。只签 `root` 的话，攻击者可以把一个小树的根冒充成大树的根。

## 6. 叶子数据该放什么（JCS）

叶子如果是 JSON，**必须先规范化再算哈希**，否则同一份语义数据因键序或空白不同会得出不同的叶子哈希，证明随即失效：

```go
import "github.com/gowebpki/jcs"

canonical, err := jcs.Transform(rawJSON)   // RFC 8785
if err != nil {
    return err
}
index := tree.Append(canonical)
```

原始字节和规范化后的字节都建议存，前者用于回溯，后者是哈希的真实输入。

## 7. 超出内存的日志

`Tree` 把全部节点哈希留在内存里，约 `2N` 个 32 字节哈希（百万叶子约 64MB）。超过这个量级就别用 `Tree` 了，换成上游的 `compact.Range` 配合外部节点存储：

```go
import "github.com/transparency-dev/merkle/compact"

rf := &compact.RangeFactory{Hash: sm3merkle.DefaultHasher.HashChildren}
rng := rf.NewEmptyRange(0)

// visitor 在每个新节点产生时被调用，这里把它写进你的存储
err := rng.Append(sm3merkle.DefaultHasher.HashLeaf(data), func(id compact.NodeID, hash []byte) {
    saveNode(id.Level, id.Index, hash)
})
```

生成证明时用 `proof.Inclusion(index, size)` 拿到需要的节点地址，从存储里取出对应哈希，再用 `nodes.Rehash(hashes, sm3merkle.DefaultHasher.HashChildren)` 组装。

**哈希层可以原样复用** —— `sm3merkle.DefaultHasher` 就是上游的 `merkle.LogHasher`，换存储不影响任何哈希语义，树根与 `Tree` 算出来的完全一致。

## 8. 错误与边界

| 情形 | 行为 |
| --- | --- |
| `LeafHash(index)`，`index >= Size()` | 返回错误 |
| `RootAt(size)` / 各证明方法，`size > Size()` | 返回错误 |
| `InclusionProof(index, size)`，`index >= size` | 返回上游错误 |
| `ConsistencyProof(size1, size2)`，`size1 > size2` | 返回上游错误 |
| 空树 `Root()` | 返回 `SM3()`，非 nil |

`Root()` 是唯一会 panic 的方法，且只在内部状态损坏时触发（正常路径走不到）。其余越界一律返回错误。

`Tree` **非并发安全**。典型写法是日志方单 goroutine 串行追加，或在外层包一把 `sync.RWMutex`：写操作（`Append` / `AppendHash`）加写锁，读操作（`Root` / 各证明方法）加读锁。
