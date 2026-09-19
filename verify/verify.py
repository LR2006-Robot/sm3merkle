#!/usr/bin/env python3
"""不依赖本项目任何 Go 代码的独立验证。

SM3 由 OpenSSL 提供（第三方 C 实现），树结构直接按 RFC 6962 §2.1 的
MTH / PATH 递归定义实现——与本项目 Go 代码里的增量进位算法是两种不同
的算法。两条路径若给出同一组结果，本项目的正确性才算被外部证据支持。

用法：python3 verify/verify.py      （需要 openssl 与 go 在 PATH 上）
"""
import functools
import pathlib
import subprocess
import sys


@functools.lru_cache(maxsize=None)
def sm3(data: bytes) -> bytes:
    return subprocess.run(["openssl", "dgst", "-sm3", "-binary"],
                          input=data, capture_output=True, check=True).stdout


def mth(entries):
    """RFC 6962 §2.1 的 Merkle Tree Hash。"""
    n = len(entries)
    if n == 0:
        return sm3(b"")
    if n == 1:
        return sm3(b"\x00" + entries[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return sm3(b"\x01" + mth(entries[:k]) + mth(entries[k:]))


def path(m, entries):
    """RFC 6962 §2.1.1 的 Merkle Audit Path。"""
    n = len(entries)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return path(m, entries[:k]) + [mth(entries[k:])]
    return path(m - k, entries[k:]) + [mth(entries[:k])]


def main() -> int:
    # 先确认这个 SM3 本身是对的：GB/T 32905-2016 的两个标准向量。
    vectors = [
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
    ]
    for data, want in vectors:
        if sm3(data).hex() != want:
            print(f"OpenSSL 的 SM3 未通过标准向量，验证无从谈起")
            return 1
    print("OpenSSL SM3 通过 GB/T 32905-2016 标准向量")

    root = pathlib.Path(__file__).resolve().parent.parent
    out = subprocess.run([r"go", "run", "./verify/dumpproofs"], cwd=root,
                         capture_output=True, text=True)
    if out.returncode != 0:
        print("go run 失败:\n" + out.stderr)
        return 1

    leaves = [f"leaf-{i}".encode() for i in range(9)]
    roots = proofs = bad = 0
    for line in out.stdout.splitlines():
        f = line.split()
        if f[0] == "root":
            size, got = int(f[1]), f[2]
            roots += 1
            if mth(leaves[:size]).hex() != got:
                bad += 1
                print(f"  根不一致 size={size}: Go={got} RFC={mth(leaves[:size]).hex()}")
        elif f[0] == "proof":
            index, size, got = int(f[1]), int(f[2]), f[3:]
            proofs += 1
            want = [h.hex() for h in path(index, tuple(leaves[:size]))]
            if want != got:
                bad += 1
                print(f"  证明不一致 index={index} size={size}\n    Go={got}\n    RFC={want}")

    print(f"比对 {roots} 个树根、{proofs} 条包含证明（size 1..9 全下标）")
    print("全部一致" if bad == 0 else f"{bad} 处不一致")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
