# 练手用的 LSM-BPF 模块

## Quick Start

### 环境

- clang
    - 我的在 clang15，但是理论上略微旧一点没关系。如果提示头文件缺失或者是不支持 bpf target，请升级
- kernel with BTF
    - 参考：https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md
- golang 1.17+
- bpftool
    - `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
- bpf2go
    - cilium 的工具

### 启动

- 一个终端
  ```bash
  go build -o bin/demo
  sudo ./bin/demo $PWD
  ```
- 另一个终端
  ```bash
  watch ls
  ```
- 如果要看日志（不要tail）
  ```bash
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```

## 代码解释

### 内核态的 eBPF 程序： [./bpf/lsm.c](./bpf/lsm.c)

内核态程序主要是三部分：
- 生成的 BTF 定义，这个理论上可以在支持 BTF 的发行版上直接用，不需要改
- map: 内核和用户态通信的数据结构
- hook: 入口点

和普通的 C 非常像，可以当 C 来写。但是栈空间只有 512 B。我没打错，就 512 Byte。

#### BTF 定义生成

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

#### map

map 不在栈空间中，一般用来让
- 用户态配置 eBPF 程序
- eBPF 程序向用户态传递结果或者性能数据

参考
- https://docs.kernel.org/bpf/maps.html#map-types

#### hook

hook 就是一个函数，可以配置为在特定时机被 hook 点调起。

我们这个 demo 主要是希望尝试写 lsm 模块，比如说和 file_open 这个 hook 有关的信息在
- https://github.com/torvalds/linux/blob/master/security/security.c#L2793

主要是需要关注 hook 需要接受的参数。

也有很多其他的 hook 点，比如说 kprobe 和 xdp 有关的。我们这个仓库暂时不关心。

### 用户态

用户态我选择了用 cilium 的 wrapper，理论上可以用 libbpf 啊或者类似的其他工具来实现。

### 构建

整体来说项目是
- （一次性）生成 vmlinux.h
- bpf2go 工具编译 ebpf 字节码，生成 stub
- 编译 go 的二进制
- 
