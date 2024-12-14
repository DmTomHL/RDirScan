# RDirScan - Web目录扫描工具

RDirScan 是一个用 Rust 编写的高性能Web目录扫描工具，具有智能WAF检测、误报过滤等特性。

其实就是半夜没事干整了这么一个，我也不知道叫什么名字好了

就是练手的项目，也没啥闪光点

大家晚安

## 特性

- 🚀 高性能异步并发扫描
- 🛡️ WAF/登录页面检测(人肉)
- 🔍 支持自定义误报过滤规则
- 🌈 彩色终端输出
- 🔒 支持SSL证书验证控制
- 🌐 支持HTTP代理
- ⏱️ 可配置的超时控制

## 安装

```bash
cargo build --release
```

编译后的可执行文件位于 `target/release/rdirscan`。

## 使用方法

基本用法：
```bash
rdirscan -u <目标URL> -d <字典文件>
```

完整参数：
```bash
USAGE:
    rdirscan [OPTIONS] --url <URL> --dict <字典文件>

OPTIONS:
    -u, --url <URL>              目标URL
    -d, --dict <FILE>            字典文件路径
    -t, --threads <NUMBER>       并发线程数 [默认: 10]
    -f, --filter <FILE>          误报过滤规则文件
    -p, --proxy <URL>           HTTP代理地址
    -k, --insecure              禁用SSL证书验证
    --timeout <SECONDS>         请求超时时间 [默认: 10]
    --connect-timeout <SECONDS> 连接超时时间 [默认: 5]
    -h, --help                  显示帮助信息
```

## 输出说明

程序使用不同颜色标记不同类型的输出：

- 🟢 绿色：成功信息
- 🔴 红色：有效发现
- 🟣 紫色：被过滤的页面
- 🟡 黄色：警告信息
- 🔵 青色：配置信息

## 无用信息筛选

工具会自动检测可能的WAF或登录页面：

1. 当连续5次遇到相同大小的响应时，会询问是否为WAF或跳转到页面
2. 用户确认后，相同大小的响应将被标记为紫色并过滤
3. 用户否认则重置计数器继续扫描

## 误报过滤

支持两种过滤方式：

1. 基于内容特征过滤：
   - 通过 `-f` 参数指定过滤规则文件
   - 文件中每行一个特征，支持正则表达式

2. 基于响应大小过滤：
   - 通过WAF检测功能自动添加
   - 运行时动态维护过滤列表

## 示例

1. 基本扫描：
```bash
rdirscan -u http://example.com -d dict.txt
```

2. 启用误报过滤：
```bash
rdirscan -u http://example.com -d dict.txt -f filter.txt
```

3. 使用代理：
```bash
rdirscan -u http://example.com -d dict.txt -p http://127.0.0.1:8080
```

4. 忽略SSL证书错误：
```bash
rdirscan -u https://example.com -d dict.txt -k
```

5. 调整并发和超时：
```bash
rdirscan -u http://example.com -d dict.txt -t 20 --timeout 15 --connect-timeout 8
```

## 许可证

MIT License
