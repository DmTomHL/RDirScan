use std::fs::File;
use std::io::{self, BufRead, Write, stdin};
use std::sync::Arc;
use std::time::Duration;
use std::collections::{HashSet, HashMap};
use tokio::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::*;
use futures::StreamExt;
use rand::seq::SliceRandom;
use reqwest::Client;
use reqwest::Proxy;
use url::Url;

/// 网站目录扫描工具
/// 作者: TomHe
#[derive(Parser, Debug)]
#[command(
    author = "TomHe",
    version,
    about = "网站目录扫描工具",
    long_about = "一个用于扫描网站目录的高性能工具。\n\
                  特性：\n\
                  - 支持多线程并发扫描\n\
                  - 随机 User-Agent\n\
                  - 支持自定义代理\n\
                  - 彩色输出结果\n\
                  - 自动保存结果到文件\n\
                  - 支持 HTTP/HTTPS\n\
                  - 自定义字典支持\n\
                  - 支持过滤误报页面\n\
                  - 自动检测WAF/登录页面"
)]
struct Args {
    /// 目标URL（例如：http://example.com）
    #[arg(short, long, help = "目标URL，必须包含 http:// 或 https://")]
    url: String,

    /// 字典文件路径
    #[arg(short, long, default_value = "Dir.txt", help = "扫描字典文件路径，每行一个路径，支持自定义")]
    dict: String,

    /// 代理服务器地址
    #[arg(short, long, help = "代理服务器地址（例如：socks5://127.0.0.1:1080）")]
    proxy: Option<String>,

    /// 请求超时时间（秒）
    #[arg(
        short = 'w', 
        long, 
        default_value = "10",
        help = "请求超时时间（秒），包括连接和读取时间"
    )]
    timeout: u64,

    /// 连接超时时间（秒）
    #[arg(
        short = 'c',
        long = "connect-timeout",
        default_value = "5",
        help = "连接超时时间（秒）"
    )]
    connect_timeout: u64,

    /// 并发线程数
    #[arg(
        short = 't', 
        long = "threads", 
        default_value = "10",
        help = "并发扫描的线程数，建议根据目标网站的承受能力调整"
    )]
    threads: usize,

    /// 误报过滤文件
    #[arg(
        short = 'f',
        long = "filter",
        help = "误报过滤文件路径，包含需要过滤的页面内容特征"
    )]
    filter_file: Option<String>,

    /// 禁用SSL证书验证
    #[arg(
        short = 'k',
        long = "insecure",
        help = "禁用SSL证书验证（不验证证书的有效性）",
        default_value = "false"
    )]
    insecure: bool,
}

#[derive(Clone)]
struct ScanState {
    content_signatures: HashSet<String>,
    // 记录响应大小和连续出现次数
    size_counter: HashMap<usize, usize>,
    // 记录已确认为WAF/登录页面的响应大小
    filtered_sizes: HashSet<usize>,
}

impl ScanState {
    fn new() -> Self {
        Self {
            content_signatures: HashSet::new(),
            size_counter: HashMap::new(),
            filtered_sizes: HashSet::new(),
        }
    }

    fn from_file(path: &str) -> Result<Self> {
        let mut state = Self::new();
        let file = File::open(path)
            .map_err(|e| anyhow!("打开过滤规则文件失败: {}", e))?;
        
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            state.content_signatures.insert(line.to_string());
        }
        Ok(state)
    }

    fn is_filtered(&self, content: &str, size: usize) -> bool {
        // 检查内容特征
        for signature in &self.content_signatures {
            if content.contains(signature) {
                return true;
            }
        }
        // 检查响应大小
        self.filtered_sizes.contains(&size)
    }

    async fn check_repeated_size(&mut self, size: usize) -> bool {
        // 更新计数器
        let count = self.size_counter.entry(size).or_insert(0);
        *count += 1;

        // 如果已经是已过滤的大小，直接返回true
        if self.filtered_sizes.contains(&size) {
            return true;
        }

        // 如果连续5次相同大小，询问用户
        if *count >= 5 && !self.filtered_sizes.contains(&size) {
            println!("\n{}", format!("检测到连续5次响应大小为 {} 字节的页面，这可能是WAF拦截或登录跳转页面。", size).yellow());
            print!("是否将该响应大小添加到过滤列表？(y/n): ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            if input.trim().eq_ignore_ascii_case("y") {
                self.filtered_sizes.insert(size);
                println!("{}", "已添加到过滤列表。".green());
                return true;
            } else {
                // 如果用户选择不过滤，重置计数器
                self.size_counter.remove(&size);
                println!("{}", "已取消过滤。".yellow());
            }
        }
        false
    }
}

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS;.NET CLR 4.0.30319) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edge/95.0.1020.40",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0",
    "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/90.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Edge/90.0.818.62",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; rv:43.0) Gecko/20100101 Firefox/43.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; AS; .NET CLR 4.0.30319) like Gecko",
];


fn get_random_user_agent() -> &'static str {
    USER_AGENTS.choose(&mut rand::thread_rng()).unwrap()
}

fn validate_url(url_str: &str) -> Result<String> {
    let url = Url::parse(url_str).map_err(|e| anyhow!("URL格式错误: {}", e))?;
    
    if !url.scheme().starts_with("http") {
        return Err(anyhow!("URL必须以 http:// 或 https:// 开头"));
    }

    if url.host_str().is_none() {
        return Err(anyhow!("URL必须包含有效的主机名"));
    }

    if let Some(port) = url.port() {
        let port_u32 = port as u32;
        if port_u32 > 65535 {
            return Err(anyhow!("端口号无效：端口号必须在 0-65535 之间"));
        }
    }

    Ok(url.to_string())
}

async fn check_path(
    client: &Client, 
    base_url: &str, 
    path: &str, 
    output_file: Arc<Mutex<File>>,
    scan_state: Arc<Mutex<ScanState>>
) -> Result<bool> {
    let base = Url::parse(base_url)
        .map_err(|e| anyhow!("基础URL解析失败: {}", e))?;
    
    let url = base.join(path)
        .map_err(|e| anyhow!("路径 '{}' 拼接失败: {}", path, e))?;
    
    let resp = match client
        .get(url.as_str())
        .header("User-Agent", get_random_user_agent())
        .send()
        .await {
            Ok(resp) => resp,
            Err(e) => {
                if e.is_timeout() {
                    return Err(anyhow!("请求超时"));
                }
                if e.is_connect() {
                    return Err(anyhow!("连接失败"));
                }
                return Err(anyhow!("请求失败: {}", e));
            }
        };

    let status = resp.status();
    
    if status.is_success() {
        let content = match resp.text().await {
            Ok(content) => content,
            Err(_) => return Err(anyhow!("读取响应内容失败")),
        };
        let content_length = content.len();
        
        // 检查是否需要过滤
        let mut state = scan_state.lock().await;
        let is_filtered = state.is_filtered(&content, content_length) || 
                         state.check_repeated_size(content_length).await;

        let message = format!("[+] 发现: {} (状态码: {}, 大小: {} 字节)", 
            url.as_str(), status, content_length);
        
        if is_filtered {
            println!("{}", message.purple());
        } else {
            println!("{}", message.red());
            // 仅在未过滤的情况下写入输出文件
            let mut file = output_file.lock().await;
            writeln!(file, "{} (大小: {} 字节)", url.as_str(), content_length)
                .map_err(|e| anyhow!("写入结果到文件失败: {}", e))?;
        }
        
        return Ok(true);
    }
    
    Ok(false)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 验证URL
    let base_url = validate_url(&args.url)
        .context("URL验证失败")?;

    // 初始化扫描
    let has_filter = args.filter_file.is_some();
    let scan_state = if let Some(ref filter_path) = args.filter_file {
        Arc::new(Mutex::new(ScanState::from_file(filter_path)?))
    } else {
        Arc::new(Mutex::new(ScanState::new()))
    };


    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .connect_timeout(Duration::from_secs(args.connect_timeout))
        .user_agent(get_random_user_agent())
        .danger_accept_invalid_certs(args.insecure);

    // 代理实现
    if let Some(ref proxy_url) = args.proxy {
        let proxy = Proxy::all(proxy_url)
            .map_err(|e| anyhow!("代理设置错误: {}", e))?;
        client_builder = client_builder.proxy(proxy);
    }

    let client = Arc::new(client_builder.build()
        .map_err(|e| anyhow!("HTTP客户端创建失败: {}", e))?);

    // 创建输出文件
    let output_file = Arc::new(Mutex::new(
        File::create("out.txt")
            .map_err(|e| anyhow!("创建输出文件失败: {}", e))?
    ));


    let file = File::open(&args.dict)
        .map_err(|e| anyhow!("打开字典文件失败: {}", e))?;
    let reader = io::BufReader::new(file);
    let paths: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .collect();

    if paths.is_empty() {
        return Err(anyhow!("字典文件为空或格式错误"));
    }

    println!("{}", "开始扫描...".green());
    println!("{}", format!("目标 URL: {}", base_url).cyan());
    println!("{}", format!("字典文件: {}", args.dict).cyan());
    println!("{}", format!("并发线程: {}", args.threads).cyan());
    println!("{}", format!("连接超时: {}秒", args.connect_timeout).cyan());
    println!("{}", format!("请求超时: {}秒", args.timeout).cyan());
    if let Some(ref proxy) = args.proxy {
        println!("{}", format!("使用代理: {}", proxy).cyan());
    }
    if has_filter {
        println!("{}", format!("已启用误报过滤").cyan());
    }
    if args.insecure {
        println!("{}", format!("已禁用SSL证书验证").yellow());
    }


    let futures = paths.into_iter().map(|path| {
        let client = Arc::clone(&client);
        let base_url = base_url.clone();
        let output_file = Arc::clone(&output_file);
        let scan_state = Arc::clone(&scan_state);
        async move {
            if let Err(e) = check_path(&client, &base_url, &path, output_file, scan_state).await {
                eprintln!("{}", format!("检查路径 {} 时出错: {}", path, e).yellow());
            }
        }
    });

   
    futures::stream::iter(futures)
        .buffer_unordered(args.threads)
        .collect::<Vec<()>>()
        .await;

    println!("{}", "\n扫描完成！结果已保存到 out.txt".green());
    Ok(())
}
