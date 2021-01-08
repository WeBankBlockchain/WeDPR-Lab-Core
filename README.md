# 项目背景

![WeDPR](https://wedpr-lab.readthedocs.io/zh_CN/latest/_static/images/wedpr_logo.png)

WeDPR是一系列**即时可用场景式**隐私保护高效解决方案套件和服务（参见[WeDPR白皮书](https://mp.weixin.qq.com/s?__biz=MzU0MDY4MDMzOA==&mid=2247483910&idx=1&sn=7b647dec9f046f1e6f94d103897f7efb&scene=19#wechat_redirect)），由微众银行区块链团队自主研发。方案致力于解决业务数字化中隐私不“隐”、共享协作不可控等隐私保护风险痛点，消除隐私主体的隐私顾虑和业务创新的合规壁垒，助力基于隐私数据的核心价值互联和新兴商业探索，营造公平、对等、共赢的多方数据协作环境，达成数据价值跨主体融合和数据治理的可控平衡。

WeDPR具备以下特色和优势：

- **场景式解决方案**：已基于具有共性的场景需求，提炼出公开可验证密文账本、多方密文决策、多方密文排名、多方密文计算、多方安全随机数生成、选择性密文披露等高效技术方案框架模板，可应用于支付、供应链金融、跨境金融、投票、选举、榜单、竞拍、招标、摇号、抽检、审计、隐私数据聚合分析、数字化身份、数字化资质凭证、智慧城市、智慧医疗等广泛业务场景。
- **即时可用**：高性能、高易用、跨平台跨语言实现、不依赖中心化可信服务、不依赖可信硬件、支持国密算法标准、隐私效果公开可验证，5分钟一键构建示例应用。
- **透明可控**：隐私控制回归属主，杜绝数据未授权使用，在『数据可用而不可见』的基础上，进一步实现数据使用全程可监管、可追溯、可验证。

WeDPR全面拥抱开放，将陆续开源一系列核心算法组件，进一步提升系统安全性的透明度，提供更透明、更可信的隐私保护效果。WeDPR-Lab就是这一系列开源的**核心算法组件**的集合。

本次开源（v1.3.0版本），新增密钥生成及管理功能，具体包含以下核心算法组件：
 1.	密钥生成及管理的核心算法，包括：
     	密钥助记词的生成
     	基于助记词的密钥生成
     	基于分层结构的密钥派生
 2.	Rust SDK，封装底层算法，提供易用、易扩展、跨语言的编程接口；
 3.	FFI接口，支持交叉编译跨语言、跨平台所调用的FFI适配接口；
 4.	其他基础工具代码。


我们期望能够通过代码开源的方式：

- 有效降低使用隐私保护算法组件的技术门槛；
- 减少业务系统集成隐私保护特性的开发成本；
- 助力全行业伙伴安全、合规地开展数据业务。

欢迎社区伙伴参与WeDPR-Lab的共建，一起为可信开放数字新生态的构建打造坚实、可靠的技术底座。

## 安装

### 安装Rust环境

安装nightly版本的Rust开发环境，可参考[Rust官方文档](https://www.rust-lang.org/zh-CN/tools/install)。

### 下载WeDPR-Lab源代码

使用git命令行工具，执行如下命令。

```bash
git clone https://github.com/WeBankBlockchain/WeDPR-Lab-Core.git
```

## 接口文档

### 生成并查看Rust SDK接口文档

在本项目的根目录（即`WeDPR-Lab-Core`目录）中，运行如下命令。

```bash
cargo doc --no-deps
```

以上命令将根据代码中的注释，在`target/doc`子目录中，生成的SDK接口文档。

进入`target/doc`文档目录后，会看到所有SDK相关的包名（包含WeDPR-Lab和其他依赖包），进入其中任意一个包名的目录，用网页浏览器打开其中的`index.html`文件，便可查看WeDPR-Lab相关的接口说明。

## 其他相关文档

- [WeDPR方案白皮书](https://mp.weixin.qq.com/s?__biz=MzU0MDY4MDMzOA==&mid=2247483910&idx=1&sn=7b647dec9f046f1e6f94d103897f7efb&scene=19#wechat_redirect)
- [WeDPR-Lab用户文档](https://wedpr-lab.readthedocs.io/zh_CN/latest/index.html)

## 项目贡献

- 点亮我们的小星星(点击项目右上方Star按钮)
- 提交代码(Pull Request)，参考我们的代码[贡献流程](./CONTRIBUTING.md)
- [提问和提交BUG](https://github.com/WeBankBlockchain/WeDPR-Lab-Core/issues)
