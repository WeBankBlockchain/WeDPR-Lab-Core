// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use wedpr_bounty::{utils, vcl};

fn main() {
    // TODO: Translate instructions to English.
    utils::print_highlight("###########################");
    utils::print_highlight("## 欢迎来到证明验证靶场! ##");
    utils::print_highlight("###########################");
    utils::print_wide(
        "本靶场旨在，寻求不满足条件但仍能通过证明验证算法的漏洞输入。",
    );
    println!(
        "{}\n",
        "关于证明生成及验证的具体算法及实现，如需了解更多，\
         您可参考WeDPR-Lab-Core\\solution。"
    );
    println!("目前，我们开放了以下个解决方案的证明验证靶场：");
    utils::print_alert(
        "▶ 1. 可验证匿名账本（verifiable confidential ledger，vcl）",
    );

    vcl::flow_vcl();

    // TODO: Extract these common message printing to common/utils.
    println!(
        "\n{}\n\n{}\n{}\n",
        "关于WeDPR，如需了解更多，欢迎通过以下方式联系我们：",
        "1. 微信公众号【微众银行区块链】",
        "2. 官方邮箱【wedpr@webank.com】"
    );
    println!();
}
