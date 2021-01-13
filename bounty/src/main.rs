// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use wedpr_bounty::{scd, utils, vcl};

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
    println!("目前，我们开放了以下两个解决方案的证明验证靶场：");
    utils::print_alert2(
        "▶ 1. 可验证匿名账本（Verifiable Confidential Ledger，VCL）",
        "▶ 2. 选择性认证披露（Selective Certificate Disclosure，SCD）",
    );

    println!("现在请选择待挑战的证明验证靶场编号：▼▼▼");
    utils::print_alert2(
        "▶ 输入 \"1\" 选择可验证匿名账本VCL（默认选项）",
        "▶ 输入 \"2\" 选择选择性认证披露SCD",
    );
    let mut choice = utils::wait_for_input();
    loop {
        if choice == "1" || choice.is_empty() {
            vcl::flow_vcl();
            break;
        } else if choice == "2" {
            scd::flow_scd();
            break;
        } else {
            utils::print_alert("输入错误！请重新输入：");
            choice = utils::wait_for_input();
        }
    }

    // TODO: Extract these common message printing to common/utils.
    println!(
        "\n{}\n\n{}\n{}\n",
        "关于WeDPR，如需了解更多，欢迎通过以下方式联系我们：",
        "1. 微信公众号【微众银行区块链】",
        "2. 官方邮箱【wedpr@webank.com】"
    );
    println!();
}
