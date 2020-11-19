// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use bounty::{bounty_utils, selective_disclosure, vcl};

fn main() {
    bounty_utils::print_highlight("###########################");
    bounty_utils::print_highlight("## 欢迎来到证明验证靶场! ##");
    bounty_utils::print_highlight("###########################");
    bounty_utils::print_wide(
        "本靶场旨在，寻求不满足条件但仍能通过证明验证算法的漏洞输入。",
    );
    println!(
        "{}\n",
        "关于证明生成及验证的具体算法及实现，如需了解更多，\
         您可参考WeDPR-Lab-Core\\solution。"
    );
    println!("在此，我们提供了2个解决方案的证明验证靶场，分别为：");
    bounty_utils::print_alert2(
        "▶ 1. 可验证匿名账本（verifiable confidential ledger，vcl）",
        "▶ 2. 选择性披露（selective disclosure）",
    );

    println!();
    println!("现在请选择待挑战的靶场编号：▼▼▼");
    bounty_utils::print_alert2(
        "▶ 输入 \"1\" ：选择进入“vcl”验证靶场。",
        "▶ 输入 \"2\" ：选择进入“选择性披露”验证靶场。",
    );
    let mut choice = bounty_utils::wait_for_input();
    loop {
        if choice == "1" || choice.is_empty() {
            vcl::flow_vcl();
            break;
        } else if choice == "2" {
            selective_disclosure::flow_sd();
            break;
        } else {
            bounty_utils::print_alert("输入错误！请重新输入：");
            choice = bounty_utils::wait_for_input();
        }
    }
    println!();
    bounty_utils::print_alert("十分感谢您的试用！");
    println!(
        "\n{}\n\n{}\n{}\n",
        "关于WeDPR，如需了解更多，欢迎通过以下方式联系我们：",
        "1. 微信公众号【微众银行区块链】",
        "2. 官方邮箱【wedpr@webank.com】"
    );
    println!();
}
