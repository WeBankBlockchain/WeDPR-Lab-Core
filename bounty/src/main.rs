// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use wedpr_bounty::{scd, utils, vcl};

fn main() {
    utils::print_highlight("######################################");
    utils::print_highlight("## Welcome to WeDPR Bounty Program! ##");
    utils::print_highlight("######################################");
    utils::print_wide(
        "Your goal is to discover any malicious input\nthat can be used to \
         break the valid verification algorithm\nsuch as zero knowledge \
         proof, etc.",
    );
    println!(
        "{}\n",
        "Please refer to the code under `solution` directory for detailed \
         implementation."
    );
    println!("So far, we provide the playgrounds for the following solutions:");
    utils::print_alert2(
        "▶ Enter 1 to select VCL (Verifiable Confidential Ledger) (default \
         option).",
        "▶ Enter 2 to select SCD (Selective Certificate Disclosure).",
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
            utils::print_alert("Invalid input! Please try again:");
            choice = utils::wait_for_input();
        }
    }

    // TODO: Extract these common message printing to common/utils.
    println!(
        "\n{}\n\n{}\n",
        "Welcome to contact us for more information about WeDPR by the \
         following Email:",
        "wedpr@webank.com",
    );
    println!();
}
