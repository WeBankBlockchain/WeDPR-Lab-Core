// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of bounty utility functions.

use colored::*;

pub fn print_highlight(message: &str) {
    println!("{}\n", message.green());
}

pub fn print_highlight2(message1: &str, message2: &str) {
    println!("{}\n{}", message1.green(), message2.green());
}

pub fn print_alert(message: &str) {
    println!("{}", message.yellow());
}

pub fn print_alert2(message1: &str, message2: &str) {
    println!("{}\n{}", message1.yellow(), message2.yellow());
}

pub fn print_alert3(message1: &str, message2: &str, message3: &str) {
    println!(
        "{}\n{}\n{}\n",
        message1.yellow(),
        message2.yellow(),
        message3.yellow()
    );
}

pub fn print_wide(message: &str) {
    println!("\n{}\n", message);
}

pub fn wait_for_input() -> String {
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line.");
    input.trim().to_string()
}

pub fn wait_for_number(error_message: &str) -> u64 {
    let mut input = wait_for_input();
    let mut input_num = input.parse::<u64>();
    loop {
        match input_num {
            Ok(v) if v <= u64::MAX => return v as u64,
            _ => {
                print_alert(error_message);
                input = wait_for_input();
                input_num = input.parse::<u64>();
            },
        }
    }
}

pub fn wait_for_number_cn() -> u64 {
    wait_for_number("请输入有效整数：")
}

pub fn pause(info_message: &str) {
    let mut enter_continue = String::new();
    print_wide(info_message);
    std::io::stdin()
        .read_line(&mut enter_continue)
        .expect("read_line should not fail");
    println!("... {}\n", enter_continue.trim());
}

pub fn pause_cn() {
    pause("按任意键继续...");
}
