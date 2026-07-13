mod cli;
mod inspection;
mod json_export;
mod models;
mod output;
mod progress;
mod scanner;
mod services;
mod ui;

use clap::Parser;
use cli::{Args, resolve_ports, validate_args};
use colored::Colorize;
use json_export::export_json;
use output::{print_scan_header, print_scan_output};
use scanner::{resolve_target, run_scan};
use std::io::{self, Write};
use ui::boot_sequence;

fn main() {
    boot_sequence();
    run_shell();
}

fn run_shell() {
    loop {
        print!("{}", "node://> ".cyan().bold());

        if io::stdout().flush().is_err() {
            break;
        }

        let mut input = String::new();

        match io::stdin().read_line(&mut input) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("{} {error}", "NODE ERROR:".red().bold());
                continue;
            }
        }

        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input {
            "exit" | "quit" => {
                println!("{}", "NODE LINK TERMINATED".yellow().bold());
                break;
            }

            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                continue;
            }

            "help" => {
                print_shell_help();
                continue;
            }

            _ => {}
        }

        let arguments = match shell_words::split(input) {
            Ok(arguments) => arguments,
            Err(error) => {
                eprintln!("{} {error}", "PARSE ERROR:".red().bold());
                continue;
            }
        };

        if arguments.first().map(String::as_str) != Some("scan") {
            eprintln!(
                "{} Unknown command. Type 'help'.",
                "NODE ERROR:".red().bold()
            );
            continue;
        }

        let clap_arguments =
            std::iter::once("protocol-node".to_string()).chain(arguments.into_iter().skip(1));

        match Args::try_parse_from(clap_arguments) {
            Ok(args) => execute_scan(args),
            Err(error) => {
                let _ = error.print();
            }
        }
    }
}

fn execute_scan(args: Args) {
    if let Err(error) = validate_args(&args) {
        eprintln!("{} {error}", "NODE ERROR:".red().bold());
        return;
    }

    let ports = match resolve_ports(&args) {
        Ok(ports) => ports,
        Err(error) => {
            eprintln!("{} {error}", "NODE ERROR:".red().bold());
            return;
        }
    };

    let ip = match resolve_target(&args.target) {
        Ok(ip) => ip,
        Err(error) => {
            eprintln!("{} {error}", "NODE ERROR:".red().bold());
            return;
        }
    };

    print_scan_header(&args, ip, ports.len());

    let scan_output = run_scan(&args, ip, ports);

    print_scan_output(&args, &scan_output);

    if let Some(json_path) = &args.json {
        match export_json(json_path, &args, ip, &scan_output) {
            Ok(()) => {
                println!(
                    "{} {}",
                    "ARCHIVE WRITTEN:".green().bold(),
                    json_path.display()
                );
            }

            Err(error) => {
                eprintln!("{} {error}", "ARCHIVE ERROR:".red().bold());
            }
        }
    }

    println!();
}

fn print_shell_help() {
    println!();
    println!("{}", "AVAILABLE NODE COMMANDS".magenta().bold());
    println!("  scan <target> [options]   Run a port scan");
    println!("  help                      Show this message");
    println!("  clear                     Clear the terminal");
    println!("  exit                      Terminate the node link");
    println!();

    println!("{}", "EXAMPLES".magenta().bold());
    println!("  scan example.com -p 80,443 --inspect");
    println!("  scan scanme.nmap.org --profile web");
    println!("  scan 127.0.0.1 -p 1-1024 --banners");
    println!();
}
