use colored::Colorize;
use std::{
    io::{self, Write},
    thread,
    time::Duration,
};

fn pause(milliseconds: u64) {
    thread::sleep(Duration::from_millis(milliseconds));
}

fn flush_stdout() {
    io::stdout()
        .flush()
        .expect("failed to flush terminal output");
}

fn clear_terminal() {
    print!("\x1B[2J\x1B[1;1H");
    flush_stdout();
}

fn print_slow_line(text: &str, character_delay_ms: u64) {
    for character in text.chars() {
        print!("{character}");
        flush_stdout();
        pause(character_delay_ms);
    }

    println!();
}

fn print_logo() {
    println!();
    println!("{}", "             protocol".bright_black());

    let logo = [
        "███╗   ██╗ ██████╗ ██████╗ ███████╗",
        "████╗  ██║██╔═══██╗██╔══██╗██╔════╝",
        "██╔██╗ ██║██║   ██║██║  ██║█████╗",
        "██║╚██╗██║██║   ██║██║  ██║██╔══╝",
        "██║ ╚████║╚██████╔╝██████╔╝███████╗",
        "╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝",
    ];

    for line in logo {
        println!("{}", line.cyan().bold());
        pause(65);
    }

    println!();
    pause(200);
    println!("{}", "[ NODE LINK ESTABLISHED ]".green().bold());
    println!();
    pause(350);
}

fn print_wired_banner() {
    println!(
        "{}",
        "┌──────────────────────────────────────────────┐".magenta()
    );
    println!(
        "{}",
        "│        W I R E D   I N I T I A L I Z E D   │"
            .magenta()
            .bold()
    );
    println!(
        "{}",
        "└──────────────────────────────────────────────┘".magenta()
    );
    println!();
}

fn animate_loading_bar(width: usize, delay_ms: u64) {
    for completed in 0..=width {
        let filled = "█".repeat(completed);
        let empty = "░".repeat(width - completed);
        let percentage = completed * 100 / width;

        print!(
            "\r[{}{}] {:>3}%",
            filled.cyan(),
            empty.bright_black(),
            percentage
        );

        flush_stdout();
        pause(delay_ms);
    }

    println!();
}

fn print_initialisation_messages() {
    let messages = [
        "> Establishing node...",
        "> Synchronizing network...",
        "> Loading reconnaissance module...",
        "> Loading scanner engine...",
        "> Loading service fingerprints...",
        "> Loading cryptographic inspection...",
    ];

    for message in messages {
        print_slow_line(message, 10);
        pause(140);
    }

    println!();
}

fn print_status_panel() {
    println!(
        "{}",
        "┌──────────────────────────────────────────────┐".magenta()
    );

    println!(
        "{}",
        format!("│ PROTOCOL NODE v{:<28}│", env!("CARGO_PKG_VERSION"))
            .magenta()
            .bold()
    );

    println!(
        "{}",
        "│ RISC-V NETWORK RECONNAISSANCE INTERFACE     │".magenta()
    );

    println!(
        "{}",
        "│ STATUS: ONLINE                              │"
            .green()
            .bold()
    );

    println!(
        "{}",
        "└──────────────────────────────────────────────┘".magenta()
    );

    println!();
}

pub fn boot_sequence() {
    clear_terminal();

    print_logo();
    print_wired_banner();

    animate_loading_bar(40, 28);

    println!();
    print_initialisation_messages();

    pause(250);
    println!("{}", "CONNECTION ESTABLISHED".green().bold());
    println!();
    pause(350);

    print_status_panel();
}

pub fn print_shell_prompt() {
    print!("{}", "node://> ".cyan().bold());
    flush_stdout();
}

pub fn print_shell_help() {
    println!();
    println!("{}", "AVAILABLE NODE COMMANDS".magenta().bold());
    println!("{}", "-----------------------".magenta());

    println!(
        "  {:<28} {}",
        "scan <target> [options]".cyan(),
        "Run a TCP port scan"
    );

    println!("  {:<28} {}", "help".cyan(), "Display available commands");

    println!("  {:<28} {}", "clear".cyan(), "Clear the terminal");

    println!("  {:<28} {}", "exit".cyan(), "Terminate the node link");

    println!();
    println!("{}", "SCAN EXAMPLES".magenta().bold());
    println!("{}", "-------------".magenta());

    println!("  scan example.com -p 80,443 --inspect");
    println!("  scan scanme.nmap.org --profile web");
    println!("  scan 127.0.0.1 -p 1-1024 --banners");
    println!("  scan example.com -p 80,443 --inspect --json scan.json");
    println!();
}

pub fn print_goodbye() {
    println!();
    println!("{}", "NODE LINK TERMINATED".yellow().bold());
    println!("{}", "DISCONNECTING FROM WIRED...".bright_black());
    println!();
}