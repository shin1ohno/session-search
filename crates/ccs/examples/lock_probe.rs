//! Test-only probe for Python flock interoperability; never shipped.
use std::fs::OpenOptions;
use std::io::{self, Write};

fn main() {
    let mut args = std::env::args().skip(1);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(args.next().expect("lock path"))
        .unwrap();
    if file.try_lock().is_err() {
        println!("blocked");
        std::process::exit(9);
    }
    println!("locked");
    io::stdout().flush().unwrap();
    if args.next().as_deref() == Some("hold") {
        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
    }
}
