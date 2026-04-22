//! BPF RBAC Client CLI

use anyhow::Result;
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "create-map" => {
            if args.len() < 6 {
                eprintln!("Usage: bpf-rbac create-map <type> <name> <key_size> <value_size> [max_entries]");
                return Ok(());
            }

            let map_type = &args[2];
            let name = &args[3];
            let key_size: u32 = args[4].parse()?;
            let value_size: u32 = args[5].parse()?;
            let max_entries: u32 = args.get(6).map(|s| s.parse()).transpose()?.unwrap_or(1024);

            println!("Connecting to BPF RBAC daemon...");

            let mut client = bpf_rbacd::protocol::client::BpfRbacClient::connect()?;

            println!("Requesting map creation:");
            println!("  Type: {}", map_type);
            println!("  Name: {}", name);
            println!("  Key size: {} bytes", key_size);
            println!("  Value size: {} bytes", value_size);
            println!("  Max entries: {}", max_entries);

            let fd = client.create_map(map_type, name, key_size, value_size, max_entries)?;

            println!("\n✓ Success! BPF map created with FD: {}", fd);
            println!("\nYou can now use this FD to read/write map data.");
        }

        "status" => match bpf_rbacd::protocol::client::BpfRbacClient::connect() {
            Ok(_) => println!("✓ BPF RBAC daemon is running"),
            Err(e) => println!("✗ Daemon not available: {}", e),
        },

        _ => print_usage(),
    }

    Ok(())
}

fn print_usage() {
    eprintln!("BPF RBAC Client - Request BPF operations from daemon");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bpf-rbac create-map <type> <name> <key_size> <value_size> [max_entries]");
    eprintln!("  bpf-rbac status");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  bpf-rbac create-map hash my_map 4 8 1024");
    eprintln!("  bpf-rbac status");
    eprintln!();
    eprintln!("Map types: hash, array, lru_hash, ringbuf");
}
