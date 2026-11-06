use beebeeb_store::Store;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("write") => {
            let path = args.get(2).ok_or("missing database path")?;
            let writer = args.get(3).ok_or("missing writer name")?;
            let count: u32 = args.get(4).ok_or("missing write count")?.parse()?;
            let mut store = Store::open(path)?;
            for index in 0..count {
                store.append_op(writer, &index.to_be_bytes(), i64::from(index))?;
            }
        }
        Some("hold-write") => {
            let path = args.get(2).ok_or("missing database path")?;
            Store::open(path)?.close()?;
            let mut connection = rusqlite::Connection::open(path)?;
            let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            transaction.execute(
                "INSERT INTO op_log(kind,payload,created_at) VALUES ('test',X'00',0)",
                [],
            )?;
            println!("READY");
            std::io::stdout().flush()?;
            loop {
                std::thread::park();
            }
        }
        _ => return Err("unknown helper command".into()),
    }
    Ok(())
}
