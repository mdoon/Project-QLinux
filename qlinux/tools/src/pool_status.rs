use key_pool::KeyPoolManager;

fn main() {
    let pool = KeyPoolManager::default();
    match pool.available_bytes() {
        Ok(bytes) => println!("Key Pool 残量: {} bytes", bytes),
        Err(e)    => eprintln!("Key Pool エラー: {}", e),
    }
}
