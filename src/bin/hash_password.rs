//! 密码哈希生成工具
//! 用法: cargo run --bin hash_password -- <password>

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: cargo run --bin hash_password -- <password>");
        std::process::exit(1);
    }

    let password = &args[1];
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");

    println!("{}", hash.to_string());
}
