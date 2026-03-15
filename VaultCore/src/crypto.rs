use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

/// Derives a 256-bit key from a password and a salt.
pub fn derive_key(password: &str, salt: &str) -> [u8; 32] {
    let mut output_key = [0u8; 32];
    
    // Salt must be at least 8 characters for Argon2
    let salt_obj = SaltString::from_b64(salt).expect("Invalid salt format");
    let argon2 = Argon2::default();
    
    let hash = argon2.hash_password(password.as_bytes(), &salt_obj)
        .expect("Failed to hash password");
    
    let hash_bytes = hash.hash.expect("Failed to retrieve hash bytes").as_bytes();
    
    // Ensure we take exactly 32 bytes for AES-256
    output_key.copy_from_slice(&hash_bytes[..32]);
    output_key
}