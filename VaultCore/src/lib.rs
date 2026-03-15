extern crate libc;
use libc::{uint8_t, size_t};
pub mod crypto;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::slice;
use libc::{uint8_t, size_t};

// --- FFI EXPORTS ---

#[no_mangle]
pub extern "C" fn encrypt_vault_data(
    key_ptr: *const uint8_t,
    data_ptr: *const uint8_t,
    data_len: size_t,
    nonce_ptr: *const uint8_t,
    out_len: *mut size_t,
) -> *mut uint8_t {
    let key = unsafe { slice::from_raw_parts(key_ptr, 32) };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let nonce_bytes = unsafe { slice::from_raw_parts(nonce_ptr, 12) };

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.encrypt(nonce, data) {
        Ok(ciphertext) => {
            unsafe { *out_len = ciphertext.len() };
            let mut boxed_slice = ciphertext.into_boxed_slice();
            let ptr = boxed_slice.as_mut_ptr();
            std::mem::forget(boxed_slice); // Transfer ownership to Swift/C
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn decrypt_vault_data(
    key_ptr: *const uint8_t,
    cipher_ptr: *const uint8_t,
    cipher_len: size_t,
    nonce_ptr: *const uint8_t,
    out_len: *mut size_t,
) -> *mut uint8_t {
    let key = unsafe { slice::from_raw_parts(key_ptr, 32) };
    let cipher_text = unsafe { slice::from_raw_parts(cipher_ptr, cipher_len) };
    let nonce_bytes = unsafe { slice::from_raw_parts(nonce_ptr, 12) };

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, cipher_text) {
        Ok(plaintext) => {
            unsafe { *out_len = plaintext.len() };
            let mut boxed_slice = plaintext.into_boxed_slice();
            let ptr = boxed_slice.as_mut_ptr();
            std::mem::forget(boxed_slice);
            ptr
        }
        Err(_) => std::ptr::null_mut(), // Returns null if authentication tag is invalid
    }
}

/// Crucial: Swift must call this to free the memory Rust allocated
#[no_mangle]
pub extern "C" fn free_vault_buffer(ptr: *mut uint8_t, len: size_t) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}