import Foundation

class VaultEngine {
    static let shared = VaultEngine()
    
    func encrypt(text: String, key: [UInt8], nonce: [UInt8]) -> Data? {
        let inputData = Array(text.utf8)
        var outLen: Int = 0
        
        // Call the Rust function
        guard let resultPtr = encrypt_vault_data(key, inputData, inputData.count, nonce, &outLen) else {
            return nil
        }
        
        // Convert pointer to Swift Data object
        let data = Data(bytes: resultPtr, count: outLen)
        
        // IMMEDIATELY free the Rust memory to prevent leaks
        free_vault_buffer(resultPtr, outLen)
        
        return data
    }
    
    func decrypt(data: Data, key: [UInt8], nonce: [UInt8]) -> String? {
        let cipherBytes = [UInt8](data)
        var outLen: Int = 0
        
        guard let resultPtr = decrypt_vault_data(key, cipherBytes, cipherBytes.count, nonce, &outLen) else {
            return nil
        }
        
        let plainData = Data(bytes: resultPtr, count: outLen)
        free_vault_buffer(resultPtr, outLen)
        
        return String(data: plainData, encoding: .utf8)
    }
}