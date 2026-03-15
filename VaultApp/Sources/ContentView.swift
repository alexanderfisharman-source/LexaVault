import SwiftUI

struct ContentView: View {
    @State private var cardNumber: String = ""
    @State private var encryptedData: Data?
    @State private var isLocked: Bool = true
    
    // Hardcoded 32-byte key for demo (In reality, use Argon2 output)
    let demoKey: [UInt8] = Array(repeating: 0x01, count: 32)
    let demoNonce: [UInt8] = Array(repeating: 0x02, count: 12)

    var body: some View {
        VStack(spacing: 20) {
            Text("SURGICAL VAULT")
                .font(.system(.headline, design: .monospaced))
            
            if isLocked {
                Button("Unlock with FaceID") {
                    // Logic for LocalAuthentication goes here
                    isLocked = false
                }
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(8)
            } else {
                SecureField("Enter Credit Card", text: $cardNumber)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()

                HStack {
                    Button("Encrypt & Save") {
                        encryptedData = VaultEngine.shared.encrypt(text: cardNumber, key: demoKey, nonce: demoNonce)
                        cardNumber = "" // Clear memory
                    }
                    
                    Button("Decrypt") {
                        if let data = encryptedData {
                            cardNumber = VaultEngine.shared.decrypt(data: data, key: demoKey, nonce: demoNonce) ?? "Error"
                        }
                    }
                }
                
                if let data = encryptedData {
                    Text("Encrypted Hex:")
                        .font(.caption)
                    Text(data.map { String(format: "%02hhx", $0) }.joined())
                        .font(.system(.caption2, design: .monospaced))
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.gray.opacity(0.1))
                }
            }
        }
        .padding()
    }
}