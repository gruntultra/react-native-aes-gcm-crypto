import Foundation
import CryptoKit

enum CryptoError: Error {
    case runtimeError(String)
}

@objc(AesGcmCrypto)
class AesGcmCrypto: NSObject {
    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }

    @objc(decryptData:withKey:error:)
    func decryptData(cipherData: Data, key: Data) throws -> Data {
        /*guard let ivData = Data(hexString: iv) else {
            throw CryptoError.runtimeError("Invalid iv")
        }
        guard let tagData = Data(hexString: tag) else {
            throw CryptoError.runtimeError("Invalid tag")
        }*/
        let ivSize = 12
        let tagSize = 16
        let entireSize = cipherData.count
        let ivData = cipherData[0...ivSize-1]
        let cipherSize = entireSize - tagSize
        let cipherData2 = cipherData[ivSize...cipherSize-1]
        let tagData = cipherData[cipherSize...entireSize-1]
        
        let skey = SymmetricKey(data: key)
        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: ivData),
                                               ciphertext: cipherData2,
                                               tag: tagData)
        let decryptedData = try AES.GCM.open(sealedBox, using: skey)
        return decryptedData
    }

    func encryptData(plainData: Data, key: Data) throws -> AES.GCM.SealedBox {
        let skey = SymmetricKey(data: key)
        return try AES.GCM.seal(plainData, using: skey)
    }

    @objc(decrypt:withKey:withResolver:withRejecter:)
    func decrypt(base64CipherText: String, key: String, resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            let keyData = Data(base64Encoded: key)!
            let decryptedData = try self.decryptData(cipherData: Data(base64Encoded: base64CipherText)!, key: keyData)
            
            resolve(String(decoding: decryptedData, as: UTF8.self))
        } catch CryptoError.runtimeError(let errorMessage) {
            reject("InvalidArgumentError", errorMessage, nil)
        } catch {
            reject("DecryptionError", "Failed to decrypt", error)
        }
    }

    @objc(encrypt:inBase64:withKey:withResolver:withRejecter:)
    func encrypt(plainText: String, inBase64: Bool, key: String, resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            let keyData = Data(base64Encoded: key)!
            let plainData = inBase64 ? Data(base64Encoded: plainText)! : plainText.data(using: .utf8)!
            let sealedBox = try self.encryptData(plainData: plainData, key: keyData)
            resolve(sealedBox.combined!.base64EncodedString())
        } catch CryptoError.runtimeError(let errorMessage) {
            reject("InvalidArgumentError", errorMessage, nil)
        } catch {
            reject("EncryptionError", "Failed to encrypt", error)
        }
    }
}
