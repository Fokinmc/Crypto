//
//  Crypto.swift
//  Crypto
//
//  Created by Alexander Naumov on 03.07.17.
//  Copyright © 2017 Alexander Naumov. All rights reserved.
//

import Foundation
import CommonCrypto


public extension String {
    public var md5: String {
        var bytes = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(self, CC_LONG(utf8.count), &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    public var sha256: String {
        var bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(self, CC_LONG(utf8.count), &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    
    public var sha256Data: Data {
        var bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(self, CC_LONG(utf8.count), &bytes)
        return Data(bytes: bytes)
    }
}
