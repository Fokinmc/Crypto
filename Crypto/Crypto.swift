//
//  Crypto.swift
//  Crypto
//
//  Created by Alexander Naumov on 03.07.17.
//  Copyright © 2017 Alexander Naumov. All rights reserved.
//

import Foundation
import OpenSSL

public extension String {
    public var md5: String {
        var bytes = [UInt8](repeating: 0, count: Int(MD5_DIGEST_LENGTH))
        MD5(self, utf8.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    public var sha256: String {
        var bytes = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        SHA256(self, utf8.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    
    public var sha256Data: Data {
        var bytes = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        SHA256(self, utf8.count, &bytes)
        return Data(bytes: bytes)
    }
}

public extension Data {
    public var sha1: String {
        let data = [UInt8](self)
        var bytes = [UInt8](repeating: 0, count: Int(SHA_DIGEST_LENGTH))
        SHA1(data, data.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

enum SignatureError: Error {
    case p12IncorrectData
    case incorrectBio(String)
    case readingP12
    case parsingP12
    case certIncorrectData
    case parsingCert
    case signingData
    case writingData
}

public func signature(manifest: Data, signaturePath: URL, p12Base64: String, p12pass: String, caCertBase64: String) throws {
    
    OPENSSL_load()
    
    guard let p12Bytes = Data(base64Encoded: p12Base64) as NSData? else { throw SignatureError.p12IncorrectData }
    guard let p12bio = BIO_new_mem_buf(p12Bytes.bytes, Int32(p12Bytes.length)) else { throw SignatureError.incorrectBio("p12") }
    defer { BIO_free(p12bio) }
    
    guard let p12 = d2i_PKCS12_bio(p12bio, nil) else { throw SignatureError.readingP12 }
    defer { PKCS12_free(p12) }
    
    var signcert: UnsafeMutablePointer<X509>?
    var pkey: UnsafeMutablePointer<EVP_PKEY>?
    
    guard PKCS12_parse(p12, p12pass, &pkey, &signcert, nil) == 1 else { throw SignatureError.parsingP12 }
    defer { EVP_PKEY_free(pkey); X509_free(signcert) }
    
    let manifest = manifest as NSData
    guard let manifestBio = BIO_new_mem_buf(manifest.bytes, Int32(manifest.length)) else { throw SignatureError.incorrectBio("manifest") }
    defer { BIO_free(manifestBio) }
    
    guard let certData = Data(base64Encoded: caCertBase64) as NSData? else { throw SignatureError.certIncorrectData }
    guard let certBio = BIO_new_mem_buf(certData.bytes, Int32(certData.length)) else { throw SignatureError.incorrectBio("certData") }
    defer { BIO_free(certBio) }
    
    guard let cert = d2i_X509_bio(certBio, nil) else { throw SignatureError.parsingCert }
    defer { X509_free(cert) }
    
    let ca = SK_X509_push(cert)
    defer { SK_X509_Free(ca) }
    
    guard let p7 = PKCS7_sign(signcert, pkey, ca, manifestBio, PKCS7_DETACHED | PKCS7_BINARY) else { throw SignatureError.signingData }
    
    let outBio = BIO_new_file(signaturePath.path, "w")
    defer { BIO_free(outBio) }
    
    guard i2d_PKCS7_bio(outBio, p7) == 1 else { throw SignatureError.writingData }
    
}
