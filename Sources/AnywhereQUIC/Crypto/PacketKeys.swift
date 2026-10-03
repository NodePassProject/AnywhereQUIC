//
//  PacketKeys.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import CryptoKit
import Foundation

struct AEADError: Error { }

struct PacketKeys {
    let suite: QUICCipherSuite
    let secret: [UInt8]
    let key: SymmetricKey
    let iv: [UInt8]
    let headerProtector: HeaderProtector

    var aead: AEADAlgorithm { self.suite.aead }

    init(suite: QUICCipherSuite, secret: [UInt8]) {
        let aead = suite.aead
        let keyBytes = KeyDerivation.expandLabel(
            secret: secret,
            label: "quic key",
            length: aead.keyLength,
            hash: suite.hash
        )
        let headerKey = KeyDerivation.expandLabel(
            secret: secret,
            label: "quic hp",
            length: aead.keyLength,
            hash: suite.hash
        )
        self.init(
            suite: suite,
            secret: secret,
            key: SymmetricKey(data: keyBytes),
            iv: KeyDerivation.expandLabel(
                secret: secret,
                label: "quic iv",
                length: AEADAlgorithm.nonceLength,
                hash: suite.hash
            ),
            headerProtector: HeaderProtector(aead: aead, key: headerKey)
        )
    }

    private init(
        suite: QUICCipherSuite,
        secret: [UInt8],
        key: SymmetricKey,
        iv: [UInt8],
        headerProtector: HeaderProtector
    ) {
        self.suite = suite
        self.secret = secret
        self.key = key
        self.iv = iv
        self.headerProtector = headerProtector
    }

    static func initial(destinationID: QUICConnectionID, isClient: Bool) -> (read: PacketKeys, write: PacketKeys) {
        let secrets = KeyDerivation.initialSecrets(destinationID: destinationID)
        let client = PacketKeys(suite: .TLS_AES_128_GCM_SHA256, secret: secrets.client)
        let server = PacketKeys(suite: .TLS_AES_128_GCM_SHA256, secret: secrets.server)
        return isClient ? (server, client) : (client, server)
    }

    func updated() -> PacketKeys {
        let nextSecret = KeyDerivation.expandLabel(
            secret: self.secret,
            label: "quic ku",
            length: self.suite.hash.digestLength,
            hash: self.suite.hash
        )
        let aead = self.suite.aead
        let keyBytes = KeyDerivation.expandLabel(
            secret: nextSecret,
            label: "quic key",
            length: aead.keyLength,
            hash: self.suite.hash
        )
        return PacketKeys(
            suite: self.suite,
            secret: nextSecret,
            key: SymmetricKey(data: keyBytes),
            iv: KeyDerivation.expandLabel(
                secret: nextSecret,
                label: "quic iv",
                length: AEADAlgorithm.nonceLength,
                hash: self.suite.hash
            ),
            headerProtector: self.headerProtector
        )
    }

    func nonce(for packetNumber: UInt64) -> [UInt8] {
        var nonce = self.iv
        var number = packetNumber.bigEndian
        withUnsafeBytes(of: &number) { raw in
            for index in 0..<8 {
                nonce[4 + index] ^= raw[index]
            }
        }
        return nonce
    }

    func seal(
        packetNumber: UInt64,
        header: UnsafeRawBufferPointer,
        payload: UnsafeMutableRawBufferPointer
    ) throws(AEADError) {
        let nonceBytes = self.nonce(for: packetNumber)
        let plaintextLength = payload.count - AEADAlgorithm.tagLength
        precondition(plaintextLength >= 0)
        let plaintext = UnsafeRawBufferPointer(rebasing: payload[0..<plaintextLength])
        do {
            switch self.aead {
            case .aes128GCM, .aes256GCM:
                let box = try AES.GCM.seal(
                    plaintext,
                    using: self.key,
                    nonce: AES.GCM.Nonce(data: nonceBytes),
                    authenticating: header
                )
                _ = box.ciphertext.copyBytes(to: payload.bindMemory(to: UInt8.self))
                _ = box.tag.copyBytes(
                    to: UnsafeMutableBufferPointer(rebasing: payload.bindMemory(to: UInt8.self)[plaintextLength...])
                )
            case .chaCha20Poly1305:
                let box = try ChaChaPoly.seal(
                    plaintext,
                    using: self.key,
                    nonce: ChaChaPoly.Nonce(data: nonceBytes),
                    authenticating: header
                )
                _ = box.ciphertext.copyBytes(to: payload.bindMemory(to: UInt8.self))
                _ = box.tag.copyBytes(
                    to: UnsafeMutableBufferPointer(rebasing: payload.bindMemory(to: UInt8.self)[plaintextLength...])
                )
            }
        } catch {
            throw AEADError()
        }
    }

    func open(
        packetNumber: UInt64,
        header: UnsafeRawBufferPointer,
        payload: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer
    ) throws(AEADError) -> Int {
        guard payload.count >= AEADAlgorithm.tagLength else {
            throw AEADError()
        }
        let ciphertextLength = payload.count - AEADAlgorithm.tagLength
        guard output.count >= ciphertextLength else {
            throw AEADError()
        }
        let nonceBytes = self.nonce(for: packetNumber)
        let ciphertext = UnsafeRawBufferPointer(rebasing: payload[0..<ciphertextLength])
        let tag = UnsafeRawBufferPointer(rebasing: payload[ciphertextLength...])
        do {
            let plaintext: Data
            switch self.aead {
            case .aes128GCM, .aes256GCM:
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonceBytes),
                    ciphertext: ciphertext,
                    tag: tag
                )
                plaintext = try AES.GCM.open(box, using: self.key, authenticating: header)
            case .chaCha20Poly1305:
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonceBytes),
                    ciphertext: ciphertext,
                    tag: tag
                )
                plaintext = try ChaChaPoly.open(box, using: self.key, authenticating: header)
            }
            _ = plaintext.copyBytes(to: output.bindMemory(to: UInt8.self))
            return plaintext.count
        } catch {
            throw AEADError()
        }
    }

    func protectHeader(_ packet: UnsafeMutableRawBufferPointer, packetNumberOffset: Int, packetNumberLength: Int) {
        let sampleOffset = packetNumberOffset + 4
        precondition(packet.count >= sampleOffset + 16)
        let mask = self.headerProtector.mask(
            sample: UnsafeRawBufferPointer(rebasing: packet[sampleOffset..<sampleOffset + 16])
        )
        let isLong = packet[0] & PacketHeader.formBit != 0
        packet[0] ^= mask.0 & (isLong ? 0x0F : 0x1F)
        let maskBytes = [mask.1, mask.2, mask.3, mask.4]
        for index in 0..<packetNumberLength {
            packet[packetNumberOffset + index] ^= maskBytes[index]
        }
    }

    func removeHeaderProtection(
        header: UnsafeMutableRawBufferPointer,
        packetNumberOffset: Int,
        sample: UnsafeRawBufferPointer
    ) -> (firstByte: UInt8, packetNumberLength: Int, truncatedPacketNumber: UInt32) {
        let mask = self.headerProtector.mask(sample: sample)
        let isLong = header[0] & PacketHeader.formBit != 0
        header[0] ^= mask.0 & (isLong ? 0x0F : 0x1F)
        let length = Int(header[0] & PacketHeader.packetNumberLengthMask) + 1
        let maskBytes = [mask.1, mask.2, mask.3, mask.4]
        var truncated: UInt32 = 0
        for index in 0..<length {
            header[packetNumberOffset + index] ^= maskBytes[index]
            truncated = truncated << 8 | UInt32(header[packetNumberOffset + index])
        }
        return (header[0], length, truncated)
    }

    func unprotectHeader(
        _ packet: UnsafeMutableRawBufferPointer,
        packetNumberOffset: Int
    ) -> (firstByte: UInt8, packetNumberLength: Int, truncatedPacketNumber: UInt32)? {
        let sampleOffset = packetNumberOffset + 4
        guard packet.count >= sampleOffset + 16 else {
            return nil
        }
        let mask = self.headerProtector.mask(
            sample: UnsafeRawBufferPointer(rebasing: packet[sampleOffset..<sampleOffset + 16])
        )
        let isLong = packet[0] & PacketHeader.formBit != 0
        packet[0] ^= mask.0 & (isLong ? 0x0F : 0x1F)
        let length = Int(packet[0] & PacketHeader.packetNumberLengthMask) + 1
        let maskBytes = [mask.1, mask.2, mask.3, mask.4]
        var truncated: UInt32 = 0
        for index in 0..<length {
            packet[packetNumberOffset + index] ^= maskBytes[index]
            truncated = truncated << 8 | UInt32(packet[packetNumberOffset + index])
        }
        return (packet[0], length, truncated)
    }
}

enum RetryIntegrity {
    private static let key: [UInt8] = [
        0xBE, 0x0C, 0x69, 0x0B, 0x9F, 0x66, 0x57, 0x5A, 0x1D, 0x76, 0x6B, 0x54, 0xE3, 0x68, 0xC8, 0x4E,
    ]
    private static let nonce: [UInt8] = [
        0x46, 0x15, 0x99, 0xD3, 0x5D, 0x63, 0x2B, 0xF2, 0x23, 0x98, 0x25, 0xBB,
    ]

    static func tag(pseudoPacket: [UInt8]) -> [UInt8] {
        let box = try! AES.GCM.seal(
            Data(),
            using: SymmetricKey(data: Self.key),
            nonce: AES.GCM.Nonce(data: Self.nonce),
            authenticating: pseudoPacket
        )
        return Array(box.tag)
    }

    static func verify(retryPacket: UnsafeRawBufferPointer, originalDestinationID: QUICConnectionID) -> Bool {
        guard retryPacket.count >= RetryPacket.integrityTagLength else {
            return false
        }
        let expected = Self.tag(pseudoPacket: RetryPacket.pseudoPacket(
            originalDestinationID: originalDestinationID,
            retryPacket: retryPacket
        ))
        let actual = Array(retryPacket[(retryPacket.count - RetryPacket.integrityTagLength)...])
        var difference: UInt8 = 0
        for index in 0..<RetryPacket.integrityTagLength {
            difference |= expected[index] ^ actual[index]
        }
        return difference == 0
    }
}
