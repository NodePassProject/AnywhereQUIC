//
//  StreamSendTests.swift
//  AnywhereQUICTests
//

import Foundation
import Testing
@testable import AnywhereQUIC

/// Drives an established `ConnectionCore` directly and decrypts what it writes, standing in for
/// the peer. The handshake is skipped by installing 1-RTT keys and transport parameters.
struct StreamSendTests {
    private final class StubTLS: QUICTLSProvider {
        func startHandshake(localTransportParameters: Data) throws -> [QUICHandshakeAction] { [] }
        func receiveCryptoData(_ data: Data, at level: QUICEncryptionLevel) throws -> [QUICHandshakeAction] { [] }
    }

    private struct Peer {
        let keys: PacketKeys
        let destinationIDLength: Int
        var largestPacketNumber: UInt64?

        mutating func open(_ datagram: [UInt8], _ body: (UInt64, Frame) -> Void) throws {
            var packet = datagram
            let header = try packet.withUnsafeBytes {
                try PacketHeader.parse($0, shortHeaderDestinationIDLength: self.destinationIDLength)
            }
            let unprotected = try #require(packet.withUnsafeMutableBytes {
                self.keys.unprotectHeader($0, packetNumberOffset: header.packetNumberOffset)
            })
            let packetNumber = PacketNumber.decode(
                truncated: unprotected.truncatedPacketNumber,
                length: unprotected.packetNumberLength,
                largestReceived: self.largestPacketNumber
            )
            self.largestPacketNumber = Swift.max(self.largestPacketNumber ?? 0, packetNumber)
            let payloadStart = header.packetNumberOffset + unprotected.packetNumberLength
            var plaintext = [UInt8](repeating: 0, count: packet.count)
            let length = try packet.withUnsafeBytes { raw in
                try plaintext.withUnsafeMutableBytes { output in
                    try self.keys.open(
                        packetNumber: packetNumber,
                        header: UnsafeRawBufferPointer(rebasing: raw[0..<payloadStart]),
                        payload: UnsafeRawBufferPointer(rebasing: raw[payloadStart...]),
                        into: output
                    )
                }
            }
            try plaintext.withUnsafeBytes { raw in
                var reader = InputBuffer(storage: UnsafeRawBufferPointer(rebasing: raw[0..<length]))
                while reader.byteCount > 0 {
                    body(packetNumber, try reader.readFrame())
                }
            }
        }
    }

    private static let start: Nanoseconds = Time.second

    private func makeConnection() -> (ConnectionCore, Peer) {
        let destinationID = QUICConnectionID([UInt8](repeating: 0xAB, count: 8))!
        let core = ConnectionCore(
            settings: QUICSettings(),
            transportParameters: QUICTransportParameters(
                initialMaxData: 1 << 30,
                initialMaxStreamDataBidirectionalLocal: 1 << 24,
                initialMaxStreamDataBidirectionalRemote: 1 << 24
            ),
            destinationID: destinationID,
            path: QUICPath(local: QUICSocketAddress(bytes: [1]), remote: QUICSocketAddress(bytes: [2])),
            tls: StubTLS(),
            now: QUICInstant(nanoseconds: Self.start)
        )
        let writeSecret = [UInt8](repeating: 0x11, count: 32)
        core.applicationSpace.writeKeys = PacketKeys(suite: .TLS_AES_128_GCM_SHA256, secret: writeSecret)
        core.applicationSpace.readKeys = PacketKeys(suite: .TLS_AES_128_GCM_SHA256, secret: [UInt8](repeating: 0x22, count: 32))
        core.remoteTransportParameters = QUICTransportParameters(
            initialMaxData: 1 << 30,
            initialMaxStreamDataBidirectionalRemote: 1 << 24,
            initialMaxStreamsBidirectional: 1000
        )
        core.hasReceivedTransportParameters = true
        core.localBidirectionalMaxStreams = 1000
        core.sendMaxOffset = 1 << 30
        core.isTLSHandshakeComplete = true
        core.isHandshakeComplete = true
        core.discardInitialSpace(now: Self.start)
        core.discardHandshakeSpace(now: Self.start)
        core.isHandshakeConfirmed = true
        core.isServerAddressVerified = true
        core.handshakeConfirmedAt = Self.start
        core.handshakePhase = .waitingForHandshake
        core.state = .established
        let peer = Peer(
            keys: PacketKeys(suite: .TLS_AES_128_GCM_SHA256, secret: writeSecret),
            destinationIDLength: destinationID.count
        )
        return (core, peer)
    }

    private func writeAll(_ core: ConnectionCore, now: Nanoseconds) -> [[UInt8]] {
        var buffer = [UInt8](repeating: 0, count: 1500)
        var datagrams: [[UInt8]] = []
        while let datagram = buffer.withUnsafeMutableBufferPointer({
            core.write(into: $0, now: QUICInstant(nanoseconds: now))
        }) {
            datagrams.append(Array(buffer[0..<datagram.count]))
        }
        core.finishWriting(now: QUICInstant(nanoseconds: now))
        return datagrams
    }

    private func acknowledge(_ packetNumbers: [UInt64], on core: ConnectionCore, now: Nanoseconds) throws {
        var remaining = packetNumbers.sorted(by: >)
        while !remaining.isEmpty {
            var batch: [UInt64] = []
            var ranges = 0
            while let next = remaining.first {
                if batch.last.map({ $0 != next + 1 }) ?? true {
                    guard ranges < ACKFrame.maxRanges else {
                        break
                    }
                    ranges += 1
                }
                batch.append(next)
                remaining.removeFirst()
            }
            try core.handleACK(
                ACKFrame(acknowledging: batch),
                space: core.applicationSpace,
                ackDelay: 0,
                receivedAt: now,
                now: now
            )
        }
    }

    @Test func roundRobinsQueuedStreams() throws {
        let (core, initialPeer) = self.makeConnection()
        var peer = initialPeer
        var order: [QUICStreamID] = []
        for _ in 0..<8 {
            let id = try core.openStream(bidirectional: true)
            try core.send(Data(count: 100_000), on: id)
            order.append(id)
        }
        let datagrams = self.writeAll(core, now: Self.start)
        #expect(datagrams.count >= order.count)
        var carried: [QUICStreamID] = []
        for datagram in datagrams.prefix(order.count) {
            try peer.open(datagram) { _, frame in
                if case .stream(let id, _, _, _) = frame {
                    carried.append(QUICStreamID(rawValue: id))
                }
            }
        }
        #expect(carried == order)
    }

    @Test(arguments: [7, 8, 9] as [UInt64])
    func deliversEveryStreamDespiteLoss(seed: UInt64) throws {
        var generator = SplitMix64(seed: seed)
        let (core, initialPeer) = self.makeConnection()
        var peer = initialPeer
        var payloads: [QUICStreamID: [UInt8]] = [:]
        for _ in 0..<60 {
            let id = try core.openStream(bidirectional: true)
            let payload = (0..<Int.random(in: 0...30_000, using: &generator)).map {
                UInt8(truncatingIfNeeded: $0 &+ Int(id.rawValue))
            }
            try core.send(Data(payload), on: id, fin: true)
            payloads[id] = payload
            if Bool.random(using: &generator) {
                try core.handleStreamFrame(
                    streamID: id.rawValue,
                    offset: 0,
                    data: UnsafeRawBufferPointer(start: nil, count: 0),
                    fin: true,
                    frameType: .stream
                )
            }
        }
        // Idle streams must not change what is sent.
        for _ in 0..<500 {
            _ = try core.openStream(bidirectional: true)
        }

        var received: [QUICStreamID: RangeSet] = [:]
        var finalSizes: [QUICStreamID: Int] = [:]
        func isComplete() -> Bool {
            return payloads.allSatisfy { id, payload in
                let covered = received[id]?.ranges ?? []
                return finalSizes[id] == payload.count && (payload.isEmpty || covered == [0..<UInt64(payload.count)])
            }
        }
        var now = Self.start
        for _ in 0..<5000 where !isComplete() {
            var arrived: [UInt64] = []
            for datagram in self.writeAll(core, now: now) {
                let isLost = Int.random(in: 0..<100, using: &generator) < 8
                var packetNumber: UInt64 = 0
                try peer.open(datagram) { number, frame in
                    packetNumber = number
                    guard !isLost, case .stream(let rawID, let offset, let data, let fin) = frame else {
                        return
                    }
                    let id = QUICStreamID(rawValue: rawID)
                    let payload = payloads[id] ?? []
                    let range = Int(offset)..<Int(offset) + data.count
                    #expect(Array(data) == Array(payload[range]))
                    received[id, default: RangeSet()].insert(UInt64(range.lowerBound)..<UInt64(range.upperBound))
                    if fin {
                        finalSizes[id] = range.upperBound
                    }
                }
                if !isLost {
                    arrived.append(packetNumber)
                }
            }
            now += 2 * Time.millisecond
            if !arrived.isEmpty {
                try self.acknowledge(arrived, on: core, now: now)
            }
            core.handleTimeout(now: QUICInstant(nanoseconds: now))
            #expect(core.state == .established)
        }
        #expect(isComplete())
        #expect(!core.streams.values.contains { $0.hasPendingSendData })
    }

    @Test func keepsSendingAfterQueuedStreamCloses() throws {
        let (core, initialPeer) = self.makeConnection()
        var peer = initialPeer
        let id = try core.openStream(bidirectional: true)
        try core.handleStreamFrame(
            streamID: id.rawValue,
            offset: 0,
            data: UnsafeRawBufferPointer(start: nil, count: 0),
            fin: true,
            frameType: .stream
        )
        try core.send(Data(count: 10), on: id, fin: true)
        let other = try core.openStream(bidirectional: true)
        var numbers: [UInt64] = []
        for datagram in self.writeAll(core, now: Self.start) {
            try peer.open(datagram) { number, _ in numbers.append(number) }
        }
        let stream = try #require(core.streams[id])
        core.enqueueStream(stream)
        try self.acknowledge(numbers, on: core, now: Self.start + Time.millisecond)
        #expect(core.streams[id] == nil)

        try core.send(Data(count: 10), on: other)
        var carried: [UInt64] = []
        for datagram in self.writeAll(core, now: Self.start + 2 * Time.millisecond) {
            try peer.open(datagram) { _, frame in
                if case .stream(let rawID, _, _, _) = frame {
                    carried.append(rawID)
                }
            }
        }
        #expect(carried == [other.rawValue])
        #expect(!core.streamSendQueue.contains { $0 == id })
    }
}
