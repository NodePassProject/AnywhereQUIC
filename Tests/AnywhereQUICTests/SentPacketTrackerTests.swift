//
//  SentPacketTrackerTests.swift
//  AnywhereQUICTests
//

import Testing
@testable import AnywhereQUIC

struct SentPacketTrackerTests {
    private struct Model {
        var packets: [SentPacket] = []
        var largestAcknowledged: UInt64?
    }

    private func makePacket(_ number: UInt64, sentAt: Nanoseconds, size: Int, eliciting: Bool) -> SentPacket {
        return SentPacket(
            packetNumber: number,
            sentAt: sentAt,
            size: size,
            frames: eliciting ? [.stream(id: 0, offset: number * 100, length: 100, fin: false)] : [.ack(largestAcknowledged: 0)],
            isACKEliciting: eliciting,
            isPTOEliciting: eliciting,
            isRetransmittable: eliciting,
            isProbe: false,
            isPMTUDProbe: false
        )
    }

    private func expectMatches(
        _ tracker: SentPacketTracker,
        _ model: Model,
        _ state: QUICCongestionState
    ) {
        #expect(tracker.packets.map(\.packetNumber) == model.packets.map(\.packetNumber))
        #expect(tracker.isEmpty == model.packets.isEmpty)
        let bytes = model.packets.filter(\.countsTowardCongestion).reduce(0) { $0 + UInt64($1.size) }
        #expect(state.bytesInFlight == bytes)
        #expect(tracker.congestionBytesInFlight == bytes)
        #expect(tracker.ackElicitingCount == model.packets.filter(\.isACKEliciting).count)
        #expect(tracker.retransmittableCount == model.packets.filter(\.isRetransmittable).count)
        #expect(tracker.ptoElicitingCount == model.packets.filter(\.isPTOEliciting).count)
        #expect(tracker.largestAcknowledged == model.largestAcknowledged)
    }

    @Test(arguments: [11, 22, 33, 44] as [UInt64])
    func matchesReferenceModel(seed: UInt64) throws {
        var generator = SplitMix64(seed: seed)
        var tracker = SentPacketTracker()
        var model = Model()
        var state = QUICCongestionState(initialRTT: 100 * Time.millisecond, maxSendUDPPayloadSize: 1200)
        var nextPacketNumber: UInt64 = 0
        var now: Nanoseconds = Time.second
        for _ in 0..<3000 {
            now += UInt64.random(in: 0...(5 * Time.millisecond), using: &generator)
            switch Int.random(in: 0..<10, using: &generator) {
            case 0..<5:
                for _ in 0..<Int.random(in: 1...20, using: &generator) {
                    var packet = self.makePacket(
                        nextPacketNumber,
                        sentAt: now,
                        size: Int.random(in: 40...1200, using: &generator),
                        eliciting: Int.random(in: 0..<8, using: &generator) != 0
                    )
                    tracker.add(packet, state: &state)
                    packet.countsTowardCongestion = true
                    model.packets.append(packet)
                    nextPacketNumber += 1
                }
            case 5..<9:
                guard nextPacketNumber > 0 else {
                    continue
                }
                let floor = model.packets.first.map { $0.packetNumber > 4 ? $0.packetNumber - 4 : 0 } ?? 0
                var acknowledged = Set<UInt64>()
                for _ in 0..<Int.random(in: 1...6, using: &generator) {
                    let lower = UInt64.random(in: floor..<nextPacketNumber, using: &generator)
                    let upper = Swift.min(nextPacketNumber - 1, lower + UInt64.random(in: 0...40, using: &generator))
                    acknowledged.formUnion(lower...upper)
                }
                let ack = ACKFrame(acknowledging: acknowledged)
                let result = try tracker.processACK(ack, state: &state)
                let expected = model.packets.filter { acknowledged.contains($0.packetNumber) }
                #expect(result.acknowledged.map(\.packetNumber) == expected.map(\.packetNumber))
                #expect(result.hasAcknowledgedACKElicitingPacket == expected.contains { $0.isACKEliciting })
                let largest = expected.first { $0.packetNumber == ack.largestAcknowledged }
                #expect(result.largestAcknowledgedSentAt == (largest?.sentAt ?? Time.never))
                #expect(result.hasNewLargestAcknowledged == (model.largestAcknowledged.map { $0 < ack.largestAcknowledged } ?? true))
                model.packets.removeAll { acknowledged.contains($0.packetNumber) }
                model.largestAcknowledged = Swift.max(model.largestAcknowledged ?? 0, ack.largestAcknowledged)
            default:
                let threshold = Swift.min(
                    Swift.max(tracker.congestionBytesInFlight / 1200 / 2, Recovery.packetThreshold),
                    Recovery.maxPacketThreshold
                )
                let lossDelay = Recovery.lossDelay(state: state)
                let expected = model.packets.filter { packet in
                    guard let largest = model.largestAcknowledged, packet.packetNumber <= largest else {
                        return false
                    }
                    return Time.elapsed(packet.sentAt, lossDelay, now) || largest >= packet.packetNumber + threshold
                }
                let result = tracker.detectLost(
                    now: now,
                    state: &state,
                    peerMaxACKDelay: 0,
                    persistentCongestionStart: 0,
                    isApplicationSpace: true
                )
                #expect(result.lost.map(\.packetNumber) == expected.map(\.packetNumber))
                #expect(result.bytesLost == expected.reduce(0) { $0 + UInt64($1.size) })
                let lost = Set(expected.map(\.packetNumber))
                model.packets.removeAll { lost.contains($0.packetNumber) }
            }
            self.expectMatches(tracker, model, state)
        }
        let removed = tracker.removeAll(state: &state)
        #expect(removed.map(\.packetNumber) == model.packets.map(\.packetNumber))
        model.packets.removeAll()
        self.expectMatches(tracker, model, state)
    }

    @Test func removesMiddleRangesFromEitherEnd() throws {
        var tracker = SentPacketTracker()
        var state = QUICCongestionState(initialRTT: 100 * Time.millisecond, maxSendUDPPayloadSize: 1200)
        for number in 0..<200 as Range<UInt64> {
            tracker.add(self.makePacket(number, sentAt: Time.second, size: 1000, eliciting: true), state: &state)
        }
        _ = try tracker.processACK(ACKFrame(acknowledging: 180...190), state: &state)
        _ = try tracker.processACK(ACKFrame(acknowledging: Array(1...10) + Array(20...30)), state: &state)
        let expected = (0..<200 as Range<UInt64>).filter { !(180...190).contains($0) && !(1...10).contains($0) && !(20...30).contains($0) }
        #expect(tracker.packets.map(\.packetNumber) == expected)
        #expect(state.bytesInFlight == UInt64(expected.count) * 1000)
    }

    @Test func reclaimOnPTOIgnoresAcknowledgedPackets() throws {
        var tracker = SentPacketTracker()
        var state = QUICCongestionState(initialRTT: 100 * Time.millisecond, maxSendUDPPayloadSize: 1200)
        for number in 0..<10 as Range<UInt64> {
            tracker.add(self.makePacket(number, sentAt: Time.second, size: 1000, eliciting: true), state: &state)
        }
        _ = try tracker.processACK(ACKFrame(acknowledging: 0...4), state: &state)
        let reclaimed = tracker.reclaimOnPTO(count: 10)
        let offsets = reclaimed.compactMap { frame -> UInt64? in
            if case .stream(_, let offset, _, _) = frame {
                return offset
            }
            return nil
        }
        #expect(offsets == [900, 800, 700, 600, 500])
        #expect(tracker.retransmittableCount == 0)
        #expect(tracker.ptoElicitingCount == 0)
    }
}
