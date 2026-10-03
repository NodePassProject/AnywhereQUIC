//
//  SentPacket.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum SentFrame {
    case ack(largestAcknowledged: UInt64)
    case ping
    case padding
    case crypto(offset: UInt64, length: Int)
    case stream(id: UInt64, offset: UInt64, length: Int, fin: Bool)
    case resetStream(id: UInt64)
    case stopSending(id: UInt64)
    case maxData(UInt64)
    case maxStreamData(id: UInt64, maximum: UInt64)
    case maxStreams(bidirectional: Bool, maximum: UInt64)
    case dataBlocked(UInt64)
    case streamDataBlocked(id: UInt64, limit: UInt64)
    case streamsBlocked(bidirectional: Bool, limit: UInt64)
    case newConnectionID(sequence: UInt64)
    case retireConnectionID(sequence: UInt64)
    case pathChallenge(UInt64)
    case pathResponse(UInt64)
    case connectionClose

    var isRetransmittable: Bool {
        switch self {
        case .ack, .ping, .padding, .pathChallenge, .pathResponse, .connectionClose:
            return false
        default:
            return true
        }
    }
}

struct SentPacket {
    var packetNumber: UInt64
    var sentAt: Nanoseconds
    var size: Int
    var frames: [SentFrame]
    var isACKEliciting: Bool
    var isPTOEliciting: Bool
    var isRetransmittable: Bool
    var isProbe: Bool
    var isPMTUDProbe: Bool
    var isPTOReclaimed = false
    var countsTowardCongestion = true

    var deliverySnapshot: DeliverySnapshot? = nil

    var info: QUICSentPacketInfo {
        return QUICSentPacketInfo(
            packetNumber: self.packetNumber,
            size: self.size,
            sentAt: QUICInstant(nanoseconds: self.sentAt),
            isACKEliciting: self.isACKEliciting
        )
    }
}

struct ACKProcessingResult {
    var acknowledged: [SentPacket] = []
    var hasAcknowledgedACKElicitingPacket = false
    var largestAcknowledgedSentAt: Nanoseconds = Time.never
    var hasNewLargestAcknowledged = false
}

struct SentPacketTracker {
    struct LossDetectionResult {
        var lost: [SentPacket] = []
        var bytesLost: UInt64 = 0
        var latestLostSentAt: Nanoseconds = Time.never
        var oldestLostSentAt: Nanoseconds = Time.never
        var hasPersistentCongestion = false
    }

    private(set) var packets: [SentPacket] = []
    private(set) var largestAcknowledged: UInt64?
    private(set) var ackElicitingCount = 0
    private(set) var retransmittableCount = 0
    private(set) var ptoElicitingCount = 0
    private(set) var congestionBytesInFlight: UInt64 = 0
    var lossTime: Nanoseconds = Time.never
    var probePacketsLeft = 0
    private(set) var congestionPacketNumber: UInt64 = 0

    var isEmpty: Bool { self.packets.isEmpty }

    mutating func add(_ packet: SentPacket, state: inout QUICCongestionState) {
        var packet = packet
        packet.countsTowardCongestion = packet.packetNumber >= self.congestionPacketNumber
        if let last = self.packets.last {
            precondition(packet.packetNumber > last.packetNumber)
        }
        self.packets.append(packet)
        if packet.countsTowardCongestion {
            state.bytesInFlight += UInt64(packet.size)
            self.congestionBytesInFlight += UInt64(packet.size)
        }
        if packet.isACKEliciting {
            self.ackElicitingCount += 1
        }
        if packet.isRetransmittable {
            self.retransmittableCount += 1
        }
        if packet.isPTOEliciting {
            self.ptoElicitingCount += 1
        }
    }

    private mutating func accountRemoval(_ packet: SentPacket, state: inout QUICCongestionState) -> UInt64 {
        if packet.isACKEliciting {
            self.ackElicitingCount -= 1
        }
        if packet.isRetransmittable, !packet.isPTOReclaimed {
            self.retransmittableCount -= 1
        }
        if packet.isPTOEliciting {
            self.ptoElicitingCount -= 1
        }
        guard packet.countsTowardCongestion else {
            return 0
        }
        state.bytesInFlight -= UInt64(packet.size)
        self.congestionBytesInFlight -= UInt64(packet.size)
        return packet.isPMTUDProbe ? 0 : UInt64(packet.size)
    }

    private func index(of packetNumber: UInt64) -> Int? {
        var low = 0
        var high = self.packets.count
        while low < high {
            let mid = (low + high) / 2
            if self.packets[mid].packetNumber < packetNumber {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low < self.packets.count && self.packets[low].packetNumber == packetNumber ? low : nil
    }

    private func firstIndex(atOrAbove packetNumber: UInt64) -> Int {
        var low = 0
        var high = self.packets.count
        while low < high {
            let mid = (low + high) / 2
            if self.packets[mid].packetNumber < packetNumber {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }

    mutating func processACK(
        _ ack: ACKFrame,
        state: inout QUICCongestionState
    ) throws(TransportError) -> ACKProcessingResult {
        var result = ACKProcessingResult()
        if self.largestAcknowledged == nil || self.largestAcknowledged! < ack.largestAcknowledged {
            self.largestAcknowledged = ack.largestAcknowledged
            result.hasNewLargestAcknowledged = true
        }
        var remove = [Bool](repeating: false, count: self.packets.count)
        var anyRemoved = false
        ack.forEachRange { range in
            var index = self.firstIndex(atOrAbove: range.lowerBound)
            while index < self.packets.count, self.packets[index].packetNumber <= range.upperBound {
                if !remove[index] {
                    remove[index] = true
                    anyRemoved = true
                    let packet = self.packets[index]
                    if packet.packetNumber == ack.largestAcknowledged {
                        result.largestAcknowledgedSentAt = packet.sentAt
                    }
                    if packet.isACKEliciting {
                        result.hasAcknowledgedACKElicitingPacket = true
                    }
                }
                index += 1
            }
        }
        guard anyRemoved else {
            return result
        }
        var kept: [SentPacket] = []
        kept.reserveCapacity(self.packets.count)
        for (index, packet) in self.packets.enumerated() {
            if remove[index] {
                _ = self.accountRemoval(packet, state: &state)
                result.acknowledged.append(packet)
            } else {
                kept.append(packet)
            }
        }
        self.packets = kept
        return result
    }

    mutating func detectLost(
        now: Nanoseconds,
        state: inout QUICCongestionState,
        peerMaxACKDelay: Nanoseconds,
        persistentCongestionStart: Nanoseconds,
        isApplicationSpace: Bool
    ) -> LossDetectionResult {
        var result = LossDetectionResult()
        self.lossTime = Time.never
        guard let largestAcknowledged = self.largestAcknowledged else {
            return result
        }
        let threshold = Swift.min(
            Swift.max(
                self.congestionBytesInFlight / UInt64(Swift.max(state.maxSendUDPPayloadSize, 1)) / 2,
                Recovery.packetThreshold
            ),
            Recovery.maxPacketThreshold
        )
        let lossDelay = Recovery.lossDelay(state: state)
        var remove = [Bool](repeating: false, count: self.packets.count)
        var anyLost = false
        for (index, packet) in self.packets.enumerated() {
            if packet.packetNumber > largestAcknowledged {
                break
            }
            let lostByTime = Time.elapsed(packet.sentAt, lossDelay, now)
            let lostByPackets = largestAcknowledged >= packet.packetNumber + threshold
            if lostByTime || lostByPackets {
                remove[index] = true
                anyLost = true
                if result.latestLostSentAt == Time.never {
                    result.latestLostSentAt = packet.sentAt
                    result.oldestLostSentAt = packet.sentAt
                }
                result.latestLostSentAt = Swift.max(result.latestLostSentAt, packet.sentAt)
                result.oldestLostSentAt = Swift.min(result.oldestLostSentAt, packet.sentAt)
            } else {
                let candidate = packet.sentAt.addingClamped(lossDelay)
                self.lossTime = self.lossTime == Time.never ? candidate : Swift.min(self.lossTime, candidate)
            }
        }
        guard anyLost else {
            return result
        }
        var kept: [SentPacket] = []
        kept.reserveCapacity(self.packets.count)
        var lastLostPacketNumber: UInt64?
        var contiguousOldest: Nanoseconds = Time.never
        var contiguousLatest: Nanoseconds = Time.never
        var contiguousRun = false
        for (index, packet) in self.packets.enumerated() {
            if remove[index] {
                result.bytesLost += self.accountRemoval(packet, state: &state)
                result.lost.append(packet)
                if packet.sentAt >= persistentCongestionStart {
                    if let last = lastLostPacketNumber, last + 1 == packet.packetNumber, contiguousRun {
                        contiguousLatest = packet.sentAt
                    } else {
                        contiguousRun = true
                        contiguousOldest = packet.sentAt
                        contiguousLatest = packet.sentAt
                    }
                    lastLostPacketNumber = packet.packetNumber
                } else {
                    contiguousRun = false
                    lastLostPacketNumber = nil
                }
            } else {
                kept.append(packet)
            }
        }
        self.packets = kept
        if isApplicationSpace,
           result.bytesLost > 0,
           contiguousOldest != Time.never,
           contiguousLatest > contiguousOldest {
            let probeTimeout = state.smoothedRTTNanoseconds
                + Swift.max(4 * state.rttVarianceNanoseconds, Recovery.granularity)
                + peerMaxACKDelay
            let period = probeTimeout * Recovery.persistentCongestionThreshold
            if contiguousLatest - contiguousOldest >= period {
                result.hasPersistentCongestion = true
            }
        }
        return result
    }

    mutating func reclaimOnPTO(count: Int) -> [SentFrame] {
        var reclaimed: [SentFrame] = []
        var remaining = count
        var index = self.packets.count - 1
        while index >= 0, remaining > 0 {
            if self.packets[index].isRetransmittable, !self.packets[index].isPTOReclaimed {
                let frames = self.packets[index].frames.filter { $0.isRetransmittable }
                self.packets[index].isPTOReclaimed = true
                self.retransmittableCount -= 1
                if self.packets[index].isPTOEliciting {
                    self.packets[index].isPTOEliciting = false
                    self.ptoElicitingCount -= 1
                }
                if !frames.isEmpty {
                    reclaimed.append(contentsOf: frames)
                    remaining -= 1
                }
            }
            index -= 1
        }
        return reclaimed
    }

    mutating func removeAll(state: inout QUICCongestionState) -> [SentPacket] {
        for packet in self.packets {
            _ = self.accountRemoval(packet, state: &state)
        }
        let removed = self.packets
        self.packets.removeAll()
        self.lossTime = Time.never
        return removed
    }

    mutating func resetCongestionState(nextPacketNumber: UInt64) {
        self.congestionPacketNumber = nextPacketNumber
        self.congestionBytesInFlight = 0
        for index in self.packets.indices {
            self.packets[index].countsTowardCongestion = false
        }
    }
}
