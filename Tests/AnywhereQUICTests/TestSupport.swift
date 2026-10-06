//
//  TestSupport.swift
//  AnywhereQUICTests
//

@testable import AnywhereQUIC

/// Deterministic generator so failures reproduce from the seed alone.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        self.state &+= 0x9E37_79B9_7F4A_7C15
        var value = self.state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}

extension ACKFrame {
    /// Builds an ACK frame covering exactly `packetNumbers`.
    init(acknowledging packetNumbers: some Sequence<UInt64>) {
        let sorted = Set(packetNumbers).sorted(by: >)
        precondition(!sorted.isEmpty)
        var ranges: [ClosedRange<UInt64>] = []
        for number in sorted {
            if let last = ranges.last, last.lowerBound == number + 1 {
                ranges[ranges.count - 1] = number...last.upperBound
            } else {
                ranges.append(number...number)
            }
        }
        precondition(ranges.count <= ACKFrame.maxRanges + 1)
        var additional: [(gap: UInt64, length: UInt64)] = []
        var smallest = ranges[0].lowerBound
        for range in ranges.dropFirst() {
            additional.append((gap: smallest - range.upperBound - 2, length: range.upperBound - range.lowerBound))
            smallest = range.lowerBound
        }
        self.init(
            largestAcknowledged: ranges[0].upperBound,
            ackDelay: 0,
            firstRange: ranges[0].upperBound - ranges[0].lowerBound,
            additionalRanges: additional,
            ecnCounts: nil
        )
    }
}
