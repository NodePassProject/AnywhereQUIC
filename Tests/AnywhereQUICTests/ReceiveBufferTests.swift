//
//  ReceiveBufferTests.swift
//  AnywhereQUICTests
//

import Foundation
import Testing
@testable import AnywhereQUIC

struct ReceiveBufferTests {
    private func receive(_ buffer: inout ReceiveBuffer, _ bytes: ArraySlice<UInt8>, at offset: Int) -> Data? {
        return bytes.withUnsafeBytes { buffer.receive(offset: UInt64(offset), data: $0) }
    }

    @Test(arguments: [1, 2, 3, 4, 5] as [UInt64])
    func reassemblesShuffledOverlappingSegments(seed: UInt64) {
        var generator = SplitMix64(seed: seed)
        for _ in 0..<40 {
            let length = Int.random(in: 1...6000, using: &generator)
            let source = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            var segments: [Range<Int>] = []
            var cursor = 0
            while cursor < length {
                let end = Swift.min(length, cursor + Int.random(in: 1...400, using: &generator))
                segments.append(cursor..<end)
                cursor = end
            }
            for _ in 0..<segments.count {
                let start = Int.random(in: 0..<length, using: &generator)
                let end = Swift.min(length, start + Int.random(in: 1...600, using: &generator))
                segments.append(start..<end)
            }
            segments.shuffle(using: &generator)

            var buffer = ReceiveBuffer()
            var delivered: [UInt8] = []
            var covered = [Bool](repeating: false, count: length)
            for segment in segments {
                if let data = self.receive(&buffer, source[segment], at: segment.lowerBound) {
                    delivered.append(contentsOf: data)
                }
                for index in segment {
                    covered[index] = true
                }
                let expectedReadOffset = covered.firstIndex(of: false) ?? length
                let buffered = covered[expectedReadOffset...].filter { $0 }.count
                #expect(buffer.readOffset == UInt64(expectedReadOffset))
                #expect(delivered.count == expectedReadOffset)
                #expect(buffer.bufferedBytes == buffered)
                #expect(buffer.hasPendingData == (buffered > 0))
            }
            #expect(delivered == source)
        }
    }

    @Test func deliversLongBacklogOnceTheHoleIsFilled() {
        let segmentLength = 100
        let segmentCount = 20_000
        let source = (0..<segmentLength * segmentCount).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        var buffer = ReceiveBuffer()
        for index in 1..<segmentCount {
            let start = index * segmentLength
            #expect(self.receive(&buffer, source[start..<start + segmentLength], at: start) == nil)
        }
        #expect(buffer.bufferedBytes == segmentLength * (segmentCount - 1))
        let delivered = self.receive(&buffer, source[0..<segmentLength], at: 0)
        #expect(delivered.map { Array($0) } == source)
        #expect(buffer.bufferedBytes == 0)
        #expect(!buffer.hasPendingData)
    }

    @Test func drainsPartiallyAndKeepsLaterChunks() {
        let source = (0..<1000).map { UInt8(truncatingIfNeeded: $0) }
        var buffer = ReceiveBuffer()
        for start in stride(from: 100, to: 1000, by: 10) where start != 500 {
            #expect(self.receive(&buffer, source[start..<start + 10], at: start) == nil)
        }
        let first = self.receive(&buffer, source[0..<100], at: 0)
        #expect(first.map { Array($0) } == Array(source[0..<500]))
        #expect(buffer.readOffset == 500)
        #expect(buffer.bufferedBytes == 490)
        let second = self.receive(&buffer, source[495..<510], at: 495)
        #expect(second.map { Array($0) } == Array(source[500..<1000]))
        #expect(buffer.bufferedBytes == 0)
    }

    @Test func discardsOrderedDataAcrossBufferedAndDiscardedRanges() {
        let source = [UInt8](repeating: 7, count: 64)
        var buffer = ReceiveBuffer()
        #expect(self.receive(&buffer, source[10..<20], at: 10) == nil)
        #expect(buffer.discardOrderedData(upTo: 15) == 20)
        #expect(buffer.readOffset == 20)
        #expect(buffer.bufferedBytes == 0)

        #expect(self.receive(&buffer, source[30..<40], at: 30) == nil)
        buffer.stopBuffering()
        #expect(buffer.bufferedBytes == 0)
        #expect(!buffer.hasPendingData)
        #expect(self.receive(&buffer, source[45..<50], at: 45) == nil)
        #expect(buffer.discardOrderedData(upTo: 30) == 20)
        #expect(buffer.readOffset == 40)
        #expect(buffer.discardOrderedData(upTo: 45) == 10)
        #expect(buffer.readOffset == 50)
    }
}
