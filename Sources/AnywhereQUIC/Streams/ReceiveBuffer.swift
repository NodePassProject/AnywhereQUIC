//
//  ReceiveBuffer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

struct ReceiveBuffer {
    private(set) var readOffset: UInt64 = 0
    private var pending: [(offset: UInt64, data: [UInt8])] = []
    private var discardedRanges = RangeSet()
    private(set) var bufferedBytes = 0
    private(set) var isBuffering = true

    var hasPendingData: Bool { !self.pending.isEmpty }

    mutating func receive(offset: UInt64, data: UnsafeRawBufferPointer) -> Data? {
        let end = offset + UInt64(data.count)
        if end <= self.readOffset {
            return nil
        }
        var start = offset
        var bytes = data
        if start < self.readOffset {
            let skip = Int(self.readOffset - start)
            bytes = UnsafeRawBufferPointer(rebasing: bytes[skip...])
            start = self.readOffset
        }
        if start == self.readOffset {
            var delivered = Data(bytes)
            self.readOffset = end
            self.drainPending(into: &delivered)
            return delivered
        }
        guard self.isBuffering else {
            self.discardedRanges.insert(start..<end)
            return nil
        }
        self.insertPending(offset: start, bytes: Array(bytes))
        return nil
    }

    private mutating func drainPending(into delivered: inout Data) {
        while let first = self.pending.first, first.offset <= self.readOffset {
            self.pending.removeFirst()
            self.bufferedBytes -= first.data.count
            let end = first.offset + UInt64(first.data.count)
            if end <= self.readOffset {
                continue
            }
            let skip = Int(self.readOffset - first.offset)
            delivered.append(contentsOf: first.data[skip...])
            self.readOffset = end
        }
    }

    private mutating func insertPending(offset: UInt64, bytes: [UInt8]) {
        var start = offset
        var chunk = bytes[...]
        var index = self.pending.firstIndex { $0.offset + UInt64($0.data.count) > start } ?? self.pending.count
        while index < self.pending.count, !chunk.isEmpty {
            let existing = self.pending[index]
            let existingEnd = existing.offset + UInt64(existing.data.count)
            if existing.offset > start {
                let gap = Int(Swift.min(UInt64(chunk.count), existing.offset - start))
                let piece = Array(chunk.prefix(gap))
                self.pending.insert((start, piece), at: index)
                self.bufferedBytes += piece.count
                chunk = chunk.dropFirst(gap)
                start += UInt64(gap)
                index += 1
                continue
            }
            let overlap = Int(Swift.min(UInt64(chunk.count), existingEnd - start))
            chunk = chunk.dropFirst(overlap)
            start += UInt64(overlap)
            index += 1
        }
        if !chunk.isEmpty {
            let piece = Array(chunk)
            self.pending.append((start, piece))
            self.bufferedBytes += piece.count
        }
    }

    mutating func stopBuffering() {
        self.isBuffering = false
        for chunk in self.pending {
            self.discardedRanges.insert(chunk.offset..<chunk.offset + UInt64(chunk.data.count))
        }
        self.pending.removeAll()
        self.bufferedBytes = 0
    }

    mutating func discardOrderedData(upTo offset: UInt64) -> UInt64 {
        guard offset > self.readOffset else {
            return 0
        }
        var dropped = Data()
        let previous = self.readOffset
        self.readOffset = offset
        self.drainPending(into: &dropped)
        self.readOffset = self.discardedRanges.firstMissing(from: Swift.max(self.readOffset, offset))
        self.discardedRanges.removeAll(below: self.readOffset)
        return self.readOffset - previous
    }
}
