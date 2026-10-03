//
//  QUICConnection+Application.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension QUICConnection {
    public func exportKeyingMaterial(label: String, context: Data, length: Int) throws -> Data {
        guard self.state == .established else {
            throw QUICError.invalidState
        }
        guard length > 0 else {
            throw QUICError.invalidArgument
        }
        return try self.tls.exportKeyingMaterial(label: label, context: context, length: length)
    }

    @discardableResult
    public func cancelPendingMigration(now: QUICInstant) -> Bool {
        guard let validation = self.pathValidation, validation.path != self.active.path else {
            return false
        }
        self.abortPathValidation(now: self.updateTimestamp(now.nanoseconds))
        return true
    }

    public func setCongestionController(_ controller: any QUICCongestionController, now: QUICInstant) {
        let now = self.updateTimestamp(now.nanoseconds)
        self.congestionController = controller
        self.congestionState.congestionWindow = QUICCongestionState.initialCongestionWindow(
            maxSendUDPPayloadSize: self.congestionState.maxSendUDPPayloadSize
        )
        self.congestionState.slowStartThreshold = .max
        self.congestionState.congestionRecoveryStartTime = nil
        controller.reset(state: &self.congestionState, now: QUICInstant(nanoseconds: now))
        self.pacer.reset()
    }
}
