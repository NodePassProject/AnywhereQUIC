# Concurrency

`QUICConnection` is `Sendable`. Every method takes the connection's lock, so calls from different threads never race on memory. The lock does not make the driving sequence atomic, so a connection still needs exactly one driver.

## The driver

The driver is the single context that runs these sequences, one at a time:

| Sequence | Steps |
| --- | --- |
| Receive | `receive(_:from:now:)` for each datagram, then `drainEvents()` or `drainEvents(into:)` |
| Write | `write(into:now:)` until it returns `nil`, then `finishWriting(now:)`, then arm a timer from `nextTimeout` |
| Timer | `handleTimeout(now:)`, then `drainEvents`, then the write sequence |

Two drivers interleaving would split events between them, so stream data could be handed out on two threads out of order, and their packets would be counted as one pacing batch.

Other threads may call self-contained methods at any time: `openStream`, `send(_:on:fin:)`, `finishSending`, `resetStream`, `stopSending`, `shutdownStream`, `extendReceiveWindow`, `sendDatagram`, `sendDatagrams`, `close`, `migrate`, `cancelPendingMigration`, `setCongestionController`, `setBrutalBandwidth` and the read-only properties. Their effects are picked up by the driver's next write sequence, so the caller should wake the driver afterwards.

## Write batches and pacing

`write(into:now:)` stops returning new packets once the current batch reaches `sendQuantum` bytes or the pacer blocks; ACK-only packets are still produced. `finishWriting(now:)` closes the batch and sets the pacing deadline reported by `nextTimeout`. When pacing is not active yet and the batch was full, the deadline is immediate. The driver must re-arm its timer from `nextTimeout` after every write sequence, otherwise a connection with queued data stalls.

The timer should fire close to the deadline. A deadline that is routinely late by more than half a pacing interval lowers the sending rate, because the pacer compensates for at most half of each wait.

## Callbacks

`QUICTLSProvider` and `QUICCongestionController` methods run while the connection's lock is held. They must not call back into the same `QUICConnection`, because the lock is not recursive and a recursive acquisition traps. They must not block either, because every thread that touches the connection waits for them.

Certificate trust evaluation can block, for example when it fetches intermediates or revocation data. A provider defers it by returning `.verifyPeer(certificates:)` instead of completing the handshake. The connection then emits `.peerVerificationRequested(certificates:)`, keeps acknowledging handshake packets and buffers 1-RTT packets. The caller evaluates the chain outside the lock and reports the result with `completePeerVerification(error:now:)`, which passes it to the provider's `completePeerVerification(error:)`. A non-nil error closes the connection with a TLS error. The handshake timeout keeps running while the evaluation is pending.
