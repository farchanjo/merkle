// DDD role: ValueObject
package schemas
// #OobVerifiedRequired gate for high reveal.
// DDD role: ValueObject
#OobVerifiedRequired: true
// #VerifiedOobHighReveal posture.
// DDD role: ValueObject
#VerifiedOobHighReveal: {
	transport_oob_ack_trusted: false
	requires_notifier_resolution: #OobVerifiedRequired
}
