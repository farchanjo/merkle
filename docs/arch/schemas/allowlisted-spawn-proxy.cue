// DDD role: ValueObject
package schemas
// #SpawnAllowlistEnabled gate.
// DDD role: ValueObject
#SpawnAllowlistEnabled: true
// #AllowlistedSpawnProxy posture.
// DDD role: ValueObject
#AllowlistedSpawnProxy: { enabled: #SpawnAllowlistEnabled, path: "/v1/proxy/spawn" }
