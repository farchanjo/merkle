// DDD role: ValueObject
package schemas

// #CryptoSignRsaEnabled product gate.
// DDD role: ValueObject
#CryptoSignRsaEnabled: true

// #CryptoSignRsaPadding is the RSA signature padding scheme.
// DDD role: ValueObject
#CryptoSignRsaPadding: "pkcs1v15"

// #CryptoSignRsaHash is the message digest for RSA sign.
// DDD role: ValueObject
#CryptoSignRsaHash: "sha256"

// #CryptoSignRsaAlgorithm wire name.
// DDD role: ValueObject
#CryptoSignRsaAlgorithm: "rsa-sha256"

// #CryptoSignRsaSha256 algorithm posture (scalars only — key formats as separate VOs).
// DDD role: ValueObject
#CryptoSignRsaSha256: {
	enabled:   #CryptoSignRsaEnabled
	algorithm: #CryptoSignRsaAlgorithm
	padding:   #CryptoSignRsaPadding
	hash:      #CryptoSignRsaHash
}

// #CryptoSignRsaKeyFormatPkcs8Pem accepted key encoding.
// DDD role: ValueObject
#CryptoSignRsaKeyFormatPkcs8Pem: true

// #CryptoSignRsaKeyFormatPkcs1Pem accepted key encoding.
// DDD role: ValueObject
#CryptoSignRsaKeyFormatPkcs1Pem: true

// #CryptoSignRsaKeyFormatPkcs8Der accepted key encoding.
// DDD role: ValueObject
#CryptoSignRsaKeyFormatPkcs8Der: true

// #CryptoSignRsaKeyFormatPkcs1Der accepted key encoding.
// DDD role: ValueObject
#CryptoSignRsaKeyFormatPkcs1Der: true
