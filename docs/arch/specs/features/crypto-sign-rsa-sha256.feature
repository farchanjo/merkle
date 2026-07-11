Feature: Crypto sign RSA-SHA256
  As an agent caller
  I want to sign messages with vault-stored RSA private keys
  So that legacy RSA-SHA256 consumers can verify signatures

  Scenario: RSA PKCS#1 v1.5 SHA-256 sign succeeds
    Given an unsealed vault with an RSA private key secret
    When CryptoSignCommand runs with algorithm RsaSha256
    Then signature_hex is returned
    And audit records crypto_sign allow

  Scenario: Malformed RSA key is rejected
    Given key bytes that are not PEM or DER PKCS#8/PKCS#1
    When crypto-sign with RsaSha256 is requested
    Then InvalidInput is returned without producing a signature
