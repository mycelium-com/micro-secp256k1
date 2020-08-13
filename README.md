# Tyny secp256k1 implementation

This code was taken from micro-ecc project.

Some of functionality has been removed:

* Random generator function;
* Non-deterministic signing;
* Private key generation;
* Key exchange functionality;
* Support for all curves with exception for secp256k1.

New functionality has been implemented:

* Normalization of signatures for compatibility with libsecp256k1 (uECC_normalize_signature function);
* Support for DER signature encoding (uECC_serialize_der and uECC_deserialize_der functions).
