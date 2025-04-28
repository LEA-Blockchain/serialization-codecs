This codebase serves as the reference implementation for the Compact Transaction Encoding ((CTE-1))[CTE-1.md] format, integrating key enhancements proposed in [LIP-0001](http://lip.getlea.org/LIP-0001.html) and [LIP-0002](http://lip.getlea.org/LIP-0002.html).

**LEB128 Implementation Limits:**

While the LEB128 standard allows encoding arbitrarily large integers, this implementation imposes practical limits for security and compatibility with 64-bit systems:

* **Maximum Bytes:** The decoder restricts reading to a maximum of 10 bytes per LEB128 number (`MAX_LEB128_BYTES`). This prevents resource exhaustion attacks from maliciously long inputs, as noted in LIP-0001's security considerations.
* **64-bit Target:** The decoded values are intended to fit within standard 64-bit signed (`int64_t`) or unsigned (`uint64_t`) integers. While the 10-byte limit ensures values typically fit, it doesn't strictly prevent silent integer wraparound if a (valid, <=10 byte) sequence represents a value just outside the 64-bit range. Applications should be aware of this standard C behavior.

**Integrated Proposals:**

* **LIP-0001:** Introduced the versatile "IxData" field (Tag `10`), replacing the simple index. It enables encoding variable-length integers (using LEB128), fixed-size data types (integers, floats), boolean constants, and legacy indices via different sub-types.
* **LIP-0002:** Added support for multiple cryptographic schemes by utilizing previously reserved bits in the Public Key List (Tag `00`) and Signature List (Tag `01`) headers. This allows specifying algorithms like Ed25519 and SLH-DSA (SPHINCS+) variants. Crucially, it defined the use of 32-byte BLAKE3 hashes for large PQC signatures within the Signature List, requiring full proofs to be handled off-chain.
