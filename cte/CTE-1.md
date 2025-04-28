# **CTE: Compact Transaction Encoding Specification v1.0**

* **Version:** 1.0
* **Date:** 2025-04-22
* **Status:** Final

## 1. Introduction

This document defines Version 1.0 of the Compact Transaction Encoding (CTE) format. CTE is a binary serialization format designed for efficient representation of transactions, particularly in environments where size constraints are critical. It utilizes a tag-based system to identify different data fields within a single transaction structure.

## 2. General Encoding Rules

* **Maximum Transaction Size:** A single CTE-encoded transaction MUST NOT exceed **1232 bytes** in total length.
* **Version Identifier:** The first byte of any valid CTE v1.0 transaction MUST be `0x01` (`00000001b`).
* **Byte Alignment:** All fields start on byte boundaries unless explicitly specified otherwise within a field's definition (e.g., bit-level definitions within a header byte).
* **Field Identification:** Data fields following the Version byte are identified by a **2-bit tag** located in the most significant bits (MSB) of the field's first byte.

## 3. Field Tag Summary

The first 2 bits of a field's header byte determine its type:

| Tag (Binary) | Tag (Hex) | Field Type        | Description                             |
| :----------- | :-------- | :---------------- | :-------------------------------------- |
| `00`         | `0x0_`    | Public Key List   | Contains a list of 32-byte public keys. |
| `01`         | `0x4_`    | Signature List    | Contains a list of 64-byte signatures.  |
| `10`         | `0x8_`    | Index Reference   | Contains a 4-bit index value.           |
| `11`         | `0xC_`    | Command Data      | Contains arbitrary application payload.   |

## 4. Field Type Specifications

### 4.1. Public Key List

* **Tag:** `00`
* **Purpose:** Encodes a list of one or more 32-byte public keys used within the transaction.
* **Format:**
    * **Header Byte:**
        | Bits  | Field           | Description                           |
        | :---- | :-------------- | :------------------------------------ |
        | 7-6   | Tag (`00`)      | Identifies this as a Public Key List. |
        | 5-2   | Length (N)      | Number of keys in the list (1-15).    |
        | 1-0   | Padding (`00`)  | Reserved, MUST be zero.               |
    * **Data:** Followed by `N` contiguous 32-byte public keys.
* **Constraints:**
    * The Length field (4 bits) supports 0-15. A value of `0000` is reserved/invalid; the list must contain at least 1 key if present. Max 15 keys.
    * Total size = `1 + (N * 32)` bytes.
* **Example (3 Public Keys):**
    * Header Byte: `00` `0011` `00` = `00001100b` = `0x0C`
    * Followed by: `3 * 32 = 96` bytes of public key data.

### 4.2. Signature List

* **Tag:** `01`
* **Purpose:** Encodes a list of one or more 64-byte signatures used to authorize the transaction.
* **Format:**
    * **Header Byte:**
        | Bits  | Field           | Description                          |
        | :---- | :-------------- | :----------------------------------- |
        | 7-6   | Tag (`01`)      | Identifies this as a Signature List. |
        | 5-2   | Length (N)      | Number of signatures in list (1-15). |
        | 1-0   | Padding (`00`)  | Reserved, MUST be zero.              |
    * **Data:** Followed by `N` contiguous 64-byte signatures.
* **Constraints:**
    * The Length field (4 bits) supports 0-15. A value of `0000` is reserved/invalid; the list must contain at least 1 signature if present. Max 15 signatures.
    * Total size = `1 + (N * 64)` bytes.
* **Example (1 Signature):**
    * Header Byte: `01` `0001` `00` = `01000100b` = `0x44`
    * Followed by: `1 * 64 = 64` bytes of signature data.

### 4.3. Index Reference

* **Tag:** `10`
* **Purpose:** Provides a zero-based index referencing an item within the preceding `Public Key List` or `Signature List`. The context determines which list is being referenced (typically, indexes following a list refer to that list).
* **Format:**
    * **Header Byte:**
        | Bits  | Field           | Description                                      |
        | :---- | :-------------- | :----------------------------------------------- |
        | 7-6   | Tag (`10`)      | Identifies this as an Index Reference.           |
        | 5-2   | Index (I)       | The 4-bit index value (0-15).                    |
        | 1-0   | Padding (`00`)  | Reserved, MUST be zero.                          |
* **Constraints:**
    * The Index value MUST correspond to a valid position within the relevant list (e.g., if the Public Key List has 5 keys, valid Index values for it are 0-4).
    * Total size = `1` byte.
* **Example (Reference Index 5):**
    * Header Byte: `10` `0101` `00` = `10010100b` = `0x94`

### 4.4. Command Data

* **Tag:** `11`
* **Purpose:** Encodes the primary transaction payload or command instructions. Uses a variable-length encoding scheme.
* **Format:** Determined by the 3rd most significant bit (Bit 5) of the first header byte.

    * **4.4.1. Short Format (Payload length 0-31 bytes):**
        * Used when Bit 5 of the header byte is `0`.
        * **Header Byte:**
            | Bits  | Field              | Description                             |
            | :---- | :----------------- | :-------------------------------------- |
            | 7-6   | Tag (`11`)         | Identifies this as Command Data.        |
            | 5     | Format Flag (`0`)  | Indicates Short Format.                 |
            | 4-0   | Length (L)         | 5-bit payload length (0-31 bytes).      |
        * **Data:** Followed by `L` bytes of payload data.
        * Total size = `1 + L` bytes.
        * **Example (Payload length 21 / `10101b`):**
            * Header Byte: `11` `0` `10101` = `11010101b` = `0xD5`
            * Followed by 21 bytes of payload.

    * **4.4.2. Extended Format (Payload length 32-1197 bytes):**
        * Used when Bit 5 of the header byte is `1`.
        * **Header Bytes (2 bytes):**
            * **Byte 1:**
                | Bits  | Field                     | Description                             |
                | :---- | :------------------------ | :-------------------------------------- |
                | 7-6   | Tag (`11`)                | Identifies this as Command Data.        |
                | 5     | Format Flag (`1`)         | Indicates Extended Format.              |
                | 4-0   | Length High Bits (LH)     | Upper 5 bits of the 11-bit length. Note: Specification document uses 3 bits (4-2), previous example used 5 bits. Let's stick to the more efficient 3+8 bits described in the *user's* specification text for 11 bits total. Let's correct the table layout. |

            * **Corrected Byte 1 for Extended Format:**
                | Bits  | Field                     | Description                             |
                | :---- | :------------------------ | :-------------------------------------- |
                | 7-6   | Tag (`11`)                | Identifies this as Command Data.        |
                | 5     | Format Flag (`1`)         | Indicates Extended Format.              |
                | 4-2   | Length High Bits (LH)     | Upper 3 bits of the 11-bit length.      |
                | 1-0   | Padding (`00`)          | Reserved, MUST be zero.                 |

            * **Byte 2:**
                | Bits  | Field                     | Description                             |
                | :---- | :------------------------ | :-------------------------------------- |
                | 7-0   | Length Low Bits (LL)      | Lower 8 bits of the 11-bit length.      |
        * **Data:** Followed by `L` bytes of payload data, where `L` is the reconstructed 11-bit length.
        * **Length Calculation:** `L = (LH << 8) | LL`
        * **Constraints:**
            * The calculated length `L` MUST be between 32 and 1197 (inclusive). Although 11 bits can represent up to 2047, the maximum is capped by the overall transaction size and minimum field overheads.
        * Total size = `2 + L` bytes.
        * **Example (Payload length 400 / `001 10010000b`):**
            * LH = `001b`
            * LL = `10010000b` = `0x90`
            * Byte 1: `11` `1` `001` `00` = `11100100b` = `0xE4`
            * Byte 2: `10010000b` = `0x90`
            * Followed by 400 bytes of payload.

## 5. Transaction Structure

A typical CTE v1.0 transaction follows this general order after the initial Version byte:

1.  **Version Byte** (`0x01`)
2.  **Public Key List** (Optional, Tag `00`)
3.  **Signature List** (Optional, Tag `01`)
4.  **Index Reference(s)** (Optional, Tag `10`, referring to keys/signatures)
5.  **Command Data** (Optional, Tag `11`)

* Each field type (except Version) may appear zero or one time in a single transaction.
* The specific combination and order of fields depend on the requirements of the command being executed.

## 6. Notes and Constraints

* **Maximum Command Data Size:** The practical maximum size for the Command Data payload is constrained by the overall transaction limit (1232 bytes) and the minimum overhead of other required fields. For a transaction requiring at least one public key (for identification/authorization) and its corresponding index, the maximum payload size is:
    `1232 (Total) - 1 (Version) - 1 (PubKey List Hdr) - 32 (PubKey) - 1 (Index Hdr) = 1197 bytes`.
* **Authorization Context:** It is generally assumed that a transaction requires at least one public key (provided in the Public Key List) and an associated Index Reference to identify the key relevant for command validation or execution context.

## 7. Future Considerations

* The reserved/padding bits within header bytes may be utilized in future versions of the CTE specification.
* Unused 2-bit tag combinations are reserved for future expansion.
* For applications frequently involving large Command Data payloads, integrating a compression scheme could be considered in future versions.

## About

This project is part of the [LEA Project](https://getlea.org).

## Author

Developed by Allwin Ketnawang.

## License

This project is licensed under the [MIT License](LICENSE).