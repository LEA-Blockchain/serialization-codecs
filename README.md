# Data Encoding Algorithms Collection

This repository contains implementations and specifications for various data encoding algorithms developed as part of the [LEA Project](https://getlea.org).

## Encoding Algorithms Included

This project currently includes the following encoding schemes:

* **BitWeave Variable-Length Encoding (BWVLE)**
    * **Location:** `bwvle/`
    * **Description:** An encoding scheme designed for the efficient and secure serialization of both scalar unsigned 64-bit integers (`uint64_t`) and variable-length byte sequences. It utilizes a 2-bit prefix code (`10` for byte sequences, `11` for scalars) to identify the data type and employs canonical encoding rules for security.
    * **[Full BWVLE Specification](./bwvle/README.md)**

* **Compact Transaction Encoding (CTE)**
    * **Location:** `cte/`
    * **Description:** A binary serialization format optimized for representing transactions compactly, particularly useful in environments with strict size constraints (max 1232 bytes per transaction in v1.0). It uses a 2-bit tag system within the first byte of each field to identify data types like Public Key Lists, Signature Lists, Index References, and variable-length Command Data.
    * **[Full CTE Specification](./cte/README.md)**
