# **BitWeave Variable-Length Encoding (BWVLE) Specification v1**

## **1\. Introduction**

This document specifies the **BitWeave Variable-Length Encoding (BWVLE)** scheme, version 1\. BWVLE is designed for the efficient and secure serialization of both scalar unsigned 64-bit integers (uint64\_t) and variable-length byte sequences.

It utilizes a prefix code where the initial bits of an encoded block unambiguously determine the type of data that follows (either a scalar or a byte sequence). A key feature is the use of the shortest possible prefix (10) to signal the more common case of byte sequences, optimizing for bulk data encoding. Version 1 adds specific security constraints regarding canonical encoding and trailing zero padding.

## **2\. Core Concepts**

### **2.1. Bit Ordering**

Unless otherwise specified, bits within the stream are processed from most significant to least significant. When reading from or writing to byte buffers, standard C array indexing applies, and bits within a byte are typically handled MSB first (bit 7 down to bit 0).

### **2.2. Helper Function: min\_bits(X)**

This function determines the minimum number of bits required to represent the unsigned integer value X.

* min\_bits(0) \= 1 (Requires one bit to represent)  
* min\_bits(X) for X \> 0 \= floor(log2(X)) \+ 1, or equivalently, the position of the most significant bit set (1-based index). In C, this can be efficiently calculated as 64 \- \_\_builtin\_clzll(X) for non-zero X.

### **2.3. Data Type Identification**

The type of data encoded is determined by reading the first two bits of a block:

* **10**: Indicates a **Byte Sequence**.  
* **11**: Indicates a **Scalar uint64\_t**.

## **3\. Encoding Formats**

### **3.1. Scalar uint64\_t Encoding**

Scalars are encoded when the leading bits are 11\. The encoding **must** use the minimal number of bits for the value V as determined by min\_bits(V).

**Structure:**

\[Prefix: 11\] \[Signal Bits\] \[Data Length Field\] \[Data Field\]

**Encoding Process for Value V:**

1. **Calculate Data Field Length (M):**  
   * M \= min\_bits(V) **(MUST be the minimal bits)**  
2. **Calculate Data Length Field's Length (N):**  
   * Let M\_bits \= min\_bits(M) (bits needed to represent M).  
   * N \= max(2, M\_bits)  
   * *Note:* The length N of the Data Length Field is forced to be at least 2 bits.  
3. **Write Prefix:**  
   * Write the bits 11\.  
4. **Write Signal Bits:**  
   * Write N '1' bits followed by one '0' bit.  
5. **Write Data Length Field:**  
   * Write the value M using exactly N bits (left-padding with '0's if necessary).  
6. **Write Data Field:**  
   * Write the value V using exactly M bits (left-padding with '0's if necessary).

**Examples (Scalar):**

* **Encode 0 (V=0):**  
  * M \= min\_bits(0) \= 1  
  * M\_bits \= min\_bits(1) \= 1  
  * N \= max(2, 1\) \= 2  
  * Prefix: 11  
  * Signal: N=2 \-\> 110  
  * Data Length Field: M=1 in N=2 bits \-\> 01  
  * Data Field: V=0 in M=1 bit \-\> 0  
  * **Result: 11 110 01 0** (Binary: 11110010\)  
* **Encode 1 (V=1):**  
  * M \= min\_bits(1) \= 1  
  * M\_bits \= min\_bits(1) \= 1  
  * N \= max(2, 1\) \= 2  
  * Prefix: 11  
  * Signal: N=2 \-\> 110  
  * Data Length Field: M=1 in N=2 bits \-\> 01  
  * Data Field: V=1 in M=1 bit \-\> 1  
  * **Result: 11 110 01 1** (Binary: 11110011\)  
* **Encode 4 (V=4):**  
  * M \= min\_bits(4) \= 3  
  * M\_bits \= min\_bits(3) \= 2  
  * N \= max(2, 2\) \= 2  
  * Prefix: 11  
  * Signal: N=2 \-\> 110  
  * Data Length Field: M=3 in N=2 bits \-\> 11  
  * Data Field: V=4 (100) in M=3 bits \-\> 100  
  * **Result: 11 110 11 100** (Binary: 1111011100\)  
* **Encode 2231 (V=2231):**  
  * M \= min\_bits(2231) \= 12  
  * M\_bits \= min\_bits(12) \= 4  
  * N \= max(2, 4\) \= 4  
  * Prefix: 11  
  * Signal: N=4 \-\> 11110  
  * Data Length Field: M=12 (1100) in N=4 bits \-\> 1100  
  * Data Field: V=2231 (100010110111) in M=12 bits \-\> 100010110111  
  * **Result: 11 11110 1100 100010110111**

### **3.2. Byte Sequence Encoding**

Byte sequences are encoded when the leading bits are 10\.

**Structure:**

\[Prefix: 10\] \[Encoded Length\] \[Raw Data Bytes\]

**Encoding Process for Data D of Length L:**

1. **Write Prefix:**  
   * Write the bits 10\.  
2. **Write Encoded Length:**  
   * Encode the length value L (which is a uint64\_t) using the **Scalar uint64\_t Encoding** process described in Section 3.1. Note that L itself must be encoded canonically.  
3. **Write Raw Data Bytes:**  
   * Write the L bytes of the data D verbatim to the bitstream, 8 bits per byte.

**Example (Byte Sequence):**

* **Encode byte sequence \[0xCA, 0xFE\] (L=2):**  
  * Prefix: 10  
  * Encode Length L=2 (canonically):  
    * V=2 \-\> M=2, M\_bits=2, N=2.  
    * Scalar Prefix: 11  
    * Signal: 110  
    * Data Length Field: M=2 in N=2 bits \-\> 10  
    * Data Field: V=2 in M=2 bits \-\> 10  
    * Encoded Length (L=2): 11 110 10 10  
  * Raw Data Bytes: 11001010 (0xCA), 11111110 (0xFE)  
  * **Result: 10 111101010 11001010 11111110**

## **4\. Decoding Process**

Decoding reverses the encoding process and includes validation checks.

1. **Read Type Prefix:** Read the first two bits.  
2. **Dispatch:**  
   * **If 10 (Byte Sequence):**  
     1. Decode the next block as a scalar uint64\_t using the Scalar Decoding process (Section 4.1) to obtain the sequence length L. If scalar decoding fails (including canonical check), report an error.  
     2. Read the subsequent L \* 8 bits (or L bytes) as the raw data sequence. Handle potential read errors (e.g., insufficient data in the stream).  
     3. Return the decoded byte sequence and the total number of bits consumed *so far*.  
   * **If 11 (Scalar uint64\_t):**  
     1. Proceed with Scalar Decoding (Section 4.1). If scalar decoding fails (including canonical check), report an error.  
     2. Return the decoded scalar value and the total number of bits consumed *so far*.  
   * **If prefix is invalid (e.g., end of stream before 2 bits):** Report a decoding error.

### **4.1. Scalar uint64\_t Decoding**

This process assumes the 11 prefix has already been consumed.

1. **Read Signal Bits:** Read bits one by one until a '0' is encountered. Count the number of preceding '1's (N).  
   * *Error Handling:* If the stream ends before a '0' is found, report an error.  
   * *Validation:* Check if N \>= 2\. If N \< 2, this indicates a corrupted or non-compliant stream. Report an error.  
2. **Read Data Length Field:** Read the next N bits. Interpret these bits as an unsigned integer M.  
   * *Error Handling:* If the stream ends before N bits are read, report an error.  
   * *Validation:* Check if M \> 0\. If M \== 0, this is invalid as min\_bits never returns 0\. Report an error. (While min\_bits(0)=1, M represents the length, which must be at least 1).  
3. **Read Data Field:** Read the next M bits. Interpret these bits as an unsigned integer V.  
   * *Error Handling:* If the stream ends before M bits are read, report an error.  
4. **Canonical Validation:**  
   * Calculate M\_check \= min\_bits(V).  
   * If M\_check \!= M, the encoding is non-canonical. Report an error.  
5. **Return Value:** The decoded scalar value is V. The total bits consumed for the scalar (excluding the initial 11 prefix) are (N \+ 1\) \+ N \+ M.

## **5\. Final Padding Verification (Security Constraint)**

This check applies **after** successfully decoding the entire expected sequence of items from a given buffer or stream.

1. **Determine Current Bit Position:** Let the total number of bits consumed be TotalBits.  
2. **Check for Byte Alignment:** Calculate RemainderBits \= TotalBits % 8\.  
3. **If RemainderBits \!= 0:**  
   * The stream does not end on a byte boundary.  
   * Read the remaining 8 \- RemainderBits bits from the current byte in the input stream.  
   * **Verify Zero Padding:** Check if *all* these remaining bits are '0'.  
   * If any remaining bit is '1', the padding is invalid. Report a decoding error.  
   * If the stream ends before these remaining bits can be read, report an error.  
4. **If RemainderBits \== 0:** The stream ends on a byte boundary, and no padding check is needed.

## About

This project is part of the [LEA Project](https://getlea.org).

## Author

Developed by Allwin Ketnawang.

## License

This project is licensed under the [MIT License](LICENSE).
