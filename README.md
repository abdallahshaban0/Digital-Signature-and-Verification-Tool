
### Explanation of Changes

1. **Title and Introduction**:
   - Updated the introduction to include ECDH key exchange alongside RSA and ECC (ECDSA), emphasizing the tool’s expanded functionality for secure key agreement.

2. **Features**:
   - Added a new bullet point for the ECDH key exchange feature, specifying the use of the SECP256K1 curve.
   - Modified the save/load feature description to include shared secrets in base64 format, reflecting their similarity to signatures in terms of handling.

3. **Requirements**:
   - Updated the `cryptography` package description to note its use for ECDH key exchange, ensuring clarity about its expanded role.

4. **Usage**:
   - Added a new subsection under "Using the Application" for the **ECDH Key Exchange Tab**, detailing the steps to generate an ECDH key pair, load another party’s public key, and compute the shared secret.
   - Clarified that the shared secret is displayed in base64 format and can be used for symmetric encryption or other cryptographic purposes.

5. **Security Features**:
   - Added a bullet point for the ECDH implementation, noting the use of the SECP256K1 curve and HKDF for deriving a secure shared secret.
   - Included a note about the need for secure public key exchange to prevent man-in-the-middle attacks in ECDH.

6. **Notes**:
   - Added a note about ECDH usage, emphasizing that the shared secret is suitable for symmetric encryption but requires secure public key exchange.
   - Retained all original notes about RSA, ECC, key security, and file support, ensuring no loss of information.

### Purpose of the Update
The update integrates the bonus task of adding ECDH key exchange into the README, accurately reflecting the enhanced functionality of the `DigitalSignatureApp`. It ensures that users understand how to use the new ECDH Key Exchange tab, the security considerations involved, and the role of the shared secret in cryptographic applications. The changes maintain the original structure and content related to RSA and ECC (ECDSA) while clearly documenting the new ECDH features, making the README a comprehensive guide for the updated tool.
