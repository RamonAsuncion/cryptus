# Cryptus

Command-Line Tool for File Encryption using AES-256 in GCM mode (Symmetric).

It's uses the simplest technique, symmetric encryption. The program uses pre-shared key to encrypt and decrypt messages.

## What the code does

- It uses `clap` to parse command-line arguments.

- If the keyfile is provided, it reads in that file otherwise it

- It uses AES-256 in GCM mode for encryption and decryption.

- For encryption, it reads the input file, encrypts it, and writes the ciphertext to a new file with the `.enc` extension.

- For decryption, it reads the encrypted file, decrypts it, and writes the plaintext to a new file with the `.dec` extension.

## References

This is not a comprehensive list. This is my first time using Rust so I searched up many basic questions, such as "How to get user input in Rust?" or looked through the Rust documentation.

1. [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
2. [Keyfile](https://en.wikipedia.org/wiki/Keyfile)
3. [Rust Documentation](https://doc.rust-lang.org/book/)
4. [Clap](https://docs.rs/clap/latest/clap/)
5. [Access Optional](https://doc.rust-lang.org/nightly/core/option/enum.Option.html)
6. [Error handing with ? operator](https://stackoverflow.com/questions/42917566/what-is-this-question-mark-operator-about)
7. [Which key sizes can I use?](https://help.salesforce.com/s/articleView?id=001117903&type=1)
8. [AES256Gcm](https://docs.rs/aes-gcm/latest/aes_gcm/)
9. [Files](https://doc.rust-lang.org/std/fs/struct.File.html)
10. [Handling errors](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
