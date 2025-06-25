# Squad
**version:** 0.1

Shamir Secret Sharing System implementation in Go.

Considerations:
- Standard Shamir Secret Sharing Scheme Settings:
  `k` shares required of `n` total shares to recover the secret
- Usage as a command-line app to split text and files
- Usage as a Go package to split byte slices
- Compatibility with adjacent libraries in other languages
- Optional inline tagging (8-byte prefix of zero bytes)
  for message integrity verification during combine step

Non-considerations:
- Large files / `io.Reader` and `io.Writer`: If you need to split
  large files, consider encrypting the file using a fast symmetric
  algorithm like AES-256 or XChaCha20, then splitting the key.
  This will save on storage for each share *and* recovery speed.
- Side-channel attacks: If the secret is important, the system you
  run this on should already be trusted (since it contains plaintext
  secrets), so side-channel attacks should be essentially a non-factor.

# Compatible Libraries

- **TypeScript & JavaScript:** [Zytekaron/squad-js](https://github.com/Zytekaron/squad-js) (npm: `@zytekaron/squad`)

# Usage

## Command-line

```shell
# Split the provided text into 3 parts, with a threshold of 2
squad split "Hello, World!" -n 3 -k 2

# Split input.txt into 10 parts with a threshold of 7,
# using "squad/share_" as the prefix for the name.
squad split -f "input.txt" -n 10 -k 7 -o "squad/share_"

# Generate a new random key, print it to the console,
# and split it into 5 parts with a threshold of 3.
# You can use the printed key to encrypt data eg using
# AES, and the key is recoverable with at least 3 shares.
openssl rand -base16 32 | tee /dev/tty | squad split -n 5 -k 3

# More options:
# - Use {i} indices (starting with 1) to place the
#   the share number in the start/middle of the name.
#   Share numbers are NOT extracted from file name or
#   sorting order; they are stored in the first byte
#   of the contents. File names do not matter.
squad split ... -o "squad/share_{i}.squad"
```

```shell
# Combine all of the share files and print the
# recovered secret directly to the console.
squad combine "squad/share_"*

# Combine all of the share files into an output file.
squad combine "squad/share_"* -o recovered.txt
```

## Go library

This project also serves as a Go library which can be used
in your own projects.

# License
**squad** is licensed under the [MIT License](./LICENSE).
