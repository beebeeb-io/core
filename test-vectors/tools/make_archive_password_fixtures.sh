#!/usr/bin/env bash
# Makes the password-protected zip fixtures in test-vectors/archives/.
#
# The passwords below are public TEST passwords, written here on purpose:
# they protect nothing but these fixtures. The archives come from two
# independent writers, 7-Zip (WinZip AES) and Info-ZIP (ZipCrypto), so the
# reader is checked against tools people actually use, not against itself.
#
# Made with: 7-Zip (z) 26.05 (x64) as `7zz`; Info-ZIP Zip 3.0 (July 5th 2008)
# as `zip`. Re-running changes the bytes (both tools salt or seed every
# archive at random); the tests check behaviour and the fixed plaintext.
#
# AE-1 fixtures: 7-Zip writes AE-2 for these files, so the AE-1 rows are
# the same archives with the AES extra field's vendor version set to 1 and
# the real CRC-32 written into both headers (WinZip's AE-1 layout); the
# reader test makes them from the AE-2 fixtures (support::to_ae1).
set -euo pipefail

out=$(cd "$(dirname "${BASH_SOURCE[0]}")/../archives" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

password='beebeeb-test-password'
other='other-test-password'
# "café-test" as an old Windows ZipCrypto tool encodes it: CP437, é = 0x82.
cp437_password=$(printf 'caf\x82-test')

for _ in $(seq 40); do printf 'The protected test file.\n'; done > secret.txt
printf 'Not protected.\n' > plain.txt
cp secret.txt other.txt
TZ=UTC touch -d '2024-03-15 12:34:56' secret.txt plain.txt other.txt

for bits in 128 192 256; do
  7zz a -bso0 -bsp0 -tzip -mm=Deflate -mem="AES$bits" -p"$password" "aes$bits.zip" secret.txt
done
# Stored (no compression), so one flipped ciphertext byte flips one
# plaintext byte and only the authentication code can catch it.
7zz a -bso0 -bsp0 -tzip -mm=Copy -mem=AES256 -p"$password" aes256-stored.zip secret.txt
zip -q -X -P "$password" zipcrypto.zip secret.txt
zip -q -X -P "$cp437_password" zipcrypto-cp437.zip secret.txt
zip -q -X mixed.zip plain.txt
zip -q -X -P "$password" mixed.zip secret.txt
zip -q -X -P "$password" two-passwords.zip secret.txt
zip -q -X -P "$other" two-passwords.zip other.txt

cp aes128.zip aes192.zip aes256.zip aes256-stored.zip zipcrypto.zip zipcrypto-cp437.zip mixed.zip two-passwords.zip "$out/"
echo "wrote 8 password fixtures to $out"
