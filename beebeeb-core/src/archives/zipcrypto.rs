//! Traditional PKWARE encryption ("ZipCrypto", APPNOTE 6.1), decryption
//! only. It is weak: the preview says so before anyone types a password
//! (`archive_zipcrypto_weak`). Files extracted from it are stored with
//! Beebeeb's own encryption.

use zeroize::Zeroize;

/// The reflected CRC-32 table (polynomial 0xEDB88320) the cipher's key
/// update uses.
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

fn crc32_byte(crc: u32, byte: u8) -> u32 {
    CRC_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8)
}

/// The cipher's three keys. Wiped on drop: they are derived from the
/// password and decrypt everything after them.
pub(crate) struct ZipCryptoKeys([u32; 3]);

impl Drop for ZipCryptoKeys {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZipCryptoKeys {
    pub(crate) fn new(password: &[u8]) -> Self {
        let mut keys = Self([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &b in password {
            keys.update(b);
        }
        keys
    }

    fn update(&mut self, plain: u8) {
        let k = &mut self.0;
        k[0] = crc32_byte(k[0], plain);
        k[1] = k[1].wrapping_add(k[0] & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
        k[2] = crc32_byte(k[2], (k[1] >> 24) as u8);
    }

    fn stream_byte(&self) -> u8 {
        let temp = (self.0[2] | 2) & 0xFFFF;
        (temp.wrapping_mul(temp ^ 1) >> 8) as u8
    }

    pub(crate) fn decrypt(&mut self, bytes: &mut [u8]) {
        for b in bytes {
            let plain = *b ^ self.stream_byte();
            self.update(plain);
            *b = plain;
        }
    }
}

/// Decrypt the 12-byte encryption header and say whether its check byte
/// matches (`check` is the CRC's high byte, or the DOS time's when the
/// entry has a data descriptor). A wrong password fails this 255 times in
/// 256; the rest are caught by the entry's CRC.
pub(crate) fn open_header(password: &[u8], header: &[u8; 12], check: u8) -> Option<ZipCryptoKeys> {
    let mut keys = ZipCryptoKeys::new(password);
    let mut plain = *header;
    keys.decrypt(&mut plain);
    let ok = plain[11] == check;
    plain.zeroize();
    ok.then_some(keys)
}
