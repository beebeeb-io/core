//! Encoder: payload bits → constellation frame.
//!
//! ## Wire format
//!
//! The 104-byte [`ConstellationPayload`] is padded to 128 bytes and
//! Reed-Solomon encoded (8 data shards + 8 parity shards, GF(2^8), each
//! shard 16 bytes). Frame `i` carries shard `i mod 16`.
//!
//! Each frame's shard is packed into a 134-bit packet:
//!
//! | bits  | meaning                                    |
//! |-------|--------------------------------------------|
//! | 0..4  | shard_index (0..15)                        |
//! | 4..132| shard data (16 bytes, LSB-first)           |
//! |132..134| 2-bit XOR checksum (parity over data)     |
//!
//! The 134 bits are then distributed across 67 node brightness slots
//! (2 bits per node, 4 quantised brightness levels). Edges carry no
//! data — they are deterministic decorations driven by `seed`.

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::frame::*;
use super::geometry::*;

pub const DATA_SHARDS: usize = 8;
pub const PARITY_SHARDS: usize = 8;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS; // 16
pub const SHARD_BYTES: usize = 16;
pub const PADDED_PAYLOAD_BYTES: usize = DATA_SHARDS * SHARD_BYTES; // 128

const _: () = assert!(ConstellationPayload::BYTE_LEN <= PADDED_PAYLOAD_BYTES);

/// Bit slots per frame (134 = 4 + 128 + 2).
pub const FRAME_BITS: usize = 134;
const _: () = assert!(NUM_NODES * 2 == FRAME_BITS);

/// Brightness levels — 4 quantisation steps spaced for visual contrast.
const BRIGHTNESS_LEVELS: [f32; 4] = [0.30, 0.55, 0.78, 1.0];

/// Edge weight levels — 4 quantisation steps. Cosmetic in v1.
const WEIGHT_LEVELS: [f32; 4] = [0.25, 0.50, 0.75, 1.0];

// ---------------------------------------------------------------------------
// RS encoding
// ---------------------------------------------------------------------------

/// Encode the payload into all 16 RS shards. Both encoder and decoder use
/// these slots to address shards by index.
pub(crate) fn encode_shards(payload: &ConstellationPayload) -> [[u8; SHARD_BYTES]; TOTAL_SHARDS] {
    let bytes = payload.to_bytes();
    let mut padded = [0u8; PADDED_PAYLOAD_BYTES];
    padded[..bytes.len()].copy_from_slice(&bytes);

    let mut shards: Vec<Vec<u8>> = (0..TOTAL_SHARDS).map(|_| vec![0u8; SHARD_BYTES]).collect();
    for i in 0..DATA_SHARDS {
        shards[i].copy_from_slice(&padded[i * SHARD_BYTES..(i + 1) * SHARD_BYTES]);
    }

    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS).expect("valid RS parameters");
    rs.encode(&mut shards).expect("RS encode never fails for this configuration");

    let mut out = [[0u8; SHARD_BYTES]; TOTAL_SHARDS];
    for (i, shard) in shards.iter().enumerate() {
        out[i].copy_from_slice(shard);
    }
    out
}

// ---------------------------------------------------------------------------
// Bit packing
// ---------------------------------------------------------------------------

/// Tiny bit-array helper. Bit 0 is the LSB of byte 0.
pub(crate) struct BitArray {
    pub bytes: [u8; FRAME_BITS.div_ceil(8)],
}

impl BitArray {
    pub fn new() -> Self {
        Self { bytes: [0u8; FRAME_BITS.div_ceil(8)] }
    }

    pub fn set(&mut self, pos: usize, value: u8) {
        let byte = pos / 8;
        let bit = pos % 8;
        self.bytes[byte] = (self.bytes[byte] & !(1u8 << bit)) | ((value & 1) << bit);
    }

    pub fn get(&self, pos: usize) -> u8 {
        let byte = pos / 8;
        let bit = pos % 8;
        (self.bytes[byte] >> bit) & 1
    }

    pub fn write_bits(&mut self, pos: usize, count: usize, value: u32) {
        for i in 0..count {
            self.set(pos + i, ((value >> i) & 1) as u8);
        }
    }

    pub fn read_bits(&self, pos: usize, count: usize) -> u32 {
        let mut v = 0u32;
        for i in 0..count {
            v |= (self.get(pos + i) as u32) << i;
        }
        v
    }

    pub fn read_two_bits(&self, pos: usize) -> u8 {
        self.get(pos) | (self.get(pos + 1) << 1)
    }
}

/// 2-bit XOR checksum over the 128 data bits (folded into 2 bits).
pub(crate) fn parity2(shard_data: &[u8; SHARD_BYTES]) -> u8 {
    let mut p: u8 = 0;
    for (i, &b) in shard_data.iter().enumerate() {
        // Spread parity contribution across both checksum bits so a single
        // bit flip in shard_data flips at least one checksum bit.
        let rotation = (i as u32) & 1;
        p ^= b.rotate_left(rotation);
    }
    let lo = (p ^ (p >> 4)) & 0xF;
    (lo ^ (lo >> 2)) & 0x3
}

/// Pack one shard into a `BitArray` of `FRAME_BITS` bits.
pub(crate) fn pack_shard(shard_index: u8, shard_data: &[u8; SHARD_BYTES]) -> BitArray {
    let mut bits = BitArray::new();
    bits.write_bits(0, 4, shard_index as u32);
    for (i, &b) in shard_data.iter().enumerate() {
        bits.write_bits(4 + i * 8, 8, b as u32);
    }
    let p = parity2(shard_data);
    bits.write_bits(132, 2, p as u32);
    bits
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encode the payload into the visualisation frame at `frame_index`.
///
/// `frame_index` selects which RS shard is conveyed. Cycling through 0..16
/// covers the entire codeword; the decoder needs any 8 distinct shards to
/// recover the payload.
pub fn constellation_encode(payload: &ConstellationPayload, frame_index: u32) -> ConstellationFrame {
    let shards = encode_shards(payload);
    let shard_index = (frame_index as usize) % TOTAL_SHARDS;
    let bits = pack_shard(shard_index as u8, &shards[shard_index]);

    let (positions, kinds) = node_positions();
    let edges_pairs = edge_pairs(&positions);

    // Cosmetic seed mixes a stable per-payload component with the frame.
    let session_seed = u64::from_le_bytes([
        payload.session_id[0], payload.session_id[1], payload.session_id[2], payload.session_id[3],
        payload.session_id[4], payload.session_id[5], payload.session_id[6], payload.session_id[7],
    ]);
    let seed = session_seed ^ (frame_index as u64).wrapping_mul(0x9E3779B97F4A7C15);

    let mut nodes = Vec::with_capacity(NUM_NODES);
    for i in 0..NUM_NODES {
        let two_bits = bits.read_two_bits(i * 2);
        let brightness = BRIGHTNESS_LEVELS[two_bits as usize];
        let pulse_phase = pseudo_unit(seed, i as u64);
        nodes.push(ConstellationNode {
            kind: kinds[i],
            x: positions[i].x,
            y: positions[i].y,
            z: positions[i].z,
            brightness,
            pulse_phase,
        });
    }

    let mut edges = Vec::with_capacity(edges_pairs.len());
    for (i, &(a, b)) in edges_pairs.iter().enumerate() {
        let level = (mix64(seed, (i as u64) ^ 0xA5A5_A5A5_A5A5_A5A5) >> 14) as usize % 4;
        edges.push(ConstellationEdge {
            from_idx: a,
            to_idx: b,
            weight: WEIGHT_LEVELS[level],
            flow_speed: pseudo_unit(seed, (i as u64) ^ 0x5A5A_5A5A_5A5A_5A5A),
        });
    }

    let ring_phase = pseudo_unit(seed, 0xFFEE_FFEE);

    ConstellationFrame {
        frame_index,
        seed,
        nodes,
        edges,
        ring_phase,
    }
}

// ---------------------------------------------------------------------------
// Cosmetic RNG (deterministic, NOT cryptographic)
// ---------------------------------------------------------------------------

fn mix64(seed: u64, mix: u64) -> u64 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ mix;
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    x
}

fn pseudo_unit(seed: u64, mix: u64) -> f32 {
    let h = mix64(seed, mix);
    ((h >> 40) as f32) / ((1u64 << 24) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_payload() -> ConstellationPayload {
        let mut session_id = [0u8; 16];
        session_id[..4].copy_from_slice(b"sess");
        let mut ephemeral_pubkey = [0u8; 32];
        for (i, b) in ephemeral_pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut nonce = [0u8; 16];
        nonce[..6].copy_from_slice(b"noncey");
        let mut confirm_code_hash = [0u8; 32];
        for (i, b) in confirm_code_hash.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        ConstellationPayload {
            session_id,
            ephemeral_pubkey,
            nonce,
            expires_at_unix_ms: 1_777_700_000_000,
            confirm_code_hash,
        }
    }

    #[test]
    fn payload_roundtrip_bytes() {
        let p = dummy_payload();
        let bytes = p.to_bytes();
        let p2 = ConstellationPayload::from_bytes(&bytes);
        assert_eq!(p, p2);
    }

    #[test]
    fn rs_shards_are_consistent_size() {
        let shards = encode_shards(&dummy_payload());
        assert_eq!(shards.len(), TOTAL_SHARDS);
        for s in &shards {
            assert_eq!(s.len(), SHARD_BYTES);
        }
    }

    #[test]
    fn pack_shard_uses_full_capacity() {
        let p = dummy_payload();
        let shards = encode_shards(&p);
        let bits = pack_shard(3, &shards[3]);
        // shard_index round-trips
        assert_eq!(bits.read_bits(0, 4), 3);
        // shard_data round-trips
        for (i, &b) in shards[3].iter().enumerate() {
            assert_eq!(bits.read_bits(4 + i * 8, 8) as u8, b);
        }
        // parity round-trips
        assert_eq!(bits.read_bits(132, 2) as u8, parity2(&shards[3]));
    }

    #[test]
    fn frame_brightness_quantises_to_known_levels() {
        let f = constellation_encode(&dummy_payload(), 0);
        assert_eq!(f.nodes.len(), NUM_NODES);
        for n in &f.nodes {
            assert!(BRIGHTNESS_LEVELS.iter().any(|lvl| (lvl - n.brightness).abs() < 1e-6));
        }
    }
}
