//! Decoder: observed node brightnesses → recovered payload.
//!
//! The decoder is stateful — it accumulates shards across frames. When at
//! least `DATA_SHARDS` distinct shards have been collected, Reed-Solomon
//! reconstruction recovers the original payload.

use std::sync::Mutex;

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::encoder::{
    BitArray, DATA_SHARDS, FRAME_BITS, PADDED_PAYLOAD_BYTES, PARITY_SHARDS, SHARD_BYTES,
    TOTAL_SHARDS, parity2,
};
use super::frame::*;
use super::geometry::NUM_NODES;

/// Quantisation thresholds matching the encoder's [0.30, 0.55, 0.78, 1.00] levels.
/// Mid-points: 0.425, 0.665, 0.89.
const BRIGHTNESS_THRESHOLDS: [f32; 3] = [0.425, 0.665, 0.89];

/// Observations below this confidence are dropped before decoding.
const MIN_CONFIDENCE: f32 = 0.25;

/// Internal state — wrapped in `Mutex` because UniFFI exports require
/// interior mutability via `&self` methods.
struct DecoderState {
    shards: [Option<[u8; SHARD_BYTES]>; TOTAL_SHARDS],
    frames_ingested: u32,
}

impl DecoderState {
    fn new() -> Self {
        Self {
            shards: [None; TOTAL_SHARDS],
            frames_ingested: 0,
        }
    }

    fn shards_collected(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }
}

/// Stateful constellation decoder.
///
/// Build with [`ConstellationDecoder::new`]; feed camera observations via
/// [`ingest_frame`]. Returns `Some(payload)` on the frame that completes the
/// codeword.
pub struct ConstellationDecoder {
    state: Mutex<DecoderState>,
}

impl ConstellationDecoder {
    pub fn new() -> Self {
        Self { state: Mutex::new(DecoderState::new()) }
    }

    /// Total frames passed to `ingest_frame` so far.
    pub fn frames_ingested(&self) -> u32 {
        self.state.lock().expect("decoder mutex").frames_ingested
    }

    /// Number of distinct shards recovered. Decoding succeeds at >= 8.
    pub fn shards_collected(&self) -> u32 {
        self.state.lock().expect("decoder mutex").shards_collected() as u32
    }

    /// 0.0..=1.0 progress estimate for UI.
    pub fn progress(&self) -> f32 {
        let n = self.shards_collected() as f32;
        (n / DATA_SHARDS as f32).min(1.0)
    }

    /// Reset accumulator. Call this between pairing attempts.
    pub fn reset(&self) {
        let mut s = self.state.lock().expect("decoder mutex");
        *s = DecoderState::new();
    }

    /// Feed a single observed frame. Returns `Some(payload)` if the codeword
    /// was completed by this frame, `None` otherwise.
    pub fn ingest_frame(&self, observations: &[ObservedNode]) -> Option<ConstellationPayload> {
        let mut state = self.state.lock().expect("decoder mutex");
        state.frames_ingested = state.frames_ingested.saturating_add(1);

        // Build a bit array from per-node brightness. Missing/low-confidence
        // observations leave the corresponding two bits as 0; the parity
        // check rejects shards we can't fully read.
        let mut bits = BitArray::new();
        let mut have_node = [false; NUM_NODES];

        for obs in observations {
            if obs.confidence < MIN_CONFIDENCE {
                continue;
            }
            let idx = obs.idx as usize;
            if idx >= NUM_NODES {
                continue;
            }
            let level = quantize_brightness(obs.brightness);
            bits.set(idx * 2, level & 1);
            bits.set(idx * 2 + 1, (level >> 1) & 1);
            have_node[idx] = true;
        }

        // Need every node read to recover the full 134-bit packet.
        if !have_node.iter().all(|h| *h) {
            return self.try_reconstruct(&state.shards);
        }

        let shard_index = bits.read_bits(0, 4) as usize;
        if shard_index >= TOTAL_SHARDS {
            return self.try_reconstruct(&state.shards);
        }

        let mut shard = [0u8; SHARD_BYTES];
        for (i, byte) in shard.iter_mut().enumerate() {
            *byte = bits.read_bits(4 + i * 8, 8) as u8;
        }

        let observed_parity = bits.read_bits(132, 2) as u8;
        let expected_parity = parity2(&shard);
        if observed_parity != expected_parity {
            // Corrupted shard — drop it and let later frames retry this slot.
            return self.try_reconstruct(&state.shards);
        }

        // Only overwrite if currently empty; first valid wins. (A future
        // version could weight by confidence instead.)
        if state.shards[shard_index].is_none() {
            state.shards[shard_index] = Some(shard);
        }

        self.try_reconstruct(&state.shards)
    }

    fn try_reconstruct(&self, shards: &[Option<[u8; SHARD_BYTES]>; TOTAL_SHARDS]) -> Option<ConstellationPayload> {
        let collected = shards.iter().filter(|s| s.is_some()).count();
        if collected < DATA_SHARDS {
            return None;
        }

        let mut option_shards: Vec<Option<Vec<u8>>> = shards
            .iter()
            .map(|s| s.map(|arr| arr.to_vec()))
            .collect();

        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS).expect("valid RS parameters");
        rs.reconstruct(&mut option_shards).ok()?;

        let mut padded = [0u8; PADDED_PAYLOAD_BYTES];
        for i in 0..DATA_SHARDS {
            let shard = option_shards[i].as_ref()?;
            if shard.len() != SHARD_BYTES {
                return None;
            }
            padded[i * SHARD_BYTES..(i + 1) * SHARD_BYTES].copy_from_slice(shard);
        }

        let mut payload_bytes = [0u8; ConstellationPayload::BYTE_LEN];
        payload_bytes.copy_from_slice(&padded[..ConstellationPayload::BYTE_LEN]);
        Some(ConstellationPayload::from_bytes(&payload_bytes))
    }
}

impl Default for ConstellationDecoder {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(NUM_NODES * 2 == FRAME_BITS);

fn quantize_brightness(b: f32) -> u8 {
    let b = b.clamp(0.0, 1.0);
    if b < BRIGHTNESS_THRESHOLDS[0] {
        0
    } else if b < BRIGHTNESS_THRESHOLDS[1] {
        1
    } else if b < BRIGHTNESS_THRESHOLDS[2] {
        2
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::super::encoder::constellation_encode;
    use super::*;

    fn dummy_payload() -> ConstellationPayload {
        let mut session_id = [0u8; 16];
        for (i, b) in session_id.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11);
        }
        let mut ephemeral_pubkey = [0u8; 32];
        for (i, b) in ephemeral_pubkey.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        let mut confirm_code_hash = [0u8; 32];
        for (i, b) in confirm_code_hash.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(19).wrapping_add(5);
        }
        ConstellationPayload {
            session_id,
            ephemeral_pubkey,
            nonce,
            expires_at_unix_ms: 1_777_700_123_456,
            confirm_code_hash,
        }
    }

    fn frame_to_observations(frame: &super::ConstellationFrame) -> Vec<ObservedNode> {
        frame
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| ObservedNode {
                idx: i as u32,
                brightness: n.brightness,
                confidence: 1.0,
            })
            .collect()
    }

    #[test]
    fn clean_roundtrip_one_frame_per_shard() {
        let payload = dummy_payload();
        let decoder = ConstellationDecoder::new();
        let mut recovered = None;
        for frame_index in 0..TOTAL_SHARDS as u32 {
            let frame = constellation_encode(&payload, frame_index);
            let obs = frame_to_observations(&frame);
            recovered = decoder.ingest_frame(&obs);
            if recovered.is_some() {
                break;
            }
        }
        assert_eq!(recovered.as_ref(), Some(&payload));
    }

    #[test]
    fn first_eight_shards_are_enough() {
        let payload = dummy_payload();
        let decoder = ConstellationDecoder::new();
        let mut recovered = None;
        // Feed only the 8 data shards (indices 0..8) — RS doesn't need parity
        // shards if all data shards are present.
        for frame_index in 0..DATA_SHARDS as u32 {
            let frame = constellation_encode(&payload, frame_index);
            let obs = frame_to_observations(&frame);
            recovered = decoder.ingest_frame(&obs);
        }
        assert_eq!(recovered.as_ref(), Some(&payload));
    }

    #[test]
    fn parity_shards_can_substitute_for_data_shards() {
        let payload = dummy_payload();
        let decoder = ConstellationDecoder::new();
        let mut recovered = None;
        // Skip the first 4 data shards, feed shards 4..12 (mix of data + parity).
        for frame_index in 4..(4 + DATA_SHARDS) as u32 {
            let frame = constellation_encode(&payload, frame_index);
            let obs = frame_to_observations(&frame);
            recovered = decoder.ingest_frame(&obs);
        }
        assert_eq!(recovered.as_ref(), Some(&payload));
    }

    #[test]
    fn under_threshold_returns_none() {
        let payload = dummy_payload();
        let decoder = ConstellationDecoder::new();
        // Feed only 7 shards — below the data-shard threshold.
        for frame_index in 0..(DATA_SHARDS as u32 - 1) {
            let frame = constellation_encode(&payload, frame_index);
            let obs = frame_to_observations(&frame);
            assert!(decoder.ingest_frame(&obs).is_none());
        }
        assert_eq!(decoder.shards_collected(), DATA_SHARDS as u32 - 1);
    }

    #[test]
    fn missing_observations_skip_the_frame() {
        let payload = dummy_payload();
        let decoder = ConstellationDecoder::new();
        // Drop one node — packet incomplete, frame should be ignored.
        let frame = constellation_encode(&payload, 0);
        let mut obs = frame_to_observations(&frame);
        obs.pop();
        assert!(decoder.ingest_frame(&obs).is_none());
        assert_eq!(decoder.shards_collected(), 0);
    }

    #[test]
    fn quantize_thresholds_recover_levels() {
        for level in 0u8..4 {
            let brightness = [0.30, 0.55, 0.78, 1.0][level as usize];
            assert_eq!(quantize_brightness(brightness), level);
        }
    }

    #[test]
    fn reset_clears_state() {
        let payload = dummy_payload();
        let decoder = ConstellationDecoder::new();
        for frame_index in 0..3 {
            let frame = constellation_encode(&payload, frame_index);
            decoder.ingest_frame(&frame_to_observations(&frame));
        }
        assert!(decoder.shards_collected() > 0);
        decoder.reset();
        assert_eq!(decoder.shards_collected(), 0);
        assert_eq!(decoder.frames_ingested(), 0);
    }
}
