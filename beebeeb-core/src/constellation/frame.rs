//! Type definitions for the Amber Constellation visual auth codec.
//!
//! A constellation is an animated 3D pattern of nodes and edges that encodes
//! a small payload (session bootstrap data). The payload travels device-to-device
//! via camera capture during the device-pairing flow.

use zeroize::Zeroizing;

/// Fixed payload that one device transmits to another during pairing.
///
/// Total size: 104 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstellationPayload {
    pub session_id: [u8; 16],
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at_unix_ms: u64,
    pub confirm_code_hash: [u8; 32],
}

impl ConstellationPayload {
    pub const BYTE_LEN: usize = 16 + 32 + 16 + 8 + 32; // 104

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        let mut o = 0;
        out[o..o + 16].copy_from_slice(&self.session_id);
        o += 16;
        out[o..o + 32].copy_from_slice(&self.ephemeral_pubkey);
        o += 32;
        out[o..o + 16].copy_from_slice(&self.nonce);
        o += 16;
        out[o..o + 8].copy_from_slice(&self.expires_at_unix_ms.to_le_bytes());
        o += 8;
        out[o..o + 32].copy_from_slice(&self.confirm_code_hash);
        out
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTE_LEN]) -> Self {
        let mut o = 0;
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&bytes[o..o + 16]);
        o += 16;
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&bytes[o..o + 32]);
        o += 32;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[o..o + 16]);
        o += 16;
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[o..o + 8]);
        let expires_at_unix_ms = u64::from_le_bytes(ts);
        o += 8;
        let mut confirm_code_hash = [0u8; 32];
        confirm_code_hash.copy_from_slice(&bytes[o..o + 32]);
        Self {
            session_id,
            ephemeral_pubkey,
            nonce,
            expires_at_unix_ms,
            confirm_code_hash,
        }
    }
}

/// A snapshot of the visualisation at a single render frame.
///
/// `frame_index` advances monotonically; the payload bits stay the same
/// across frames but are spread across multiple shards (each frame conveys
/// one shard of the Reed-Solomon codeword).
#[derive(Debug, Clone)]
pub struct ConstellationFrame {
    pub frame_index: u32,
    pub seed: u64,
    pub nodes: Vec<ConstellationNode>,
    pub edges: Vec<ConstellationEdge>,
    pub ring_phase: f32,
}

#[derive(Debug, Clone, Copy)]
pub struct ConstellationNode {
    /// 0 = outer sphere node, 1 = inner core node.
    pub kind: u8,
    pub x: f32,
    pub y: f32,
    pub z: f32,
    /// Normalised brightness in 0.0..=1.0. Quantised into 4 levels by the
    /// encoder; the decoder reads these levels back as 2 data bits per node.
    pub brightness: f32,
    /// Cosmetic per-node animation phase in 0.0..=1.0.
    pub pulse_phase: f32,
}

#[derive(Debug, Clone, Copy)]
pub struct ConstellationEdge {
    pub from_idx: u32,
    pub to_idx: u32,
    /// Normalised weight in 0.0..=1.0. Quantised into 4 levels by the
    /// encoder; the decoder reads these levels back as 2 data bits per edge.
    pub weight: f32,
    /// Cosmetic flow speed in 0.0..=1.0.
    pub flow_speed: f32,
}

/// Output of `constellation_new_session` — the encoder side of the pairing flow.
#[derive(Debug, Clone)]
pub struct ConstellationSessionInit {
    pub payload: ConstellationPayload,
    /// Eight-digit numeric confirmation code shown to the user.
    pub confirm_code: String,
    /// X25519 private scalar — kept on the displaying device until the
    /// scanning device confirms with the matching code.
    ///
    /// Wrapped in [`Zeroizing`] so the key bytes are wiped from memory as
    /// soon as this struct is dropped. Treat it like any other key handle:
    /// move it, do not copy it across boundaries.
    pub ephemeral_private: Zeroizing<[u8; 32]>,
}

/// Decoder input: a single observed node from the camera frame processor.
#[derive(Debug, Clone, Copy)]
pub struct ObservedNode {
    /// Index in 0..67. Decoded by matching detected positions against the
    /// known fibonacci-sphere geometry.
    pub idx: u32,
    /// Detected brightness in 0.0..=1.0.
    pub brightness: f32,
    /// Detection confidence in 0.0..=1.0. Used to weight evidence across
    /// frames; observations below `MIN_CONFIDENCE` are ignored.
    pub confidence: f32,
}

/// Decoder input: a single observed edge from the camera frame processor.
#[derive(Debug, Clone, Copy)]
pub struct ObservedEdge {
    pub from_idx: u32,
    pub to_idx: u32,
    pub weight: f32,
    pub confidence: f32,
}
