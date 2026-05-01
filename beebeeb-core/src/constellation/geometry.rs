//! Deterministic constellation geometry.
//!
//! Both encoder and decoder use the same node positions, computed from a
//! pair of fibonacci spheres (one outer, one inner). The decoder snaps each
//! detected blob to the nearest known position to recover its index.

use std::collections::BTreeSet;
use std::f32::consts::PI;

pub const NUM_OUTER_NODES: usize = 55;
pub const NUM_INNER_NODES: usize = 12;
pub const NUM_NODES: usize = NUM_OUTER_NODES + NUM_INNER_NODES; // 67

pub const OUTER_RADIUS: f32 = 1.0;
pub const INNER_RADIUS: f32 = 0.4;

/// Each node connects to its `EDGE_K` nearest neighbours. Edges are
/// deduplicated so the resulting set has unique `(min, max)` pairs.
pub const EDGE_K: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub fn distance_sq(&self, other: &Vec3) -> f32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        dx * dx + dy * dy + dz * dz
    }
}

/// Compute the 67 deterministic node positions plus their kinds.
///
/// Indices `0..NUM_OUTER_NODES` lie on the outer sphere (kind 0). Indices
/// `NUM_OUTER_NODES..NUM_NODES` lie on the inner sphere (kind 1).
pub fn node_positions() -> ([Vec3; NUM_NODES], [u8; NUM_NODES]) {
    let mut positions = [Vec3 { x: 0.0, y: 0.0, z: 0.0 }; NUM_NODES];
    let mut kinds = [0u8; NUM_NODES];

    let golden_angle = PI * (3.0 - (5.0_f32).sqrt());

    for i in 0..NUM_OUTER_NODES {
        let n = NUM_OUTER_NODES as f32;
        let y = 1.0 - (i as f32 / (n - 1.0)) * 2.0;
        let r_xz = (1.0 - y * y).max(0.0).sqrt();
        let theta = golden_angle * i as f32;
        positions[i] = Vec3 {
            x: theta.cos() * r_xz * OUTER_RADIUS,
            y: y * OUTER_RADIUS,
            z: theta.sin() * r_xz * OUTER_RADIUS,
        };
        kinds[i] = 0;
    }

    let inner_offset = golden_angle * 0.5;
    for i in 0..NUM_INNER_NODES {
        let n = NUM_INNER_NODES as f32;
        let y = 1.0 - (i as f32 / (n - 1.0)) * 2.0;
        let r_xz = (1.0 - y * y).max(0.0).sqrt();
        let theta = golden_angle * i as f32 + inner_offset;
        let idx = NUM_OUTER_NODES + i;
        positions[idx] = Vec3 {
            x: theta.cos() * r_xz * INNER_RADIUS,
            y: y * INNER_RADIUS,
            z: theta.sin() * r_xz * INNER_RADIUS,
        };
        kinds[idx] = 1;
    }

    (positions, kinds)
}

/// Compute the deterministic edge graph (`(from_idx, to_idx)` with
/// `from_idx < to_idx`). Each node contributes its `EDGE_K` nearest
/// neighbours; the union (after dedup) is returned in sorted order so that
/// the encoder and decoder agree on edge slot ordering.
pub fn edge_pairs(positions: &[Vec3; NUM_NODES]) -> Vec<(u32, u32)> {
    let mut set = BTreeSet::new();
    let mut buf: Vec<(f32, usize)> = Vec::with_capacity(NUM_NODES);
    for i in 0..NUM_NODES {
        buf.clear();
        for j in 0..NUM_NODES {
            if j == i {
                continue;
            }
            buf.push((positions[i].distance_sq(&positions[j]), j));
        }
        buf.sort_by(|a, b| a.0.partial_cmp(&b.0).expect("finite distances"));
        for &(_, j) in buf.iter().take(EDGE_K) {
            let (a, b) = if i < j { (i, j) } else { (j, i) };
            set.insert((a as u32, b as u32));
        }
    }
    set.into_iter().collect()
}
