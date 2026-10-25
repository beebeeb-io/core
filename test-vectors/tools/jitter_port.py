"""An independent Python port of the jitter rule of beebeeb_core::direct_transfer (task 2173), used to compute the
jittered waits in test-vectors/direct_upload.json WITHOUT running the Rust code.

The rule (core: `window.rs`): the seed is scrambled by splitmix64 into a nonzero xorshift64* state; "equal jitter" of an
exponential delay `exp` (milliseconds) is `exp / 2` plus a random share of the other half: `half + next() % (half + 1)`.
`UploadChunkState` (core: `upload.rs`) draws one value per wait the CLIENT chooses (a plain failure's doubling backoff
`1 s * 2^(failures - 1)`, an unstated hold poll of `min(5 s * 2^polls, 15 s)`) and none for a wait the server stated.

Run `python3 test-vectors/tools/jitter_port.py` for a few values.
"""
M64 = (1 << 64) - 1


class Rng:
    """An independent port of the jitter rule (core: window.rs splitmix64 + xorshift64* + equal jitter)."""

    def __init__(self, seed):
        z = (seed + 0x9E3779B97F4A7C15) & M64
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        z ^= z >> 31
        self.state = z or 0x9E3779B97F4A7C15

    def next(self):
        x = self.state
        x ^= x >> 12
        x ^= (x << 25) & M64
        x ^= x >> 27
        self.state = x
        return (x * 0x2545F4914F6CDD1D) & M64

    def equal_jitter(self, exp_ms):
        half = exp_ms // 2
        return half + (0 if half == 0 else self.next() % (half + 1))


class Sim:
    """The expected waits of one chunk's client-side backoff: base 1 s doubling per failure, equal jitter."""

    def __init__(self, seed):
        self.rng = Rng(seed)
        self.failures = 0
        self.holds = 0

    def stated(self):
        """A failure whose wait the server stated: counted, no jitter drawn."""
        self.failures += 1

    def failure(self):
        """A failure the client backs off for itself: counted, one jitter draw."""
        self.failures += 1
        return self.rng.equal_jitter(1000 * 2 ** (self.failures - 1))

    def hold_poll(self):
        exp = min(5000 * 2 ** min(self.holds, 16), 15000)
        self.holds += 1
        return self.rng.equal_jitter(exp)


if __name__ == "__main__":
    sim = Sim(11)
    print("seed 11, first three failure waits (ms):", [sim.failure() for _ in range(3)])
    sim = Sim(9)
    print("seed 9, first five unstated hold polls (ms):", [sim.hold_poll() for _ in range(5)])
