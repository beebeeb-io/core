# test-vectors/tools

Generators for the direct-transfer vectors (task 2173). The JSON files are the contract; these scripts are how they are written, so a rule
change edits a script, regenerates the file, and the diff of the JSON is what a reviewer reads.

```sh
python3 test-vectors/tools/make_direct_transfer_vectors.py test-vectors/direct_transfer.json
python3 test-vectors/tools/make_direct_upload_vectors.py test-vectors/direct_upload.json
python3 test-vectors/tools/jitter_port.py     # a few jittered values, to eyeball the port
```

`jitter_port.py` is an independent Python port of the jitter rule of `UploadChunkState` (splitmix64 seed, xorshift64*, equal jitter), so the
jittered waits in `direct_upload.json` come from an implementation that does not share its code with the Rust they test. Expected values of the
other rows are hand-authored from the spec and from the server's own bodies; every upload row carries a `source`.
