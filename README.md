# atlas-vdi

Opens VirtualBox `.vdi` images as a `BlockSource`. The block map is validated against the file and unallocated blocks read as zeros.

- Snapshot and differencing images are reported as unsupported.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
