# Third-party notices

Burrow-owned code is offered under the terms in [LICENSE.md](LICENSE.md),
FSL-1.1-ALv2. That license does not replace the licenses or copyright notices of
upstream portions or external dependencies. Preserve the applicable notices when
redistributing them or a binary containing them.

## Adapted and referenced projects

### Mole / historical Burrow digger

Copyright (c) 2025 tw93. [MIT license text](LICENSES/Mole-MIT.txt).

Burrow's cleanup, protection tables, uninstall, optimization, inventory, status,
analysis, history and formatting modules include Rust adaptations of the historical
Mole-based Burrow digger. The upstream starting point is
[Mole V1.42.0, revision 9daf936ea5fd1a0648579434c76000cd9cfa1253](https://github.com/tw93/Mole/tree/9daf936ea5fd1a0648579434c76000cd9cfa1253),
whose [license at that revision](https://github.com/tw93/Mole/blob/9daf936ea5fd1a0648579434c76000cd9cfa1253/LICENSE)
is MIT. Porting, additional Rust code and subsequent fixes were made in Burrow in
2026. Source comments retain references to the original modules and behavioral rules.
The relevant upstream MIT notice remains applicable to adapted portions.

This attribution is to the historical MIT version. It does not describe current
Mole main's license. The fixture version distinction for uninstall is documented in
[FIXTURE_PROVENANCE.md](FIXTURE_PROVENANCE.md).

### Stats

Copyright (c) 2019 Serhiy Mytrovtsiy. [MIT license text](LICENSES/Stats-MIT.txt).

The Bluetooth battery-field names in `src/status/bluetooth.rs` were informed by
[Stats' Bluetooth reader](https://github.com/exelban/stats/blob/0edcad84e0e9721def7b425cae3ccd869a650ccc/Modules/Bluetooth/readers.swift).
The license text was verified against that pinned revision during publication.
No Stats application or binary is bundled here.

### fclones

Copyright (c) 2020 Piotr Kołaczkowski. [MIT license text](LICENSES/fclones-MIT.txt).

The duplicate command invokes [fclones](https://github.com/pkolaczk/fclones) as an
external process. This repository contains neither its source nor a prebuilt binary.
The preserved report fixture came from version 0.35.0, and the included notice is
from [that version](https://github.com/pkolaczk/fclones/blob/v0.35.0/LICENSE).
Distributors who bundle another version must include the notices for that version.

## Rust dependencies

The following versions and license expressions come from the packages resolved by
`Cargo.lock`. Original license/notice files are copied without editing into
`LICENSES/cargo/`; their hashes and source repositories are recorded in
[LICENSES/cargo-packages.json](LICENSES/cargo-packages.json). `OR` denotes the
upstream package's alternative licenses, not an additional Burrow restriction.
The inventory includes build dependencies and the Windows-only packages.

| Package | Version | Upstream license expression | Notices |
|---|---|---|---|
| [adler2](https://github.com/oyvindln/adler2) | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | [files](LICENSES/cargo/adler2-2.0.1/) |
| [autocfg](https://github.com/cuviper/autocfg) | 1.5.1 | Apache-2.0 OR MIT | [files](LICENSES/cargo/autocfg-1.5.1/) |
| [bitflags](https://github.com/bitflags/bitflags) | 2.13.0 | MIT OR Apache-2.0 | [files](LICENSES/cargo/bitflags-2.13.0/) |
| [bytemuck](https://github.com/Lokathor/bytemuck) | 1.25.1 | Zlib OR Apache-2.0 OR MIT | [files](LICENSES/cargo/bytemuck-1.25.1/) |
| [byteorder-lite](https://github.com/image-rs/byteorder-lite) | 0.1.0 | Unlicense OR MIT | [files](LICENSES/cargo/byteorder-lite-0.1.0/) |
| [cfg-if](https://github.com/rust-lang/cfg-if) | 1.0.4 | MIT OR Apache-2.0 | [files](LICENSES/cargo/cfg-if-1.0.4/) |
| [crc32fast](https://github.com/srijs/rust-crc32fast) | 1.5.0 | MIT OR Apache-2.0 | [files](LICENSES/cargo/crc32fast-1.5.0/) |
| [fdeflate](https://github.com/image-rs/fdeflate) | 0.3.7 | MIT OR Apache-2.0 | [files](LICENSES/cargo/fdeflate-0.3.7/) |
| [flate2](https://github.com/rust-lang/flate2-rs) | 1.1.9 | MIT OR Apache-2.0 | [files](LICENSES/cargo/flate2-1.1.9/) |
| [image](https://github.com/image-rs/image) | 0.25.10 | MIT OR Apache-2.0 | [files](LICENSES/cargo/image-0.25.10/) |
| [miniz_oxide](https://github.com/Frommi/miniz_oxide/tree/master/miniz_oxide) | 0.8.9 | MIT OR Zlib OR Apache-2.0 | [files](LICENSES/cargo/miniz_oxide-0.8.9/) |
| [moxcms](https://github.com/awxkee/moxcms.git) | 0.8.1 | BSD-3-Clause OR Apache-2.0 | [files](LICENSES/cargo/moxcms-0.8.1/) |
| [num-traits](https://github.com/rust-num/num-traits) | 0.2.19 | MIT OR Apache-2.0 | [files](LICENSES/cargo/num-traits-0.2.19/) |
| [png](https://github.com/image-rs/image-png) | 0.18.1 | MIT OR Apache-2.0 | [files](LICENSES/cargo/png-0.18.1/) |
| [pxfm](https://github.com/awxkee/pxfm) | 0.1.30 | BSD-3-Clause OR Apache-2.0 | [files](LICENSES/cargo/pxfm-0.1.30/) |
| [simd-adler32](https://github.com/mcountryman/simd-adler32) | 0.3.9 | MIT | [files](LICENSES/cargo/simd-adler32-0.3.9/) |
| [windows-link](https://github.com/microsoft/windows-rs) | 0.2.1 | MIT OR Apache-2.0 | [files](LICENSES/cargo/windows-link-0.2.1/) |
| [windows-sys](https://github.com/microsoft/windows-rs) | 0.61.2 | MIT OR Apache-2.0 | [files](LICENSES/cargo/windows-sys-0.61.2/) |
| [zune-core](https://github.com/etemesi254/zune-image) | 0.5.1 | MIT OR Apache-2.0 OR Zlib | [files](LICENSES/cargo/zune-core-0.5.1/) |
| [zune-jpeg](https://github.com/etemesi254/zune-image/tree/dev/crates/zune-jpeg) | 0.5.15 | MIT OR Apache-2.0 OR Zlib | [files](LICENSES/cargo/zune-jpeg-0.5.15/) |

The source snapshot resolves dependencies through Cargo and does not vendor their
implementation code. A binary distributor must retain the applicable dependency
notices, including those from the Rust toolchain's standard library, and notices
for any separately bundled tools.
