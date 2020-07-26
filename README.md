# examples-rust-slack-kot

An AWS Lambda function receiving slash commands and punching in

## Requirements
- [Rust](https://www.rust-lang.org/)
- (macOS) [musl-cross](https://github.com/FiloSottile/homebrew-musl-cross)
  - Run `ln -s /usr/local/bin/x86_64-linux-musl-gcc /usr/local/bin/musl-gcc` in addition to install

## Settings
- Set env
  - GOOGLE_CREDENTIAL
  - SHEETS_URL
  - KOT_ACCESS_TOKEN

## (macOS) Build
```shell-session
$ cargo build --release --target x86_64-unknown-linux-musl
```
