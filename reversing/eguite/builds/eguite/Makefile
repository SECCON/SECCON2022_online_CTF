all:
	cargo rustc --release --target=x86_64-unknown-linux-gnu \
							-- -C link-args=-Wl,-S -C panic=abort
	cargo rustc --release --target=x86_64-pc-windows-gnu \
							-- -C link-args=-Wl,-S -C panic=abort
