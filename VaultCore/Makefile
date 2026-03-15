ARCHS = x86_64-apple-ios aarch64-apple-ios-sim aarch64-apple-ios
LIB_NAME = libvault_core.a

all: build-all

build-all:
	@for target in $(ARCHS); do \
		rustup target add $$target; \
		cargo build --target $$target --release; \
	done
	@mkdir -p ../VaultApp/Libs
	# For simplicity, copy the Intel Sim build to the app dir
	cp target/x86_64-apple-ios/release/$(LIB_NAME) ../VaultApp/Libs/

clean:
	cargo clean
	rm -rf ../VaultApp/Libs