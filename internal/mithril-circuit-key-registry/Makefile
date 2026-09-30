.PHONY: all build test check doc

CARGO = cargo

all: test build

build:
	${CARGO} build --release --features rustls,snark

test:
	${CARGO} test --features rustls,snark

check:
	${CARGO} check --release --all-features --all-targets
	${CARGO} clippy --release --all-features --all-targets
	${CARGO} fmt --check

doc:
	${CARGO} doc --no-deps --open --features rustls,snark
