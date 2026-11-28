# crates/ccs/build.rs refuses to build without CCS_BUILD_COMMIT. The
# pre-commit-test hook runs `make test` when this target exists, so a commit
# runs the Rust tests the same way a person does.
.PHONY: test
test:
	CCS_BUILD_COMMIT=$$(git rev-parse HEAD) cargo test --locked --workspace
