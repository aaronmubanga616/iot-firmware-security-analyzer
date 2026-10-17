# Synthetic fixture policy

Create small artificial byte sequences with pytest's `tmp_path` fixture when a
test needs a file. The foundation integration tests create an artificial image
name and confirm the CLI rejects it because analysis is not implemented.

Do not add real firmware, extracted files, credentials, private keys or password
hashes. Later fixtures must cover malformed and hostile inputs without executing
their content or contacting any device. Do not force-add ignored binary files;
prefer generating synthetic bytes within the test.
