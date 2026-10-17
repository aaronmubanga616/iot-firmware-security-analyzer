# Synthetic fixture policy

Create small artificial byte sequences with pytest's `tmp_path` fixture when a
test needs a file. Tests generate artificial ELF headers, raw filesystem and
compression magic, malformed inputs and repeated signatures. Integration tests
inspect synthetic images through installed commands, preserve input bytes and
confirm that the unsupported `analyze` operation is rejected.

Do not add real firmware, extracted files, credentials, private keys or password
hashes. Later fixtures must cover malformed and hostile inputs without executing
their content or contacting any device. Do not force-add ignored binary files;
prefer generating synthetic bytes within the test.
