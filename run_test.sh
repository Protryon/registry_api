#!/bin/bash
cd publish_test
rm -rf Cargo.lock target
cargo publish --registry 'test' --allow-dirty
cargo search --registry test publish_test
cargo owner --registry test -l
cargo owner --registry test -a magic
cargo owner --registry test -l
cargo owner --registry test -r magic
cargo owner --registry test -l
cd ../dep_test
rm -rf Cargo.lock target # checksum changes as we rebuild and redeploy same version per test
echo 'waiting for index flush'
sleep 60 # let the index refresh
cargo build
cargo publish --registry 'test' --allow-dirty
cargo yank --vers 0.1.0 --registry 'test' publish_test
cargo yank --vers 0.1.0 --undo --registry 'test' publish_test
cargo yank --vers 0.1.0 --registry 'test' publish_test