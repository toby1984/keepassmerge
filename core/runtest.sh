#!/bin/bash
rm merged.kdbx
java --enable-preview -jar target/keepassmerge.jar src/test/resources/src_2_entries.kdbx src/test/resources/src_3_entries.kdbx ./merged.kdbx
