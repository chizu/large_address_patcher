#!/usr/bin/python
"""Patch the large address aware flag into a Windows executable.

Useful for Wine apps that only work in 32-bit mode but need more memory. Some
applications will break enabling this flag.

Usage: ./large_address_patcher.py something.exe"""
import sys
import io
import struct

LARGE_ADDRESS_AWARE = 0x20

with io.open(sys.argv[1], 'r+b') as exe:
    # Magic header for Windows executables
    assert 0x5A4D == struct.unpack('h', exe.read(2))[0]

    # PE header
    exe.seek(0x3C)

    # Verify PE header
    pe_pos = struct.unpack('i', exe.read(4))[0]
    exe.seek(pe_pos)
    assert 0x4550 == struct.unpack('i', exe.read(4))[0]

    # Check if already large address aware
    exe.seek(pe_pos + 0x12)
    pe_flags = struct.unpack('h', exe.read(2))[0]
    if pe_flags & LARGE_ADDRESS_AWARE:
        print("Already large address aware.")
    else:
        print(pe_flags)
        print("Not large address aware... adding flag.")
        new_flags = pe_flags | LARGE_ADDRESS_AWARE
        exe.seek(pe_pos + 0x12)
        exe.write(struct.pack('h', new_flags))
