#!/usr/bin/env python3
"""Generate a synthetic pcap with realistic header mixes for benchmarks and soak tests.

Usage: make_test_pcap.py <output.pcap> <packet_count> [scan|exfil]

With a scenario argument, the final 20% of the file has attack traffic interleaved
1:1 with normal traffic: "scan" is a TCP SYN port sweep from a previously unseen
host, "exfil" is a sudden large one-sided upload from a known host to a new server.
"""

import random
import struct
import sys


def ethernet(src_last: int, dst_last: int, ether_type: int) -> bytes:
    src = bytes([0x02, 0, 0, 0, 0, src_last])
    dst = bytes([0x02, 0, 0, 0, 0, dst_last])
    return dst + src + struct.pack(">H", ether_type)


def ipv4(src_last: int, dst_last: int, protocol: int, payload_length: int) -> bytes:
    total = 20 + payload_length
    return struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, random.getrandbits(16), 0, 64, protocol, 0,
        bytes([10, 0, 0, src_last]), bytes([10, 0, 1, dst_last]),
    )


def ipv6(src_last: int, dst_last: int, next_header: int, payload_length: int) -> bytes:
    src = bytes(15) + bytes([src_last])
    dst = bytes([0x20, 0x01]) + bytes(13) + bytes([dst_last])
    return struct.pack(">IHBB", 0x60000000, payload_length, next_header, 64) + src + dst


def tcp(src_port: int, dst_port: int, flags: int) -> bytes:
    return struct.pack(">HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, flags, 65535, 0, 0)


def udp(src_port: int, dst_port: int, payload_length: int) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + payload_length, 0)


def build_packet() -> bytes:
    choice = random.random()
    src, dst = random.randint(1, 40), random.randint(1, 40)
    payload = bytes(random.randint(0, 1200))
    if choice < 0.55:
        segment = tcp(random.randint(1024, 65000), random.choice([80, 443, 22]), 0x18)
        return ethernet(src, dst, 0x0800) + ipv4(src, dst, 6, len(segment) + len(payload)) + segment + payload
    if choice < 0.80:
        datagram = udp(random.randint(1024, 65000), random.choice([53, 123, 5353]), len(payload))
        return ethernet(src, dst, 0x0800) + ipv4(src, dst, 17, 8 + len(payload)) + datagram + payload
    if choice < 0.90:
        segment = tcp(random.randint(1024, 65000), 443, 0x10)
        return ethernet(src, dst, 0x86DD) + ipv6(src, dst, 6, len(segment) + len(payload)) + segment + payload
    if choice < 0.95:
        vlan = struct.pack(">HH", 100, 0x0800)
        datagram = udp(5353, 5353, len(payload))
        return ethernet(src, dst, 0x8100) + vlan + ipv4(src, dst, 17, 8 + len(payload)) + datagram + payload
    if choice < 0.98:
        return ethernet(src, dst, 0x0800) + ipv4(src, dst, 1, 8) + struct.pack(">BBHI", 8, 0, 0, 0)
    return ethernet(src, dst, 0x0806) + bytes(28)


SCANNER_HOST = 99
SCAN_TARGET = 5
EXFIL_SOURCE = 7
EXFIL_TARGET = 88


def build_scan_packet(sweep_index: int) -> bytes:
    port = 1 + (sweep_index % 2000)
    segment = tcp(43210, port, 0x02)
    frame = ethernet(SCANNER_HOST, SCAN_TARGET, 0x0800)
    return frame + ipv4(SCANNER_HOST, SCAN_TARGET, 6, len(segment)) + segment


def build_exfil_packet() -> bytes:
    payload = bytes(1400)
    segment = tcp(55555, 443, 0x18)
    frame = ethernet(EXFIL_SOURCE, EXFIL_TARGET, 0x0800)
    return frame + ipv4(EXFIL_SOURCE, EXFIL_TARGET, 6, len(segment) + len(payload)) + segment + payload


def main() -> None:
    output_path, packet_count = sys.argv[1], int(sys.argv[2])
    scenario = sys.argv[3] if len(sys.argv) > 3 else "normal"
    random.seed(7)
    snaplen = 128
    attack_start = packet_count - packet_count // 5
    attack_builders = {
        "scan": build_scan_packet,
        "exfil": lambda index: build_exfil_packet(),
    }
    attacks_emitted = 0
    with open(output_path, "wb") as output:
        output.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        timestamp_us = 1_700_000_000_000_000
        chunk = []
        for index in range(packet_count):
            in_attack_window = scenario in attack_builders and index >= attack_start
            if in_attack_window and index % 2 == 0:
                packet = attack_builders[scenario](attacks_emitted)
                attacks_emitted += 1
                timestamp_us += random.randint(10, 200)
            else:
                packet = build_packet()
                timestamp_us += random.randint(10, 2000)
            captured = packet[:snaplen]
            chunk.append(
                struct.pack("<IIII", timestamp_us // 1_000_000, timestamp_us % 1_000_000,
                            len(captured), len(packet))
            )
            chunk.append(captured)
            if index % 100_000 == 0:
                output.write(b"".join(chunk))
                chunk = []
        output.write(b"".join(chunk))
    if scenario in attack_builders:
        print(f"attack window starts at packet {attack_start}, {attacks_emitted} attack packets")


if __name__ == "__main__":
    main()
