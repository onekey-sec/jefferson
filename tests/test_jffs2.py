import subprocess
import sys

import pytest
from dissect import cstruct

from jefferson.jffs2 import (
    CSTRUCT_DEFINITIONS,
    JFFS2_FEATURE_INCOMPAT,
    JFFS2_MAGIC_BITMASK,
    JFFS2_NODETYPE_CLEANMARKER,
    JFFS2_NODETYPE_DIRENT,
    mtd_crc,
    scan_fs,
    set_endianness,
)


def make_parser(endianness):
    parser = cstruct.cstruct(endian=endianness)
    parser.load(CSTRUCT_DEFINITIONS)
    return parser


def build_unknown_node(endianness, nodetype, totlen):
    parser = make_parser(endianness)
    node = parser.Jffs2_unknown_node(
        magic=JFFS2_MAGIC_BITMASK,
        nodetype=nodetype,
        totlen=totlen,
        hdr_crc=0,
    )
    node.hdr_crc = mtd_crc(node.dumps()[: parser.Jffs2_unknown_node.size - 4])
    return node.dumps()


def build_dirent(endianness, name=b"file"):
    parser = make_parser(endianness)
    dirent = parser.Jffs2_raw_dirent(
        magic=JFFS2_MAGIC_BITMASK,
        nodetype=JFFS2_NODETYPE_DIRENT,
        totlen=parser.Jffs2_raw_dirent.size + len(name),
        hdr_crc=0,
        pino=1,
        version=1,
        ino=2,
        mctime=0,
        nsize=len(name),
        type=1,
        unused=b"\x00\x00",
        node_crc=0,
        name_crc=mtd_crc(name),
    )
    dirent.hdr_crc = mtd_crc(dirent.dumps()[: parser.Jffs2_unknown_node.size - 4])
    dirent.node_crc = mtd_crc(dirent.dumps()[: parser.Jffs2_raw_dirent.size - 8])
    return dirent.dumps() + name


def run_cli(image, destination):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "jefferson.cli",
            str(image),
            "-d",
            str(destination),
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=2,
    )


def test_cli_terminates_for_reported_zero_length_image(tmp_path):
    image = tmp_path / "zero-totlen.jffs2"
    image.write_bytes(
        build_unknown_node("<", JFFS2_NODETYPE_CLEANMARKER, 0) + bytes(52)
    )

    result = run_cli(image, tmp_path / "out")

    assert result.returncode == 0
    assert "Jffs2_raw_dirent count: 0" in result.stdout


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_cli_skips_zero_length_node_and_continues(tmp_path, endianness):
    image = tmp_path / "zero-totlen.jffs2"
    image.write_bytes(
        build_unknown_node(endianness, JFFS2_NODETYPE_CLEANMARKER, 0)
        + build_dirent(endianness)
    )

    result = run_cli(image, tmp_path / "out")

    assert result.returncode == 0
    assert "Jffs2_raw_dirent count: 1" in result.stdout


@pytest.mark.parametrize("totlen", range(1, 12))
def test_scan_fs_skips_undersized_nodes_and_continues(totlen):
    set_endianness("<")
    image = build_unknown_node("<", JFFS2_NODETYPE_CLEANMARKER, totlen)
    image += build_dirent("<")

    fs = scan_fs(image, "<")

    assert 2 in fs[JFFS2_NODETYPE_DIRENT]


def test_scan_fs_accepts_minimum_node_header(capsys):
    set_endianness("<")
    image = build_unknown_node("<", JFFS2_FEATURE_INCOMPAT, 12) + bytes(13)

    scan_fs(image, "<")

    assert "Unknown node type" in capsys.readouterr().out
