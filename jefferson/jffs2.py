import binascii
import contextlib
import mmap
import os
import stat
import struct
import sys
import zlib
from pathlib import Path

from dissect import cstruct
from lzallright import LZOCompressor as lzo

import jefferson.compression.jffs2_lzma as jffs2_lzma
import jefferson.compression.jffs2_lzma_nosize as jffs2_lzma_nosize
import jefferson.compression.rtime as rtime


def PAD(x):
    return ((x) + 3) & ~3


JFFS2_OLD_MAGIC_BITMASK = 0x1984
JFFS2_MAGIC_BITMASK = 0x1985
JFFS2_COMPR_NONE = 0x00
JFFS2_COMPR_ZERO = 0x01
JFFS2_COMPR_RTIME = 0x02
JFFS2_COMPR_RUBINMIPS = 0x03
JFFS2_COMPR_COPY = 0x04
JFFS2_COMPR_DYNRUBIN = 0x05
JFFS2_COMPR_ZLIB = 0x06
JFFS2_COMPR_LZO = 0x07
JFFS2_COMPR_LZMA = 0x08
JFFS2_COMPR_LZMA_NO_SIZE = 0x15

# /* Compatibility flags. */
JFFS2_COMPAT_MASK = 0xC000  # /* What do to if an unknown nodetype is found */
JFFS2_NODE_ACCURATE = 0x2000
# /* INCOMPAT: Fail to mount the filesystem */
JFFS2_FEATURE_INCOMPAT = 0xC000
# /* ROCOMPAT: Mount read-only */
JFFS2_FEATURE_ROCOMPAT = 0x8000
# /* RWCOMPAT_COPY: Mount read/write, and copy the node when it's GC'd */
JFFS2_FEATURE_RWCOMPAT_COPY = 0x4000
# /* RWCOMPAT_DELETE: Mount read/write, and delete the node when it's GC'd */
JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000

JFFS2_NODETYPE_DIRENT = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1
JFFS2_NODETYPE_INODE = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2
JFFS2_NODETYPE_CLEANMARKER = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3
JFFS2_NODETYPE_PADDING = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4
JFFS2_NODETYPE_SUMMARY = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 6
JFFS2_NODETYPE_XATTR = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 8
JFFS2_NODETYPE_XREF = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 9

CSTRUCT_DEFINITIONS = """
struct Jffs2_unknown_node {
    uint16 magic;
    uint16 nodetype;
    uint32 totlen;
    uint32 hdr_crc;
};

struct Jffs2_raw_dirent {
    uint16 magic;
    uint16 nodetype;
    uint32 totlen;
    uint32 hdr_crc;
    uint32 pino;
    uint32 version;
    uint32 ino;
    uint32 mctime;
    uint8 nsize;
    uint8 type;
    uint8 unused[2];
    uint32 node_crc;
    uint32 name_crc;
};

struct Jffs2_raw_inode {
    uint16 magic;
    uint16 nodetype;
    uint32 totlen;
    uint32 hdr_crc;
    uint32 ino;
    uint32 version;
    uint32 mode;
    uint16 uid;
    uint16 gid;
    uint32 isize;
    uint32 atime;
    uint32 mtime;
    uint32 ctime;
    uint32 offset;
    uint32 csize;
    uint32 dsize;
    uint8 compr;
    uint8 usercompr;
    uint16 flags;
    uint32 data_crc;
    uint32 node_crc;
};

struct Jffs2_device_node_old {
    uint16 old_id;
};

struct Jffs2_device_node_new {
    uint32 new_id;
};
"""


def mtd_crc(data):
    return (binascii.crc32(data, -1) ^ -1) & 0xFFFFFFFF


def is_safe_path(basedir, real_path):
    basedir = os.path.realpath(basedir)
    return basedir == os.path.commonpath((basedir, real_path))


NODETYPES = {}


def set_endianness(endianness):
    global Jffs2_device_node_new, Jffs2_device_node_old, Jffs2_unknown_node, Jffs2_raw_dirent, Jffs2_raw_inode, parse_device_node_new, parse_device_node_old, NODETYPES

    parser = cstruct.cstruct(endian=endianness)
    parser.load(CSTRUCT_DEFINITIONS)

    Jffs2_device_node_new = parser.Jffs2_device_node_new
    Jffs2_device_node_old = parser.Jffs2_device_node_old
    Jffs2_unknown_node = parser.Jffs2_unknown_node
    Jffs2_raw_dirent = parser.Jffs2_raw_dirent
    Jffs2_raw_inode = parser.Jffs2_raw_inode

    parse_device_node_new = Jffs2_device_node_new
    parse_device_node_old = Jffs2_device_node_old

    NODETYPES = {
        JFFS2_FEATURE_INCOMPAT: Jffs2_unknown_node,
        JFFS2_NODETYPE_DIRENT: Jffs2_raw_dirent,
        JFFS2_NODETYPE_INODE: Jffs2_raw_inode,
        JFFS2_NODETYPE_CLEANMARKER: "JFFS2_NODETYPE_CLEANMARKER",
        JFFS2_NODETYPE_PADDING: "JFFS2_NODETYPE_PADDING",
    }


set_endianness("<")


def parse_unknown_node(data):
    node = Jffs2_unknown_node(data)
    node.hdr_crc_match = mtd_crc(data[: Jffs2_unknown_node.size - 4]) == node.hdr_crc
    return node


def parse_dirent(data, node_offset):
    dirent = Jffs2_raw_dirent(data)
    dirent.name = data[Jffs2_raw_dirent.size : Jffs2_raw_dirent.size + dirent.nsize]
    dirent.node_offset = node_offset

    if mtd_crc(data[: Jffs2_raw_dirent.size - 8]) == dirent.node_crc:
        dirent.node_crc_match = True
    else:
        print("node_crc does not match!")
        dirent.node_crc_match = False

    if mtd_crc(dirent.name) == dirent.name_crc:
        dirent.name_crc_match = True
    else:
        print("data_crc does not match!")
        dirent.name_crc_match = False
    return dirent


def parse_inode(data):
    inode = Jffs2_raw_inode(data)

    node_data = data[Jffs2_raw_inode.size : Jffs2_raw_inode.size + inode.csize]
    try:
        if inode.compr == JFFS2_COMPR_NONE:
            inode.data = node_data
        elif inode.compr == JFFS2_COMPR_ZERO:
            inode.data = b"\x00" * inode.dsize
        elif inode.compr == JFFS2_COMPR_ZLIB:
            inode.data = zlib.decompress(node_data)
        elif inode.compr == JFFS2_COMPR_RTIME:
            inode.data = rtime.decompress(node_data, inode.dsize)
        elif inode.compr == JFFS2_COMPR_LZMA:
            inode.data = jffs2_lzma.decompress(node_data, inode.dsize)
        elif inode.compr == JFFS2_COMPR_LZO:
            inode.data = lzo.decompress(node_data)
        elif inode.compr == JFFS2_COMPR_LZMA_NO_SIZE:
            inode.data = jffs2_lzma_nosize.decompress(node_data, inode.dsize)
        else:
            print("compression not implemented", inode)
            print(node_data.hex()[:20])
            inode.data = node_data
    except Exception as e:
        print(
            "Decompression error on inode {}: {}".format(inode.ino, e), file=sys.stderr
        )
        inode.data = b"\x00" * inode.dsize

    if len(inode.data) != inode.dsize:
        print("data length mismatch!")

    if mtd_crc(data[: Jffs2_raw_inode.size - 8]) == inode.node_crc:
        inode.node_crc_match = True
    else:
        print("hdr_crc does not match!")
        inode.node_crc_match = False

    if mtd_crc(node_data) == inode.data_crc:
        inode.data_crc_match = True
    else:
        print("data_crc does not match!")
        inode.data_crc_match = False
    return inode


def scan_fs(content, endianness, verbose=False):
    pos = 0
    jffs2_old_magic_bitmask_str = struct.pack(endianness + "H", JFFS2_OLD_MAGIC_BITMASK)
    jffs2_magic_bitmask_str = struct.pack(endianness + "H", JFFS2_MAGIC_BITMASK)

    fs = {}
    fs[JFFS2_NODETYPE_INODE] = {}
    fs[JFFS2_NODETYPE_DIRENT] = {}

    while True:
        find_result = content.find(
            jffs2_magic_bitmask_str, pos, len(content) - Jffs2_unknown_node.size
        )
        find_result_old = content.find(
            jffs2_old_magic_bitmask_str, pos, len(content) - Jffs2_unknown_node.size
        )
        if find_result == -1 and find_result_old == -1:
            break
        if find_result != -1:
            pos = find_result
        else:
            pos = find_result_old

        unknown_node = parse_unknown_node(content[pos : pos + Jffs2_unknown_node.size])
        if not unknown_node.hdr_crc_match:
            pos += 1
            continue
        offset = pos
        pos += PAD(unknown_node.totlen)

        if unknown_node.magic in [
            JFFS2_MAGIC_BITMASK,
            JFFS2_OLD_MAGIC_BITMASK,
        ]:
            if unknown_node.nodetype in NODETYPES:
                if unknown_node.nodetype == JFFS2_NODETYPE_DIRENT:
                    dirent = parse_dirent(
                        content[offset : offset + unknown_node.totlen], offset
                    )
                    if dirent.ino in fs[JFFS2_NODETYPE_DIRENT]:
                        if (
                            dirent.version
                            > fs[JFFS2_NODETYPE_DIRENT][dirent.ino].version
                        ):
                            fs[JFFS2_NODETYPE_DIRENT][dirent.ino] = dirent
                    else:
                        fs[JFFS2_NODETYPE_DIRENT][dirent.ino] = dirent
                    if verbose:
                        print("0x%08X:" % (offset), dirent)
                elif unknown_node.nodetype == JFFS2_NODETYPE_INODE:
                    inode = parse_inode(content[offset : offset + unknown_node.totlen])

                    if inode.ino in fs[JFFS2_NODETYPE_INODE]:
                        fs[JFFS2_NODETYPE_INODE][inode.ino].append(inode)
                    else:
                        fs[JFFS2_NODETYPE_INODE][inode.ino] = [inode]
                    if verbose:
                        print("0x%08X:" % (offset), inode)
                elif unknown_node.nodetype == JFFS2_NODETYPE_CLEANMARKER:
                    pass
                elif unknown_node.nodetype == JFFS2_NODETYPE_PADDING:
                    pass
                elif unknown_node.nodetype == JFFS2_NODETYPE_SUMMARY:
                    pass
                elif unknown_node.nodetype == JFFS2_NODETYPE_XATTR:
                    pass
                elif unknown_node.nodetype == JFFS2_NODETYPE_XREF:
                    pass
                else:
                    print("Unknown node type", unknown_node.nodetype, unknown_node)
    return fs


def get_device(inode):
    if not stat.S_ISBLK(inode.mode) and not stat.S_ISCHR(inode.mode):
        return None

    if inode.dsize == Jffs2_device_node_new.size:
        node = parse_device_node_new(inode.data)
        return os.makedev(
            (node.new_id & 0xFFF00) >> 8,
            (node.new_id & 0xFF) | ((node.new_id >> 12) & 0xFFF00),
        )

    if inode.dsize == Jffs2_device_node_old.size:
        node = parse_device_node_old(inode.data)
        return os.makedev((node.old_id >> 8) & 0xFF, node.old_id & 0xFF)
    return None


def sort_version(item):
    return item.version


def dump_fs(fs, target):
    node_dict = {}

    for dirent in fs[JFFS2_NODETYPE_DIRENT].values():
        dirent.inodes = []
        for ino, inodes in fs[JFFS2_NODETYPE_INODE].items():
            if ino == dirent.ino:
                dirent.inodes = sorted(inodes, key=sort_version)
        node_dict[dirent.ino] = dirent

    for dirent in fs[JFFS2_NODETYPE_DIRENT].values():
        pnode_pino = dirent.pino
        pnodes = []
        for _ in range(100):
            if pnode_pino not in node_dict:
                break
            pnode = node_dict[pnode_pino]
            pnode_pino = pnode.pino
            pnodes.append(pnode)
        pnodes.reverse()

        node_names = []

        for pnode in pnodes:
            node_names.append(pnode.name.decode())
        node_names.append(dirent.name.decode())
        path = "/".join(node_names)

        target_path = os.path.realpath(os.path.join(target, path))

        if not is_safe_path(target, target_path):
            print(f"Path traversal attempt to {target_path}, discarding.")
            continue

        for inode in dirent.inodes:
            try:
                if stat.S_ISDIR(inode.mode):
                    print("writing S_ISDIR", path)
                    if not os.path.isdir(target_path):
                        os.makedirs(target_path)
                elif stat.S_ISLNK(inode.mode):
                    print("writing S_ISLNK", path)
                    if not os.path.islink(target_path):
                        if os.path.exists(target_path):
                            continue
                        os.symlink(inode.data, target_path)
                elif stat.S_ISREG(inode.mode):
                    print("writing S_ISREG", path)
                    if not os.path.isfile(target_path):
                        if not os.path.isdir(os.path.dirname(target_path)):
                            os.makedirs(os.path.dirname(target_path))
                        with open(target_path, "wb") as fd:
                            for inode in dirent.inodes:
                                fd.seek(inode.offset)
                                fd.write(inode.data)
                    os.chmod(target_path, stat.S_IMODE(inode.mode))
                    break
                elif stat.S_ISCHR(inode.mode):
                    print("writing S_ISBLK", path)
                    os.mknod(target_path, inode.mode, get_device(inode))
                elif stat.S_ISBLK(inode.mode):
                    print("writing S_ISBLK", path)
                    os.mknod(target_path, inode.mode, get_device(inode))
                elif stat.S_ISFIFO(inode.mode):
                    print("skipping S_ISFIFO", path)
                elif stat.S_ISSOCK(inode.mode):
                    print("skipping S_ISSOCK", path)
                else:
                    print("unhandled inode.mode: %o" % inode.mode, inode, dirent)

            except OSError as error:
                print("OS error(%i): %s" % (error.errno, error.strerror), inode, dirent)


def extract_jffs2(file: Path, destination: Path, verbose: int) -> int:
    with contextlib.ExitStack() as context_stack:
        filesystem = context_stack.enter_context(file.open("rb"))
        filesystem_len = os.fstat(filesystem.fileno()).st_size
        if 0 == filesystem_len:
            return -1
        content = context_stack.enter_context(
            mmap.mmap(filesystem.fileno(), filesystem_len, access=mmap.ACCESS_READ)
        )
        magic = struct.unpack("<H", content[0:2])[0]
        if magic in [JFFS2_OLD_MAGIC_BITMASK, JFFS2_MAGIC_BITMASK]:
            endianness = "<"
        else:
            endianness = ">"

        set_endianness(endianness)

        fs = scan_fs(content, endianness, verbose=verbose)
        print("dumping fs to %s (endianness: %s)" % (destination, endianness))
        for key, value in fs.items():
            print("%s count: %i" % (NODETYPES[key].__name__, len(value)))

        dump_fs(fs, destination)
    return 0
