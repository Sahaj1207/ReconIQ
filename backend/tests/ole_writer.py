"""
Minimal OLE / Compound File Binary (CFB v3) writer for test fixtures: Outlook .msg files, legacy
Office documents and vbaProject.bin parts. Streams under 4096 bytes go into the mini stream, as
real files do. Siblings are chained through right-sibling links (valid, just not balanced).

Also provides MS-OVBA helpers to build VBA project streams.
"""

import struct
from typing import Dict, List, Union

Tree = Dict[str, Union[bytes, "Tree"]]

SECTOR, MINI_SECTOR, CUTOFF = 512, 64, 4096
FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def _chain(blob: bytes, unit: int, table: List[int], store: List[bytes]) -> int:
    if not blob:
        return ENDOFCHAIN
    count = -(-len(blob) // unit)
    start = len(store)
    for i in range(count):
        store.append(blob[i * unit:(i + 1) * unit].ljust(unit, b"\0"))
        table.append(start + i + 1 if i < count - 1 else ENDOFCHAIN)
    return start


def build_ole(tree: Tree) -> bytes:
    entries: List[dict] = [{"name": "Root Entry", "type": 5, "children": []}]

    def add(node: Tree, parent: int) -> None:
        for name in sorted(node, key=lambda n: (len(n), n.upper())):
            value = node[name]
            idx = len(entries)
            entries.append({"name": name, "type": 2 if isinstance(value, bytes) else 1,
                            "data": value if isinstance(value, bytes) else None, "children": []})
            entries[parent]["children"].append(idx)
            if not isinstance(value, bytes):
                add(value, idx)

    add(tree, 0)

    fat: List[int] = []
    sectors: List[bytes] = []
    minifat: List[int] = []
    mini: List[bytes] = []
    for e in entries:
        if e["type"] == 2:
            data = e["data"]
            e["size"] = len(data)
            e["start"] = _chain(data, SECTOR, fat, sectors) if len(data) >= CUTOFF else _chain(data, MINI_SECTOR, minifat, mini)
    mini_stream = b"".join(mini)
    entries[0]["start"] = _chain(mini_stream, SECTOR, fat, sectors)
    entries[0]["size"] = len(mini_stream)
    minifat_blob = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_start = _chain(minifat_blob, SECTOR, fat, sectors) if minifat else ENDOFCHAIN

    dir_blob = b""
    for e in entries:
        kids = e["children"]
        for a, b in zip(kids, kids[1:]):
            entries[a]["right"] = b
        e["child"] = kids[0] if kids else NOSTREAM
    for e in entries:
        name = e["name"].encode("utf-16-le") + b"\0\0"
        dir_blob += name.ljust(64, b"\0") + struct.pack(
            "<HBBIII16sIQQIQ", len(name), e["type"], 1, NOSTREAM, e.get("right", NOSTREAM), e["child"],
            b"\0" * 16, 0, 0, 0, e.get("start", ENDOFCHAIN if e["type"] != 1 else 0), e.get("size", 0))
    dir_start = _chain(dir_blob, SECTOR, fat, sectors)

    fat_sectors = 1
    while (len(sectors) + fat_sectors) > fat_sectors * (SECTOR // 4):
        fat_sectors += 1
    fat_ids = list(range(len(sectors), len(sectors) + fat_sectors))
    fat += [FATSECT] * fat_sectors
    fat += [FREESECT] * (fat_sectors * (SECTOR // 4) - len(fat))
    fat_blob = b"".join(struct.pack("<I", v) for v in fat)
    sectors += [fat_blob[i * SECTOR:(i + 1) * SECTOR] for i in range(fat_sectors)]

    difat = fat_ids + [FREESECT] * (109 - len(fat_ids))
    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16
              + struct.pack("<HHHHH", 0x003E, 0x0003, 0xFFFE, 9, 6) + b"\0" * 6
              + struct.pack("<IIIIIIIII", 0, fat_sectors, dir_start, 0, CUTOFF, minifat_start,
                            -(-len(minifat_blob) // SECTOR), ENDOFCHAIN, 0)
              + b"".join(struct.pack("<I", v) for v in difat))
    assert len(header) == SECTOR
    return header + b"".join(sectors)


# --- MS-OVBA helpers ---

def ovba_compress_literal(data: bytes) -> bytes:
    """A valid CompressedContainer using only literal tokens (flag byte 0 + up to 8 literals)."""
    out = b"\x01"
    for i in range(0, len(data), 4096):
        chunk = data[i:i + 4096]
        body = b"".join(b"\x00" + chunk[j:j + 8] for j in range(0, len(chunk), 8))
        out += struct.pack("<H", 0xB000 | (len(body) - 1)) + body
    return out


def vba_project(modules: Dict[str, str], pcode_padding: int = 600) -> Tree:
    """A VBA storage subtree: 'dir' plus one stream per module (fake p-code followed by compressed source)."""
    records = struct.pack("<HII", 0x0001, 4, 1)                        # PROJECTSYSKIND
    records += struct.pack("<HI", 0x0009, 4) + struct.pack("<IH", 1, 0)  # PROJECTVERSION (6-byte payload quirk)
    streams: Tree = {"_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00"}
    for name, source in modules.items():
        encoded = name.encode("latin-1")
        records += struct.pack("<HI", 0x0019, len(encoded)) + encoded                         # MODULENAME
        records += struct.pack("<HI", 0x001A, len(encoded)) + encoded                         # MODULESTREAMNAME
        records += struct.pack("<HI", 0x0032, 2 * len(encoded)) + name.encode("utf-16-le")
        records += struct.pack("<HII", 0x0031, 4, pcode_padding)                              # MODULEOFFSET
        streams[name] = b"\xab" * pcode_padding + ovba_compress_literal(source.encode("latin-1"))
    records += struct.pack("<HI", 0x0010, 0)
    streams["dir"] = ovba_compress_literal(records)
    return streams
