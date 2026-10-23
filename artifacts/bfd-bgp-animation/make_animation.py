"""Create the editable topology, or assemble GDI+ GIF frames (standard library only)."""
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent


def topology():
    doc = ET.Element('mxfile', host='app.diagrams.net')
    page = ET.SubElement(doc, 'diagram', name='Anycast DNS with BFD and BGP', id='bfd-bgp')
    graph = ET.SubElement(page, 'mxGraphModel', pageWidth='1000', pageHeight='720', adaptiveColors='auto')
    root = ET.SubElement(graph, 'root')
    ET.SubElement(root, 'mxCell', id='0')
    ET.SubElement(root, 'mxCell', id='1', parent='0')
    nodes = {
        'a': ('Server A / DNS / Advertises 203.0.113.53/32', 40, 220, 240, 140),
        'b': ('Server B / DNS / Advertises 203.0.113.53/32', 40, 430, 240, 140),
        'c': ('Router C / BFD to BGP / Selects DNS next hop', 440, 220, 270, 350),
        'd': ('Client D / DNS queries to 203.0.113.53', 810, 335, 150, 140),
    }
    for key, (label, x, y, w, h) in nodes.items():
        cell = ET.SubElement(root, 'mxCell', id=key, value=label,
                             style='rounded=1;whiteSpace=wrap;html=1;fontSize=18;fillColor=#16243B;strokeColor=#536682;fontColor=#EDF4FF;',
                             vertex='1', parent='1')
        ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y), width=str(w), height=str(h), **{'as': 'geometry'})
    for key, source, target, label in [('ac','a','c','BGP /32 + BFD'),('bc','b','c','BGP /32 + BFD'),('dc','d','c','DNS queries')]:
        cell = ET.SubElement(root, 'mxCell', id=key, source=source, target=target, value=label, parent='1', edge='1',
                             style='edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=none;strokeColor=#6A9FFF;fontColor=#EDF4FF;')
        ET.SubElement(cell, 'mxGeometry', relative='1', **{'as':'geometry'})
    ET.indent(doc)
    ET.ElementTree(doc).write(ROOT / 'bfd-bgp-topology.drawio', encoding='utf-8', xml_declaration=True)


def gif_parts(raw):
    assert raw[:6] in (b'GIF87a', b'GIF89a')
    packed = raw[10]
    p = 13
    palette = b''
    if packed & 128:
        n = 3 * (2 ** ((packed & 7) + 1))
        palette, p = raw[p:p+n], p+n
    while p < len(raw):
        tag = raw[p]
        p += 1
        if tag == 0x21:
            p += 1
            while raw[p]:
                p += raw[p] + 1
            p += 1
        elif tag == 0x2C:
            descriptor = bytearray(raw[p:p+9])
            p += 9
            local_packed = descriptor[8]
            if local_packed & 128:
                n = 3 * (2 ** ((local_packed & 7) + 1))
                local_palette, p = raw[p:p+n], p+n
            else:
                local_palette = palette
                descriptor[8] = (local_packed & 0x40) | 0x80 | (packed & 7)
            start = p
            p += 1
            while raw[p]:
                p += raw[p] + 1
            p += 1
            return raw[6:10], bytes(descriptor), local_palette, raw[start:p]
        else:
            raise ValueError(f'Unexpected GIF block {tag:02x}')
    raise ValueError('No image block')


def assemble():
    paths = sorted((ROOT / '.frames').glob('frame-*.gif'))
    assert len(paths) == 224, len(paths)
    data = bytearray(b'GIF89a' + struct.pack('<HHBBB', 1000, 720, 0x70, 0, 0))
    data += b'\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00'
    for i, path in enumerate(paths):
        dims, descriptor, palette, pixels = gif_parts(path.read_bytes())
        assert struct.unpack('<HH', dims) == (1000, 720)
        delay = 12 if i % 2 == 0 else 13  # GIF centiseconds: exactly 8 fps.
        data += b'\x21\xf9\x04\x04' + struct.pack('<H', delay) + b'\x00\x00'
        data += b'\x2c' + descriptor + palette + pixels
    data += b'\x3b'
    target = ROOT / 'bfd-bgp-interaction.gif'
    target.write_bytes(data)
    assert len(data) < 10_000_000, f'GIF too large: {len(data)}'
    print(f'{target}\n{len(data):,} bytes | 224 frames | 28 seconds | 1000 x 720 | infinite loop')


if __name__ == '__main__':
    topology() if sys.argv[1:] == ['topology'] else assemble()
