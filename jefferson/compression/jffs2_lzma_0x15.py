import lzma

def decompress(data, outlen):
    lzma_header = data[0:5]
    lzma_data = data[0:5] + outlen.to_bytes(8, "little") + data[5:]
    decompressed = lzma.decompress(lzma_data)
    return decompressed
