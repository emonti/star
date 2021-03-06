import struct, zlib, sys
magic = 0xcdcdcdcd

assert sys.argv[1].endswith('.dylib')
assert sys.argv[2].endswith('xz')
a = zlib.compress(open(sys.argv[1]).read())
b = open(sys.argv[2]).read()
stuff = struct.pack('III', magic, len(a) + len(b) + 12, len(a)) + a + b
fp = open('wad.bin', 'w')
fp.write(stuff)
