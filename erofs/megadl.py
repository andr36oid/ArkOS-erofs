#!/usr/bin/env python3
"""megadl.py <mega file link> <output file>: fetch and decrypt one public MEGA file."""
import base64, json, struct, sys, urllib.request
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:  # Debian and Ubuntu package it as Cryptodome
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter

link, out = sys.argv[1], sys.argv[2]
handle, key = link.split("/file/")[1].split("#")
def b64(s):
    s = s.replace("-", "+").replace("_", "/").replace(",", "")
    return base64.b64decode(s + "=" * (-len(s) % 4))
k = struct.unpack(">8I", b64(key))
aes_key = struct.pack(">4I", k[0] ^ k[4], k[1] ^ k[5], k[2] ^ k[6], k[3] ^ k[7])
iv = (k[4] << 32) | k[5]
req = urllib.request.Request("https://g.api.mega.co.nz/cs?id=1",
    data=json.dumps([{"a": "g", "g": 1, "p": handle}]).encode(),
    headers={"Content-Type": "application/json", "User-Agent": "generic-client"})
info = json.load(urllib.request.urlopen(req, timeout=60))[0]
if isinstance(info, int): sys.exit("MEGA error %d" % info)
attr = AES.new(aes_key, AES.MODE_CBC, b"\0" * 16).decrypt(b64(info["at"])).rstrip(b"\0")
print("name:", attr.decode(errors="replace"), "size:", info["s"], flush=True)
ctr = AES.new(aes_key, AES.MODE_CTR, counter=Counter.new(64, prefix=struct.pack(">Q", iv), initial_value=0))
done = 0
with urllib.request.urlopen(urllib.request.Request(info["g"], headers={"User-Agent": "generic-client"}), timeout=120) as r, open(out, "wb") as f:
    while True:
        block = r.read(1 << 20)
        if not block: break
        f.write(ctr.decrypt(block)); done += len(block)
if done != info["s"]: sys.exit("short download %d of %d" % (done, info["s"]))
print("ok", done)
