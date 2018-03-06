from Cryptodome.Hash import HMAC, SHA1

key = b'\xd8\x899\xe4\xcc\x06\x83\r\x0b\x1e%r\xdck\xf5\x9b{\x8c\xf78^\x12\xaa\xc5\x11}D0\xb4?4\x18{\x15\xba\xef3\xfe\x82\xbfxc=\xb8\x06v\x96\x10'
h = HMAC.new(key, digestmod=SHA1)
h.update("abc".encode())
h.hexdigest()
h.update("def".encode())
res = h.hexdigest()
print('Result 1: {}'.format(res))

hmac = HMAC.new(key, digestmod=SHA1)
hmac.update("abcdef".encode())
res1 = hmac.hexdigest()
print('Result 2: {}'.format(res1))
