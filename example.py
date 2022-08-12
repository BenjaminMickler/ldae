import ldae

k = ldae.key(filename="test.key")
if not k.exists:
    k.create()
l = ldae.ldae(k)
a = l.encrypt("Hello, World!")
print(a)
b = l.decrypt(a)
print(b)