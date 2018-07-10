import urlparse

path="http://www.facebook.com/psas.asas?id=1"
u = urlparse.urlsplit(path)
scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
print(netloc)
print(path)