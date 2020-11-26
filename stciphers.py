import ctypes

from urllib3.contrib.securetransport import Security, SecurityConst, _assert_no_error


ssl_context = context = Security.SSLCreateContext(
    None, SecurityConst.kSSLClientSide, SecurityConst.kSSLStreamType
)

# get number of supported ciphers
numCiphers = ctypes.c_size_t(0)
result = Security.SSLGetNumberEnabledCiphers(context, ctypes.byref(numCiphers))
_assert_no_error(result)
# get actual ciphers
ciphers = (Security.SSLCipherSuite * numCiphers.value)()
result = Security.SSLGetEnabledCiphers(
    context, ctypes.cast(ciphers, ctypes.POINTER(ctypes.c_uint32)), numCiphers
)
_assert_no_error(result)
for c in ciphers:
    print(hex(c))
