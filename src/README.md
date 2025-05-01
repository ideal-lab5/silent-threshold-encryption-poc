# Beacons and stuff...

This is a 'toy' network thet uses silent threshold encryption to enable timelock encryption with silent setup.

install gRPCurl, then:

```
./grpcurl -plaintext -proto ideal/beacon/src/hello.proto -d '{"name": "gRPC"}' '127.0.0.1:30333' hello.World/Hello
{
  "message": "Hello, gRPC!"
}
```