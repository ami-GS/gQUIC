[![Build Status](https://travis-ci.org/ami-GS/gQUIC.svg?branch=master)](https://travis-ci.org/ami-GS/gQUIC)

# gQUIC
QUIC(Quick UDP Internet Connection) implementation in go
[draft-hamilton-early-deployment-quic-00](https://tools.ietf.org/html/draft-hamilton-early-deployment-quic-00)


#### RUN example
running example locally
1. Server: run loop for waiting client connection
2. Client: send packet with version
3. Server: check whether the version can be used from server (as of now)
4. To be implemented

```sh
>> go run ./examples/main.go
```

#### TODO
* Encryption
* Connection negotiation

#### License
The MIT License (MIT) Copyright (c) 2015 ami-GS
