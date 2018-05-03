[![Build Status](https://travis-ci.org/ami-GS/gQUIC.svg?branch=master)](https://travis-ci.org/ami-GS/gQUIC)

# gQUIC
QUIC(Quick UDP Internet Connection) implementation in go
[draft-hamilton-early-deployment-quic-00](https://tools.ietf.org/html/draft-hamilton-early-deployment-quic-00)

### Notice
Currently implementing latest draft in `latest` directory, the latest is really different from this draft.

This is test implementation of IETF QUIC, not google QUIC.
I noticed the name gQUIC is too confusing, this would be changed in the future.

#### RUN example
Running example locally

If you notice procedure bellows are different from spec, I would be appreciate your suggestion.

1. Server: run loop for waiting client connection
2. Client: send packet with version (no frame)
3. Server: check whether the version can be used from server (as of now)
4. Client: send packet with Stream frame, data with "testData" (Server Ack)
6. Client: send Ping (Server Ack as Pong)
6. Client: send GoAway, reason with "This is GoAway reason" (Server Ack)
6. Client: send ConnectionClose, reason with "This is Connection Close reason" (Server Ack)
8. To be implemented

```sh
>> go run ./examples/main.go
```

#### TODO
* Encryption
* Connection negotiation

#### License
The MIT License (MIT) Copyright (c) 2015 ami-GS
