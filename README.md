# gQUIC
QUIC(Quick UDP Internet Connection) implementation in go
[draft-ietf-quic-transport-15](https://tools.ietf.org/html/draft-ietf-quic-transport-15)

### Notice
*This is WIP, not fully functional.*
This is test implementation of IETF QUIC, not google QUIC. Sorry for confusing naming


# RUN example
commands bellow can run server and client transferring application data.
the `DEBUG=1` can show the packets exchanged between server and client.

```sh
>> cd gQUIC/latest/example
>> DEBUG=1 go run main.go
```



#### License
The MIT License (MIT) Copyright (c) 2018 ami-GS
