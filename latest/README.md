# gQUIC
QUIC(Quick UDP Internet Connection) implementation in go
[draft-ietf-quic-transport-14](https://tools.ietf.org/html/draft-ietf-quic-transport-14)

Implementing in separate directory, because this draft is really progressing comparing to my previous implementation.

# RUN example
commands bellow can run server and client transferring application data.
the `DEBUG=1` can show the packets exchanged between server and client.

```sh
>> cd gQUIC/latest/example
>> DEBUG=1 go run main.go
```



#### License
The MIT License (MIT) Copyright (c) 2018 ami-GS
