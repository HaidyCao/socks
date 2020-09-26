# socks

## TODO
* 流量管理
* 多用户
* 时长管理

# Multi Socks Protocol
## Version 1

### 1. Requst

| Type | Version | Authentication |  RSV  | ULEN |   UNAME   | PLEN | PASSWD   |
|   -  |   :-:   |      :-:       |  :-:  |  :-: |    :-:    |  :-: |   :-:    |
| LEN  |    1    |       1        |   1   |   1  |  1 to 255 |   1  | 1 to 255 |

+ Version
  + 0x01
+ Authentication
  + 0x02 Username/Password. see http://www.faqs.org/rfcs/rfc1929.html
+ RSV. RESERVED
+ Username length
+ Username
+ Password length
+ Password

### 2. Response
| Version |  RSV  | Result |
|   :-    |  :-:  |   :-:  |
|    1    |   1   |   1    |

+ Version
  + 0x01
+ Token
+ Result
  + 0x00 Success
  + others failure

### 3. Packet

| Type | Version | CMD | Total Len | Sequence | HLEN | Host | Port | Session | Packet length | checksum | packet |
|  -   |   :-:   | :-: |    :-:    |    :-:   |  :-: | :-:  |  :-: |   :-:   |      :-:      |    :-:   |   :-:  |
| Len  |    1    |  1  |     2     |     2    |   1  |  n   |   2  |    4    |       2       |     2    |    n   |

+ Version
  + 0x01
+ CMD
  + 0x01 Connect
  + 0x02 Write data
  + 0x03 Close
  + 0x04 Connect Result
  + 0x05 Drain Data
  + 0x06 Free Drain Data
  + 0x07 Error Message
  + 0x08 Heartbeat
+ Total Len 
+ Sequence
+ HLEN
  + Host len
+ Host string ipv4 ipv6 or domain
+ Port
+ Packet length 
  + big-endian
+ Session
+ checksum
  + big-endian; set checksum to 0x00, get calculate value and rewrite checksum
+ packet
  + data

### Heartbeat
+ Client send `Heartbeat` request

# DNS
https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168