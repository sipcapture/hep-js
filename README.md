[![Dependency Status](https://david-dm.org/sipcapture/hep-js.svg)](https://david-dm.org/sipcapture/hep-js)

[![Logo](https://avatars0.githubusercontent.com/u/6690913?v=3&s=100)](http://sipcapture.org)

# hep-js
HEP: Javascript/Node implementation of HEP/EEP Encapsulation Protocol


This module provides Node with [HEP/EEP](http://hep.sipcapture.org) packet encapsulation capabilities.
For more information about HEP and SIPCAPTURE Projects, please visit [http://sipcapture.org](http://sipcapture.org)

### Install:
```
npm install hep-js
```


### Example Usage:
```
var hep_message = HEPjs.encapsulate(payload,rcinfo);
```

#### Example: payload
```
ACK sip:883510000000091@domain.net SIP/2.0
Via: SIP/2.0/UDP 192.168.1.23:5060;rport;branch=z9hG4bK484759904 
From: <sip:somebody@somewhere.net>;tag=412285373 
To: <sip:883510000000091@domain.net>;tag=1d24a28a0bded6c40d31e6db8aab9ac6.4679 
Call-ID: 1003554701 
CSeq: 20 ACK 
Content-Length: 0 
```

#### Example: rcinfo
```
rcinfo = { type: 'HEP',
  version: 3,
  payload_type: 'SIP',
  captureId: '2001',
  capturePass: 'myHep',
  ip_family: 2,
  time_sec: 1433719443,
  time_usec: 979,
  protocol: 17,
  proto_type: 1,
  srcIp: '192.168.100.1',
  dstIp: '192.168.1.23',
  srcPort: 5060,
  dstPort: 5060 
}
```

#### HEP/EEP Specs:

http://hep.sipcapture.org/
