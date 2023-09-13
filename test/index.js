var should = require("chai").should(),
  hepnode = require("../index"),
  encode = hepnode.encode,
  decode = hepnode.decode,
  encapsulate = hepnode.encapsulate,
  decapsulate = hepnode.decapsulate;

describe("#escape", function () {
  it("HEP Encoder", function () {
    encode("HEP3").should.equal("HEP3").toString("binary");
  });
});

describe("#unescape", function () {
  it("HEP Decoder", function () {
    decode("HEP3".toString("binary")).should.equal("HEP3");
  });
});

describe("ipv6", function () {
  const rcinfo = {
    protocolFamily: 10,
    protocol: 6,
    srcIp: "2001:566:f831:79:0:36:3dd6:3201",
    dstIp: "2001:555:f831:720::1234",
    srcPort: 12298,
    dstPort: 6100,
    timeSeconds: 1433719443,
    timeUseconds: 979,
    payloadType: 1,
    captureId: 2001,
    hepNodeName: "abc"
  };

  const payload =
    'INVITE sip:9999999996;phone-context=ims.mnc123.mnc100.3gppnetwork.org@ims.mnc123.mnc100.3gppnetwork.org;user=phone SIP/2.0\r\nVia: SIP/2.0/TCP [2001:566:f831:23:0:32:f692:9d01]:6100;branch=z9hG4bK-524287-1---9322df8bee339153;rport;transport=TCP\r\nMax-Forwards: 70\r\nRoute: <sip:[2001:566:f831:720::1234]:12657;lr>\r\nProxy-Require: sec-agree\r\nRequire: sec-agree\r\nContact: <sip:18559990299@[2001:568:f831:23:0:32:f692:9d01]:6100>;+sip.instance="<urn:gsma:imei:35269610-004503-0>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.mid-call;+g.3gpp.srvcc-alerting;+g.3gpp.ps2cs-srvcc-orig-pre-alerting\r\nTo: <sip:9999999996;phone-context=ims.mnc123.mnc100.3gppnetwork.org@ims.mnc123.mnc100.3gppnetwork.org;user=phone>\r\nFrom: <sip:18559990299@ims.mnc123.mnc100.3gppnetwork.org>;tag=6e42722f\r\nCall-ID: UYbWSyst2FrgtQ8hAkq2Ig..@2001:555:f831:23:0:32:f692:9d01\r\nCSeq: 1 INVITE\r\nSession-Expires: 1800\r\nAccept: application/sdp, application/3gpp-ims+xml\r\nAllow: INVITE, ACK, OPTIONS, CANCEL, BYE, UPDATE, INFO, REFER, NOTIFY, MESSAGE, PRACK\r\nContent-Type: application/sdp\r\nSupported: timer, 100rel, precondition, gruu, sec-agree\r\nUser-Agent: SM-G975W-G975WVLS5GUD1 Samsung IMS 6.0\r\nSecurity-Verify: ipsec-3gpp;prot=esp;mod=trans;spi-c=12656;spi-s=12657;port-c=12656;port-s=12657;alg=hmac-sha-1-96;ealg=null\r\nP-Preferred-Identity: <sip:18559990299@ims.mnc123.mnc100.3gppnetwork.org>\r\nAccept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"\r\nP-Early-Media: supported\r\nP-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel\r\nP-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3022202b001afad00\r\nContent-Length: 920\r\n\r\nv=0\r\no=SAMSUNG-IMS-UE 448775668462 448775668462 IN IP6 2001:555:f831:23:0:32:f692:9d01\r\ns=SS VOIP\r\nc=IN IP6 2001:566:f831:23:0:32:f692:9d01\r\nt=0 0\r\nm=audio 1284 RTP/AVP 127 116 107 118 96 111 110\r\nb=AS:50\r\nb=RS:0\r\nb=RR:2500\r\na=rtpmap:127 EVS/16000\r\na=fmtp:127 br=5.9-24.4;bw=nb-swb;ch-aw-recv=2\r\na=rtpmap:116 AMR-WB/16000/1\r\na=fmtp:116 mode-set=0,1,2;mode-change-capability=2;max-red=220\r\na=rtpmap:107 AMR-WB/16000/1\r\na=fmtp:107 mode-set=0,1,2;octet-align=1;mode-change-capability=2;max-red=220\r\na=rtpmap:118 AMR/8000/1\r\na=fmtp:118 mode-change-capability=2;max-red=220\r\na=rtpmap:96 AMR/8000/1\r\na=fmtp:96 octet-align=1;mode-change-capability=2;max-red=220\r\na=rtpmap:111 telephone-event/16000\r\na=fmtp:111 0-15\r\na=rtpmap:110 telephone-event/8000\r\na=fmtp:110 0-15\r\na=curr:qos local none\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\na=des:qos optional remote sendrecv\r\na=sendrecv\r\na=ptime:20\r\na=maxptime:240\r\n\r\n\r\n';

  it("HEP encapsulate/decapsulate", function () {
    const hepCapsulated = encapsulate(payload, rcinfo);
    decapsulate(hepCapsulated).should.eql({rcinfo: rcinfo, payload: payload});
  });
});
