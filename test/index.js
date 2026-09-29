var assert = require('assert'),
    should = require('chai').should(),
    hepnode = require('../index'),
    encode = hepnode.encode,
    decode = hepnode.decode,
    encapsulate = hepnode.encapsulate,
    decapsulate = hepnode.decapsulate;

describe('#escape', function() {
  it('HEP Encoder', function() {
    encode('HEP3').should.equal('HEP3').toString("binary");
  });

});

describe('#unescape', function() {
  it('HEP Decoder', function() {
    decode(('HEP3').toString("binary")).should.equal('HEP3');
  });

});

describe('ipv4', function() {
  it('round-trips an IPv4 SIP packet', function() {
    var rcinfo = {
      ip_family: 2,
      protocol: 17,
      srcIp: '192.168.100.1',
      dstIp: '192.168.1.23',
      srcPort: 5060,
      dstPort: 5060,
      time_sec: 1433719443,
      time_usec: 979,
      proto_type: 1,
      captureId: 2001,
      capturePass: 'myHep'
    };
    var payload = 'OPTIONS sip:127.0.0.1 SIP/2.0\r\nCall-ID: ipv4\r\n';
    var decoded = decapsulate(encapsulate(payload, rcinfo));
    decoded.payload.should.equal(payload);
    decoded.rcinfo.protocolFamily.should.equal(2);
    decoded.rcinfo.srcIp.should.equal(rcinfo.srcIp);
    decoded.rcinfo.dstIp.should.equal(rcinfo.dstIp);
    decoded.rcinfo.srcPort.should.equal(5060);
    decoded.rcinfo.dstPort.should.equal(5060);
    decoded.rcinfo.timeSeconds.should.equal(1433719443);
    decoded.rcinfo.payloadType.should.equal(1);
    decoded.rcinfo.capturePass.should.equal('myHep');
  });
});

describe('ipv6', function() {
  var rcinfo = {
    protocolFamily: 10,
    protocol: 6,
    srcIp: '2001:566:f831:79:0:36:3dd6:3201',
    dstIp: '2001:555:f831:720::1234',
    srcPort: 12298,
    dstPort: 6100,
    timeSeconds: 1433719443,
    timeUseconds: 979,
    payloadType: 1,
    captureId: 2001,
    hepNodeName: 'abc'
  };
  var payload = 'INVITE sip:9999999996@ims.example SIP/2.0\r\nCall-ID: ipv6\r\n';

  it('round-trips compressed and uncompressed IPv6 addresses', function() {
    decapsulate(encapsulate(payload, rcinfo)).should.eql({rcinfo: rcinfo, payload: payload});
  });

  it('round-trips loopback and IPv4-embedded IPv6', function() {
    var info = {
      ip_family: 10,
      protocol: 17,
      srcIp: '::1',
      dstIp: '::ffff:192.0.2.1',
      srcPort: 5060,
      dstPort: 5060,
      time_sec: 1,
      time_usec: 2,
      proto_type: 1,
      captureId: 7
    };
    var decoded = decapsulate(encapsulate('ping', info));
    decoded.rcinfo.srcIp.should.equal('::1');
    decoded.rcinfo.dstIp.should.equal('::ffff:c000:201');
    decoded.rcinfo.protocolFamily.should.equal(10);
  });
});

describe('UTF-8 encapsulation', function() {
  var rcinfo = {
    ip_family: 2,
    protocol: 17,
    srcIp: '192.168.100.1',
    dstIp: '192.168.1.23',
    srcPort: 5060,
    dstPort: 5060,
    time_sec: 1433719443,
    time_usec: 979,
    proto_type: 1,
    captureId: 2001,
    capturePass: 'myHep'
  };

  it('keeps a multi-byte payload intact (#39)', function() {
    var payload = 'š'.repeat(20);
    var decoded = decapsulate(encapsulate(payload, rcinfo));
    assert.strictEqual(decoded.payload, payload);
  });

  it('keeps surrogate pairs in the payload intact', function() {
    var payload = 'INVITE sip:привет@example SIP/2.0\r\nCall-ID: 😀\r\n';
    var decoded = decapsulate(encapsulate(payload, rcinfo));
    assert.strictEqual(decoded.payload, payload);
  });

  it('keeps multi-byte strings in rcinfo chunks', function() {
    var info = {
      ip_family: rcinfo.ip_family,
      protocol: rcinfo.protocol,
      srcIp: rcinfo.srcIp,
      dstIp: rcinfo.dstIp,
      srcPort: rcinfo.srcPort,
      dstPort: rcinfo.dstPort,
      time_sec: rcinfo.time_sec,
      time_usec: rcinfo.time_usec,
      proto_type: rcinfo.proto_type,
      captureId: rcinfo.captureId,
      capturePass: 'пароль',
      hepNodeName: 'узел-š',
      correlation_id: 'corr-š-😀'
    };
    var payload = 'š';
    var decoded = decapsulate(encapsulate(payload, info));
    assert.strictEqual(decoded.payload, payload);
    assert.strictEqual(decoded.rcinfo.capturePass, info.capturePass);
    assert.strictEqual(decoded.rcinfo.hepNodeName, info.hepNodeName);
    assert.strictEqual(decoded.rcinfo.correlation_id, info.correlation_id);
  });

  it('keeps multi-byte vendor extension strings', function() {
    hepnode.addVendorExtensions({
      0x0009: {
        0x0080: {
          keyName: 'note'
        }
      }
    });
    var info = {
      ip_family: rcinfo.ip_family,
      protocol: rcinfo.protocol,
      srcIp: rcinfo.srcIp,
      dstIp: rcinfo.dstIp,
      srcPort: rcinfo.srcPort,
      dstPort: rcinfo.dstPort,
      time_sec: rcinfo.time_sec,
      time_usec: rcinfo.time_usec,
      proto_type: rcinfo.proto_type,
      captureId: rcinfo.captureId,
      capturePass: rcinfo.capturePass,
      note: 'заметка-š'
    };
    var decoded = decapsulate(encapsulate('ok', info));
    assert.strictEqual(decoded.payload, 'ok');
    assert.strictEqual(decoded.rcinfo.note, info.note);
  });
});
