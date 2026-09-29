/**
 * HEP-js: A simple HEP3 Library for Node.JS
 *
 * Copyright (C) 2015 Lorenzo Mangani (SIPCAPTURE.ORG)
 * Copyright (C) 2015 Alexandr Dubovikov (SIPCAPTURE.ORG)
 * Copyright (C) 2019 QXIP BV (QXIP.NET)
 *
 * Project Homepage: http://github.com/sipcapture
 *
 * This file is part of HEP-js
 *
 * HEP-js is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * HEP-js is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *
 **/

var debug = false;

// Module import
var Parser = require("binary-parser").Parser;
var mixinDeep = require('mixin-deep');
/**
 * @type {{}[][]}
 */
var extensions = [];

module.exports = {
  /**
   * Decode HEP3 Packet to JSON Object.
   *
   * @param  {Buffer} message
   * @return {{rcinfo: {type:string, version:number, payloadType?: number, payload_type?: number, captureId: string, hepNodeName?: string, capturePass: string, protocolFamily?: number, ip_family?: number, protocol: number, proto_type: number, mos?: number, correlation_id: string, srcIp: string, dstIp: string, srcPort: number|string, dstPort: number|string, time_sec?: number, timeSeconds?: number, timeUseconds?: number, time_usec?: number}, payload: string} | false}
   */
  decapsulate: function(message) {
    if (debug) console.log('Decoding HEP3 Packet...');
    try {
	var HEP = hepHeader.parse(message);
	if(HEP.payload && HEP.payload.length>0){
	  var data = HEP.payload;
	  var tot = 0;
	  var decoded = {};
	  var PAYLOAD;
	  while(true){
	    PAYLOAD = hepParse.parse( data.slice(tot) );
	    var tmp = hepDecode(PAYLOAD);
	    decoded = mixinDeep(decoded, tmp);
	    tot += PAYLOAD.length;
	    if(tot>=HEP.payload.length) { break; }
	  }
	  if(debug) console.log(decoded);
	  return decoded;
	}
    } catch(e) {
	return false;
    }
	return false;
  },
  /**
   * Encode HEP3 Packet from JSON Object.
   *
   * @param  {String} msg
   * @param  {{type:string, version:number, payloadType?: number, payload_type?: number, captureId: string, hepNodeName?: string, capturePass: string, protocolFamily?: number, ip_family?: number, protocol: number, proto_type: number, mos?: number, correlation_id: string, srcIp: string, dstIp: string, srcPort: number|string, dstPort: number|string, time_sec?: number, timeSeconds?: number, timeUseconds?: number, time_usec?: number}} rcinfo
   * @return {Buffer} HEP packet
   */
  encapsulate: function(msg,rcinfo) {
	if (debug) console.log('Encapsulating HEP3 Packet...');
	var header = Buffer.allocUnsafe(6);
	header.write("HEP3");

	var ip_family = Buffer.allocUnsafe(7);
	ip_family.writeUInt16BE(0x0000, 0);
	ip_family.writeUInt16BE(0x0001,2);
	let ip_protocol_family = rcinfo.ip_family || rcinfo.protocolFamily
	ip_family.writeUInt8(ip_protocol_family,6);
	ip_family.writeUInt16BE(ip_family.length,4);

	var ip_proto = Buffer.allocUnsafe(7);
	ip_proto.writeUInt16BE(0x0000, 0);
	ip_proto.writeUInt16BE(0x0002, 2);
	ip_proto.writeUInt8(rcinfo.protocol,6);
	ip_proto.writeUInt16BE(ip_proto.length,4);

	/* ip: family 2 is IPv4 (chunks 0x0003/0x0004), family 10 is IPv6 (0x0005/0x0006) */
	var src_ip = ipAddressChunk(ip_protocol_family, rcinfo.srcIp, true);
	var dst_ip = ipAddressChunk(ip_protocol_family, rcinfo.dstIp, false);

	var src_port = Buffer.allocUnsafe(8);
	var tmpA = rcinfo.srcPort ? parseInt(rcinfo.srcPort,10) : 0;
	src_port.writeUInt16BE(0x0000, 0);
	src_port.writeUInt16BE(0x0007, 2);
	src_port.writeUInt16BE(tmpA,6);
	src_port.writeUInt16BE(src_port.length,4);

	var dst_port = Buffer.allocUnsafe(8);
	tmpA = rcinfo.dstPort ? parseInt(rcinfo.dstPort, 10) : 0;
	dst_port.writeUInt16BE(0x0000, 0);
	dst_port.writeUInt16BE(0x0008, 2);
	dst_port.writeUInt16BE(tmpA,6);
	dst_port.writeUInt16BE(dst_port.length,4);

	let timeInSeconds = rcinfo.time_sec || rcinfo.timeSeconds
	tmpA = ToUint32(timeInSeconds);
	var time_sec = Buffer.allocUnsafe(10);
	time_sec.writeUInt16BE(0x0000, 0);
	time_sec.writeUInt16BE(0x0009, 2);
	time_sec.writeUInt32BE(tmpA,6);
	time_sec.writeUInt16BE(time_sec.length,4);

	let timeInMicroSeconds = rcinfo.time_usec || rcinfo.timeUseconds
	tmpA = ToUint32(timeInMicroSeconds);
	var time_usec = Buffer.allocUnsafe(10);
	time_usec.writeUInt16BE(0x0000, 0);
	time_usec.writeUInt16BE(0x000a, 2);
	time_usec.writeUInt32BE(tmpA,6);
	time_usec.writeUInt16BE(time_usec.length,4);

	var proto_type = Buffer.allocUnsafe(7);
	proto_type.writeUInt16BE(0x0000, 0);
	proto_type.writeUInt16BE(0x000b,2);
	var payloadTypeValue = rcinfo.proto_type;
	if (payloadTypeValue == null && rcinfo.payloadType != null) payloadTypeValue = rcinfo.payloadType;
	if (payloadTypeValue == null && rcinfo.payload_type != null) payloadTypeValue = rcinfo.payload_type;
	proto_type.writeUInt8(payloadTypeValue,6);
	proto_type.writeUInt16BE(proto_type.length,4);

	tmpA = ToUint32(rcinfo.captureId);
	var capt_id = Buffer.allocUnsafe(10);
	capt_id.writeUInt16BE(0x0000, 0);
	capt_id.writeUInt16BE(0x000c, 2);
	capt_id.writeUInt32BE(tmpA,6);
	capt_id.writeUInt16BE(capt_id.length,4);
	  
	// HEPNodeName w/ Fallback to HEP Capture ID
	let tmpB = rcinfo.hepNodeName ? rcinfo.hepNodeName : "" + rcinfo.captureId;
	var hepnodename_chunk = writeUtf8Chunk(0x0000, 0x0013, tmpB);

	var auth_chunk = typeof rcinfo.capturePass === 'string'
	  ? writeUtf8Chunk(0x0000, 0x000e, rcinfo.capturePass)
	  : Buffer.allocUnsafe(0);

	var payload_chunk = writeUtf8Chunk(0x0000, 0x000f, msg);

	var extensions_chunk = Buffer.allocUnsafe(0);
	for(var i in extensions) {
	  for(var j in extensions[i]) {
	    var extdef = extensions[i][j];
	    if(typeof extdef === "object" &&
	       typeof extdef.keyName === "string" &&
	       typeof rcinfo[extdef.keyName] !== 'undefined') {
		var this_chunk;
		var data = rcinfo[extdef.keyName];
		var failed = true;
		if(/\d{1,}/.test(extdef.type)) {
		  var bitLength = extdef.type.match(/\d{1,}/)[0];
		  var size = Math.floor(bitLength/8)+6;
		  this_chunk = Buffer.allocUnsafe(size);
		  this_chunk.writeUInt16BE(i, 0);
		  this_chunk.writeUInt16BE(j, 2);
		  if(typeof this_chunk["write"+extdef.type] === 'function') {
		    this_chunk['write'+extdef.type](data ,6);
		    failed = false;
		  }
		  else if(typeof this_chunk["write"+extdef.type+"BE"] === 'function') {
		    this_chunk['write'+extdef.type+"BE"](data ,6);
		    failed = false;
		  }
		  this_chunk.writeUInt16BE(this_chunk.length,4);
		}
		else if(/string$/.test(extdef.type) || extdef.type === undefined) {
		  this_chunk = writeUtf8Chunk(i, j, data);
		  failed = false;
		}
		if(typeof this_chunk !== 'undefined' && !failed) {
		  extensions_chunk = Buffer.concat([extensions_chunk, this_chunk]);
		}
	    }
	  }
	}

	var hep_message, correlation_chunk;

	if ((rcinfo.proto_type == 34 || rcinfo.proto_type == 35 || rcinfo.proto_type == 36 || rcinfo.proto_type == 37 ) && rcinfo.correlation_id.length) {

		// create correlation chunk
	        correlation_chunk = writeUtf8Chunk(0x0000, 0x0011, rcinfo.correlation_id);

	        tmpA = ToUint16(rcinfo.mos);
		var mos = Buffer.allocUnsafe(8);
		mos.writeUInt16BE(0x0000, 0);
		mos.writeUInt16BE(0x0020, 2);
		mos.writeUInt16BE(tmpA,6);
		mos.writeUInt16BE(mos.length,4);

		hep_message = Buffer.concat([
			header, 
			ip_family,
			ip_proto,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			time_sec,
			time_usec,
			proto_type,
			capt_id,
			hepnodename_chunk,
			auth_chunk,
			correlation_chunk,
			mos,
			payload_chunk,
			extensions_chunk
		]);

	}
	// HEP TYPE 101 w/ mandatory json_chunk (string)
	else if (rcinfo.transaction_type && rcinfo.transaction_type.length && rcinfo.correlation_id.length) {

		// create correlation chunk
	        correlation_chunk = writeUtf8Chunk(0x0000, 0x0011, rcinfo.correlation_id);

	        // create transaction_type chunk
	        var transaction_type = writeUtf8Chunk(0x0000, 0x0024, rcinfo.transaction_type);

		hep_message = Buffer.concat([
			header, 
			ip_family,
			ip_proto,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			time_sec,
			time_usec,
			proto_type,
			capt_id,
			hepnodename_chunk,
			auth_chunk,
			correlation_chunk,
			transaction_type,
			payload_chunk,
			extensions_chunk
		]);

	}
	else if (rcinfo.correlation_id && rcinfo.correlation_id.length) {

		// create correlation chunk
	        correlation_chunk = writeUtf8Chunk(0x0000, 0x0011, rcinfo.correlation_id);
		
		hep_message = Buffer.concat([
			header, 
			ip_family,
			ip_proto,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			time_sec,
			time_usec,
			proto_type,
			capt_id,
			hepnodename_chunk,
			auth_chunk,
			correlation_chunk,
			payload_chunk,
			extensions_chunk
		]);
	}
	else {

		hep_message = Buffer.concat([
			header,
			ip_family,
			ip_proto,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			time_sec,
			time_usec,
			proto_type,
			capt_id,
			hepnodename_chunk,
			auth_chunk,
			payload_chunk,
			extensions_chunk
		]);

	}
	hep_message.writeUInt16BE(hep_message.length, 4);
	return hep_message;

  },

  encode: function(json) {
    return String(json)
      .toString("binary");
  },

  decode: function(hep) {
    return String(hep)
      .toString('utf8');
  },

  addVendorExtensions: function(json) {
    extensions = mixinDeep(extensions, json);
  }
};


/* Functions */

function writeUtf8Chunk(vendor, type, text) {
	var size = Buffer.byteLength(text, 'utf8');
	var chunk = Buffer.allocUnsafe(6 + size);
	chunk.writeUInt16BE(vendor, 0);
	chunk.writeUInt16BE(type, 2);
	chunk.write(text, 6, size, 'utf8');
	chunk.writeUInt16BE(chunk.length, 4);
	return chunk;
}

function ipAddressChunk(family, address, isSource) {
	var ipv6 = Number(family) === 10;
	var type = ipv6 ? (isSource ? 0x0005 : 0x0006) : (isSource ? 0x0003 : 0x0004);
	var body = ipv6 ? ipv6ToBuffer(address || '::') : ipv4ToBuffer(address);
	var chunk = Buffer.allocUnsafe(6 + body.length);
	chunk.writeUInt16BE(0x0000, 0);
	chunk.writeUInt16BE(type, 2);
	body.copy(chunk, 6);
	chunk.writeUInt16BE(chunk.length, 4);
	return chunk;
}

function ipv4ToBuffer(address) {
	var d = address ? String(address).split('.') : ['127','0','0','1'];
	var buf = Buffer.allocUnsafe(4);
	buf[0] = +d[0];
	buf[1] = +d[1];
	buf[2] = +d[2];
	buf[3] = +d[3];
	return buf;
}

function ipv6ToBuffer(address) {
	var buf = Buffer.alloc(16);
	var str = String(address || '::');
	var zone = str.indexOf('%');
	if (zone !== -1) str = str.slice(0, zone);
	var halves = str.split('::');
	if (halves.length > 2) throw new Error('Bad IPv6 address');
	var head = ipv6Groups(halves[0]);
	var tail = halves.length === 2 ? ipv6Groups(halves[1]) : [];
	var groups;
	if (halves.length === 1) {
		if (head.length !== 8) throw new Error('Bad IPv6 address');
		groups = head;
	} else {
		var missing = 8 - head.length - tail.length;
		if (missing < 1) throw new Error('Bad IPv6 address');
		groups = head.concat(new Array(missing).fill(0), tail);
	}
	for (var i = 0; i < 8; i++) buf.writeUInt16BE(groups[i], i * 2);
	return buf;
}

function ipv6Groups(part) {
	if (!part) return [];
	var out = [];
	var pieces = part.split(':');
	for (var i = 0; i < pieces.length; i++) {
		var group = pieces[i];
		if (group.indexOf('.') !== -1) {
			var octets = group.split('.');
			if (octets.length !== 4) throw new Error('Bad IPv6 address');
			out.push(((+octets[0]) << 8) | (+octets[1]));
			out.push(((+octets[2]) << 8) | (+octets[3]));
			continue;
		}
		if (!/^[0-9a-fA-F]{1,4}$/.test(group)) throw new Error('Bad IPv6 address');
		out.push(parseInt(group, 16));
	}
	return out;
}

function formatIPv6(buf) {
	var bestStart = -1;
	var bestLen = 0;
	var i = 0;
	while (i < 8) {
		if (buf.readUInt16BE(i * 2) !== 0) { i++; continue; }
		var j = i;
		while (j < 8 && buf.readUInt16BE(j * 2) === 0) j++;
		if ((j - i) > bestLen) {
			bestStart = i;
			bestLen = j - i;
		}
		i = j;
	}
	if (bestLen < 2) bestStart = -1;
	var out = [];
	for (i = 0; i < 8;) {
		if (i === bestStart) {
			out.push('');
			i += bestLen;
			if (i >= 8) out.push('');
			continue;
		}
		out.push(buf.readUInt16BE(i * 2).toString(16));
		i++;
	}
	var text = out.join(':');
	if (text === ':') return '::';
	if (text.charAt(0) === ':') return ':' + text;
	return text;
}

var modulo = function (a, b) {
        return a - Math.floor(a/b)*b;
};

var ToUint32 = function (x) {
        return modulo(ToInteger(x), Math.pow(2, 32));
};

var ToUint16 = function (x) {
        return modulo(ToInteger(x), Math.pow(2, 16));
};

var ToInteger =function (x) {
        x = Number(x);
        return x < 0 ? Math.ceil(x) : Math.floor(x);
};

var ntohl = function (val) {
    return ((val & 0xFF) << 24)
           | ((val & 0xFF00) << 8)
           | ((val >> 8) & 0xFF00)
           | ((val >> 24) & 0xFF);
};

var inet_pton = function inet_pton(a) {

  var r, m, x, i, j, f = String.fromCharCode;
  // IPv4
  m = a.match(/^(?:\d{1,3}(?:\.|$)){4}/);
  if (m) {
    m = m[0].split('.');
    m = f(m[0]) + f(m[1]) + f(m[2]) + f(m[3]);
    // Return if 4 bytes, otherwise false.
    return m.length === 4 ? m : false;
  }
  r = /^((?:[\da-f]{1,4}(?::|)){0,8})(::)?((?:[\da-f]{1,4}(?::|)){0,8})$/;
  // IPv6
  m = a.match(r);
  if (m) {
    // Translate each hexadecimal value.
    for (j = 1; j < 4; j++) {
      // Indice 2 is :: and if no length, continue.
      if (j === 2 || m[j].length === 0) {
        continue;
      }
      m[j] = m[j].split(':');
      for (i = 0; i < m[j].length; i++) {
        m[j][i] = parseInt(m[j][i], 16);
        // Would be NaN if it was blank, return false.
        if (isNaN(m[j][i])) {
          // Invalid IP.
          return false;
        }
        m[j][i] = f(m[j][i] >> 8) + f(m[j][i] & 0xFF);
      }
      m[j] = m[j].join('');
    }
    x = m[1].length + m[3].length;
    if (x === 16) {
      return m[1] + m[3];
    } else if (x < 16 && m[2].length > 0) {
      return m[1] + (new Array(16 - x + 1))
        .join('\x00') + m[3];
    }
  }
  // Invalid IP.
  return false;
};

// Build an IP packet header Parser
var hepHeader = new Parser()
  .endianess("big")
  .string("hep", { length: 4, stripNull: true, assert: "HEP3" })
  .uint16("hepLength")
  .buffer("payload", { length: function () {return this.hepLength - 6; } }); // Length of HepMessage is defined including the 6 Byte Header

var hepParse = new Parser()
  .endianess("big")
  .uint16("vendor")
  .uint16("type")
  .uint16("length")
  .buffer("chunk", { length: function () {return this.length-6;} }); // Length of Chunk is defined including the 6 Byte header

var hepIps = new Parser()
  .endianess("big")
  .array("ip",{
     type: "uint8",
     length: 4
  });

var hepDecode = function(data){
  switch(data.type) {
    case 1:
	return { rcinfo: { protocolFamily: data.chunk.readUInt8() } };
    case 2:
	return { rcinfo: { protocol: data.chunk.readUInt8() } };
    case 3:
	return { rcinfo: { srcIp: hepIps.parse(data.chunk).ip.join('.') } };
    case 4:
	return { rcinfo: { dstIp: hepIps.parse(data.chunk).ip.join('.') } };
    case 5:
	return { rcinfo: { srcIp: formatIPv6(data.chunk) } };
    case 6:
	return { rcinfo: { dstIp: formatIPv6(data.chunk) } };
    case 7:
	return { rcinfo: { srcPort: data.chunk.readUInt16BE() } };
    case 8:
	return { rcinfo: { dstPort: data.chunk.readUInt16BE() } };
    case 9:
	return { rcinfo: { timeSeconds: data.chunk.readUInt32BE() } };
    case 10:
	return { rcinfo: { timeUseconds: data.chunk.readUInt32BE() } };
    case 11:
	return { rcinfo: { payloadType: data.chunk.readUInt8() } };
    case 12:
	return { rcinfo: { captureId: data.chunk.readUInt32BE() } };
    case 14:
	return { rcinfo: { capturePass: data.chunk.toString() } };
    case 15:
	return { payload: data.chunk.toString() };
    case 17:
        return { rcinfo: { correlation_id: data.chunk.toString() } };
    case 19:
	return { rcinfo: { hepNodeName: data.chunk.toString() } };
    case 32:
	return { rcinfo: { mos: data.chunk.readUInt16BE() } };
    case 36:
	return { rcinfo: { transaction_type: data.chunk.readUInt16BE() } };
    default:
	var returnData = {};
	if(typeof extensions[data.vendor] === 'object' &&
	   typeof extensions[data.vendor][data.type] === 'object' &&
	   typeof extensions[data.vendor][data.type].keyName) {
	    returnData.rcinfo = {};
	    var keyName = extensions[data.vendor][data.type].keyName;
	    var type = extensions[data.vendor][data.type].type;
	    if(typeof type === 'string') {
	      if(typeof data.chunk['read'+type] === 'function') {
		returnData.rcinfo[keyName] = data.chunk['read'+type]();
	      }
	      else if(typeof data.chunk['read'+type+"BE"] === 'function') {
		returnData.rcinfo[keyName] = data.chunk['read'+type+"BE"]();
	      }
	    }
	    else {
	      returnData.rcinfo[keyName] = data.chunk.toString();
	    }
	}
	return returnData;
  }
};

function deepMerge(o1,o2) {
 for (var k in o2) {
   if (typeof(o2[k])=='object') {
       if(!o1[k]) o1[k] = {};
       //console.log(merge(o1[k],o2[k]) );
       o1[k] = deepMerge(o1[k],o2[k]);
   } else { 
       o1[k] = o2[k];
   }
 }
 return o1;
}


/*
   Appendix A: HEP3 JSON Format (prototype)
*/

/*
var hepPacket = {
       "type": "HEP",
       "version": 3,
       "rcinfo": {
         "protocolFamily": 2,
         "protocol": 17,
         "srcIp": "192.168.3.12",
         "srcPort": 5060,
         "dstIp": "192.168.3.11",
         "dstPort": 5060,
         "timestamp": "2015-06-11T12:36:08:222Z",
         "timestampUSecs": 0,
         "captureId": 241,
	 "hepNodeName": "ams01-voip",
         "capturePass": "myHep",
         "payload_type": "SIP"
       },
       "payload": {
           "data": "INVITE sip:9999@homer SIP/2.0\r\n..."
       }
   };

*/
