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

const debug = false;

// Module import
const Parser = require("binary-parser").Parser;
const mixinDeep = require("mixin-deep");
const assert = require("assert");
const ip = require("ip");

let extensions = {};

module.exports = {
	/**
	 * Decode HEP3 Packet to JSON Object.
	 *
	 * @param  {Buffer} hep message
	 * @return {Object}
	 */
	decapsulate: function (message) {
		if (debug) console.log('Decoding HEP3 Packet...');
		try {
			let HEP = hepHeader.parse(message);
			if (HEP.payload && HEP.payload.length > 0) {
				let data = HEP.payload;
				let tot = 0;
				let decoded = {};
				let PAYLOAD;
				while (true) {
					PAYLOAD = hepParse.parse(data.subarray(tot));
					let tmp = hepDecode(PAYLOAD);
					decoded = mixinDeep(decoded, tmp);
					tot += PAYLOAD.length;
					if (tot >= HEP.payload.length) { break; }
				}
				if (debug) console.log(decoded);
				return decoded;
			}
		} catch (e) {
			return false;
		}

	},
	/**
	 * Encode HEP3 Packet from JSON Object.
	 *
	 * @param  {String} sip_msg
	 * @param  {String} hep_json
	 * @return {Buffer} hep message
	 */
	encapsulate: function (msg, rcinfo) {
		if (debug) console.log('Sending HEP3 Packet...');
		let header = Buffer.allocUnsafe(6);
		header.write("HEP3");

		let ip_family = Buffer.allocUnsafe(7);
		ip_family.writeUInt16BE(0x0000, 0);
		ip_family.writeUInt16BE(0x0001, 2);
		ip_family.writeUInt8(rcinfo.protocolFamily, 6);
		ip_family.writeUInt16BE(ip_family.length, 4);

		let ip_proto = Buffer.allocUnsafe(7);
		ip_proto.writeUInt16BE(0x0000, 0);
		ip_proto.writeUInt16BE(0x0002, 2);
		ip_proto.writeUInt8(rcinfo.protocol, 6);
		ip_proto.writeUInt16BE(ip_proto.length, 4);

		/*ip*/
		let src_ip = Buffer.allocUnsafe(rcinfo.protocolFamily == 10 ? 22 : 10);
		src_ip.writeUInt16BE(0x0000, 0);
		src_ip.writeUInt16BE(rcinfo.protocolFamily == 10 ? 0x0005 : 0x0003, 2);
		ip.toBuffer(rcinfo.srcIp).copy(src_ip, 6);
		src_ip.writeUInt16BE(src_ip.length, 4);

		let dst_ip = Buffer.allocUnsafe(rcinfo.protocolFamily == 10 ? 22 : 10);
		dst_ip.writeUInt16BE(0x0000, 0);
		dst_ip.writeUInt16BE(rcinfo.protocolFamily == 10 ? 0x0006 : 0x0004, 2);
		ip.toBuffer(rcinfo.dstIp).copy(dst_ip, 6);
		dst_ip.writeUInt16BE(dst_ip.length, 4);

		/*port*/
		let src_port = Buffer.allocUnsafe(8);
		let tmpA = rcinfo.srcPort ? parseInt(rcinfo.srcPort, 10) : 0;
		src_port.writeUInt16BE(0x0000, 0);
		src_port.writeUInt16BE(0x0007, 2);
		src_port.writeUInt16BE(tmpA, 6);
		src_port.writeUInt16BE(src_port.length, 4);

		let dst_port = Buffer.allocUnsafe(8);
		tmpA = rcinfo.dstPort ? parseInt(rcinfo.dstPort, 10) : 0;
		dst_port.writeUInt16BE(0x0000, 0);
		dst_port.writeUInt16BE(0x0008, 2);
		dst_port.writeUInt16BE(tmpA, 6);
		dst_port.writeUInt16BE(dst_port.length, 4);

		tmpA = ToUint32(rcinfo.timeSeconds);
		let time_sec = Buffer.allocUnsafe(10);
		time_sec.writeUInt16BE(0x0000, 0);
		time_sec.writeUInt16BE(0x0009, 2);
		time_sec.writeUInt32BE(tmpA, 6);
		time_sec.writeUInt16BE(time_sec.length, 4);

		tmpA = ToUint32(rcinfo.timeUseconds);
		let time_usec = Buffer.allocUnsafe(10);
		time_usec.writeUInt16BE(0x0000, 0);
		time_usec.writeUInt16BE(0x000a, 2);
		time_usec.writeUInt32BE(tmpA, 6);
		time_usec.writeUInt16BE(time_usec.length, 4);

		let proto_type = Buffer.allocUnsafe(7);
		proto_type.writeUInt16BE(0x0000, 0);
		proto_type.writeUInt16BE(0x000b, 2);
		proto_type.writeUInt8(rcinfo.payloadType, 6);
		proto_type.writeUInt16BE(proto_type.length, 4);

		tmpA = ToUint32(rcinfo.captureId);
		let capt_id = Buffer.allocUnsafe(10);
		capt_id.writeUInt16BE(0x0000, 0);
		capt_id.writeUInt16BE(0x000c, 2);
		capt_id.writeUInt32BE(tmpA, 6);
		capt_id.writeUInt16BE(capt_id.length, 4);

		// HEPNodeName w/ Fallback to HEP Capture ID
		tmpA = rcinfo.hepNodeName ? rcinfo.hepNodeName : "" + rcinfo.captureId;
		let hepnodename_chunk = Buffer.allocUnsafe(6 + tmpA.length);
		hepnodename_chunk.writeUInt16BE(0x0000, 0);
		hepnodename_chunk.writeUInt16BE(0x0013, 2);
		hepnodename_chunk.write(tmpA, 6, tmpA.length);
		hepnodename_chunk.writeUInt16BE(hepnodename_chunk.length, 4);

		let auth_chunk;
		if (typeof rcinfo.capturePass === 'string') {
			auth_chunk = Buffer.allocUnsafe(6 + rcinfo.capturePass.length);
			auth_chunk.writeUInt16BE(0x0000, 0);
			auth_chunk.writeUInt16BE(0x000e, 2);
			auth_chunk.write(rcinfo.capturePass, 6, rcinfo.capturePass.length);
			auth_chunk.writeUInt16BE(auth_chunk.length, 4);
		}
		else {
			auth_chunk = Buffer.allocUnsafe(0);
		}

		let payload_chunk = Buffer.allocUnsafe(6 + msg.length);
		payload_chunk.writeUInt16BE(0x0000, 0);
		payload_chunk.writeUInt16BE(0x000f, 2);
		payload_chunk.write(msg, 6, msg.length);
		payload_chunk.writeUInt16BE(payload_chunk.length, 4);

		let extensions_chunk = Buffer.allocUnsafe(0);
		for (let i in extensions) {
			for (let j in extensions[i]) {
				let extdef = extensions[i][j];
				if (typeof extdef === "object" &&
					typeof extdef.keyName === "string" &&
					typeof rcinfo[extdef.keyName] !== 'undefined') {
					let this_chunk;
					let data = rcinfo[extdef.keyName];
					let failed = true;
					if (/\d{1,}/.test(extdef.type)) {
						const bitLength = extdef.type.match(/\d{1,}/)[0];
						const size = Math.floor(bitLength / 8) + 6;
						this_chunk = Buffer.allocUnsafe(size);
						this_chunk.writeUInt16BE(i, 0);
						this_chunk.writeUInt16BE(j, 2);
						if (typeof this_chunk["write" + extdef.type] === 'function') {
							this_chunk['write' + extdef.type](data, 6);
							failed = false;
						}
						else if (typeof this_chunk["write" + extdef.type + "BE"] === 'function') {
							this_chunk['write' + extdef.type + "BE"](data, 6);
							failed = false;
						}
						this_chunk.writeUInt16BE(this_chunk.length, 4);
					}
					else if (/string$/.test(extdef.type) || extdef.type === undefined) {
						this_chunk = Buffer.allocUnsafe(6 + data.length);
						this_chunk.writeUInt16BE(i, 0);
						this_chunk.writeUInt16BE(j, 2);
						this_chunk.write(data, 6, data.length);
						this_chunk.writeUInt16BE(this_chunk.length, 4);
						failed = false;
					}
					if (typeof this_chunk !== 'undefined' && !failed) {
						extensions_chunk = Buffer.concat([extensions_chunk, this_chunk]);
					}
				}
			}
		}

		let hep_message, correlation_chunk;

		if ((rcinfo.proto_type == 32 || rcinfo.proto_type == 35) && rcinfo.correlation_id.length) {

			// create correlation chunk
			correlation_chunk = Buffer.allocUnsafe(6 + rcinfo.correlation_id.length);
			correlation_chunk.writeUInt16BE(0x0000, 0);
			correlation_chunk.writeUInt16BE(0x0011, 2);
			correlation_chunk.write(rcinfo.correlation_id, 6, rcinfo.correlation_id.length);
			correlation_chunk.writeUInt16BE(correlation_chunk.length, 4);

			tmpA = ToUint16(rcinfo.mos);
			let mos = Buffer.allocUnsafe(8);
			mos.writeUInt16BE(0x0000, 0);
			mos.writeUInt16BE(0x0020, 2);
			mos.writeUInt16BE(tmpA, 6);
			mos.writeUInt16BE(mos.length, 4);

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
			correlation_chunk = Buffer.allocUnsafe(6 + rcinfo.correlation_id.length);
			correlation_chunk.writeUInt16BE(0x0000, 0);
			correlation_chunk.writeUInt16BE(0x0011, 2);
			correlation_chunk.write(rcinfo.correlation_id, 6, rcinfo.correlation_id.length);
			correlation_chunk.writeUInt16BE(correlation_chunk.length, 4);

			// create transaction_type chunk
			var transaction_type = Buffer.allocUnsafe(6 + rcinfo.transaction_type.length);
			transaction_type.writeUInt16BE(0x0000, 0);
			transaction_type.writeUInt16BE(0x0024, 2);
			transaction_type.write(rcinfo.transaction_type, 6, rcinfo.transaction_type.length);
			transaction_type.writeUInt16BE(transaction_type.length, 4);

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
			correlation_chunk = Buffer.allocUnsafe(6 + rcinfo.correlation_id.length);
			correlation_chunk.writeUInt16BE(0x0000, 0);
			correlation_chunk.writeUInt16BE(0x0011, 2);
			correlation_chunk.write(rcinfo.correlation_id, 6, rcinfo.correlation_id.length);
			correlation_chunk.writeUInt16BE(correlation_chunk.length, 4);

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

	encode: function (json) {
		return String(json)
			.toString("binary");
	},

	decode: function (hep) {
		return String(hep)
			.toString('utf8');
	},

	addVendorExtensions: function (json) {
		extensions = mixinDeep(extensions, json);
	}
};


/* Functions */

const modulo = function (a, b) {
	return a - Math.floor(a / b) * b;
};

const ToUint32 = function (x) {
	return modulo(ToInteger(x), Math.pow(2, 32));
};

const ToUint16 = function (x) {
	return modulo(ToInteger(x), Math.pow(2, 16));
};

const ToInteger = function (x) {
	x = Number(x);
	return x < 0 ? Math.ceil(x) : Math.floor(x);
};

// Build an IP packet header Parser
const hepHeader = new Parser()
	.endianess("big")
	.string("hep", { length: 4, stripNull: true, assert: "HEP3" })
	.uint16("hepLength")
	.buffer("payload", { length: function () { return this.hepLength - 6; } }); // Length of HepMessage is defined including the 6 Byte Header

const hepParse = new Parser()
	.endianess("big")
	.uint16("vendor")
	.uint16("type")
	.uint16("length")
	.buffer("chunk", { length: function () { return this.length - 6; } }); // Length of Chunk is defined including the 6 Byte header

const hepDecode = function (data) {
	switch (data.type) {
		case 1:
			return { rcinfo: { protocolFamily: data.chunk.readUInt8() } };
		case 2:
			return { rcinfo: { protocol: data.chunk.readUInt8() } };
		case 3:
			return { rcinfo: { srcIp: ip.toString(data.chunk) } };
		case 4:
			return { rcinfo: { dstIp: ip.toString(data.chunk) } };
		case 5:
			return { rcinfo: { srcIp: ip.toString(data.chunk) } };
		case 6:
			return { rcinfo: { dstIp: ip.toString(data.chunk) } };
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
			if (typeof extensions[data.vendor] === 'object' &&
				typeof extensions[data.vendor][data.type] === 'object' &&
				typeof extensions[data.vendor][data.type].keyName) {
				returnData.rcinfo = {};
				const keyName = extensions[data.vendor][data.type].keyName;
				const type = extensions[data.vendor][data.type].type;
				if (typeof type === 'string') {
					if (typeof data.chunk['read' + type] === 'function') {
						returnData.rcinfo[keyName] = data.chunk['read' + type]();
					}
					else if (typeof data.chunk['read' + type + "BE"] === 'function') {
						returnData.rcinfo[keyName] = data.chunk['read' + type + "BE"]();
					}
				}
				else {
					returnData.rcinfo[keyName] = data.chunk.toString();
				}
			}
			return returnData;
	}
};