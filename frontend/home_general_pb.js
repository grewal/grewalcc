// source: home_general.proto
/**
 * @fileoverview
 * @enhanceable
 * @suppress {missingRequire} reports error on implicit type usages.
 * @suppress {messageConventions} JS Compiler reports an error if a variable or
 *     field starts with 'MSG_' and isn't a translatable message.
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck

var jspb = require('google-protobuf');
var goog = jspb;
var global =
    (typeof globalThis !== 'undefined' && globalThis) ||
    (typeof window !== 'undefined' && window) ||
    (typeof global !== 'undefined' && global) ||
    (typeof self !== 'undefined' && self) ||
    (function () { return this; }).call(null) ||
    Function('return this')();

goog.exportSymbol('proto.grewal.HomeGeneralRequest', null, global);
goog.exportSymbol('proto.grewal.HomeGeneralResponse', null, global);
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.grewal.HomeGeneralRequest = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.grewal.HomeGeneralRequest, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.grewal.HomeGeneralRequest.displayName = 'proto.grewal.HomeGeneralRequest';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.grewal.HomeGeneralResponse = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.grewal.HomeGeneralResponse, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.grewal.HomeGeneralResponse.displayName = 'proto.grewal.HomeGeneralResponse';
}



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.grewal.HomeGeneralRequest.prototype.toObject = function(opt_includeInstance) {
  return proto.grewal.HomeGeneralRequest.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.grewal.HomeGeneralRequest} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.grewal.HomeGeneralRequest.toObject = function(includeInstance, msg) {
  var f, obj = {
httpHost: jspb.Message.getFieldWithDefault(msg, 1, ""),
remoteIp: jspb.Message.getFieldWithDefault(msg, 2, ""),
userAgent: jspb.Message.getFieldWithDefault(msg, 3, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.grewal.HomeGeneralRequest}
 */
proto.grewal.HomeGeneralRequest.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.grewal.HomeGeneralRequest;
  return proto.grewal.HomeGeneralRequest.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.grewal.HomeGeneralRequest} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.grewal.HomeGeneralRequest}
 */
proto.grewal.HomeGeneralRequest.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setHttpHost(value);
      break;
    case 2:
      var value = /** @type {string} */ (reader.readString());
      msg.setRemoteIp(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.setUserAgent(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.grewal.HomeGeneralRequest.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.grewal.HomeGeneralRequest.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.grewal.HomeGeneralRequest} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.grewal.HomeGeneralRequest.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHttpHost();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getRemoteIp();
  if (f.length > 0) {
    writer.writeString(
      2,
      f
    );
  }
  f = message.getUserAgent();
  if (f.length > 0) {
    writer.writeString(
      3,
      f
    );
  }
};


/**
 * optional string http_host = 1;
 * @return {string}
 */
proto.grewal.HomeGeneralRequest.prototype.getHttpHost = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.grewal.HomeGeneralRequest} returns this
 */
proto.grewal.HomeGeneralRequest.prototype.setHttpHost = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional string remote_ip = 2;
 * @return {string}
 */
proto.grewal.HomeGeneralRequest.prototype.getRemoteIp = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * @param {string} value
 * @return {!proto.grewal.HomeGeneralRequest} returns this
 */
proto.grewal.HomeGeneralRequest.prototype.setRemoteIp = function(value) {
  return jspb.Message.setProto3StringField(this, 2, value);
};


/**
 * optional string user_agent = 3;
 * @return {string}
 */
proto.grewal.HomeGeneralRequest.prototype.getUserAgent = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * @param {string} value
 * @return {!proto.grewal.HomeGeneralRequest} returns this
 */
proto.grewal.HomeGeneralRequest.prototype.setUserAgent = function(value) {
  return jspb.Message.setProto3StringField(this, 3, value);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.grewal.HomeGeneralResponse.prototype.toObject = function(opt_includeInstance) {
  return proto.grewal.HomeGeneralResponse.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.grewal.HomeGeneralResponse} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.grewal.HomeGeneralResponse.toObject = function(includeInstance, msg) {
  var f, obj = {
htmlOutput: jspb.Message.getFieldWithDefault(msg, 1, "")
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.grewal.HomeGeneralResponse}
 */
proto.grewal.HomeGeneralResponse.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.grewal.HomeGeneralResponse;
  return proto.grewal.HomeGeneralResponse.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.grewal.HomeGeneralResponse} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.grewal.HomeGeneralResponse}
 */
proto.grewal.HomeGeneralResponse.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setHtmlOutput(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.grewal.HomeGeneralResponse.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.grewal.HomeGeneralResponse.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.grewal.HomeGeneralResponse} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.grewal.HomeGeneralResponse.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getHtmlOutput();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
};


/**
 * optional string html_output = 1;
 * @return {string}
 */
proto.grewal.HomeGeneralResponse.prototype.getHtmlOutput = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * @param {string} value
 * @return {!proto.grewal.HomeGeneralResponse} returns this
 */
proto.grewal.HomeGeneralResponse.prototype.setHtmlOutput = function(value) {
  return jspb.Message.setProto3StringField(this, 1, value);
};


goog.object.extend(exports, proto.grewal);
