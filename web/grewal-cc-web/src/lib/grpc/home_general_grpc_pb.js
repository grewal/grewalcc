// GENERATED CODE -- DO NOT EDIT!

// Original file comments:
// File: services/grewalcc/home_general.proto (Final, Lean Version)
//
// Standard syntax declaration
'use strict';
var grpc = require('@grpc/grpc-js');
var home_general_pb = require('./home_general_pb.js');

function serialize_grewal_GeneralRequest(arg) {
  if (!(arg instanceof home_general_pb.GeneralRequest)) {
    throw new Error('Expected argument of type grewal.GeneralRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_grewal_GeneralRequest(buffer_arg) {
  return home_general_pb.GeneralRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_grewal_GeneralResponse(arg) {
  if (!(arg instanceof home_general_pb.GeneralResponse)) {
    throw new Error('Expected argument of type grewal.GeneralResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_grewal_GeneralResponse(buffer_arg) {
  return home_general_pb.GeneralResponse.deserializeBinary(new Uint8Array(buffer_arg));
}


var HomeGeneralService = exports.HomeGeneralService = {
  // Defines a single Remote Procedure Call (RPC) named GetHomeGeneral.
// For a call this function, a client MUST send a
// `GeneralRequest` message and can EXPECT to receive a
// `GeneralResponse` message in return. This is the API contract.
getHomeGeneral: {
    path: '/grewal.HomeGeneral/GetHomeGeneral',
    requestStream: false,
    responseStream: false,
    requestType: home_general_pb.GeneralRequest,
    responseType: home_general_pb.GeneralResponse,
    requestSerialize: serialize_grewal_GeneralRequest,
    requestDeserialize: deserialize_grewal_GeneralRequest,
    responseSerialize: serialize_grewal_GeneralResponse,
    responseDeserialize: deserialize_grewal_GeneralResponse,
  },
};

exports.HomeGeneralClient = grpc.makeGenericClientConstructor(HomeGeneralService, 'HomeGeneral');
