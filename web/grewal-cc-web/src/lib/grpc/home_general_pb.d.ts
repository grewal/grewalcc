// package: grewal
// file: home_general.proto

import * as jspb from "google-protobuf";

export class GeneralRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GeneralRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GeneralRequest): GeneralRequest.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: GeneralRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GeneralRequest;
  static deserializeBinaryFromReader(message: GeneralRequest, reader: jspb.BinaryReader): GeneralRequest;
}

export namespace GeneralRequest {
  export type AsObject = {
  }
}

export class GeneralResponse extends jspb.Message {
  getRemoteIp(): string;
  setRemoteIp(value: string): void;

  getUserAgent(): string;
  setUserAgent(value: string): void;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GeneralResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GeneralResponse): GeneralResponse.AsObject;
  static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
  static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
  static serializeBinaryToWriter(message: GeneralResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GeneralResponse;
  static deserializeBinaryFromReader(message: GeneralResponse, reader: jspb.BinaryReader): GeneralResponse;
}

export namespace GeneralResponse {
  export type AsObject = {
    remoteIp: string,
    userAgent: string,
  }
}

