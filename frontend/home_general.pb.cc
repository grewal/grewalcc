// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: home_general.proto

#include "home_general.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

namespace grewal {
PROTOBUF_CONSTEXPR HomeGeneralRequest::HomeGeneralRequest(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.http_host_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.remote_ip_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.user_agent_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct HomeGeneralRequestDefaultTypeInternal {
  PROTOBUF_CONSTEXPR HomeGeneralRequestDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~HomeGeneralRequestDefaultTypeInternal() {}
  union {
    HomeGeneralRequest _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 HomeGeneralRequestDefaultTypeInternal _HomeGeneralRequest_default_instance_;
PROTOBUF_CONSTEXPR HomeGeneralResponse::HomeGeneralResponse(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.html_output_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct HomeGeneralResponseDefaultTypeInternal {
  PROTOBUF_CONSTEXPR HomeGeneralResponseDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~HomeGeneralResponseDefaultTypeInternal() {}
  union {
    HomeGeneralResponse _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 HomeGeneralResponseDefaultTypeInternal _HomeGeneralResponse_default_instance_;
}  // namespace grewal
static ::_pb::Metadata file_level_metadata_home_5fgeneral_2eproto[2];
static constexpr ::_pb::EnumDescriptor const** file_level_enum_descriptors_home_5fgeneral_2eproto = nullptr;
static constexpr ::_pb::ServiceDescriptor const** file_level_service_descriptors_home_5fgeneral_2eproto = nullptr;

const uint32_t TableStruct_home_5fgeneral_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::grewal::HomeGeneralRequest, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::grewal::HomeGeneralRequest, _impl_.http_host_),
  PROTOBUF_FIELD_OFFSET(::grewal::HomeGeneralRequest, _impl_.remote_ip_),
  PROTOBUF_FIELD_OFFSET(::grewal::HomeGeneralRequest, _impl_.user_agent_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::grewal::HomeGeneralResponse, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::grewal::HomeGeneralResponse, _impl_.html_output_),
};
static const ::_pbi::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::grewal::HomeGeneralRequest)},
  { 9, -1, -1, sizeof(::grewal::HomeGeneralResponse)},
};

static const ::_pb::Message* const file_default_instances[] = {
  &::grewal::_HomeGeneralRequest_default_instance_._instance,
  &::grewal::_HomeGeneralResponse_default_instance_._instance,
};

const char descriptor_table_protodef_home_5fgeneral_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\022home_general.proto\022\006grewal\"N\n\022HomeGene"
  "ralRequest\022\021\n\thttp_host\030\001 \001(\t\022\021\n\tremote_"
  "ip\030\002 \001(\t\022\022\n\nuser_agent\030\003 \001(\t\"*\n\023HomeGene"
  "ralResponse\022\023\n\013html_output\030\001 \001(\t2X\n\013Home"
  "General\022I\n\016GetHomeGeneral\022\032.grewal.HomeG"
  "eneralRequest\032\033.grewal.HomeGeneralRespon"
  "seb\006proto3"
  ;
static ::_pbi::once_flag descriptor_table_home_5fgeneral_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_home_5fgeneral_2eproto = {
    false, false, 250, descriptor_table_protodef_home_5fgeneral_2eproto,
    "home_general.proto",
    &descriptor_table_home_5fgeneral_2eproto_once, nullptr, 0, 2,
    schemas, file_default_instances, TableStruct_home_5fgeneral_2eproto::offsets,
    file_level_metadata_home_5fgeneral_2eproto, file_level_enum_descriptors_home_5fgeneral_2eproto,
    file_level_service_descriptors_home_5fgeneral_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_home_5fgeneral_2eproto_getter() {
  return &descriptor_table_home_5fgeneral_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2 static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_home_5fgeneral_2eproto(&descriptor_table_home_5fgeneral_2eproto);
namespace grewal {

// ===================================================================

class HomeGeneralRequest::_Internal {
 public:
};

HomeGeneralRequest::HomeGeneralRequest(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:grewal.HomeGeneralRequest)
}
HomeGeneralRequest::HomeGeneralRequest(const HomeGeneralRequest& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  HomeGeneralRequest* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.http_host_){}
    , decltype(_impl_.remote_ip_){}
    , decltype(_impl_.user_agent_){}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.http_host_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.http_host_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_http_host().empty()) {
    _this->_impl_.http_host_.Set(from._internal_http_host(), 
      _this->GetArenaForAllocation());
  }
  _impl_.remote_ip_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.remote_ip_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_remote_ip().empty()) {
    _this->_impl_.remote_ip_.Set(from._internal_remote_ip(), 
      _this->GetArenaForAllocation());
  }
  _impl_.user_agent_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.user_agent_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_user_agent().empty()) {
    _this->_impl_.user_agent_.Set(from._internal_user_agent(), 
      _this->GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:grewal.HomeGeneralRequest)
}

inline void HomeGeneralRequest::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.http_host_){}
    , decltype(_impl_.remote_ip_){}
    , decltype(_impl_.user_agent_){}
    , /*decltype(_impl_._cached_size_)*/{}
  };
  _impl_.http_host_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.http_host_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.remote_ip_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.remote_ip_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.user_agent_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.user_agent_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

HomeGeneralRequest::~HomeGeneralRequest() {
  // @@protoc_insertion_point(destructor:grewal.HomeGeneralRequest)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void HomeGeneralRequest::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.http_host_.Destroy();
  _impl_.remote_ip_.Destroy();
  _impl_.user_agent_.Destroy();
}

void HomeGeneralRequest::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void HomeGeneralRequest::Clear() {
// @@protoc_insertion_point(message_clear_start:grewal.HomeGeneralRequest)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.http_host_.ClearToEmpty();
  _impl_.remote_ip_.ClearToEmpty();
  _impl_.user_agent_.ClearToEmpty();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* HomeGeneralRequest::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // string http_host = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_http_host();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "grewal.HomeGeneralRequest.http_host"));
        } else
          goto handle_unusual;
        continue;
      // string remote_ip = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_remote_ip();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "grewal.HomeGeneralRequest.remote_ip"));
        } else
          goto handle_unusual;
        continue;
      // string user_agent = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 26)) {
          auto str = _internal_mutable_user_agent();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "grewal.HomeGeneralRequest.user_agent"));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* HomeGeneralRequest::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:grewal.HomeGeneralRequest)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // string http_host = 1;
  if (!this->_internal_http_host().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_http_host().data(), static_cast<int>(this->_internal_http_host().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "grewal.HomeGeneralRequest.http_host");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_http_host(), target);
  }

  // string remote_ip = 2;
  if (!this->_internal_remote_ip().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_remote_ip().data(), static_cast<int>(this->_internal_remote_ip().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "grewal.HomeGeneralRequest.remote_ip");
    target = stream->WriteStringMaybeAliased(
        2, this->_internal_remote_ip(), target);
  }

  // string user_agent = 3;
  if (!this->_internal_user_agent().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_user_agent().data(), static_cast<int>(this->_internal_user_agent().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "grewal.HomeGeneralRequest.user_agent");
    target = stream->WriteStringMaybeAliased(
        3, this->_internal_user_agent(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:grewal.HomeGeneralRequest)
  return target;
}

size_t HomeGeneralRequest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:grewal.HomeGeneralRequest)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string http_host = 1;
  if (!this->_internal_http_host().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_http_host());
  }

  // string remote_ip = 2;
  if (!this->_internal_remote_ip().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_remote_ip());
  }

  // string user_agent = 3;
  if (!this->_internal_user_agent().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_user_agent());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData HomeGeneralRequest::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    HomeGeneralRequest::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*HomeGeneralRequest::GetClassData() const { return &_class_data_; }


void HomeGeneralRequest::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<HomeGeneralRequest*>(&to_msg);
  auto& from = static_cast<const HomeGeneralRequest&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:grewal.HomeGeneralRequest)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_http_host().empty()) {
    _this->_internal_set_http_host(from._internal_http_host());
  }
  if (!from._internal_remote_ip().empty()) {
    _this->_internal_set_remote_ip(from._internal_remote_ip());
  }
  if (!from._internal_user_agent().empty()) {
    _this->_internal_set_user_agent(from._internal_user_agent());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void HomeGeneralRequest::CopyFrom(const HomeGeneralRequest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:grewal.HomeGeneralRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool HomeGeneralRequest::IsInitialized() const {
  return true;
}

void HomeGeneralRequest::InternalSwap(HomeGeneralRequest* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.http_host_, lhs_arena,
      &other->_impl_.http_host_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.remote_ip_, lhs_arena,
      &other->_impl_.remote_ip_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.user_agent_, lhs_arena,
      &other->_impl_.user_agent_, rhs_arena
  );
}

::PROTOBUF_NAMESPACE_ID::Metadata HomeGeneralRequest::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_home_5fgeneral_2eproto_getter, &descriptor_table_home_5fgeneral_2eproto_once,
      file_level_metadata_home_5fgeneral_2eproto[0]);
}

// ===================================================================

class HomeGeneralResponse::_Internal {
 public:
};

HomeGeneralResponse::HomeGeneralResponse(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:grewal.HomeGeneralResponse)
}
HomeGeneralResponse::HomeGeneralResponse(const HomeGeneralResponse& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  HomeGeneralResponse* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.html_output_){}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.html_output_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.html_output_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_html_output().empty()) {
    _this->_impl_.html_output_.Set(from._internal_html_output(), 
      _this->GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:grewal.HomeGeneralResponse)
}

inline void HomeGeneralResponse::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.html_output_){}
    , /*decltype(_impl_._cached_size_)*/{}
  };
  _impl_.html_output_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.html_output_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

HomeGeneralResponse::~HomeGeneralResponse() {
  // @@protoc_insertion_point(destructor:grewal.HomeGeneralResponse)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void HomeGeneralResponse::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.html_output_.Destroy();
}

void HomeGeneralResponse::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void HomeGeneralResponse::Clear() {
// @@protoc_insertion_point(message_clear_start:grewal.HomeGeneralResponse)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.html_output_.ClearToEmpty();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* HomeGeneralResponse::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // string html_output = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_html_output();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "grewal.HomeGeneralResponse.html_output"));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* HomeGeneralResponse::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:grewal.HomeGeneralResponse)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // string html_output = 1;
  if (!this->_internal_html_output().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_html_output().data(), static_cast<int>(this->_internal_html_output().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "grewal.HomeGeneralResponse.html_output");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_html_output(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:grewal.HomeGeneralResponse)
  return target;
}

size_t HomeGeneralResponse::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:grewal.HomeGeneralResponse)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string html_output = 1;
  if (!this->_internal_html_output().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_html_output());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData HomeGeneralResponse::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    HomeGeneralResponse::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*HomeGeneralResponse::GetClassData() const { return &_class_data_; }


void HomeGeneralResponse::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<HomeGeneralResponse*>(&to_msg);
  auto& from = static_cast<const HomeGeneralResponse&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:grewal.HomeGeneralResponse)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_html_output().empty()) {
    _this->_internal_set_html_output(from._internal_html_output());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void HomeGeneralResponse::CopyFrom(const HomeGeneralResponse& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:grewal.HomeGeneralResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool HomeGeneralResponse::IsInitialized() const {
  return true;
}

void HomeGeneralResponse::InternalSwap(HomeGeneralResponse* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.html_output_, lhs_arena,
      &other->_impl_.html_output_, rhs_arena
  );
}

::PROTOBUF_NAMESPACE_ID::Metadata HomeGeneralResponse::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_home_5fgeneral_2eproto_getter, &descriptor_table_home_5fgeneral_2eproto_once,
      file_level_metadata_home_5fgeneral_2eproto[1]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace grewal
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::grewal::HomeGeneralRequest*
Arena::CreateMaybeMessage< ::grewal::HomeGeneralRequest >(Arena* arena) {
  return Arena::CreateMessageInternal< ::grewal::HomeGeneralRequest >(arena);
}
template<> PROTOBUF_NOINLINE ::grewal::HomeGeneralResponse*
Arena::CreateMaybeMessage< ::grewal::HomeGeneralResponse >(Arena* arena) {
  return Arena::CreateMessageInternal< ::grewal::HomeGeneralResponse >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
