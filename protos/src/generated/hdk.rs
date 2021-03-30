// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

// This file is generated by rust-protobuf 2.22.1. Do not edit
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `solution/ktb/hdk.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
// const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_22_1;

#[derive(PartialEq,Clone,Default)]
pub struct HdkResult {
    // message fields
    pub mnemonic: ::std::string::String,
    pub master_key: ::std::vec::Vec<u8>,
    pub key_pair: ::protobuf::SingularPtrField<ExtendedKeyPair>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a HdkResult {
    fn default() -> &'a HdkResult {
        <HdkResult as ::protobuf::Message>::default_instance()
    }
}

impl HdkResult {
    pub fn new() -> HdkResult {
        ::std::default::Default::default()
    }

    // string mnemonic = 1;


    pub fn get_mnemonic(&self) -> &str {
        &self.mnemonic
    }
    pub fn clear_mnemonic(&mut self) {
        self.mnemonic.clear();
    }

    // Param is passed by value, moved
    pub fn set_mnemonic(&mut self, v: ::std::string::String) {
        self.mnemonic = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_mnemonic(&mut self) -> &mut ::std::string::String {
        &mut self.mnemonic
    }

    // Take field
    pub fn take_mnemonic(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.mnemonic, ::std::string::String::new())
    }

    // bytes master_key = 2;


    pub fn get_master_key(&self) -> &[u8] {
        &self.master_key
    }
    pub fn clear_master_key(&mut self) {
        self.master_key.clear();
    }

    // Param is passed by value, moved
    pub fn set_master_key(&mut self, v: ::std::vec::Vec<u8>) {
        self.master_key = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_master_key(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.master_key
    }

    // Take field
    pub fn take_master_key(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.master_key, ::std::vec::Vec::new())
    }

    // .com.webank.wedpr.scd.proto.ExtendedKeyPair key_pair = 3;


    pub fn get_key_pair(&self) -> &ExtendedKeyPair {
        self.key_pair.as_ref().unwrap_or_else(|| <ExtendedKeyPair as ::protobuf::Message>::default_instance())
    }
    pub fn clear_key_pair(&mut self) {
        self.key_pair.clear();
    }

    pub fn has_key_pair(&self) -> bool {
        self.key_pair.is_some()
    }

    // Param is passed by value, moved
    pub fn set_key_pair(&mut self, v: ExtendedKeyPair) {
        self.key_pair = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_key_pair(&mut self) -> &mut ExtendedKeyPair {
        if self.key_pair.is_none() {
            self.key_pair.set_default();
        }
        self.key_pair.as_mut().unwrap()
    }

    // Take field
    pub fn take_key_pair(&mut self) -> ExtendedKeyPair {
        self.key_pair.take().unwrap_or_else(|| ExtendedKeyPair::new())
    }
}

impl ::protobuf::Message for HdkResult {
    fn is_initialized(&self) -> bool {
        for v in &self.key_pair {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.mnemonic)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.master_key)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.key_pair)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.mnemonic.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.mnemonic);
        }
        if !self.master_key.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.master_key);
        }
        if let Some(ref v) = self.key_pair.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.mnemonic.is_empty() {
            os.write_string(1, &self.mnemonic)?;
        }
        if !self.master_key.is_empty() {
            os.write_bytes(2, &self.master_key)?;
        }
        if let Some(ref v) = self.key_pair.as_ref() {
            os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> HdkResult {
        HdkResult::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "mnemonic",
                |m: &HdkResult| { &m.mnemonic },
                |m: &mut HdkResult| { &mut m.mnemonic },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "master_key",
                |m: &HdkResult| { &m.master_key },
                |m: &mut HdkResult| { &mut m.master_key },
            ));
            fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<ExtendedKeyPair>>(
                "key_pair",
                |m: &HdkResult| { &m.key_pair },
                |m: &mut HdkResult| { &mut m.key_pair },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<HdkResult>(
                "HdkResult",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static HdkResult {
        static instance: ::protobuf::rt::LazyV2<HdkResult> = ::protobuf::rt::LazyV2::INIT;
        instance.get(HdkResult::new)
    }
}

impl ::protobuf::Clear for HdkResult {
    fn clear(&mut self) {
        self.mnemonic.clear();
        self.master_key.clear();
        self.key_pair.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for HdkResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for HdkResult {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ExtendedKeyPair {
    // message fields
    pub extended_private_key: ::std::vec::Vec<u8>,
    pub extended_public_key: ::std::vec::Vec<u8>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a ExtendedKeyPair {
    fn default() -> &'a ExtendedKeyPair {
        <ExtendedKeyPair as ::protobuf::Message>::default_instance()
    }
}

impl ExtendedKeyPair {
    pub fn new() -> ExtendedKeyPair {
        ::std::default::Default::default()
    }

    // bytes extended_private_key = 1;


    pub fn get_extended_private_key(&self) -> &[u8] {
        &self.extended_private_key
    }
    pub fn clear_extended_private_key(&mut self) {
        self.extended_private_key.clear();
    }

    // Param is passed by value, moved
    pub fn set_extended_private_key(&mut self, v: ::std::vec::Vec<u8>) {
        self.extended_private_key = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_extended_private_key(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.extended_private_key
    }

    // Take field
    pub fn take_extended_private_key(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.extended_private_key, ::std::vec::Vec::new())
    }

    // bytes extended_public_key = 2;


    pub fn get_extended_public_key(&self) -> &[u8] {
        &self.extended_public_key
    }
    pub fn clear_extended_public_key(&mut self) {
        self.extended_public_key.clear();
    }

    // Param is passed by value, moved
    pub fn set_extended_public_key(&mut self, v: ::std::vec::Vec<u8>) {
        self.extended_public_key = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_extended_public_key(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.extended_public_key
    }

    // Take field
    pub fn take_extended_public_key(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.extended_public_key, ::std::vec::Vec::new())
    }
}

impl ::protobuf::Message for ExtendedKeyPair {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.extended_private_key)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.extended_public_key)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.extended_private_key.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.extended_private_key);
        }
        if !self.extended_public_key.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.extended_public_key);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.extended_private_key.is_empty() {
            os.write_bytes(1, &self.extended_private_key)?;
        }
        if !self.extended_public_key.is_empty() {
            os.write_bytes(2, &self.extended_public_key)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> ExtendedKeyPair {
        ExtendedKeyPair::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "extended_private_key",
                |m: &ExtendedKeyPair| { &m.extended_private_key },
                |m: &mut ExtendedKeyPair| { &mut m.extended_private_key },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "extended_public_key",
                |m: &ExtendedKeyPair| { &m.extended_public_key },
                |m: &mut ExtendedKeyPair| { &mut m.extended_public_key },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<ExtendedKeyPair>(
                "ExtendedKeyPair",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static ExtendedKeyPair {
        static instance: ::protobuf::rt::LazyV2<ExtendedKeyPair> = ::protobuf::rt::LazyV2::INIT;
        instance.get(ExtendedKeyPair::new)
    }
}

impl ::protobuf::Clear for ExtendedKeyPair {
    fn clear(&mut self) {
        self.extended_private_key.clear();
        self.extended_public_key.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ExtendedKeyPair {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExtendedKeyPair {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x16solution/ktb/hdk.proto\x12\x1acom.webank.wedpr.scd.proto\"\x8e\x01\
    \n\tHdkResult\x12\x1a\n\x08mnemonic\x18\x01\x20\x01(\tR\x08mnemonic\x12\
    \x1d\n\nmaster_key\x18\x02\x20\x01(\x0cR\tmasterKey\x12F\n\x08key_pair\
    \x18\x03\x20\x01(\x0b2+.com.webank.wedpr.scd.proto.ExtendedKeyPairR\x07k\
    eyPair\"s\n\x0fExtendedKeyPair\x120\n\x14extended_private_key\x18\x01\
    \x20\x01(\x0cR\x12extendedPrivateKey\x12.\n\x13extended_public_key\x18\
    \x02\x20\x01(\x0cR\x11extendedPublicKeyB\x1e\n\x1acom.webank.wedpr.ktb.p\
    rotoP\x01b\x06proto3\
";

static file_descriptor_proto_lazy: ::protobuf::rt::LazyV2<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::LazyV2::INIT;

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    file_descriptor_proto_lazy.get(|| {
        parse_descriptor_proto()
    })
}
