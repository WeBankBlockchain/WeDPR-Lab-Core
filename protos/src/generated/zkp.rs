// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

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
//! Generated file from `crypto/zkp.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
// const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_22_1;

#[derive(PartialEq,Clone,Default)]
pub struct PBBalanceProof {
    // message fields
    pub t1: ::std::vec::Vec<u8>,
    pub t2: ::std::vec::Vec<u8>,
    pub t3: ::std::vec::Vec<u8>,
    pub m1: ::std::vec::Vec<u8>,
    pub m2: ::std::vec::Vec<u8>,
    pub m3: ::std::vec::Vec<u8>,
    pub m4: ::std::vec::Vec<u8>,
    pub m5: ::std::vec::Vec<u8>,
    pub m6: ::std::vec::Vec<u8>,
    pub check1: ::std::vec::Vec<u8>,
    pub check2: ::std::vec::Vec<u8>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a PBBalanceProof {
    fn default() -> &'a PBBalanceProof {
        <PBBalanceProof as ::protobuf::Message>::default_instance()
    }
}

impl PBBalanceProof {
    pub fn new() -> PBBalanceProof {
        ::std::default::Default::default()
    }

    // bytes t1 = 1;


    pub fn get_t1(&self) -> &[u8] {
        &self.t1
    }
    pub fn clear_t1(&mut self) {
        self.t1.clear();
    }

    // Param is passed by value, moved
    pub fn set_t1(&mut self, v: ::std::vec::Vec<u8>) {
        self.t1 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_t1(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.t1
    }

    // Take field
    pub fn take_t1(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.t1, ::std::vec::Vec::new())
    }

    // bytes t2 = 2;


    pub fn get_t2(&self) -> &[u8] {
        &self.t2
    }
    pub fn clear_t2(&mut self) {
        self.t2.clear();
    }

    // Param is passed by value, moved
    pub fn set_t2(&mut self, v: ::std::vec::Vec<u8>) {
        self.t2 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_t2(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.t2
    }

    // Take field
    pub fn take_t2(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.t2, ::std::vec::Vec::new())
    }

    // bytes t3 = 3;


    pub fn get_t3(&self) -> &[u8] {
        &self.t3
    }
    pub fn clear_t3(&mut self) {
        self.t3.clear();
    }

    // Param is passed by value, moved
    pub fn set_t3(&mut self, v: ::std::vec::Vec<u8>) {
        self.t3 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_t3(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.t3
    }

    // Take field
    pub fn take_t3(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.t3, ::std::vec::Vec::new())
    }

    // bytes m1 = 4;


    pub fn get_m1(&self) -> &[u8] {
        &self.m1
    }
    pub fn clear_m1(&mut self) {
        self.m1.clear();
    }

    // Param is passed by value, moved
    pub fn set_m1(&mut self, v: ::std::vec::Vec<u8>) {
        self.m1 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m1(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m1
    }

    // Take field
    pub fn take_m1(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m1, ::std::vec::Vec::new())
    }

    // bytes m2 = 5;


    pub fn get_m2(&self) -> &[u8] {
        &self.m2
    }
    pub fn clear_m2(&mut self) {
        self.m2.clear();
    }

    // Param is passed by value, moved
    pub fn set_m2(&mut self, v: ::std::vec::Vec<u8>) {
        self.m2 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m2(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m2
    }

    // Take field
    pub fn take_m2(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m2, ::std::vec::Vec::new())
    }

    // bytes m3 = 6;


    pub fn get_m3(&self) -> &[u8] {
        &self.m3
    }
    pub fn clear_m3(&mut self) {
        self.m3.clear();
    }

    // Param is passed by value, moved
    pub fn set_m3(&mut self, v: ::std::vec::Vec<u8>) {
        self.m3 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m3(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m3
    }

    // Take field
    pub fn take_m3(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m3, ::std::vec::Vec::new())
    }

    // bytes m4 = 7;


    pub fn get_m4(&self) -> &[u8] {
        &self.m4
    }
    pub fn clear_m4(&mut self) {
        self.m4.clear();
    }

    // Param is passed by value, moved
    pub fn set_m4(&mut self, v: ::std::vec::Vec<u8>) {
        self.m4 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m4(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m4
    }

    // Take field
    pub fn take_m4(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m4, ::std::vec::Vec::new())
    }

    // bytes m5 = 8;


    pub fn get_m5(&self) -> &[u8] {
        &self.m5
    }
    pub fn clear_m5(&mut self) {
        self.m5.clear();
    }

    // Param is passed by value, moved
    pub fn set_m5(&mut self, v: ::std::vec::Vec<u8>) {
        self.m5 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m5(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m5
    }

    // Take field
    pub fn take_m5(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m5, ::std::vec::Vec::new())
    }

    // bytes m6 = 9;


    pub fn get_m6(&self) -> &[u8] {
        &self.m6
    }
    pub fn clear_m6(&mut self) {
        self.m6.clear();
    }

    // Param is passed by value, moved
    pub fn set_m6(&mut self, v: ::std::vec::Vec<u8>) {
        self.m6 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m6(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m6
    }

    // Take field
    pub fn take_m6(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m6, ::std::vec::Vec::new())
    }

    // bytes check1 = 10;


    pub fn get_check1(&self) -> &[u8] {
        &self.check1
    }
    pub fn clear_check1(&mut self) {
        self.check1.clear();
    }

    // Param is passed by value, moved
    pub fn set_check1(&mut self, v: ::std::vec::Vec<u8>) {
        self.check1 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_check1(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.check1
    }

    // Take field
    pub fn take_check1(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.check1, ::std::vec::Vec::new())
    }

    // bytes check2 = 11;


    pub fn get_check2(&self) -> &[u8] {
        &self.check2
    }
    pub fn clear_check2(&mut self) {
        self.check2.clear();
    }

    // Param is passed by value, moved
    pub fn set_check2(&mut self, v: ::std::vec::Vec<u8>) {
        self.check2 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_check2(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.check2
    }

    // Take field
    pub fn take_check2(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.check2, ::std::vec::Vec::new())
    }
}

impl ::protobuf::Message for PBBalanceProof {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.t1)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.t2)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.t3)?;
                },
                4 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m1)?;
                },
                5 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m2)?;
                },
                6 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m3)?;
                },
                7 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m4)?;
                },
                8 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m5)?;
                },
                9 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m6)?;
                },
                10 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.check1)?;
                },
                11 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.check2)?;
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
        if !self.t1.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.t1);
        }
        if !self.t2.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.t2);
        }
        if !self.t3.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.t3);
        }
        if !self.m1.is_empty() {
            my_size += ::protobuf::rt::bytes_size(4, &self.m1);
        }
        if !self.m2.is_empty() {
            my_size += ::protobuf::rt::bytes_size(5, &self.m2);
        }
        if !self.m3.is_empty() {
            my_size += ::protobuf::rt::bytes_size(6, &self.m3);
        }
        if !self.m4.is_empty() {
            my_size += ::protobuf::rt::bytes_size(7, &self.m4);
        }
        if !self.m5.is_empty() {
            my_size += ::protobuf::rt::bytes_size(8, &self.m5);
        }
        if !self.m6.is_empty() {
            my_size += ::protobuf::rt::bytes_size(9, &self.m6);
        }
        if !self.check1.is_empty() {
            my_size += ::protobuf::rt::bytes_size(10, &self.check1);
        }
        if !self.check2.is_empty() {
            my_size += ::protobuf::rt::bytes_size(11, &self.check2);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.t1.is_empty() {
            os.write_bytes(1, &self.t1)?;
        }
        if !self.t2.is_empty() {
            os.write_bytes(2, &self.t2)?;
        }
        if !self.t3.is_empty() {
            os.write_bytes(3, &self.t3)?;
        }
        if !self.m1.is_empty() {
            os.write_bytes(4, &self.m1)?;
        }
        if !self.m2.is_empty() {
            os.write_bytes(5, &self.m2)?;
        }
        if !self.m3.is_empty() {
            os.write_bytes(6, &self.m3)?;
        }
        if !self.m4.is_empty() {
            os.write_bytes(7, &self.m4)?;
        }
        if !self.m5.is_empty() {
            os.write_bytes(8, &self.m5)?;
        }
        if !self.m6.is_empty() {
            os.write_bytes(9, &self.m6)?;
        }
        if !self.check1.is_empty() {
            os.write_bytes(10, &self.check1)?;
        }
        if !self.check2.is_empty() {
            os.write_bytes(11, &self.check2)?;
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

    fn new() -> PBBalanceProof {
        PBBalanceProof::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "t1",
                |m: &PBBalanceProof| { &m.t1 },
                |m: &mut PBBalanceProof| { &mut m.t1 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "t2",
                |m: &PBBalanceProof| { &m.t2 },
                |m: &mut PBBalanceProof| { &mut m.t2 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "t3",
                |m: &PBBalanceProof| { &m.t3 },
                |m: &mut PBBalanceProof| { &mut m.t3 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m1",
                |m: &PBBalanceProof| { &m.m1 },
                |m: &mut PBBalanceProof| { &mut m.m1 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m2",
                |m: &PBBalanceProof| { &m.m2 },
                |m: &mut PBBalanceProof| { &mut m.m2 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m3",
                |m: &PBBalanceProof| { &m.m3 },
                |m: &mut PBBalanceProof| { &mut m.m3 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m4",
                |m: &PBBalanceProof| { &m.m4 },
                |m: &mut PBBalanceProof| { &mut m.m4 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m5",
                |m: &PBBalanceProof| { &m.m5 },
                |m: &mut PBBalanceProof| { &mut m.m5 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m6",
                |m: &PBBalanceProof| { &m.m6 },
                |m: &mut PBBalanceProof| { &mut m.m6 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "check1",
                |m: &PBBalanceProof| { &m.check1 },
                |m: &mut PBBalanceProof| { &mut m.check1 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "check2",
                |m: &PBBalanceProof| { &m.check2 },
                |m: &mut PBBalanceProof| { &mut m.check2 },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<PBBalanceProof>(
                "PBBalanceProof",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static PBBalanceProof {
        static instance: ::protobuf::rt::LazyV2<PBBalanceProof> = ::protobuf::rt::LazyV2::INIT;
        instance.get(PBBalanceProof::new)
    }
}

impl ::protobuf::Clear for PBBalanceProof {
    fn clear(&mut self) {
        self.t1.clear();
        self.t2.clear();
        self.t3.clear();
        self.m1.clear();
        self.m2.clear();
        self.m3.clear();
        self.m4.clear();
        self.m5.clear();
        self.m6.clear();
        self.check1.clear();
        self.check2.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PBBalanceProof {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PBBalanceProof {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct PBEqualityProof {
    // message fields
    pub m1: ::std::vec::Vec<u8>,
    pub t1: ::std::vec::Vec<u8>,
    pub t2: ::std::vec::Vec<u8>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a PBEqualityProof {
    fn default() -> &'a PBEqualityProof {
        <PBEqualityProof as ::protobuf::Message>::default_instance()
    }
}

impl PBEqualityProof {
    pub fn new() -> PBEqualityProof {
        ::std::default::Default::default()
    }

    // bytes m1 = 1;


    pub fn get_m1(&self) -> &[u8] {
        &self.m1
    }
    pub fn clear_m1(&mut self) {
        self.m1.clear();
    }

    // Param is passed by value, moved
    pub fn set_m1(&mut self, v: ::std::vec::Vec<u8>) {
        self.m1 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_m1(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.m1
    }

    // Take field
    pub fn take_m1(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.m1, ::std::vec::Vec::new())
    }

    // bytes t1 = 2;


    pub fn get_t1(&self) -> &[u8] {
        &self.t1
    }
    pub fn clear_t1(&mut self) {
        self.t1.clear();
    }

    // Param is passed by value, moved
    pub fn set_t1(&mut self, v: ::std::vec::Vec<u8>) {
        self.t1 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_t1(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.t1
    }

    // Take field
    pub fn take_t1(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.t1, ::std::vec::Vec::new())
    }

    // bytes t2 = 3;


    pub fn get_t2(&self) -> &[u8] {
        &self.t2
    }
    pub fn clear_t2(&mut self) {
        self.t2.clear();
    }

    // Param is passed by value, moved
    pub fn set_t2(&mut self, v: ::std::vec::Vec<u8>) {
        self.t2 = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_t2(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.t2
    }

    // Take field
    pub fn take_t2(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.t2, ::std::vec::Vec::new())
    }
}

impl ::protobuf::Message for PBEqualityProof {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.m1)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.t1)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.t2)?;
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
        if !self.m1.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.m1);
        }
        if !self.t1.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.t1);
        }
        if !self.t2.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.t2);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.m1.is_empty() {
            os.write_bytes(1, &self.m1)?;
        }
        if !self.t1.is_empty() {
            os.write_bytes(2, &self.t1)?;
        }
        if !self.t2.is_empty() {
            os.write_bytes(3, &self.t2)?;
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

    fn new() -> PBEqualityProof {
        PBEqualityProof::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "m1",
                |m: &PBEqualityProof| { &m.m1 },
                |m: &mut PBEqualityProof| { &mut m.m1 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "t1",
                |m: &PBEqualityProof| { &m.t1 },
                |m: &mut PBEqualityProof| { &mut m.t1 },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "t2",
                |m: &PBEqualityProof| { &m.t2 },
                |m: &mut PBEqualityProof| { &mut m.t2 },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<PBEqualityProof>(
                "PBEqualityProof",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static PBEqualityProof {
        static instance: ::protobuf::rt::LazyV2<PBEqualityProof> = ::protobuf::rt::LazyV2::INIT;
        instance.get(PBEqualityProof::new)
    }
}

impl ::protobuf::Clear for PBEqualityProof {
    fn clear(&mut self) {
        self.m1.clear();
        self.t1.clear();
        self.t2.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PBEqualityProof {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PBEqualityProof {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x10crypto/zkp.proto\x12\x1dcom.webank.wedpr.crypto.proto\"\xce\x01\n\
    \x0cBalanceProof\x12\x0e\n\x02t1\x18\x01\x20\x01(\x0cR\x02t1\x12\x0e\n\
    \x02t2\x18\x02\x20\x01(\x0cR\x02t2\x12\x0e\n\x02t3\x18\x03\x20\x01(\x0cR\
    \x02t3\x12\x0e\n\x02m1\x18\x04\x20\x01(\x0cR\x02m1\x12\x0e\n\x02m2\x18\
    \x05\x20\x01(\x0cR\x02m2\x12\x0e\n\x02m3\x18\x06\x20\x01(\x0cR\x02m3\x12\
    \x0e\n\x02m4\x18\x07\x20\x01(\x0cR\x02m4\x12\x0e\n\x02m5\x18\x08\x20\x01\
    (\x0cR\x02m5\x12\x0e\n\x02m6\x18\t\x20\x01(\x0cR\x02m6\x12\x16\n\x06chec\
    k1\x18\n\x20\x01(\x0cR\x06check1\x12\x16\n\x06check2\x18\x0b\x20\x01(\
    \x0cR\x06check2\"?\n\rEqualityProof\x12\x0e\n\x02m1\x18\x01\x20\x01(\x0c\
    R\x02m1\x12\x0e\n\x02t1\x18\x02\x20\x01(\x0cR\x02t1\x12\x0e\n\x02t2\x18\
    \x03\x20\x01(\x0cR\x02t2B!\n\x1dcom.webank.wedpr.crypto.protoP\x01b\x06p\
    roto3\
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
