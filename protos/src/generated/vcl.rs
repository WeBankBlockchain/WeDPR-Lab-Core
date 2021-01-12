// This file is generated by rust-protobuf 2.20.0. Do not edit
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![rustfmt::skip]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `solution/vcl/vcl.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
// const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_20_0;

#[derive(PartialEq,Clone,Default)]
pub struct EncodedOwnerSecret {
    // message fields
    pub credit_value: i64,
    pub secret_blinding: ::std::vec::Vec<u8>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a EncodedOwnerSecret {
    fn default() -> &'a EncodedOwnerSecret {
        <EncodedOwnerSecret as ::protobuf::Message>::default_instance()
    }
}

impl EncodedOwnerSecret {
    pub fn new() -> EncodedOwnerSecret {
        ::std::default::Default::default()
    }

    // int64 credit_value = 1;


    pub fn get_credit_value(&self) -> i64 {
        self.credit_value
    }
    pub fn clear_credit_value(&mut self) {
        self.credit_value = 0;
    }

    // Param is passed by value, moved
    pub fn set_credit_value(&mut self, v: i64) {
        self.credit_value = v;
    }

    // bytes secret_blinding = 2;


    pub fn get_secret_blinding(&self) -> &[u8] {
        &self.secret_blinding
    }
    pub fn clear_secret_blinding(&mut self) {
        self.secret_blinding.clear();
    }

    // Param is passed by value, moved
    pub fn set_secret_blinding(&mut self, v: ::std::vec::Vec<u8>) {
        self.secret_blinding = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_secret_blinding(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.secret_blinding
    }

    // Take field
    pub fn take_secret_blinding(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.secret_blinding, ::std::vec::Vec::new())
    }
}

impl ::protobuf::Message for EncodedOwnerSecret {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int64()?;
                    self.credit_value = tmp;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.secret_blinding)?;
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
        if self.credit_value != 0 {
            my_size += ::protobuf::rt::value_size(1, self.credit_value, ::protobuf::wire_format::WireTypeVarint);
        }
        if !self.secret_blinding.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.secret_blinding);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if self.credit_value != 0 {
            os.write_int64(1, self.credit_value)?;
        }
        if !self.secret_blinding.is_empty() {
            os.write_bytes(2, &self.secret_blinding)?;
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

    fn new() -> EncodedOwnerSecret {
        EncodedOwnerSecret::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeInt64>(
                "credit_value",
                |m: &EncodedOwnerSecret| { &m.credit_value },
                |m: &mut EncodedOwnerSecret| { &mut m.credit_value },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "secret_blinding",
                |m: &EncodedOwnerSecret| { &m.secret_blinding },
                |m: &mut EncodedOwnerSecret| { &mut m.secret_blinding },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<EncodedOwnerSecret>(
                "EncodedOwnerSecret",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static EncodedOwnerSecret {
        static instance: ::protobuf::rt::LazyV2<EncodedOwnerSecret> = ::protobuf::rt::LazyV2::INIT;
        instance.get(EncodedOwnerSecret::new)
    }
}

impl ::protobuf::Clear for EncodedOwnerSecret {
    fn clear(&mut self) {
        self.credit_value = 0;
        self.secret_blinding.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for EncodedOwnerSecret {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncodedOwnerSecret {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct EncodedConfidentialCredit {
    // message fields
    pub point: ::std::vec::Vec<u8>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a EncodedConfidentialCredit {
    fn default() -> &'a EncodedConfidentialCredit {
        <EncodedConfidentialCredit as ::protobuf::Message>::default_instance()
    }
}

impl EncodedConfidentialCredit {
    pub fn new() -> EncodedConfidentialCredit {
        ::std::default::Default::default()
    }

    // bytes point = 1;


    pub fn get_point(&self) -> &[u8] {
        &self.point
    }
    pub fn clear_point(&mut self) {
        self.point.clear();
    }

    // Param is passed by value, moved
    pub fn set_point(&mut self, v: ::std::vec::Vec<u8>) {
        self.point = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_point(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.point
    }

    // Take field
    pub fn take_point(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.point, ::std::vec::Vec::new())
    }
}

impl ::protobuf::Message for EncodedConfidentialCredit {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.point)?;
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
        if !self.point.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.point);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.point.is_empty() {
            os.write_bytes(1, &self.point)?;
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

    fn new() -> EncodedConfidentialCredit {
        EncodedConfidentialCredit::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                "point",
                |m: &EncodedConfidentialCredit| { &m.point },
                |m: &mut EncodedConfidentialCredit| { &mut m.point },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<EncodedConfidentialCredit>(
                "EncodedConfidentialCredit",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static EncodedConfidentialCredit {
        static instance: ::protobuf::rt::LazyV2<EncodedConfidentialCredit> = ::protobuf::rt::LazyV2::INIT;
        instance.get(EncodedConfidentialCredit::new)
    }
}

impl ::protobuf::Clear for EncodedConfidentialCredit {
    fn clear(&mut self) {
        self.point.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for EncodedConfidentialCredit {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncodedConfidentialCredit {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct VclResult {
    // message fields
    pub credit: ::std::string::String,
    pub secret: ::std::string::String,
    pub proof: ::std::string::String,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a VclResult {
    fn default() -> &'a VclResult {
        <VclResult as ::protobuf::Message>::default_instance()
    }
}

impl VclResult {
    pub fn new() -> VclResult {
        ::std::default::Default::default()
    }

    // string credit = 1;


    pub fn get_credit(&self) -> &str {
        &self.credit
    }
    pub fn clear_credit(&mut self) {
        self.credit.clear();
    }

    // Param is passed by value, moved
    pub fn set_credit(&mut self, v: ::std::string::String) {
        self.credit = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_credit(&mut self) -> &mut ::std::string::String {
        &mut self.credit
    }

    // Take field
    pub fn take_credit(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.credit, ::std::string::String::new())
    }

    // string secret = 2;


    pub fn get_secret(&self) -> &str {
        &self.secret
    }
    pub fn clear_secret(&mut self) {
        self.secret.clear();
    }

    // Param is passed by value, moved
    pub fn set_secret(&mut self, v: ::std::string::String) {
        self.secret = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_secret(&mut self) -> &mut ::std::string::String {
        &mut self.secret
    }

    // Take field
    pub fn take_secret(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.secret, ::std::string::String::new())
    }

    // string proof = 3;


    pub fn get_proof(&self) -> &str {
        &self.proof
    }
    pub fn clear_proof(&mut self) {
        self.proof.clear();
    }

    // Param is passed by value, moved
    pub fn set_proof(&mut self, v: ::std::string::String) {
        self.proof = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_proof(&mut self) -> &mut ::std::string::String {
        &mut self.proof
    }

    // Take field
    pub fn take_proof(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.proof, ::std::string::String::new())
    }
}

impl ::protobuf::Message for VclResult {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.credit)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.secret)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.proof)?;
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
        if !self.credit.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.credit);
        }
        if !self.secret.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.secret);
        }
        if !self.proof.is_empty() {
            my_size += ::protobuf::rt::string_size(3, &self.proof);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.credit.is_empty() {
            os.write_string(1, &self.credit)?;
        }
        if !self.secret.is_empty() {
            os.write_string(2, &self.secret)?;
        }
        if !self.proof.is_empty() {
            os.write_string(3, &self.proof)?;
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

    fn new() -> VclResult {
        VclResult::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "credit",
                |m: &VclResult| { &m.credit },
                |m: &mut VclResult| { &mut m.credit },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "secret",
                |m: &VclResult| { &m.secret },
                |m: &mut VclResult| { &mut m.secret },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "proof",
                |m: &VclResult| { &m.proof },
                |m: &mut VclResult| { &mut m.proof },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<VclResult>(
                "VclResult",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static VclResult {
        static instance: ::protobuf::rt::LazyV2<VclResult> = ::protobuf::rt::LazyV2::INIT;
        instance.get(VclResult::new)
    }
}

impl ::protobuf::Clear for VclResult {
    fn clear(&mut self) {
        self.credit.clear();
        self.secret.clear();
        self.proof.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for VclResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for VclResult {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x16solution/vcl/vcl.proto\x12\x1acom.webank.wedpr.vcl.proto\"`\n\x12E\
    ncodedOwnerSecret\x12!\n\x0ccredit_value\x18\x01\x20\x01(\x03R\x0bcredit\
    Value\x12'\n\x0fsecret_blinding\x18\x02\x20\x01(\x0cR\x0esecretBlinding\
    \"1\n\x19EncodedConfidentialCredit\x12\x14\n\x05point\x18\x01\x20\x01(\
    \x0cR\x05point\"Q\n\tVclResult\x12\x16\n\x06credit\x18\x01\x20\x01(\tR\
    \x06credit\x12\x16\n\x06secret\x18\x02\x20\x01(\tR\x06secret\x12\x14\n\
    \x05proof\x18\x03\x20\x01(\tR\x05proofB\x1e\n\x1acom.webank.wedpr.vcl.pr\
    otoP\x01b\x06proto3\
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
