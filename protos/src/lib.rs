// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of protobuf definitions and their generated code.
use crate::generated::zkp::{PBBalanceProof, PBEqualityProof};
use protobuf::Message;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, point_to_bytes, scalar_to_bytes,
    ArithmeticProof, BalanceProof, EqualityProof, FormatProof, KnowledgeProof,
};
pub mod generated;

#[cfg(not(tarpaulin_include))]
use wedpr_l_utils::error::WedprError;

pub fn proto_to_bytes<T: Message>(proto: &T) -> Result<Vec<u8>, WedprError> {
    return match proto.write_to_bytes() {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::DecodeError),
    };
}

pub fn bytes_to_proto<T: Message>(proto_bytes: &[u8]) -> Result<T, WedprError> {
    return match T::parse_from_bytes(proto_bytes) {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::DecodeError),
    };
}

/// from struct BalanceProof to PBBalanceProof
pub fn balance_proof_to_pb(balance_proof: &BalanceProof) -> PBBalanceProof {
    let mut pb_proof = PBBalanceProof::new();
    pb_proof.set_check1(scalar_to_bytes(&balance_proof.check1));
    pb_proof.set_check2(scalar_to_bytes(&balance_proof.check2));
    pb_proof.set_m1(scalar_to_bytes(&balance_proof.m1));
    pb_proof.set_m2(scalar_to_bytes(&balance_proof.m2));
    pb_proof.set_m3(scalar_to_bytes(&balance_proof.m3));
    pb_proof.set_m4(scalar_to_bytes(&balance_proof.m4));
    pb_proof.set_m5(scalar_to_bytes(&balance_proof.m5));
    pb_proof.set_m6(scalar_to_bytes(&balance_proof.m6));
    pb_proof
}

// from PBBalanceProof to struct BalanceProof
pub fn pb_to_balance_proof(
    balance_proof: &PBBalanceProof,
) -> Result<BalanceProof, WedprError> {
    Ok(BalanceProof {
        check1: bytes_to_scalar(balance_proof.get_check1())?,
        check2: bytes_to_scalar(balance_proof.get_check2())?,
        m1: bytes_to_scalar(balance_proof.get_m1())?,
        m2: bytes_to_scalar(balance_proof.get_m2())?,
        m3: bytes_to_scalar(balance_proof.get_m3())?,
        m4: bytes_to_scalar(balance_proof.get_m4())?,
        m5: bytes_to_scalar(balance_proof.get_m5())?,
        m6: bytes_to_scalar(balance_proof.get_m6())?,
    })
}

// from struct KnowledgeProof to PBBalanceProof
pub fn knowledge_proof_to_pb(
    knowledge_proof: &KnowledgeProof,
) -> PBBalanceProof {
    let mut pb_proof = PBBalanceProof::new();
    pb_proof.set_t1(point_to_bytes(&knowledge_proof.t1));
    pb_proof.set_m1(scalar_to_bytes(&knowledge_proof.m1));
    pb_proof.set_m2(scalar_to_bytes(&knowledge_proof.m2));
    pb_proof
}

// from PBBalanceProof to struct KnowledgeProof
pub fn pb_to_knowledge_proof(
    knowledge_proof: &PBBalanceProof,
) -> Result<KnowledgeProof, WedprError> {
    Ok(KnowledgeProof {
        t1: bytes_to_point(&knowledge_proof.get_t1())?,
        m1: bytes_to_scalar(&knowledge_proof.get_m1())?,
        m2: bytes_to_scalar(&knowledge_proof.get_m2())?,
    })
}

// from struct FormatProof to PBBalanceProof
pub fn format_proof_to_pb(format_proof: &FormatProof) -> PBBalanceProof {
    let mut pb_proof = PBBalanceProof::new();
    pb_proof.set_t1(point_to_bytes(&format_proof.t1));
    pb_proof.set_t2(point_to_bytes(&format_proof.t2));
    pb_proof.set_m1(scalar_to_bytes(&format_proof.m1));
    pb_proof.set_m2(scalar_to_bytes(&format_proof.m2));
    pb_proof
}

// from PBBalanceProof to struct FormatProof
pub fn pb_to_format_proof(
    format_proof: &PBBalanceProof,
) -> Result<FormatProof, WedprError> {
    Ok(FormatProof {
        t1: bytes_to_point(&format_proof.get_t1())?,
        t2: bytes_to_point(&format_proof.get_t2())?,
        m1: bytes_to_scalar(&format_proof.get_m1())?,
        m2: bytes_to_scalar(&format_proof.get_m2())?,
    })
}

// from struct ArithmeticProof to PBBalanceProof
pub fn arithmetric_proof_to_pb(
    arithmetric_proof: &ArithmeticProof,
) -> PBBalanceProof {
    let mut pb_proof = PBBalanceProof::new();
    pb_proof.set_t1(point_to_bytes(&arithmetric_proof.t1));
    pb_proof.set_t2(point_to_bytes(&arithmetric_proof.t2));
    pb_proof.set_t3(point_to_bytes(&arithmetric_proof.t3));
    pb_proof.set_m1(scalar_to_bytes(&arithmetric_proof.m1));
    pb_proof.set_m2(scalar_to_bytes(&arithmetric_proof.m2));
    pb_proof.set_m3(scalar_to_bytes(&arithmetric_proof.m3));
    pb_proof.set_m4(scalar_to_bytes(&arithmetric_proof.m4));
    pb_proof.set_m5(scalar_to_bytes(&arithmetric_proof.m5));
    pb_proof
}

// from PBBalanceProof to struct ArithmeticProof
pub fn pb_to_arithmetric_proof(
    arithmetric_proof: &PBBalanceProof,
) -> Result<ArithmeticProof, WedprError> {
    Ok(ArithmeticProof {
        t1: bytes_to_point(&arithmetric_proof.get_t1())?,
        t2: bytes_to_point(&arithmetric_proof.get_t2())?,
        t3: bytes_to_point(&arithmetric_proof.get_t3())?,
        m1: bytes_to_scalar(&arithmetric_proof.get_m1())?,
        m2: bytes_to_scalar(&arithmetric_proof.get_m2())?,
        m3: bytes_to_scalar(&arithmetric_proof.get_m3())?,
        m4: bytes_to_scalar(&arithmetric_proof.get_m4())?,
        m5: bytes_to_scalar(&arithmetric_proof.get_m5())?,
    })
}

// from struct EqualityProof to PBEqualityProof
pub fn equality_proof_to_pb(equality_proof: &EqualityProof) -> PBEqualityProof {
    let mut pb_proof = PBEqualityProof::new();
    pb_proof.set_t1(point_to_bytes(&equality_proof.t1));
    pb_proof.set_t2(point_to_bytes(&equality_proof.t2));
    pb_proof.set_m1(scalar_to_bytes(&equality_proof.m1));
    pb_proof
}

// from PBEqualityProof to struct EqualityProof
pub fn pb_to_equality_proof(
    equality_proof: &PBEqualityProof,
) -> Result<EqualityProof, WedprError> {
    Ok(EqualityProof {
        t1: bytes_to_point(&equality_proof.get_t1())?,
        t2: bytes_to_point(&equality_proof.get_t2())?,
        m1: bytes_to_scalar(&equality_proof.get_m1())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use generated::zkp::PBBalanceProof;

    #[test]
    fn test_parser() {
        let mut proof = PBBalanceProof::new();
        proof.set_check1("test1".as_bytes().to_vec());
        proof.set_check2("test2".as_bytes().to_vec());
        let bytes = proto_to_bytes(&proof).unwrap();
        let proof_parser = bytes_to_proto::<PBBalanceProof>(&bytes).unwrap();
        assert_eq!(proof_parser, proof);
    }
}
