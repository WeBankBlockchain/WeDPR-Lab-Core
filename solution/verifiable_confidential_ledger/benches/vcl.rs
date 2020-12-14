// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Performance tests for VCL components.

extern crate criterion;
use criterion::{criterion_group, criterion_main, Criterion};

extern crate verifiable_confidential_ledger;
use verifiable_confidential_ledger::vcl;

fn create_prove_sum_balance_helper(c: &mut Criterion) {
    let label = format!("create_prove_sum_balance_helper");

    let c1_value = 10;
    let c2_value = 20;

    let (_, c1_secret) = vcl::make_credit(c1_value);
    let (_, c2_secret) = vcl::make_credit(c2_value);
    let (_, c3_secret) = vcl::make_credit(c1_value + c2_value);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
        });
    });
}

fn create_verify_sum_balance_helper(c: &mut Criterion) {
    let label = format!("create_verify_sum_balance_helper");

    let c1_value = 10;
    let c2_value = 20;

    let (c1_credit, c1_secret) = vcl::make_credit(c1_value);
    let (c2_credit, c2_secret) = vcl::make_credit(c2_value);
    let (c3_credit, c3_secret) = vcl::make_credit(c1_value + c2_value);

    let sum_proof = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(
                true,
                vcl::verify_sum_balance(
                    &c1_credit, &c2_credit, &c3_credit, &sum_proof
                )
            );
        });
    });
}

fn create_prove_product_balance_helper(c: &mut Criterion) {
    let label = format!("create_prove_product_balance_helper");

    let c1_value = 10;
    let c2_value = 20;

    let (_, c1_secret) = vcl::make_credit(c1_value);
    let (_, c2_secret) = vcl::make_credit(c2_value);
    let (_, c3_secret) = vcl::make_credit(c1_value * c2_value);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ =
                vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);
        });
    });
}

fn create_verify_product_balance_helper(c: &mut Criterion) {
    let label = format!("create_verify_product_balance_helper");

    let c1_value = 10;
    let c2_value = 20;

    let (c1_credit, c1_secret) = vcl::make_credit(c1_value);
    let (c2_credit, c2_secret) = vcl::make_credit(c2_value);
    let (c3_credit, c3_secret) = vcl::make_credit(c1_value * c2_value);

    let product_proof =
        vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(
                true,
                vcl::verify_product_balance(
                    &c1_credit,
                    &c2_credit,
                    &c3_credit,
                    &product_proof
                )
            );
        });
    });
}

fn create_prove_range_helper(c: &mut Criterion) {
    let label = format!("create_prove_range_helper");

    let (_, c1_secret) = vcl::make_credit(10);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = vcl::prove_range(&c1_secret);
        });
    });
}

fn create_verify_range_helper(c: &mut Criterion) {
    let label = format!("create_verify_range_helper");

    let (c1_credit, c1_secret) = vcl::make_credit(10);
    let range_proof = vcl::prove_range(&c1_secret);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(true, vcl::verify_range(&c1_credit, &range_proof));
        });
    });
}

criterion_group! {
    name = vcl_benches;
    config = Criterion::default().sample_size(10);
    targets =
    create_prove_sum_balance_helper,
    create_verify_sum_balance_helper,
    create_prove_product_balance_helper,
    create_verify_product_balance_helper,
    create_prove_range_helper,
    create_verify_range_helper
}
criterion_main!(vcl_benches);
