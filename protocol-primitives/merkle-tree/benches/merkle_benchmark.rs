use criterion::{black_box, criterion_group, criterion_main, Criterion};
use merkle_tree::MerkleTree;

fn build_tree(c: &mut Criterion) {
    let data: Vec<&[u8]> = (0..1000)
        .map(|i| format!("tx{}", i).into_bytes())
        .map(|v| v.leak() as &[u8])
        .collect();

    c.bench_function("build_merkle_tree", |b| {
        b.iter(|| {
            MerkleTree::new(black_box(data.clone()));
        })
    });
}

fn generate_proof(c: &mut Criterion) {
    let data: Vec<&[u8]> = (0..1000)
        .map(|i| format!("tx{}", i).into_bytes())
        .map(|v| v.leak() as &[u8])
        .collect();

    let tree = MerkleTree::new(data.clone());

    c.bench_function("generate_merkle_proof", |b| {
        b.iter(|| {
            tree.proof(black_box(500));
        })
    });
}

fn verify_proof(c: &mut Criterion) {
    let data: Vec<&[u8]> = (0..1000)
        .map(|i| format!("tx{}", i).into_bytes())
        .map(|v| v.leak() as &[u8])
        .collect();

    let tree = MerkleTree::new(data.clone());
    let proof = tree.proof(500);
    let root = tree.root();

    c.bench_function("verify_merkle_proof", |b| {
        b.iter(|| {
            MerkleTree::verify(
                black_box(&data[500]),
                black_box(&proof.clone()),
                black_box(&root.clone()),
                black_box(500),
            );
        })
    });
}

criterion_group!(benches, build_tree, generate_proof, verify_proof);
criterion_main!(benches);