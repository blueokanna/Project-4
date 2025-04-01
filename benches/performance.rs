use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use LiuProject2::{f_open, tally, KeyPair, Timelock, WithdrawableSig, ZKProof, Ballot};

fn bench_signing(c: &mut Criterion) {
    let voter = KeyPair::generate();
    let message = b"Performance Test message for signing";
    let Y = EdwardsPoint::identity();

    c.bench_function("signing", |b| {
        b.iter(|| {
            black_box(WithdrawableSig::sign(message, &voter.secret, &Y))
        })
    });
}

fn bench_zk_proof(c: &mut Criterion) {
    let witness = Scalar::random(&mut OsRng);

    c.bench_function("zk_proof", |b| {
        b.iter(|| {
            black_box(ZKProof::zk_prove(witness.clone()))
        })
    });
}

fn bench_confirmed_sig(c: &mut Criterion) {
    let msg = b"Test message for confirmation";
    let sk = Scalar::random(&mut OsRng);
    let gamma = vec![EdwardsPoint::identity()];
    let sigma = WithdrawableSig::sign(msg, &sk, &gamma[0]).unwrap();

    // 生成 Ballot，而不是 WithdrawableSig
    let ballot = Ballot {
        R: *sigma.sigma1(),
        P: *sigma.sigma2(),
        sigma,
        bids: vec![],
    };

    c.bench_function("confirmed_sig", |b| {
        b.iter(|| {
            black_box(f_open(&ballot, &gamma[0]))
        })
    });
}

fn bench_tally(c: &mut Criterion) {
    let ballot = Ballot {
        R: EdwardsPoint::identity(),
        P: EdwardsPoint::identity(),
        sigma: WithdrawableSig::sign(b"test", &Scalar::random(&mut OsRng), &EdwardsPoint::identity()).unwrap(),
        bids: vec![],
    };

    let timelock = Timelock::new(
        EdwardsPoint::identity(),
        f_open(&ballot, &EdwardsPoint::identity()).unwrap(),
        EdwardsPoint::identity(),
        ZKProof::zk_prove(Scalar::random(&mut OsRng)).unwrap(),
        3,
        std::time::Duration::from_secs(3600),
    );

    c.bench_function("tally", |b| {
        b.iter(|| {
            black_box(tally(&timelock))
        })
    });
}

criterion_group!(benches, bench_signing, bench_zk_proof, bench_confirmed_sig, bench_tally);
criterion_main!(benches);
