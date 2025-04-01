use blake3::Hasher;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use chrono::Local;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use digest::{FixedOutput, HashMarker, OutputSizeUser, Reset, Update};
use generic_array::GenericArray;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;
use rsntp::SntpClient;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use log::{error, info};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PublicParams {
    pub security_param: u32,
    pub candidate_num: usize,
    pub voter_num: usize,
    pub time_difficulty: u32,
    pub event: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EAKeyPair {
    pub public: EdwardsPoint,
    secret: Scalar,
}

impl EAKeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);
        let public = ED25519_BASEPOINT_POINT * secret;
        Self { public, secret }
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("签名验证失败")]
    VerificationError,
    #[error("无效的加密参数")]
    ParameterError,
    #[error("密钥生成失败")]
    KeyGenError,
    #[error("零知识证明验证失败")]
    ZKPError,
    #[error("撤销操作失败")]
    RevocationError,
    #[error("注册过程失败")]
    RegisterError,
    #[error("其它错误")]
    OtherError,
}

#[derive(Clone)]
pub struct Blake3Adapter {
    hasher: Hasher,
}

impl Blake3Adapter {
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
        }
    }
}

impl Default for Blake3Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Blake3Adapter {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

impl FixedOutput for Blake3Adapter {
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let result = self.finalize_fixed();
        out.copy_from_slice(result.as_slice());
    }
    fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize> {
        let mut buf = [0u8; 64];
        let mut reader = self.hasher.finalize_xof();
        reader.fill(&mut buf);
        GenericArray::clone_from_slice(&buf)
    }
}

impl Reset for Blake3Adapter {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl OutputSizeUser for Blake3Adapter {
    type OutputSize = typenum::U64;
}

impl HashMarker for Blake3Adapter {}

fn rfc6979_nonce(secret: &Scalar, msg: &[u8], extra: &[u8]) -> Scalar {
    let mut adapter = Blake3Adapter::new();
    adapter.update(&secret.to_bytes());
    adapter.update(msg);
    adapter.update(extra);
    let hash_out = adapter.finalize_fixed();
    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(&hash_out.as_slice()[..32]);
    Scalar::from_bytes_mod_order(nonce_bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: EdwardsPoint,
    pub secret: Scalar,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);
        let public = ED25519_BASEPOINT_POINT * secret;
        Self { public, secret }
    }

    pub fn evolve(&self) -> Self {
        let mut adapter = Blake3Adapter::new();
        adapter.update(&self.secret.to_bytes());
        let hash_out = adapter.finalize_fixed();
        let mut new_secret_bytes = [0u8; 32];
        new_secret_bytes.copy_from_slice(&hash_out.as_slice()[..32]);
        let new_secret = Scalar::from_bytes_mod_order(new_secret_bytes);
        let new_public = ED25519_BASEPOINT_POINT * new_secret;
        Self {
            public: new_public,
            secret: new_secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawableSig {
    sigma1: EdwardsPoint,
    sigma2: EdwardsPoint,
    sigma3: EdwardsPoint,
}

impl WithdrawableSig {
    pub fn sigma1(&self) -> &EdwardsPoint {
        &self.sigma1
    }

    pub fn sigma2(&self) -> &EdwardsPoint {
        &self.sigma2
    }

    pub fn sigma3(&self) -> &EdwardsPoint {
        &self.sigma3
    }
    pub fn sign(msg: &[u8], sk: &Scalar, Y: &EdwardsPoint) -> Result<Self, CryptoError> {
        let mut hasher = Blake3Adapter::new();
        hasher.update(b"revocable-signature-v1");
        hasher.update(msg);
        hasher.update(Y.compress().as_bytes());
        let h = Scalar::from_hash(hasher);
        if h == Scalar::ZERO {
            return Err(CryptoError::ParameterError);
        }
        let r = h + sk;
        let sigma1 = ED25519_BASEPOINT_POINT * r;
        let sigma3 = *Y;
        let h_inv = h.invert();
        let sigma2 = (sigma1 + (*Y * sk)) * h_inv;
        Ok(Self {
            sigma1,
            sigma2,
            sigma3,
        })
    }

    pub fn verify(
        msg: &[u8],
        pk: &EdwardsPoint,
        Y: &EdwardsPoint,
        sig: &Self,
    ) -> Result<(), CryptoError> {
        let mut hasher = Blake3Adapter::new();
        hasher.update(b"revocable-signature-v1");
        hasher.update(msg);
        hasher.update(Y.compress().as_bytes());
        let h = Scalar::from_hash(hasher);
        if sig.sigma1 - (ED25519_BASEPOINT_POINT * h) != *pk {
            return Err(CryptoError::VerificationError);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedSig {
    delta1: Scalar,
    delta2: Scalar,
    delta3: EdwardsPoint,
    delta4: Scalar,
    delta5: Scalar,
}

impl ConfirmedSig {
    pub fn confirm(
        msg: &[u8],
        sk: &Scalar,
        gamma: &[EdwardsPoint],
        sig: &WithdrawableSig,
    ) -> Result<Self, CryptoError> {
        let mut hasher = Blake3Adapter::new();
        hasher.update(b"revocable-signature-v1");
        hasher.update(msg);
        let r_prime = Scalar::from_hash(hasher);

        if gamma.len() < 2 {
            return Err(CryptoError::ParameterError);
        }
        let es = rfc6979_nonce(sk, msg, b"es");
        let tj = Self::hash_pubkey(&gamma[1], es)?;
        let zj = es - r_prime * tj;
        let ts = rfc6979_nonce(sk, msg, b"ts");
        let zs = es - r_prime * ts;

        Ok(Self {
            delta1: ts,
            delta2: zs - r_prime * ts,
            delta3: sig.sigma3,
            delta4: tj,
            delta5: zj,
        })
    }

    fn hash_pubkey(pk: &EdwardsPoint, e: Scalar) -> Result<Scalar, CryptoError> {
        let mut hasher = Blake3Adapter::new();
        hasher.update(b"revocable-signature-v1");
        hasher.update(pk.compress().as_bytes());
        hasher.update(&e.to_bytes());
        Ok(Scalar::from_hash(hasher))
    }
}

#[derive(Serialize, Deserialize)]
pub struct Ballot {
    pub R: EdwardsPoint,
    pub P: EdwardsPoint,
    pub sigma: WithdrawableSig,
    pub bids: Vec<[u8; 32]>,
}

pub fn cast_vote_ext(
    pp: &PublicParams,
    r: &[u8; 8],
    candidate_pubkeys: &[EdwardsPoint],
    voter: &KeyPair,
    Y: &EdwardsPoint,
    message: &[u8],
) -> Result<Ballot, CryptoError> {
    let mut gamma = vec![*Y];
    gamma.extend_from_slice(candidate_pubkeys);
    let sigma = WithdrawableSig::sign(message, &voter.secret, Y)?;
    let mut bids = Vec::with_capacity(candidate_pubkeys.len());
    let mut rng = OsRng;
    for _ in 0..candidate_pubkeys.len() {
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let mut hasher = Hasher::new();
        hasher.update(&buf);
        let digest = hasher.finalize();
        let mut bid = [0u8; 32];
        bid.copy_from_slice(digest.as_bytes());
        bids.push(bid);
    }
    Ok(Ballot {
        R: sigma.sigma1,
        P: sigma.sigma2,
        sigma,
        bids,
    })
}

#[derive(Serialize, Deserialize)]
pub struct Timelock {
    pub B: EdwardsPoint,
    pub sigma: ConfirmedSig,
    pub C: EdwardsPoint,
    pub proof: ZKProof,
    pub allowed_revocations: u32,
    pub current_revocations: u32,
    pub revocation_timelock: Duration,
    pub last_revocation: Option<SystemTime>,
}

impl Timelock {
    pub fn new(
        B: EdwardsPoint,
        sigma: ConfirmedSig,
        C: EdwardsPoint,
        proof: ZKProof,
        allowed_revocations: u32,
        revocation_timelock: Duration,
    ) -> Self {
        Self {
            B,
            sigma,
            C,
            proof,
            allowed_revocations,
            current_revocations: 0,
            revocation_timelock,
            last_revocation: None,
        }
    }

    pub fn revoke(&mut self) -> Result<(), CryptoError> {
        let now = SystemTime::now();
        if self.current_revocations >= self.allowed_revocations {
            return Err(CryptoError::RevocationError);
        }
        if let Some(last) = self.last_revocation {
            if now.duration_since(last).unwrap_or(Duration::ZERO) < self.revocation_timelock {
                return Err(CryptoError::RevocationError);
            }
        }
        self.current_revocations += 1;
        self.last_revocation = Some(now);
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
pub struct ZKProof {
    range_proof: RangeProof,
    v_commitments: Vec<CompressedRistretto>, // 存储 Pedersen 承诺
}

impl ZKProof {
    pub fn zk_prove(witness: Scalar) -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        let bp_gens = BulletproofGens::new(64, 16);
        let pedersen_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"ZKProof");

        // 将 witness 转换为字节并生成 u64 数组
        let witness_bytes = witness.to_bytes(); // 32 字节
        let witness_vals: Vec<u64> = witness_bytes
            .chunks(8) // 每 8 个字节一个 u64
            .map(|chunk| {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(chunk);
                u64::from_le_bytes(arr) // 使用 little-endian 字节序转换为 u64
            })
            .collect();

        // 输出 witness_vals 以进行调试
        //println!("Witness values: {:?}", witness_vals);

        // 为每个 witness 值生成随机的盲因子，确保 v_blinding 的长度与 witness_vals 匹配
        let v_blinding: Vec<Scalar> = (0..witness_vals.len())
            .map(|_| Scalar::random(&mut rng))
            .collect();

        // 输出盲因子以进行调试
        //println!("Blinding factors: {:?}", v_blinding);

        // 检查 witness_vals 和 v_blinding 长度是否一致
        if witness_vals.len() != v_blinding.len() {
            error!("Error: witness_vals and v_blinding length mismatch!");
            return Err(CryptoError::ZKPError);
        }

        // 生成范围证明
        let (range_proof, v_commitments) = RangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pedersen_gens,
            &mut transcript,
            &witness_vals,
            &v_blinding,
            64, // 64位范围证明
            &mut rng,
        )
        .map_err(|_| CryptoError::ZKPError)?;

        // 输出生成的范围证明和承诺
        //println!("Range proof generated: {:?}", range_proof);
        //println!("Commitments generated: {:?}", v_commitments);

        Ok(Self {
            range_proof,
            v_commitments,
        })
    }

    pub fn zk_verify(&self) -> Result<(), CryptoError> {
        let mut transcript = Transcript::new(b"ZKProof");
        let pedersen_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 16);

        // 验证范围证明
        self.range_proof
            .verify_multiple_with_rng(
                &bp_gens,
                &pedersen_gens,
                &mut transcript,
                &self.v_commitments,
                64,
                &mut OsRng,
            )
            .map_err(|_| CryptoError::ZKPError)
    }
}

pub fn f_open(ballot: &Ballot, Y: &EdwardsPoint) -> Result<ConfirmedSig, CryptoError> {
    let gamma = vec![*Y, ballot.P]; // Use full candidate set

    let sigma_scalar = Scalar::from_bytes_mod_order(ballot.sigma.sigma1.compress().to_bytes());

    ConfirmedSig::confirm(b"F.Open", &sigma_scalar, &gamma, &ballot.sigma)
}

pub fn extract_witness(
    Y: &EdwardsPoint,
    presig: &WithdrawableSig,
    fullsig: &ConfirmedSig,
) -> Scalar {
    let mut adapter = Blake3Adapter::new();
    adapter.update(Y.compress().as_bytes());
    adapter.update(&presig.sigma1.compress().to_bytes());
    adapter.update(&fullsig.delta1.to_bytes());
    Scalar::from_hash(adapter)
}

pub fn tally(timelock: &Timelock) -> (Vec<[u8; 32]>, ConfirmedSig) {
    info!("正在进行投票统计...");
    let mut identifiers = Vec::new();
    identifiers.push(timelock.B.compress().to_bytes());
    (identifiers, timelock.sigma.clone())
}

pub fn link_votes(ballot1: &Ballot, ballot2: &Ballot) -> u8 {
    if ballot1.sigma.sigma1.compress().to_bytes() == ballot2.sigma.sigma1.compress().to_bytes() {
        1
    } else {
        0
    }
}

pub fn time_sync() -> Box<[u8]> {
    let ntp_servers = vec![
        "ntp.aliyun.com",
        "ntp.tencent.com",
        "time.google.com",
        "pool.ntp.org",
        "time.cloudflare.com",
        "time.apple.com",
        "time.windows.com",
        "ntp.ntsc.ac.cn",
        "sgp.ntp.org.cn",
        "cn.pool.ntp.org",
        "north-america.pool.ntp.org",
        "africa.pool.ntp.org",
        "europe.pool.ntp.org",
    ];

    let client = SntpClient::new();
    for server in ntp_servers {
        if let Ok(result) = client.synchronize(server) {
            if let Ok(ntp_datetime) = result.datetime().into_chrono_datetime() {
                return ntp_datetime.timestamp().to_le_bytes().into();
            }
        }
    }

    // 如果所有 NTP 服务器都失败，返回本地时间
    Local::now().timestamp().to_le_bytes().into()
}
