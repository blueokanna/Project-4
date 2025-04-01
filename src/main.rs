use std::time::{Duration, SystemTime};
use chrono::Local;
use curve25519_dalek::Scalar;
use log::{error, info, LevelFilter};
use rand::rngs::OsRng;
use LiuProject2::{cast_vote_ext, link_votes, tally, time_sync, ConfirmedSig, CryptoError, EAKeyPair, KeyPair, PublicParams, Timelock, WithdrawableSig, ZKProof};

/// -------------- 以下 main() 展示整个电子投票流程 --------------
///
/// 流程说明：
/// 1. Setup：调用 setup() 初始化公共参数和选举机构密钥对
/// 2. Register：选民调用 register() 进行登记，获得自己的密钥及加密密钥对
/// 3. Cast：选民调用 cast_vote_ext() 生成匿名投票，产生预签名
/// 4. Adaptor：候选人对选票执行适配，生成全签名、承诺及时间锁（模拟 adaptor()）
/// 5. F.Open：候选人调用 f_open() 从预签名中获得全签名
/// 6. Ext：候选人与选民交互后调用 extract_witness() 提取证人
/// 7. Tally：智能合约调用 tally() 统计选票
/// 8. Link：调用 link_votes() 判断两票是否来自同一选民
fn main() -> Result<(), CryptoError> {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    // ------------------- 1) Setup -------------------
    // 设置公共参数，包含安全参数、候选人数量、选民数量等
    let pp = PublicParams {
        security_param: 256,  // 安全参数 λ，影响加密强度
        candidate_num: 2,     // 候选人数量
        voter_num: 10000,     // 选民数量
        time_difficulty: 10,  // 时间难度（可根据系统需求调整）
        event: time_sync().to_vec(), // 事件标识，基于当前时间同步获取
    };
    // 生成选举机构的密钥对（EA密钥对）
    let ea_keys = EAKeyPair::generate();
    info!("Setup 完成，公共参数和选举机构密钥已生成。");

    // ------------------- 2) Register -------------------
    // 生成两个选民的密钥对，模拟选民注册
    let voter1_keypair = KeyPair::generate(); // 选民1的密钥对
    let voter2_keypair = KeyPair::generate(); // 选民2的密钥对
    let voter1_id = "voter_001"; // 选民1的ID
    let voter2_id = "voter_002"; // 选民2的ID
    info!(
        "选民 {} 和 {} 登记成功，密钥对已生成。",
        voter1_id, voter2_id
    );

    // ------------------- 3) Cast -------------------
    // 选民投票过程：使用选民的私钥生成签名并投票
    let message = b"I wanna vote A"; // 投票消息
    let r = [0u8; 8];  // 随机数（示例中未做实际生成）
    let candidate1 = ea_keys.public; // 第一个候选人的公钥（选举机构的公钥）
    let candidate2 = KeyPair::generate().public; // 第二个候选人的公钥
    let candidates = vec![candidate1, candidate2]; // 候选人列表
    let Y = candidate1; // 选举机构的公钥（作为环签名的部分）

    // ------------------- 投票1 -------------------
    // 选民1进行投票
    let ballot1 = cast_vote_ext(&pp, &r, &candidates, &voter1_keypair, &Y, message)?;
    info!(
        "选民1 投票成功，匿名地址 R: {:?}，预签名 P: {:?}",
        ballot1.R.compress(),
        ballot1.P.compress()
    );

    // ------------------- 投票2 -------------------
    // 选民2进行投票
    let ballot2 = cast_vote_ext(&pp, &r, &candidates, &voter2_keypair, &Y, message)?;
    info!(
        "选民2 投票成功，匿名地址 R: {:?}，预签名 P: {:?}",
        ballot2.R.compress(),
        ballot2.P.compress()
    );

    // ------------------- 4) Link -------------------
    // 链接验证：检测两个选票是否来自同一选民
    let same_voter = link_votes(&ballot1, &ballot1); // 比较同一选民
    let different_voter = link_votes(&ballot1, &ballot2); // 比较不同选民

    // 打印链接检测结果
    info!("Link 检测结果：");
    info!("  - 同一选民返回: {}", same_voter); // 应为1
    info!("  - 不同选民返回: {}", different_voter); // 应为0

    // ------------------- 5) 投票信息展示 -------------------
    // 显示投票的详细信息，例如候选人的公钥、选民的匿名地址等
    info!("投票详细信息:");
    for (i, ballot) in vec![ballot1, ballot2].iter().enumerate() {
        info!(
            "选民 {} 的投票详情：",
            i + 1
        );
        info!("  - 匿名地址 R: {:?}", ballot.R.compress());
        info!("  - 预签名 P: {:?}", ballot.P.compress());
        info!("  - 随机生成的标识符（bids）：{:?}", ballot.bids);
        println!("\n");
    }

    // ------------------- 6) 确认签名 -------------------
    // 模拟候选人使用私钥对选票进行确认签名（承诺与零知识证明）
    let gamma = vec![Y, candidate1, candidate2]; // 将选举机构公钥与候选人公钥组成环
    let sig = WithdrawableSig::sign(message, &voter1_keypair.secret, &Y)?;

    // 对选票进行确认签名，确保其有效性
    let confirmed_sig = ConfirmedSig::confirm(
        b"F.Open",
        &voter1_keypair.secret,
        &gamma,
        &sig,
    )?;

    info!("选民1的确认签名已生成：{:?}", confirmed_sig);

    // ------------------- 7) 撤销机制 -------------------
    // 演示撤销签名：在这个例子中我们模拟撤销操作
    let mut timelock = Timelock::new(
        candidate1,
        confirmed_sig.clone(),
        candidate2,
        ZKProof::zk_prove(Scalar::random(&mut OsRng))?,
        1, // 最大撤销次数
        Duration::new(360, 0), // 撤销时间锁为6分钟
    );

    // 尝试撤销一次
    match timelock.revoke() {
        Ok(()) => info!("撤销操作成功"),
        Err(e) => error!("撤销操作失败: {}", e),
    }

    // ------------------- 8) Time Sync -------------------
    // 时间同步：通过NTP获取准确时间（用于时间锁等功能）
    let synced_time = time_sync();

    // Ensure that synced_time has at least 8 bytes
    if synced_time.len() >= 8 {
        let synced_time_u64 = u64::from_le_bytes(synced_time[0..8].try_into().unwrap()); // Convert the first 8 bytes
        info!(
            "同步时间成功：{:?}",
            SystemTime::UNIX_EPOCH + Duration::from_secs(synced_time_u64)
        );
    } else {
        error!("同步时间获取失败，返回本地时间");
        let local_time = Local::now().timestamp();
        info!(
            "本地时间：{:?}",
            SystemTime::UNIX_EPOCH + Duration::from_secs(local_time as u64)
        );
    }

    // ------------------- 9) 投票统计 -------------------
    // 调用 tally 函数，传递 Timelock 实例
    let (bids, final_sig) = tally(&timelock);

    // 打印投票统计结果
    info!("投票统计结果：");
    info!("  - 所有标识符：{:?}", bids);
    info!("  - 最终签名：{:?}", final_sig);

    Ok(())
}

