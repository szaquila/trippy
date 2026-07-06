use std::collections::{HashMap, HashSet};
use trippy_core::Hop;

/// 后台验证：根据选中路由，逐跳验证哪些地址应该可见
///
/// 返回需要从 hidden 集合中移除的 (ttl, addr_idx) 列表
pub fn verify_visible_addrs(
    hops: &[&Hop],
    selections: &HashMap<u8, usize>,
    hidden: &HashSet<(u8, usize)>,
) -> Vec<(u8, usize)> {
    let hops_data: Vec<(u8, usize, Vec<(usize, usize)>)> = hops.iter().map(|h| {
        let addrs: Vec<(usize, usize)> = h.addrs_with_counts()
            .enumerate()
            .map(|(i, (_, &c))| (i, c))
            .collect();
        (h.ttl(), h.addr_count(), addrs)
    }).collect();
    verify_from_data(&hops_data, selections, hidden)
}

/// 从预提取的数据验证（可脱离 Hop 引用在后台线程运行）
pub fn verify_from_data(
    hops_data: &[(u8, usize, Vec<(usize, usize)>)],
    selections: &HashMap<u8, usize>,
    hidden: &HashSet<(u8, usize)>,
) -> Vec<(u8, usize)> {
    if selections.is_empty() || hidden.is_empty() {
        return vec![];
    }

    let first_ttl = selections.keys().min().copied().unwrap_or(0);

    // 从选中跳开始，逐跳验证
    let mut verified: Vec<(u8, usize)> = Vec::new();
    let mut valid_counts: Vec<usize> = Vec::new();

    // 初始化：选中跳的选中地址计数
    for (&ttl, &sel_idx) in selections {
        if let Some((_, _, addrs)) = hops_data.iter().find(|(t, _, _)| *t == ttl) {
            if let Some((_, count)) = addrs.get(sel_idx) {
                valid_counts.push(*count);
                for addr_idx in 0..addrs.len() {
                    if hidden.contains(&(ttl, addr_idx)) {
                        verified.push((ttl, addr_idx));
                    }
                }
            }
        }
    }

    // 逐跳向下验证
    for &(ttl, _, ref addrs) in hops_data {
        if ttl <= first_ttl || selections.contains_key(&ttl) {
            continue;
        }
        if addrs.is_empty() {
            continue;
        }

        let mut new_valid_counts = Vec::new();
        for &(addr_idx, count) in addrs {
            // 检查是否与任一有效计数兼容
            let compatible = valid_counts.iter().any(|&base| {
                let diff = (count as isize - base as isize).unsigned_abs();
                let threshold = (base as f64 * 0.5).max(2.0) as usize;
                diff <= threshold
            });
            if compatible {
                new_valid_counts.push(count);
                if hidden.contains(&(ttl, addr_idx)) {
                    verified.push((ttl, addr_idx));
                }
            }
        }

        if !new_valid_counts.is_empty() {
            valid_counts = new_valid_counts;
        }
    }

    verified
}
