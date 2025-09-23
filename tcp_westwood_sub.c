// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP Westwood+: end-to-end bandwidth estimation for TCP
 *
 *      Angelo Dell'Aera: author of the first version of TCP Westwood+ in Linux 2.4
 *
 * Support at http://c3lab.poliba.it/index.php/Westwood
 * Main references in literature:
 *
 * - Mascolo S, Casetti, M. Gerla et al.
 *   "TCP Westwood: bandwidth estimation for TCP" Proc. ACM Mobicom 2001
 *
 * - A. Grieco, s. Mascolo
 *   "Performance evaluation of New Reno, Vegas, Westwood+ TCP" ACM Computer
 *     Comm. Review, 2004
 *
 * - A. Dell'Aera, L. Grieco, S. Mascolo.
 *   "Linux 2.4 Implementation of Westwood+ TCP with Rate-Halving :
 *    A Performance Evaluation Over the Internet" (ICC 2004), Paris, June 2004
 *
 * Westwood+ employs end-to-end bandwidth measurement to set cwnd and
 * ssthresh after packet loss. The probing phase is as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <net/tcp.h>
#include <linux/win_minmax.h>

#define WESTWOOD_BW_FILTER_WINDOW   10    /* BBR启发的时间窗口 */
#define WESTWOOD_RTT_FILTER_WINDOW  10    
#define WESTWOOD_PROBE_RTT_INTERVAL (10 * HZ)  
#define WESTWOOD_IDLE_RESTART_THRESH (1000)    /* 1秒空闲重启测量 */
#define WESTWOOD_PACING_RATE_RATIO  110        /* 1.1倍测量带宽，保守 */

struct westwood {
    /* 带宽测量 - 统计方法 */
    struct minmax bw;              /* 窗口内最大带宽 (bytes/sec) */
    u32    bw_sample_count;
    
    /* RTT测量 */
    u32    min_rtt_us;             /* 窗口内最小RTT */
    u32    min_rtt_stamp;
    u32    rtt_sample_count;
    
    /* 状态维护 */
    u32    prior_cwnd;             /* 仅用于undo */
    u32    last_sample_time;
    
    /* 鲁棒性控制 */
    u32    probe_rtt_done_stamp;
    
    /* 统计信息 */
    u32    bw_samples_total;
    u32    rtt_samples_total;
    u32    ca_events_total;        /* 拥塞事件计数 */
};

static void westwood_reset_measurements(struct westwood *w)
{
    w->min_rtt_us = ~0U;
    w->bw_sample_count = 0;
    w->rtt_sample_count = 0;
    w->last_sample_time = 0;
    /* 保留滤波器历史和统计信息，体现统计连续性 */
}

static void tcp_westwood_init(struct sock *sk)
{
    struct westwood *w = inet_csk_ca(sk);
    
    memset(w, 0, sizeof(*w));
    westwood_reset_measurements(w);
    
    minmax_reset(&w->bw, 0, 0);
    
    w->min_rtt_stamp = tcp_jiffies32;
    w->probe_rtt_done_stamp = tcp_jiffies32;
}

/* 核心思想：BDP = BW * minRTT，流的"自然"容量 */
static u32 westwood_bdp_packets(const struct sock *sk, u32 bw_bps, u32 min_rtt_us)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    u64 bdp_bytes;
    
    if (min_rtt_us == ~0U || bw_bps == 0 || tp->mss_cache == 0)
        return 0;
        
    bdp_bytes = div64_u64((u64)bw_bps * min_rtt_us, USEC_PER_SEC);
    
    return max_t(u32, 4, (u32)div_u64(bdp_bytes, tp->mss_cache));
}

static u32 tcp_westwood_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct westwood *w = inet_csk_ca(sk);
    u32 bw_bps, bdp_pkts;
    
    bw_bps = minmax_get(&w->bw);
    bdp_pkts = westwood_bdp_packets(sk, bw_bps, w->min_rtt_us);
    
    if (bdp_pkts == 0) {
        /* 没有有效测量时，采用保守策略 */
        return max_t(u32, 2, tp->snd_cwnd >> 1);
    }
    
    /* 核心思想：收敛到测量的BDP，而非固定比例衰减 */
    return max_t(u32, 2, bdp_pkts);
}

static u32 tcp_westwood_undo_cwnd(struct sock *sk)
{
    const struct westwood *w = inet_csk_ca(sk);
    return max(tcp_sk(sk)->snd_cwnd, w->prior_cwnd);
}

static void tcp_westwood_state(struct sock *sk, u8 new_state)
{
    struct westwood *w = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    
    switch (new_state) {
    case TCP_CA_Recovery:
    case TCP_CA_Loss:
        /* 进入拥塞恢复，记录prior_cwnd用于undo */
        w->prior_cwnd = tp->snd_cwnd;
        w->ca_events_total++;
        break;
    case TCP_CA_CWR:
        /* ECN触发的CWR状态 */
        w->prior_cwnd = tp->snd_cwnd;
        w->ca_events_total++;
        break;
    default:
        /* 其他状态不需要特殊处理 */
        break;
    }
}

static void westwood_update_min_rtt(struct sock *sk, u32 rtt_us)
{
    struct westwood *w = inet_csk_ca(sk);
    bool rtt_expired;
    
    /* 检查RTT是否过期，需要刷新 */
    rtt_expired = time_after32(tcp_jiffies32,
        w->probe_rtt_done_stamp + WESTWOOD_PROBE_RTT_INTERVAL);
    
    /* 更新最小RTT：取新样本或过期时重置 */
    if (rtt_us < w->min_rtt_us || rtt_expired) {
        w->min_rtt_us = rtt_us;
        w->min_rtt_stamp = tcp_jiffies32;
        if (rtt_expired)
            w->probe_rtt_done_stamp = tcp_jiffies32;
    }
}

/* 核心测量逻辑：体现"统计方法"和"时间换鲁棒性" */
static void westwood_update_bandwidth(struct sock *sk, const struct rate_sample *rs)
{
    struct westwood *w = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u32 time_diff_us;
    u64 bw_sample;
    
    if (rs->delivered <= 0 || rs->interval_us <= 0)
        return;
        
    /* 空闲检测：长时间空闲后重新开始统计 */
    if (w->last_sample_time > 0) {
        time_diff_us = tcp_stamp_us_delta(tp->tcp_mstamp, w->last_sample_time);
        if (time_diff_us > WESTWOOD_IDLE_RESTART_THRESH * USEC_PER_MSEC) {
            westwood_reset_measurements(w);
        }
    }
    
    bw_sample = div64_u64((u64)rs->delivered * tp->mss_cache * USEC_PER_SEC,
                  rs->interval_us);
    
    /* 统计滤波：使用窗口最大值，体现"将鲁棒性交给时间" */
    w->bw_sample_count++;
    w->bw_samples_total++;
    minmax_running_max(&w->bw, WESTWOOD_BW_FILTER_WINDOW,
               w->bw_sample_count, (u32)bw_sample);
    
    w->last_sample_time = tp->tcp_mstamp;
}

static void westwood_update_rtt(struct sock *sk, const struct rate_sample *rs)
{
    struct westwood *w = inet_csk_ca(sk);
    
    if (rs->rtt_us <= 0)
        return;
        
    w->rtt_sample_count++;
    w->rtt_samples_total++;
    
    /* 直接更新最小RTT，避免冗余滤波 */
    westwood_update_min_rtt(sk, rs->rtt_us);
}


/* 设置pacing速率 - 独立函数，职责清晰 */
static void westwood_update_pacing(struct sock *sk)
{
    struct westwood *w = inet_csk_ca(sk);
    
    if (w->min_rtt_us < ~0U) {
        u32 bw_bps = minmax_get(&w->bw);
        if (bw_bps > 0) {
            /* 使用保守的1.1倍测量带宽 */
            sk->sk_pacing_rate = min_t(u64,
                (u64)bw_bps * WESTWOOD_PACING_RATE_RATIO / 100,
                sk->sk_max_pacing_rate);
        }
    }
}

static void tcp_westwood_cong_control(struct sock *sk, u32 ack, int flag,
                      const struct rate_sample *rs)
{
    /* 更新测量数据 - 核心职责 */
    westwood_update_bandwidth(sk, rs);
    westwood_update_rtt(sk, rs);
    
    /* 设置pacing - 基于测量结果 */
    westwood_update_pacing(sk);
}

static void tcp_westwood_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    struct westwood *w = inet_csk_ca(sk);
    
    switch (event) {
    case CA_EVENT_ECN_IS_CE:
    case CA_EVENT_LOSS:
        /* 只记录拥塞事件统计 */
        w->ca_events_total++;
        break;
    default:
        break;
    }
}

static size_t tcp_westwood_get_info(struct sock *sk, u32 ext, int *attr,
                    union tcp_cc_info *info)
{
    const struct westwood *w = inet_csk_ca(sk);
    
    if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
        info->vegas.tcpv_enabled = 1;                    /* 算法启用状态 */
        info->vegas.tcpv_rttcnt = w->rtt_samples_total;  /* RTT样本总数 */
        info->vegas.tcpv_rtt = w->min_rtt_us;           /* 当前最小RTT */
        info->vegas.tcpv_minrtt = w->min_rtt_us;        /* 修复：最小RTT值，而非带宽 */
        
        *attr = INET_DIAG_VEGASINFO;
        return sizeof(struct tcpvegas_info);
    }
    return 0;
}

static struct tcp_congestion_ops tcp_westwood __read_mostly = {
    .init           = tcp_westwood_init,
    .ssthresh       = tcp_westwood_ssthresh,
    .cong_control   = tcp_westwood_cong_control,
    .undo_cwnd      = tcp_westwood_undo_cwnd,
    .set_state      = tcp_westwood_state,
    .cwnd_event     = tcp_westwood_cwnd_event,
    .get_info       = tcp_westwood_get_info,
    .owner          = THIS_MODULE,
    .name           = "westwood_sub"
};

static int __init tcp_westwood_register(void)
{
    BUILD_BUG_ON(sizeof(struct westwood) > ICSK_CA_PRIV_SIZE);
    return tcp_register_congestion_control(&tcp_westwood);
}

static void __exit tcp_westwood_unregister(void)
{
    tcp_unregister_congestion_control(&tcp_westwood);
}

module_init(tcp_westwood_register);
module_exit(tcp_westwood_unregister);

MODULE_AUTHOR("Stephen Hemminger, Angelo Dell'Aera");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Westwood+");
