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

/* Constants for clarity and tunability */
#define WESTWOOD_BW_FILTER_WINDOW   10  /* Bandwidth filter window in RTTs */
#define WESTWOOD_MIN_RTT_EXPIRE_SEC 10  /* Expire min_rtt after 10 seconds */

static int debug = 0;
module_param(debug, int, 0644);

/* TCP Westwood structure */
struct westwood {
    u32    last_bdp;
    u32    min_rtt_us;          /* Minimum RTT observed so far */
    u32    rtt_cnt;
    u32    next_rtt_delivered;
    struct minmax bw;           /* Windowed max-filter for bandwidth */
    u32    prior_cwnd;
    u8     prev_ca_state;
    u32    min_rtt_stamp;       /* Timestamp of the last min_rtt update */
};

static void tcp_westwood_init(struct sock *sk)
{
    struct westwood *w = inet_csk_ca(sk);

    w->last_bdp = 0;
    w->prior_cwnd = 0;
    w->min_rtt_us = ~0U; /* Initialize with max value */
    w->rtt_cnt = 0;
    minmax_reset(&w->bw, w->rtt_cnt, 0);
    w->next_rtt_delivered = 0;
    w->min_rtt_stamp = tcp_jiffies32;
}

/* Westwood doesn't use these callbacks in this simple version */
static void tcp_westwood_event(struct sock *sk, enum tcp_ca_event event) {}
static void tcp_westwood_state(struct sock *sk, u8 new_state) {}

static u32 tcp_westwood_undo_cwnd(struct sock *sk)
{
    struct westwood *w = inet_csk_ca(sk);
    return max_t(u32, tcp_sk(sk)->snd_cwnd, w->prior_cwnd);
}

static u32 tcp_westwood_ssthresh(struct sock *sk)
{
    /* Let cong_control handle ssthresh setting on loss event */
    return tcp_sk(sk)->snd_ssthresh;
}

static void tcp_westwood_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct westwood *w = inet_csk_ca(sk);
    u8 prev_state = w->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
    u64 bw, bdp;

    /* 1. RTT and Bandwidth Sampling (The BBR part) */
    if (!before(rs->prior_delivered, w->next_rtt_delivered)) {
        w->next_rtt_delivered = tp->delivered;
        w->rtt_cnt++;
    }

    if (rs->delivered > 0 && rs->interval_us > 0) {
        bw = (u64)rs->delivered * USEC_PER_SEC;
        do_div(bw, rs->interval_us);
        /* Apply the windowed max-filter for robust bandwidth estimation */
        minmax_running_max(&w->bw, WESTWOOD_BW_FILTER_WINDOW, w->rtt_cnt, bw);
    }

    /* 2. Robust min_rtt Tracking (BBR-inspired robustness) */
    if (rs->rtt_us > 0) {
        /* Update min_rtt if it's a new minimum or if the old one is stale */
        if (rs->rtt_us < w->min_rtt_us ||
            time_after32(tcp_jiffies32, w->min_rtt_stamp + WESTWOOD_MIN_RTT_EXPIRE_SEC * HZ)) {
            w->min_rtt_us = rs->rtt_us;
            w->min_rtt_stamp = tcp_jiffies32;
        }
    }

    w->prev_ca_state = state;

    /* 3. Core Westwood Logic on Packet Loss */
    if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
        w->prior_cwnd = tp->snd_cwnd;

        /* Calculate BDP using robust max-filtered bandwidth and min_rtt */
        if (w->min_rtt_us != ~0U) {
            bw = minmax_get(&w->bw); /* Get Bytes/sec */
            bdp = (bw * w->min_rtt_us);
            do_div(bdp, USEC_PER_SEC); /* BDP in bytes */
            w->last_bdp = max_t(u32, 2, bdp / tp->mss_cache); /* BDP in packets */
        } else {
            /* Fallback if we have no RTT samples yet */
            w->last_bdp = 0;
        }

        /*
         * CRITICAL FIX: Set ssthresh to the calculated BDP, not cwnd/2.
         * This is the essence of Westwood algorithm.
         */
        if (w->last_bdp > 0)
            tp->snd_ssthresh = w->last_bdp;
        else
            tp->snd_ssthresh = max_t(u32, 2, tp->snd_cwnd >> 1);

        /* Let PRR handle the cwnd reduction smoothly */

    } else if (state == TCP_CA_Open) {
        /* 4. Standard Congestion Avoidance (Reno-like Probing) */
        tcp_reno_cong_avoid(sk, 0, rs->acked_sacked);
    }

    /* 5. Add Stable and Smooth Pacing */
    if (tp->srtt_us) {
        u64 rate = (u64)tp->snd_cwnd * tp->mss_cache * USEC_PER_SEC;
        do_div(rate, tp->srtt_us >> 3); /* srtt_us is in 1/8 us */
        sk->sk_pacing_rate = min_t(u64, rate, sk->sk_max_pacing_rate);
    }

    if (debug)
        printk("##st:%d->%d bw:%llu max_bw:%u bdp:%u cwnd:%d ssthresh:%d min_rtt:%u pacing:%lu\n",
            prev_state, state, bw, minmax_get(&w->bw), w->last_bdp,
            tp->snd_cwnd, tp->snd_ssthresh, w->min_rtt_us, sk->sk_pacing_rate);
}

static struct tcp_congestion_ops tcp_westwood __read_mostly = {
    .init           = tcp_westwood_init,
    .ssthresh       = tcp_westwood_ssthresh,
    .cong_control   = tcp_westwood_cong_control,
    .undo_cwnd      = tcp_westwood_undo_cwnd,
    .set_state      = tcp_westwood_state,
    .cwnd_event     = tcp_westwood_event,
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
