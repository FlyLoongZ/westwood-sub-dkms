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

#define CAL_SCALE 8
#define CAL_UNIT (1 << CAL_SCALE)

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

/* Westwood+ algorithm parameters */
#define WESTWOOD_RTT_MAX_US           500000    /* 500ms max RTT for BDP calc */
#define WESTWOOD_RTT_INIT_US          100000    /* 100ms initial RTT */
#define WESTWOOD_BW_WINDOW_RTT        20    /* bandwidth estimation window */
#define WESTWOOD_BW_MIN_SAMPLES       2    /* minimum samples for reliable BW */
#define WESTWOOD_STALE_TIMEOUT_SEC    10    /* stale sample timeout */

/* Pacing rate parameters */
#define WESTWOOD_PACING_GAIN_NORMAL      90    /* 90% of estimated BW in normal state */
#define WESTWOOD_PACING_GAIN_RECOVERY    80    /* 80% of estimated BW during recovery */
#define WESTWOOD_PACING_DEGRADE_RATE     90    /* 90% when degrading stale samples */
#define WESTWOOD_INITIAL_PACING_MS       100    /* 1 MSS per 100ms initial pacing */
#define WESTWOOD_MIN_PACING_MS           200    /* 1 MSS per 200ms minimum pacing */

static int debug = 0;
module_param(debug, int, 0644);

/* TCP Westwood structure */
struct westwood {
    u32    last_bdp;
    u32    rtt;
    u32    min_rtt_us;          /* minimum observed RTT */
    u32    rtt_cnt;
    u32    next_rtt_delivered;
    struct minmax bw;
    u32    prior_cwnd;
    u8     prev_ca_state;
    u32    app_limited;         /* detect application-limited periods */
    u64    last_bw_sample;      /* last bandwidth sample */
    u32    bw_sample_cnt;       /* bandwidth sample count */
    u32    last_bw_sample_time; /* time of last bandwidth sample */
};

/*
 * @tcp_westwood_create
 * This function initializes fields used in TCP Westwood+,
 * it is called after the initial SYN, so the sequence numbers
 * are correct but new passive connections we have no
 * information about RTTmin at this time so we simply set it to
 * TCP_WESTWOOD_INIT_RTT. This value was chosen to be too conservative
 * since in this way we're sure it will be updated in a consistent
 * way as soon as possible. It will reasonably happen within the first
 * RTT period of the connection lifetime.
 */
/* Calculate BDP (Bandwidth-Delay Product) in packets */
static u32 tcp_westwood_bdp(struct westwood *w)
{
    u64 bw, bdp;

    if (w->min_rtt_us >= WESTWOOD_RTT_MAX_US || w->bw_sample_cnt < WESTWOOD_BW_MIN_SAMPLES)
        return 0;

    bw = minmax_get(&w->bw);
    if (bw == 0)
        return 0;

    /* bw is in (bytes * BW_UNIT) / us, min_rtt_us is in us */
    /* bdp = bw * min_rtt_us / BW_UNIT gives bytes */
    bdp = (u64)bw * w->min_rtt_us;
    do_div(bdp, BW_UNIT);

    return max_t(u32, 2, (u32)bdp);
}

static void tcp_westwood_init(struct sock *sk)
{
    struct westwood *w = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u64 initial_pacing_rate;

    w->last_bdp = TCP_INIT_CWND;
    w->prior_cwnd = TCP_INIT_CWND;
    w->min_rtt_us = WESTWOOD_RTT_INIT_US;
    w->rtt_cnt = 0;
    minmax_reset(&w->bw, w->rtt_cnt, 0);
    w->next_rtt_delivered = 0;
    w->app_limited = 0;
    w->last_bw_sample = 0;
    w->bw_sample_cnt = 0;
    w->last_bw_sample_time = tcp_jiffies32;

    /* Set initial conservative pacing rate from the start */
    initial_pacing_rate = div_u64((u64)tp->mss_cache * USEC_PER_SEC, WESTWOOD_INITIAL_PACING_MS * 1000);
    sk->sk_pacing_rate = min_t(u64, initial_pacing_rate, sk->sk_max_pacing_rate);
}

static void tcp_westwood_event(struct sock *sk, enum tcp_ca_event event)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct westwood *w = inet_csk_ca(sk);

    switch (event) {
    case CA_EVENT_COMPLETE_CWR:
        tp->snd_cwnd = tp->snd_ssthresh = w->last_bdp;
        break;
    default:
        /* don't care */
        break;
    }
}

static void tcp_westwood_state(struct sock *sk, u8 new_state)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (new_state == TCP_CA_Loss) {
        tp->snd_cwnd = tcp_packets_in_flight(tp) + 1;
    }
}

static u32 tcp_westwood_undo_cwnd(struct sock *sk)
{
    struct westwood *w = inet_csk_ca(sk);
    u32 bdp = tcp_westwood_bdp(w);

    if (bdp > 0)
        return max_t(u32, bdp, w->prior_cwnd);

    /* Fallback to conservative undo */
    return max_t(u32, 2, w->prior_cwnd);
}

static u32 tcp_westwood_ssthresh(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct westwood *w = inet_csk_ca(sk);
    u32 bdp;

    w->prior_cwnd = tp->snd_cwnd;
    bdp = tcp_westwood_bdp(w);

    if (bdp > 0) {
        /* Pure Westwood: use full BDP as ssthresh, not half */
        w->last_bdp = bdp;
        tp->snd_ssthresh = bdp;
        return bdp;
    }

    /* Fallback to standard behavior */
    return max_t(u32, 2, tp->snd_cwnd >> 1);
}

static void tcp_westwood_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct westwood *w = inet_csk_ca(sk);
    u8 prev_state = w->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
    u64 bw = 0, pacing_rate = 0;

    if (!before(rs->prior_delivered, w->next_rtt_delivered)) {
        w->next_rtt_delivered = tp->delivered;
        w->rtt_cnt++;
    }

    /* Enhanced bandwidth estimation with better sampling */
    if (rs->delivered > 0 && rs->interval_us > 0) {
        bw = (u64)rs->delivered * BW_UNIT;
        do_div(bw, rs->interval_us);

        /* Improved bandwidth estimation: always filter out application-limited samples */
        if (!rs->is_app_limited) {
            minmax_running_max(&w->bw, WESTWOOD_BW_WINDOW_RTT, w->rtt_cnt, bw);
            w->last_bw_sample = bw;
            w->bw_sample_cnt++;
            w->last_bw_sample_time = tcp_jiffies32;
        }

        /* Track application-limited periods for better BDP estimation */
        w->app_limited = rs->is_app_limited ? 1 : 0;

        /* Set pacing rate based on estimated bandwidth - simplified */
        pacing_rate = minmax_get(&w->bw);
        if (pacing_rate > 0) {
            /* Convert from (Bytes * BW_UNIT) / us to Bytes/s */
            pacing_rate = div_u64(pacing_rate * USEC_PER_SEC, BW_UNIT);

            /* Apply gain based on congestion state */
            if (state == TCP_CA_Recovery)
                pacing_rate = (pacing_rate * WESTWOOD_PACING_GAIN_RECOVERY) / 100;
            else
                pacing_rate = (pacing_rate * WESTWOOD_PACING_GAIN_NORMAL) / 100;

            sk->sk_pacing_rate = min_t(u64, pacing_rate, sk->sk_max_pacing_rate);
        } else {
            /* Initial conservative pacing rate when no bandwidth samples */
            pacing_rate = div_u64((u64)tp->mss_cache * USEC_PER_SEC,
                        WESTWOOD_INITIAL_PACING_MS * 1000);
            sk->sk_pacing_rate = min_t(u64, pacing_rate, sk->sk_max_pacing_rate);
        }
    } else {
        /* Handle stale bandwidth samples - simplified degradation */
        u32 time_since_last_sample = tcp_jiffies32 - w->last_bw_sample_time;
        if (w->bw_sample_cnt > 0 && time_since_last_sample > WESTWOOD_STALE_TIMEOUT_SEC * HZ) {
            pacing_rate = sk->sk_pacing_rate;
            if (pacing_rate > 0) {
                u64 min_pacing;
                /* Gradually reduce pacing rate */
                pacing_rate = (pacing_rate * WESTWOOD_PACING_DEGRADE_RATE) / 100;
                /* Ensure minimum pacing rate */
                min_pacing = div_u64((u64)tp->mss_cache * USEC_PER_SEC,
                            WESTWOOD_MIN_PACING_MS * 1000);
                pacing_rate = max_t(u64, pacing_rate, min_pacing);
                sk->sk_pacing_rate = min_t(u64, pacing_rate, sk->sk_max_pacing_rate);
            }
        }
    }

    if (rs->rtt_us > 0 && rs->rtt_us < w->min_rtt_us)
        w->min_rtt_us = rs->rtt_us;

    w->prev_ca_state = state;
    if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
        /* ssthresh is already set by tcp_westwood_ssthresh() callback */
        /* Just update our last_bdp for consistency */
        w->last_bdp = tcp_westwood_bdp(w);
        if (w->last_bdp == 0)
            w->last_bdp = max_t(u32, TCP_INIT_CWND, tp->snd_cwnd >> 1);
    } else if (state == TCP_CA_Open && prev_state != TCP_CA_Open) {
        /* Smooth transition to open state */
        if (w->last_bdp > 0) {
            tp->snd_cwnd = min_t(u32, w->last_bdp, tp->snd_cwnd + (tp->snd_cwnd >> 2));
        }
    } else if (state == TCP_CA_Open) {
        /* Enhanced congestion avoidance with BDP awareness */
        if (w->last_bdp > 0 && tp->snd_cwnd < w->last_bdp) {
            /* Fast convergence to BDP when under-utilizing */
            tcp_cong_avoid_ai(tp, w->last_bdp, rs->acked_sacked);
        } else {
            /* Standard Reno behavior when near or above BDP */
            tcp_reno_cong_avoid(sk, 0, rs->acked_sacked);
        }
    }
    if (debug)
        printk("##st:%d->%d bw:%llu last_bdp:%d cwnd:%d minrtt:%d pacing:%lu\n",
            prev_state, state, bw, w->last_bdp, tp->snd_cwnd, w->min_rtt_us, sk->sk_pacing_rate);
}

/* Extract info for Tcp socket info provided via netlink. */
static size_t tcp_westwood_info(struct sock *sk, u32 ext, int *attr,
                union tcp_cc_info *info)
{
    const struct westwood *ca = inet_csk_ca(sk);

    if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
        info->vegas.tcpv_enabled = 1;
        info->vegas.tcpv_rttcnt    = 0;
        info->vegas.tcpv_rtt    = jiffies_to_usecs(ca->rtt);
        info->vegas.tcpv_minrtt    = ca->min_rtt_us;

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
    .cwnd_event     = tcp_westwood_event,
    .get_info       = tcp_westwood_info,
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
