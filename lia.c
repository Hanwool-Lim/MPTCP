/*
 *	MPTCP implementation - Linked Increase congestion control Algorithm (LIA)
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <asm/div64.h>


/* Scaling is done in the numerator with alpha_scale_num and in the denominator
 * with alpha_scale_den.
 *
 * To downscale, we just need to use alpha_scale.
 *
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den ^ 2)
 */
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

//add
#define ALPHA_SHIFT	7
#define ALPHA_SCALE	(1u<<ALPHA_SHIFT)
#define ALPHA_MIN	((3*ALPHA_SCALE)/10)	/* ~0.3 */
#define ALPHA_MAX	(10*ALPHA_SCALE)	/* 10.0 */
#define ALPHA_BASE	ALPHA_SCALE		/* 1.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

//add
#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/10)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

static int win_thresh __read_mostly = 15;
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");

struct mptcp_ccc {
	u64	alpha;
	bool	forced_update;
	
	//add
	u64	sum_rtt;	/* sum of rtt's measured within last rtt */
	u16	cnt_rtt;	/* # of rtts measured within last rtt */
	u32	base_rtt;	/* min of all rtt in usec */
	u32	max_rtt;	/* max of all rtt in usec */
	u32	end_seq;	/* right edge of current RTT */
	u32	alpha_2;		/* Additive increase */
	u32	beta;		/* Muliplicative decrease */
	u16	acked;		/* # packets acked by current ACK */
	u8	rtt_above;	/* average rtt has gone above threshold */
	u8	rtt_low;	/* # of rtts measurements below threshold */
	
	u32 prev_loss_event_cwnd; //loss cwnd //add
};

static inline int mptcp_ccc_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mptcp_get_alpha(const struct sock *meta_sk)
{
	return ((struct mptcp_ccc *)inet_csk_ca(meta_sk))->alpha;
}

static inline void mptcp_set_alpha(const struct sock *meta_sk, u64 alpha)
{
	((struct mptcp_ccc *)inet_csk_ca(meta_sk))->alpha = alpha;
}

static inline u64 mptcp_ccc_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline bool mptcp_get_forced(const struct sock *meta_sk)
{
	return ((struct mptcp_ccc *)inet_csk_ca(meta_sk))->forced_update;
}

static inline void mptcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct mptcp_ccc *)inet_csk_ca(meta_sk))->forced_update = force;
}

//add
static void rtt_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_ccc *ca = inet_csk_ca(sk);

	ca->end_seq = tp->snd_nxt;
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;

	/* TODO: age max_rtt? */
}

//add
static void tcp_illinois_init(struct sock *sk)
{
	struct mptcp_ccc *ca = inet_csk_ca(sk);

	ca->alpha_2 = ALPHA_MAX;
	ca->beta = BETA_BASE;
	ca->base_rtt = 0x7fffffff;
	ca->max_rtt = 0;

	ca->acked = 0;
	ca->rtt_low = 0;
	ca->rtt_above = 0;

	rtt_reset(sk);
}

//add
static void tcp_illinois_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct mptcp_ccc *ca = inet_csk_ca(sk);
	s32 rtt_us = sample->rtt_us;

	ca->acked = sample->pkts_acked;

	/* dup ack, no rtt sample */
	if (rtt_us < 0)
		return;

	/* ignore bogus values, this prevents wraparound in alpha math */
	if (rtt_us > RTT_MAX)
		rtt_us = RTT_MAX;

	/* keep track of minimum RTT seen so far */
	if (ca->base_rtt > rtt_us)
		ca->base_rtt = rtt_us;

	/* and max */
	if (ca->max_rtt < rtt_us)
		ca->max_rtt = rtt_us;

	++ca->cnt_rtt;
	ca->sum_rtt += rtt_us;
}

//add
static inline u32 avg_delay(const struct mptcp_ccc *ca)
{
	u64 t = ca->sum_rtt;

	do_div(t, ca->cnt_rtt);
	return t - ca->base_rtt;
}

//add
static inline u32 max_delay(const struct mptcp_ccc *ca)
{
	return ca->max_rtt - ca->base_rtt;
}

static void mptcp_ccc_recalc_alpha(const struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct mptcp_tcp_sock *mptcp;
	int best_cwnd = 0, best_rtt = 0, can_send = 0;
	u64 max_numerator = 0, sum_denominator = 0, alpha = 1;

	if (!mpcb)
		return;

	/* Do regular alpha-calculation for multiple subflows */

	/* Find the max numerator of the alpha-calculation */
	mptcp_for_each_sub(mpcb, mptcp) {
		const struct sock *sub_sk = mptcp_to_sock(mptcp);
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		u64 tmp;

		if (!mptcp_ccc_sk_can_send(sub_sk))
			continue;

		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */
		tmp = div64_u64(mptcp_ccc_scale(sub_tp->snd_cwnd,
				alpha_scale_num), (u64)sub_tp->srtt_us * sub_tp->srtt_us);

		if (tmp >= max_numerator) {
			max_numerator = tmp;
			best_cwnd = sub_tp->snd_cwnd;
			best_rtt = sub_tp->srtt_us;
		}
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sub(mpcb, mptcp) {
		const struct sock *sub_sk = mptcp_to_sock(mptcp);
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!mptcp_ccc_sk_can_send(sub_sk))
			continue;

		sum_denominator += div_u64(
				mptcp_ccc_scale(sub_tp->snd_cwnd,
						alpha_scale_den) * best_rtt,
						sub_tp->srtt_us);
	}
	sum_denominator *= sum_denominator;
	if (unlikely(!sum_denominator)) {
		pr_err("%s: sum_denominator == 0\n", __func__);
		mptcp_for_each_sub(mpcb, mptcp) {
			const struct sock *sub_sk = mptcp_to_sock(mptcp);
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			pr_err("%s: pi:%d, state:%d\n, rtt:%u, cwnd: %u",
			       __func__, sub_tp->mptcp->path_index,
			       sub_sk->sk_state, sub_tp->srtt_us,
			       sub_tp->snd_cwnd);
		}
	}

	alpha = div64_u64(mptcp_ccc_scale(best_cwnd, alpha_scale_num), sum_denominator);

	if (unlikely(!alpha))
		alpha = 1;

exit:
	mptcp_set_alpha(mptcp_meta_sk(sk), alpha);
}

static void mptcp_ccc_init(struct sock *sk)
{
	if (mptcp(tcp_sk(sk))) {
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
		mptcp_set_alpha(mptcp_meta_sk(sk), 1);
		tcp_illinois_init(sk);
		
		ca->prev_loss_event_cwnd = 2U; //add
	}
	
	
	/* If we do not mptcp, behave like reno: return */
}

//add
static u32 alpha(struct mptcp_ccc *ca, u32 da, u32 dm)
{
	u32 d1 = dm / 100;	/* Low threshold */

	if (da <= d1) {
		/* If never got out of low delay zone, then use max */
		if (!ca->rtt_above)
			return ALPHA_MAX;

		/* Wait for 5 good RTT's before allowing alpha to go alpha max.
		 * This prevents one good RTT from causing sudden window increase.
		 */
		if (++ca->rtt_low < theta)
			return ca->alpha_2;

		ca->rtt_low = 0;
		ca->rtt_above = 0;
		return ALPHA_MAX;
	}

	ca->rtt_above = 1;
	
	dm -= d1;
	da -= d1;
	return (dm * ALPHA_MAX) / (dm + (da  * (ALPHA_MAX - ALPHA_MIN)) / ALPHA_MIN);
}

//add
static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 20;
	d3 = (8 * dm) / 10;
	
	if (da >= d3 || d3 <= d2)
		return BETA_MAX;
	else
		return BETA_MIN;

	return (BETA_MIN * d3 - BETA_MAX * d2 + (BETA_MAX - BETA_MIN) * da) / (d3 - d2);
}

//add
static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_ccc *ca = inet_csk_ca(sk);

	if (tp->snd_cwnd < win_thresh) {
		ca->alpha_2 = ALPHA_BASE;
		ca->beta = BETA_BASE;
	} else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->alpha_2 = alpha(ca, da, dm);
		ca->beta = beta(da, dm);
	}

	rtt_reset(sk);
}

static void mptcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		mptcp_ccc_recalc_alpha(sk);
}

static void mptcp_ccc_set_state(struct sock *sk, u8 ca_state)
{
	struct mptcp_ccc *ca = inet_csk_ca(sk);
	
	if (!mptcp(tcp_sk(sk)))
		return;
	
	mptcp_set_forced(mptcp_meta_sk(sk), 1);
	
	if (ca_state == TCP_CA_Loss) {
		ca->alpha_2 = ALPHA_BASE;
		ca->beta = BETA_BASE;
		ca->rtt_low = 0;
		ca->rtt_above = 0;
		rtt_reset(sk);
	}
}

//add
static u32 tcp_illinois_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_ccc *ca = inet_csk_ca(sk);
	
	ca->prev_loss_event_cwnd = tp->snd_cwnd;

	/* Multiplicative decrease */
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->beta) >> BETA_SHIFT), tp->snd_cwnd/2);
}

static void mptcp_ccc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	struct mptcp_ccc *ca = inet_csk_ca(sk);
	int snd_cwnd;
	u64 alpha;

	if (after(ack, ca->end_seq))
		update_params(sk);

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		mptcp_ccc_recalc_alpha(sk);
		return;
	}

	if (tp->snd_cwnd <= ca->prev_loss_event_cwnd){
		u32 delta;

		/* snd_cwnd_cnt is # of packets since last cwnd increment */
		tp->snd_cwnd_cnt += ca->acked;
		ca->acked = 1;

		/* This is close approximation of:
		 * tp->snd_cwnd += alpha/tp->snd_cwnd
		*/
		delta = (tp->snd_cwnd_cnt * ca->alpha_2) >> ALPHA_SHIFT;
		if (delta >= tp->snd_cwnd) {
			tp->snd_cwnd = min(tp->snd_cwnd + delta / tp->snd_cwnd, (u32)tp->snd_cwnd_clamp);
			tp->snd_cwnd_cnt = 0;
		}
		return;
	}
	
	if (mptcp_get_forced(mptcp_meta_sk(sk))) {
		mptcp_ccc_recalc_alpha(sk);
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
	}
	
	alpha = mptcp_get_alpha(mptcp_meta_sk(sk));

	/* This may happen, if at the initialization, the mpcb
	 * was not yet attached to the sock, and thus
	 * initializing alpha failed.
	 */
	if (unlikely(!alpha))
		alpha = 1;

	snd_cwnd = (int)div_u64((u64)mptcp_ccc_scale(1, alpha_scale), alpha);

	/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
	 * Thus, we select here the max value.
	 */
	if (snd_cwnd < tp->snd_cwnd)
		snd_cwnd = tp->snd_cwnd;

	if (tp->snd_cwnd_cnt >= snd_cwnd) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			tp->snd_cwnd++;
			mptcp_ccc_recalc_alpha(sk);
		}

		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}

static struct tcp_congestion_ops mptcp_ccc = {
	.init		= mptcp_ccc_init,
	.ssthresh	= tcp_illinois_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cong_avoid	= mptcp_ccc_cong_avoid,
	.cwnd_event	= mptcp_ccc_cwnd_event,
	.set_state	= mptcp_ccc_set_state,
	.pkts_acked	= tcp_illinois_acked,
	.owner		= THIS_MODULE,
	.name		= "lia",
};

static int __init mptcp_ccc_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_ccc) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mptcp_ccc);
}

static void __exit mptcp_ccc_unregister(void)
{
	tcp_unregister_congestion_control(&mptcp_ccc);
}

module_init(mptcp_ccc_register);
module_exit(mptcp_ccc_unregister);

MODULE_AUTHOR("Christoph Paasch, Sébastien Barré");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP LINKED INCREASE CONGESTION CONTROL ALGORITHM");
MODULE_VERSION("0.1");
