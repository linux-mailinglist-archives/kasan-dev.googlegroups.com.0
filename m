Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2UDRSLAMGQEADQDVKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E41BF565942
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:19 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id f34-20020a9d03a5000000b0060c46a7869asf3447021otf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947178; cv=pass;
        d=google.com; s=arc-20160816;
        b=lOKDxFPF8agYNl1Q8wP4cp1C0GF1TwbtG1fHlpgYZmLEuBNGEgVGl4vp/MASKIs12N
         lsisOfnjVHjKWQbw0i5MeanyeCQaJI9uLtKnzgQE7Lsrlniw7ExrtoORlAsn4fftqMhn
         kDqkonaon45CypZWOgnfG5qV4LA1FzI8rSkR3ObHqoPfG0NiWtgP+dTxbJHUiwNXJiRn
         tHcdMdYtskIt7cg7O8xKDBBv5ufJRD/mC8KJyr9A1c2W6W91g5VCmdCFU1wgKTeK0ysB
         YoCHBLIScPA0E8Mvcn6gs7o8lj/VYbJlSGyRpMhM1Up8U2Yc9NbCAVYaH4Fzc57VI8/H
         lw6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qEILV5uqu4UecZ5cJhtesyHxtrkqnlMrg2oPAXJmpCU=;
        b=QHfVyMEdeht48+CuPy7YMHDl7zTrGoRP3FuZFFSxAdyzQ2cUmUojUSpPAny6zppEMb
         lx7NBciom6YVwwtVPyEg4KEEOYCpf/JzFcSxXiIvxgD3Dm5KNAmTecGYadEaG83Et47s
         AcHg08aXJybOu1CE0YTktcfFL97NFvyinDdp5EDxa0YO0jRff585XgPjf/D0hd/5Lq/4
         KZT4yK0mBm5rJ2Jlq3GNYoK4rzwAfayRhU57Vdjx8+7ONm/6GK3IxZwZ04mMF4kt1f8a
         XrVCKuuTYUqjIbzPViKIQpmM7/BX7AJQ36xwcCmrQfTsNQmHmRzLN0edcYggXBUyiB3h
         hoHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JoVGDf6y;
       spf=pass (google.com: domain of 36qhdygukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=36QHDYgUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qEILV5uqu4UecZ5cJhtesyHxtrkqnlMrg2oPAXJmpCU=;
        b=iHWbZXL9HVUD82JX4C8VrAF6/R2eQYnHzCzmqzcAftQdknjgPvs0/5iVTlh4arB9JR
         BeC8+XGQtxz4HK6458rkb4PHiuLV7pb6XodVfLbybx7ZcmUNgID+YjMsTuU6V0mK317j
         YPURju7D4fxTfp0hcjSwpEsm9KWF2FhabfvTMQ3dQdzQmZCzrnLK9Em/QOwRDssB5Qg5
         PNNjN3YLfjElHsLSA+HWDLFDTodDaYvF037qHJTxu6h1icHiIv2RAxYth4+cKF8G7okw
         FUlh5FVOBMNJdne7SPexMXZl86Mbyam511g3rW9yYlBDQ51ATk/+pC68WnBcHdSSdPIw
         g+7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qEILV5uqu4UecZ5cJhtesyHxtrkqnlMrg2oPAXJmpCU=;
        b=CXBNriIciONu7qDUkbY7iYhuS7hqodZWJUMkezT+x/CODfNtZ7U5fNf6POHzMn0bZs
         bbwyJbbWjW7lEBAQr38gSd7H3SpzC3ThCqW5dPMx8abqwNr0zklZhKZ+KayDkitm9bM3
         +ZdWWo1nGsQMXjg1IE0t6F0oyw8ctv7FHU/Uca/EntBZRgSwPba1OtgDabXymdThYamg
         JxzhWsq9Gcl9KdP+z/6rE9I1/rMIKIpQk6UuHuE5ey3qvxNoGBGmZTdhrRagnXKMfFPj
         mEEYojgE9cBtNfuQ6+qFX+49kPtU9+lPSFT9j4CKC/agSkLVM8ZMx6p7rRp1DjPD+3ih
         n9KQ==
X-Gm-Message-State: AJIora9oKLa5Bv07X58HHGl9cGVYS892uALkbzF2mYm082yWhgu5QrgE
	7C/Iz2SA7qU6GPN1xVrSPIc=
X-Google-Smtp-Source: AGRyM1spioBaB8Gi8l0Zp0teuF6j8IhisRQh0jgwXkPk+6Nv6STWXgT9iY3jqpyvUedXJl83Xb1YNg==
X-Received: by 2002:a05:6808:86:b0:337:b224:8ccb with SMTP id s6-20020a056808008600b00337b2248ccbmr5282278oic.224.1656947178510;
        Mon, 04 Jul 2022 08:06:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:17f1:0:b0:606:140a:e39d with SMTP id j104-20020a9d17f1000000b00606140ae39dls9492756otj.7.gmail;
 Mon, 04 Jul 2022 08:06:18 -0700 (PDT)
X-Received: by 2002:a9d:e86:0:b0:616:be57:df48 with SMTP id 6-20020a9d0e86000000b00616be57df48mr12495006otj.345.1656947178052;
        Mon, 04 Jul 2022 08:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947178; cv=none;
        d=google.com; s=arc-20160816;
        b=fYwS3xiRSta8qfw0FfYo73rakRmbKmEzTt3HdletSm+icZ5vAqEvf+WZoWr7AC9uYu
         Mn10oRuY/jqq5tyMSFuBdKaSOyIbiNDneNT5A1ytIj4TZ8Fmro0JKRmM0GtyHZ79fCkU
         OY4UmWxTJic+oURn6yOblQfkKfSEo/fxLx1UKTtf6aaV5o/m0FGtW24VKp+vZPJQDgFZ
         W+8HLLoSWkTO5CWxWUs8TaSZ+mTezEaziRq8QhYM1DKv9zJfwqYlfg09mmeN2/DgHua3
         cEczcLVxxMixySVL0muODsTX9rAM/NLlhew22HmZHop1sQ7y79dxvE/vGPhNApT92VoV
         Gb2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=V6/7gBssT9f8qylfI12t9/BYdohkMdKIWfeQweBYfic=;
        b=r/ZMcTatbB+jYjO/40WK1LgQ2SNmrwbLUQ3f/cXlkJzj2YCmwiTPsi6Sgg2S6OQcGv
         ZPKDz2LMoKWNSytW5ma+THax0rk8xpskTqr3AyRC6rU3s8rZRpJpQ6RjMgRn9H+HY1c/
         EMjLmOEEOrjY6WSMv9mJvDQEhoHesQFQkcClEyyn3yYMdCpEuh+ehmyG3EJtjY2rRn+A
         Ra76pTHE7t17YZ1iQgzw59xSO78zvRuXQ4W/yBvvRbPzgsTsoWh+mWPIBlGYWfwmHQgO
         EIN2uM6n4xEhT/AdyMik21AONnz9nHyTBks9yXjIECL03GsDpkRvcvMUbqLUBb/CKpfG
         bbDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JoVGDf6y;
       spf=pass (google.com: domain of 36qhdygukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=36QHDYgUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id o17-20020a056870969100b00101a5546931si3345780oaq.4.2022.07.04.08.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36qhdygukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-2dc7bdd666fso68300777b3.7
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:18 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a81:11c7:0:b0:31c:8c85:c4be with SMTP id
 190-20020a8111c7000000b0031c8c85c4bemr8356031ywr.235.1656947177651; Mon, 04
 Jul 2022 08:06:17 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:08 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-9-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 08/14] perf/hw_breakpoint: Remove useless code related to
 flexible breakpoints
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JoVGDf6y;       spf=pass
 (google.com: domain of 36qhdygukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=36QHDYgUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Flexible breakpoints have never been implemented, with
bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
flexible count in fetch_bp_busy_slots().

This again causes suboptimal code generation, when we always know that
`!!slots.flexible` will be 0.

Just get rid of the flexible "placeholder" and remove all real code
related to it. Make a note in the comment related to the constraints
algorithm but don't remove them from the algorithm, so that if in future
flexible breakpoints need supporting, it should be trivial to revive
them (along with reverting this change).

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Also remove struct bp_busy_slots, and simplify functions.
---
 kernel/events/hw_breakpoint.c | 57 +++++++++++------------------------
 1 file changed, 17 insertions(+), 40 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 9c9bf17666a5..8b40fca1a063 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -45,8 +45,6 @@ struct bp_cpuinfo {
 #else
 	unsigned int	*tsk_pinned;
 #endif
-	/* Number of non-pinned cpu/task breakpoints in a cpu */
-	unsigned int	flexible; /* XXX: placeholder, see fetch_this_slot() */
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
@@ -67,12 +65,6 @@ static const struct rhashtable_params task_bps_ht_params = {
 
 static bool constraints_initialized __ro_after_init;
 
-/* Gather the number of total pinned and un-pinned bp in a cpuset */
-struct bp_busy_slots {
-	unsigned int pinned;
-	unsigned int flexible;
-};
-
 /* Serialize accesses to the above constraints */
 static DEFINE_MUTEX(nr_bp_mutex);
 
@@ -190,14 +182,14 @@ static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
 }
 
 /*
- * Report the number of pinned/un-pinned breakpoints we have in
- * a given cpu (cpu > -1) or in all of them (cpu = -1).
+ * Returns the max pinned breakpoint slots in a given
+ * CPU (cpu > -1) or across all of them (cpu = -1).
  */
-static void
-fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
-		    enum bp_type_idx type)
+static int
+max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 {
 	const struct cpumask *cpumask = cpumask_of_bp(bp);
+	int pinned_slots = 0;
 	int cpu;
 
 	for_each_cpu(cpu, cpumask) {
@@ -210,24 +202,10 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
 		else
 			nr += task_bp_pinned(cpu, bp, type);
 
-		if (nr > slots->pinned)
-			slots->pinned = nr;
-
-		nr = info->flexible;
-		if (nr > slots->flexible)
-			slots->flexible = nr;
+		pinned_slots = max(nr, pinned_slots);
 	}
-}
 
-/*
- * For now, continue to consider flexible as pinned, until we can
- * ensure no flexible event can ever be scheduled before a pinned event
- * in a same cpu.
- */
-static void
-fetch_this_slot(struct bp_busy_slots *slots, int weight)
-{
-	slots->pinned += weight;
+	return pinned_slots;
 }
 
 /*
@@ -298,7 +276,12 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
 }
 
 /*
- * Constraints to check before allowing this new breakpoint counter:
+ * Constraints to check before allowing this new breakpoint counter.
+ *
+ * Note: Flexible breakpoints are currently unimplemented, but outlined in the
+ * below algorithm for completeness.  The implementation treats flexible as
+ * pinned due to no guarantee that we currently always schedule flexible events
+ * before a pinned event in a same CPU.
  *
  *  == Non-pinned counter == (Considered as pinned for now)
  *
@@ -340,8 +323,8 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
  */
 static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 {
-	struct bp_busy_slots slots = {0};
 	enum bp_type_idx type;
+	int max_pinned_slots;
 	int weight;
 	int ret;
 
@@ -357,15 +340,9 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	type = find_slot_idx(bp_type);
 	weight = hw_breakpoint_weight(bp);
 
-	fetch_bp_busy_slots(&slots, bp, type);
-	/*
-	 * Simulate the addition of this breakpoint to the constraints
-	 * and see the result.
-	 */
-	fetch_this_slot(&slots, weight);
-
-	/* Flexible counters need to keep at least one slot */
-	if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
+	/* Check if this new breakpoint can be satisfied across all CPUs. */
+	max_pinned_slots = max_bp_pinned_slots(bp, type) + weight;
+	if (max_pinned_slots > hw_breakpoint_slots_cached(type))
 		return -ENOSPC;
 
 	ret = arch_reserve_bp_slot(bp);
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-9-elver%40google.com.
