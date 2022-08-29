Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJXLWKMAMGQEH3CUZPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 34C635A4C47
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:44 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id bn39-20020a05651c17a700b0026309143eeesf1093909ljb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777318; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0BhDkWvne0dQfO0cIOy7Gf/YU5K9aJkQO20GlNQJa0+4014M2uR3VtjuuD2eq3d+Q
         mEXVFq3XlfGLpvi1xN/b9Vq+wbOSX0Zdso5NTd+4kYR4HUVy5MOyJh89NXtlRES3cVJV
         VU2D9GyjBvnHMuDjTmxktP5bEby1lOivSmYqyf1i4YrthnfnNDIrEQJYERHdqItiBpmg
         7FC74uQpMRF1BDjI7ctq7dM6qhYebKZ9smwhJ7shVF1raJruvqTAraqA1fVpEKt7xWrQ
         6oT6o0kCSeFkRdD9YuQzEAEEFZAw+5+eZSN0gjlgzG5irpUsbPtAbe4S9Nf9j64KpWWZ
         0CWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=g2ZdVujOFoLA8vX+xBr+x0J/fAHbiGIzkGbZ8hqFx8I=;
        b=CDCHBdhn6mgA0SVyTz5Nd4xsPRUZm8drNlEXzMxkC9+4KcyijkC82FuHj7CvN/1bds
         2fRRI2FrnK4x+iIp+4quEXn2n6vuoIgOu5dIst/RMaZ/G2OYohOr00+eOO7GL+k4dmgS
         jSXkRJccd51iqXV/WCfblcveEQDqrXD/05mtqSJaLq0qjE8TuleXftVzog+SM8nY1DZH
         eJRYLsTAOmLCjrNlVCQakjElZMEmTv3eCJDk4v4zYiKfE60VO8MOSV0EFXRyWBu89RjF
         WMMDz4R1p1756DDNUO3KUXQFTf1px98fv5CZUezRqXqr91/JCYRcZPe8PQhNYva6Hfok
         pxdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tfLpVgev;
       spf=pass (google.com: domain of 3plumywukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pLUMYwUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=g2ZdVujOFoLA8vX+xBr+x0J/fAHbiGIzkGbZ8hqFx8I=;
        b=mgFhz/gxCSFiOuM9yggWTY1pKUEiQ0Qx8WOXH3It0kq0duuygL/Pop9NRvx+AfPQui
         QCvcPS/nvkWyjfUhasiaVPGfR6ZFy82ZB+Xf2p5iT3sshny8TODwwWZoP2w7kq7galwY
         2Vc7mGuLZL8j3TyYAznIrZBfaZW0dMmRqFC5I82CKbV7xEaawjEODLFQbzQcMIbPJXJH
         Eyn07q/EXXUYg+53J3Zf4pbeN1GrlDptRctPcwK5O7IyKo5cBKI3iSGA/k5+/3hnQP4l
         zwDrffuQTfCTIIY/BfcTXIF0uzF8j8OKGimL78v7spLYf1hV5T066rcj5a/n80PWe4ua
         4EOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=g2ZdVujOFoLA8vX+xBr+x0J/fAHbiGIzkGbZ8hqFx8I=;
        b=6IarnnbkZrXa1Mb7pTl40WGf/JLIrwR+4DIDyYPsUy0Z+omoe6wEsYyMsrnl02AwjZ
         2o5wbLIonVz6pbXO8ip6P4zgxYZNU+Ct0nt8VuXoCaPpUATk5tO7xDmdXIbK0Ot1LTER
         rE5rEuX+stEysf05H2jqIgGgBf8+3E8PVa4LmhlM/cl/azeAsgagoDdX/IMapzeum/Cu
         3i0bmv9TQHtEwHo7C0sfLUMMOP94pxpt9uSvc7z5QkWOp6d2i2IOdd8SIZL0ZElLxWlQ
         3eGp3XHko3dXOMMQbCRqrZMfpT8Y2bWmyBs/7YYRvyyP0EJfpH38ogF/1YvYnb/jlbfo
         ZOkw==
X-Gm-Message-State: ACgBeo3/g+AjqAfaau+AHWMadFHgDPLTCbuK7H3sAG9/LMTUEQaJlzTs
	Ay2byiKc6OYnd5ZUnI+uFF0=
X-Google-Smtp-Source: AA6agR6uKuxXbD+21xH5spnz5AdpKgh/4XxBY2hSXjELkFw157aqIudu0ydcE6TAHKQjGiRV5lAuew==
X-Received: by 2002:a2e:a4a6:0:b0:264:41eb:bb7d with SMTP id g6-20020a2ea4a6000000b0026441ebbb7dmr2217886ljm.230.1661777318723;
        Mon, 29 Aug 2022 05:48:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3588:b0:48b:3a68:3b0 with SMTP id
 m8-20020a056512358800b0048b3a6803b0ls4737697lfr.0.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:37 -0700 (PDT)
X-Received: by 2002:a05:6512:3e24:b0:494:737c:7857 with SMTP id i36-20020a0565123e2400b00494737c7857mr593826lfv.166.1661777317391;
        Mon, 29 Aug 2022 05:48:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777317; cv=none;
        d=google.com; s=arc-20160816;
        b=OdUvBk62MbSPMn0XpZTfmE/qi6pk03l7/VVjznUrwm/jV3m5ESnsgqVxbvx+sDQSOo
         hh+WPg8OpY+65FNv04syhkCnhiomf1qqVb/i7hmT5o00/g86fSNaNNVHZ4vNVZJu/WQJ
         f0CZcclnI6NXfXl9pzYJvn86e1kURtms7NglZTmi4DQYXm1fEV3b0oUSe8f8FCph2Bvo
         IwMXVOYz/XsHqJc8WQX6YBkSJkPdCRmhBFy2guwzZeM88MocqfrcT+1094AydimoDkW/
         MWgZP3GaWPIFIGfkHOvIRyZ4omblN/bbGrDp1K0OGp3132KrF77xRYVcyMvoL2JDPDt+
         gDfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=0cyxDQ8FzaGmiYK/SL7v1Jw9OhmpUGtWUZkd+KNQhJo=;
        b=htN8xh7PNBht+OTzWgpq+mbftnx9iIeOQpgg+7K0N1LTpOw2+xeEdcxlaoFezqHRNP
         h1DTLO0A6kh4EcSKL2FZH/lapfk5vdoMUVP3zPb9mRt5zvIAkDEhFwyERzXmMHh0Kshb
         HvZS2zDj8TpvQjKWE7icnyxYJHtjEzi7RG9QSZSmbj9fmdZf3dBRevcesF1cY3RDMDfg
         K9KszK3E6zfD7AFJt8yY1sCFNzrS0y/o9xtAONXEnQprCT2mAVE2d1ZMOl9rYcc5IvLl
         QRJVoyN82F7iQyM+S/g3vtZmg06XZJRJRiLythY9s7SLAfDlEYNQn0HPSUfAjJRfxBvD
         ciOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tfLpVgev;
       spf=pass (google.com: domain of 3plumywukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pLUMYwUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bd15-20020a05651c168f00b002663282f080si78900ljb.5.2022.08.29.05.48.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3plumywukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sb14-20020a1709076d8e00b0073d48a10e10so2271536ejc.16
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:37 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a17:907:7b9f:b0:741:9ae3:89a6 with SMTP id
 ne31-20020a1709077b9f00b007419ae389a6mr2487790ejc.311.1661777316752; Mon, 29
 Aug 2022 05:48:36 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:19 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-15-elver@google.com>
Subject: [PATCH v4 14/14] perf/hw_breakpoint: Optimize toggle_bp_slot() for
 CPU-independent task targets
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tfLpVgev;       spf=pass
 (google.com: domain of 3plumywukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pLUMYwUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

We can still see that a majority of the time is spent hashing task pointers:

    ...
    16.98%  [kernel]       [k] rhashtable_jhash2
    ...

Doing the bookkeeping in toggle_bp_slots() is currently O(#cpus),
calling task_bp_pinned() for each CPU, even if task_bp_pinned() is
CPU-independent. The reason for this is to update the per-CPU
'tsk_pinned' histogram.

To optimize the CPU-independent case to O(1), keep a separate
CPU-independent 'tsk_pinned_all' histogram.

The major source of complexity are transitions between "all
CPU-independent task breakpoints" and "mixed CPU-independent and
CPU-dependent task breakpoints". The code comments list all cases that
require handling.

After this optimization:

 | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
 |      Total time: 1.758 [sec]
 |
 |       34.336621 usecs/op
 |     4395.087500 usecs/op/cpu

    38.08%  [kernel]       [k] queued_spin_lock_slowpath
    10.81%  [kernel]       [k] smp_cfm_core_cond
     3.01%  [kernel]       [k] update_sg_lb_stats
     2.58%  [kernel]       [k] osq_lock
     2.57%  [kernel]       [k] llist_reverse_order
     1.45%  [kernel]       [k] find_next_bit
     1.21%  [kernel]       [k] flush_tlb_func_common
     1.01%  [kernel]       [k] arch_install_hw_breakpoint

Showing that the time spent hashing keys has become insignificant.

With the given benchmark parameters, that's an improvement of 12%
compared with the old O(#cpus) version.

And finally, using the less aggressive parameters from the preceding
changes, we now observe:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.067 [sec]
 |
 |       35.292187 usecs/op
 |     2258.700000 usecs/op/cpu

Which is an improvement of 12% compared to without the histogram
optimizations (baseline is 40 usecs/op). This is now on par with the
theoretical ideal (constraints disabled), and only 12% slower than no
breakpoints at all.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v3:
* Fix typo "5 cases" -> "4 cases".
* Update hw_breakpoint_is_used() to check tsk_pinned_all.

v2:
* New patch.
---
 kernel/events/hw_breakpoint.c | 155 +++++++++++++++++++++++++++-------
 1 file changed, 124 insertions(+), 31 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index a489f31fe147..7ef0e98d31e2 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -66,6 +66,8 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 
 /* Number of pinned CPU breakpoints globally. */
 static struct bp_slots_histogram cpu_pinned[TYPE_MAX];
+/* Number of pinned CPU-independent task breakpoints. */
+static struct bp_slots_histogram tsk_pinned_all[TYPE_MAX];
 
 /* Keep track of the breakpoints attached to tasks */
 static struct rhltable task_bps_ht;
@@ -200,6 +202,8 @@ static __init int init_breakpoint_slots(void)
 	for (i = 0; i < TYPE_MAX; i++) {
 		if (!bp_slots_histogram_alloc(&cpu_pinned[i], i))
 			goto err;
+		if (!bp_slots_histogram_alloc(&tsk_pinned_all[i], i))
+			goto err;
 	}
 
 	return 0;
@@ -210,8 +214,10 @@ static __init int init_breakpoint_slots(void)
 		if (err_cpu == cpu)
 			break;
 	}
-	for (i = 0; i < TYPE_MAX; i++)
+	for (i = 0; i < TYPE_MAX; i++) {
 		bp_slots_histogram_free(&cpu_pinned[i]);
+		bp_slots_histogram_free(&tsk_pinned_all[i]);
+	}
 
 	return -ENOMEM;
 }
@@ -245,6 +251,26 @@ bp_slots_histogram_max(struct bp_slots_histogram *hist, enum bp_type_idx type)
 	return 0;
 }
 
+static int
+bp_slots_histogram_max_merge(struct bp_slots_histogram *hist1, struct bp_slots_histogram *hist2,
+			     enum bp_type_idx type)
+{
+	for (int i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
+		const int count1 = atomic_read(&hist1->count[i]);
+		const int count2 = atomic_read(&hist2->count[i]);
+
+		/* Catch unexpected writers; we want a stable snapshot. */
+		ASSERT_EXCLUSIVE_WRITER(hist1->count[i]);
+		ASSERT_EXCLUSIVE_WRITER(hist2->count[i]);
+		if (count1 + count2 > 0)
+			return i + 1;
+		WARN(count1 < 0, "inconsistent breakpoint slots histogram");
+		WARN(count2 < 0, "inconsistent breakpoint slots histogram");
+	}
+
+	return 0;
+}
+
 #ifndef hw_breakpoint_weight
 static inline int hw_breakpoint_weight(struct perf_event *bp)
 {
@@ -273,7 +299,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 	 * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
 	 */
 	lockdep_assert_held_write(&bp_cpuinfo_sem);
-	return bp_slots_histogram_max(tsk_pinned, type);
+	return bp_slots_histogram_max_merge(tsk_pinned, &tsk_pinned_all[type], type);
 }
 
 /*
@@ -366,40 +392,22 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 	return pinned_slots;
 }
 
-/*
- * Add a pinned breakpoint for the given task in our constraint table
- */
-static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
-				enum bp_type_idx type, int weight)
-{
-	struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
-
-	/*
-	 * If bp->hw.target, tsk_pinned is only modified, but not used
-	 * otherwise. We can permit concurrent updates as long as there are no
-	 * other uses: having acquired bp_cpuinfo_sem as a reader allows
-	 * concurrent updates here. Uses of tsk_pinned will require acquiring
-	 * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
-	 */
-	lockdep_assert_held_read(&bp_cpuinfo_sem);
-	bp_slots_histogram_add(tsk_pinned, task_bp_pinned(cpu, bp, type), weight);
-}
-
 /*
  * Add/remove the given breakpoint in our constraint table
  */
 static int
-toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
-	       int weight)
+toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type, int weight)
 {
-	const struct cpumask *cpumask = cpumask_of_bp(bp);
-	int cpu;
+	int cpu, next_tsk_pinned;
 
 	if (!enable)
 		weight = -weight;
 
-	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
+		/*
+		 * Update the pinned CPU slots, in per-CPU bp_cpuinfo and in the
+		 * global histogram.
+		 */
 		struct bp_cpuinfo *info = get_bp_info(bp->cpu, type);
 
 		lockdep_assert_held_write(&bp_cpuinfo_sem);
@@ -408,9 +416,91 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 		return 0;
 	}
 
-	/* Pinned counter task profiling */
-	for_each_cpu(cpu, cpumask)
-		toggle_bp_task_slot(bp, cpu, type, weight);
+	/*
+	 * If bp->hw.target, tsk_pinned is only modified, but not used
+	 * otherwise. We can permit concurrent updates as long as there are no
+	 * other uses: having acquired bp_cpuinfo_sem as a reader allows
+	 * concurrent updates here. Uses of tsk_pinned will require acquiring
+	 * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
+	 */
+	lockdep_assert_held_read(&bp_cpuinfo_sem);
+
+	/*
+	 * Update the pinned task slots, in per-CPU bp_cpuinfo and in the global
+	 * histogram. We need to take care of 4 cases:
+	 *
+	 *  1. This breakpoint targets all CPUs (cpu < 0), and there may only
+	 *     exist other task breakpoints targeting all CPUs. In this case we
+	 *     can simply update the global slots histogram.
+	 *
+	 *  2. This breakpoint targets a specific CPU (cpu >= 0), but there may
+	 *     only exist other task breakpoints targeting all CPUs.
+	 *
+	 *     a. On enable: remove the existing breakpoints from the global
+	 *        slots histogram and use the per-CPU histogram.
+	 *
+	 *     b. On disable: re-insert the existing breakpoints into the global
+	 *        slots histogram and remove from per-CPU histogram.
+	 *
+	 *  3. Some other existing task breakpoints target specific CPUs. Only
+	 *     update the per-CPU slots histogram.
+	 */
+
+	if (!enable) {
+		/*
+		 * Remove before updating histograms so we can determine if this
+		 * was the last task breakpoint for a specific CPU.
+		 */
+		int ret = rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
+
+		if (ret)
+			return ret;
+	}
+	/*
+	 * Note: If !enable, next_tsk_pinned will not count the to-be-removed breakpoint.
+	 */
+	next_tsk_pinned = task_bp_pinned(-1, bp, type);
+
+	if (next_tsk_pinned >= 0) {
+		if (bp->cpu < 0) { /* Case 1: fast path */
+			if (!enable)
+				next_tsk_pinned += hw_breakpoint_weight(bp);
+			bp_slots_histogram_add(&tsk_pinned_all[type], next_tsk_pinned, weight);
+		} else if (enable) { /* Case 2.a: slow path */
+			/* Add existing to per-CPU histograms. */
+			for_each_possible_cpu(cpu) {
+				bp_slots_histogram_add(&get_bp_info(cpu, type)->tsk_pinned,
+						       0, next_tsk_pinned);
+			}
+			/* Add this first CPU-pinned task breakpoint. */
+			bp_slots_histogram_add(&get_bp_info(bp->cpu, type)->tsk_pinned,
+					       next_tsk_pinned, weight);
+			/* Rebalance global task pinned histogram. */
+			bp_slots_histogram_add(&tsk_pinned_all[type], next_tsk_pinned,
+					       -next_tsk_pinned);
+		} else { /* Case 2.b: slow path */
+			/* Remove this last CPU-pinned task breakpoint. */
+			bp_slots_histogram_add(&get_bp_info(bp->cpu, type)->tsk_pinned,
+					       next_tsk_pinned + hw_breakpoint_weight(bp), weight);
+			/* Remove all from per-CPU histograms. */
+			for_each_possible_cpu(cpu) {
+				bp_slots_histogram_add(&get_bp_info(cpu, type)->tsk_pinned,
+						       next_tsk_pinned, -next_tsk_pinned);
+			}
+			/* Rebalance global task pinned histogram. */
+			bp_slots_histogram_add(&tsk_pinned_all[type], 0, next_tsk_pinned);
+		}
+	} else { /* Case 3: slow path */
+		const struct cpumask *cpumask = cpumask_of_bp(bp);
+
+		for_each_cpu(cpu, cpumask) {
+			next_tsk_pinned = task_bp_pinned(cpu, bp, type);
+			if (!enable)
+				next_tsk_pinned += hw_breakpoint_weight(bp);
+			bp_slots_histogram_add(&get_bp_info(cpu, type)->tsk_pinned,
+					       next_tsk_pinned, weight);
+		}
+	}
 
 	/*
 	 * Readers want a stable snapshot of the per-task breakpoint list.
@@ -419,8 +509,8 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 
 	if (enable)
 		return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
-	else
-		return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
+
+	return 0;
 }
 
 __weak int arch_reserve_bp_slot(struct perf_event *bp)
@@ -850,6 +940,9 @@ bool hw_breakpoint_is_used(void)
 			 */
 			if (WARN_ON(atomic_read(&cpu_pinned[type].count[slot])))
 				return true;
+
+			if (atomic_read(&tsk_pinned_all[type].count[slot]))
+				return true;
 		}
 	}
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-15-elver%40google.com.
