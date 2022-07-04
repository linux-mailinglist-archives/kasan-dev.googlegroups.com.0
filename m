Return-Path: <kasan-dev+bncBC7OBJGL2MHBB64DRSLAMGQELCNIG5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 73AF2565949
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:36 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id y35-20020a0565123f2300b0047f70612402sf3135880lfa.12
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947196; cv=pass;
        d=google.com; s=arc-20160816;
        b=dIWirmIjCzOX0Wwdi8Nxw5krjuNMTSod0PwW36Miwtue7YX9+/on2BYeVPRAFu88PV
         pwXPHjuwvijCReN3RzsgYhp33znK6PYwb6mRf+u32wlxeepIKva3FePk994xGOtgyXHd
         dkPBKkI6etNp571KpC7xnAIhbmtktNRDMDo5BRA4eacFJDmSy4gtGghqEldPyqdbhIGO
         izEVmj8xPSFdCUNiP/25LK570WD/s0x0dGaKFAFy0nPTRFNOfgXwx6nRTKp7lIVSoVHq
         uJNRol9gquY72TJIkQf1smRMw3hoXZ9V0GTUWGOc4tWKypeqllsZ0rB1cyCZrQgd5X2V
         nR8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=8bCf/NqH3vWOICDm2NO1ehye+En9ChyUgdYDKy7DFhA=;
        b=JOYd+pXggIiNXOqdSfSJIvL5p7gd1lKl5CW7tpycxyefITJbQyR7zP7xApK6Z/jRKD
         iXzW8Be3/Ca7ARkXE4agQrBcqs6NGjIpQIeeUa2D/FHU+2XjCvRD+yd98xaMo/EQ1jac
         VhWaYhcUTf8jQxQ3ejGTOB0/3itSZ3fMO3vgHUUaFhFuwDHiKAaqCmHvuCrBhRYfqB9k
         rr9cDW97KCZsiebxuDLrAApNZTPVI66QaecwB4o/y1kImpvBdLIMnkfqOGdzC5aIjs52
         pBullFMoEO6gmdZL/7JWWN4rY9723OBxnJAFhRpRzl5z9xrGmG2WeHryvVyZ9sxVrISB
         4CvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g2A+ZBHo;
       spf=pass (google.com: domain of 3-qhdygukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-QHDYgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8bCf/NqH3vWOICDm2NO1ehye+En9ChyUgdYDKy7DFhA=;
        b=IrFtZ9yY0vQ3qCS/MXb1WJxA02Yg2UieGiChOiKLi8RXpWgqw6MlAs3NOzHsTJpAz/
         qNgdLrasvBGHSDKeIepJR4saXU+nP+MlYRf9WZP2b2wOXlVXt2CfItbEgR5rtQxq4Xw5
         kBmG7D8Ez3O0T4OVqlJFs+draub91kLlr5T/bzr4pqMGKc3sjy+HYuTnXHoH6eccx7Mj
         2uCCrrf4Ey0ENW3NSFKzctvf/BRr8HekoHtP6jdIHwY1E9HroSPmxHU5w7appQNlesYP
         U+9i4cCg9/Xb620EL1zaXmy89mOgf+gIckoZ8wHNwLhwpYW3nKBmao4Hmu5Ssr96gkXg
         FSUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8bCf/NqH3vWOICDm2NO1ehye+En9ChyUgdYDKy7DFhA=;
        b=oc/2TrXXZ7NgsvTTgH7xN5Q8HFdFQLrOMbqvAjM9j3Eqjzjylulrhjo34x66T59FXH
         OooXYhJC7rus30Rv5ilnqSBs4ydRjltBP64EJaUNnYlcCg8bOxcY7ylHYp9PX5F5Xw8d
         r3ohLEieXtvt/bM0QIjfU0zz2ZNMmfTYzq+bd8mUyZX28/LAADHkSeDcEpcaAMTPvRAV
         6lSXD2R1e9BSzQPkSZdWPEHbTbkbv7E/k/aBoZpgBlv0KE4pxSPPk9PLbsfpvKcMVkNK
         ZcLjTtmEDvFBl4eB46eXCX4+VsMTvIEyV/fmEKFLKCB6sZNkLGaYuCrA48LU+y7GZjiG
         UEVA==
X-Gm-Message-State: AJIora+YyPZobDZarLv0P37AwthfU65Ye+cHEtboQfs4BPuxk/mNpQ/R
	n2nrfzKcbf5lmkgg+7I/KKA=
X-Google-Smtp-Source: AGRyM1utem8VRCJzdVuJ0IiUnaU/UlXJnLVcKzFble6WtAhs2NiDFDm40pA0/9AGM5yadA7KfXl5UA==
X-Received: by 2002:a05:6512:13a4:b0:479:3b9f:f13c with SMTP id p36-20020a05651213a400b004793b9ff13cmr19207346lfa.380.1656947195852;
        Mon, 04 Jul 2022 08:06:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls780996lfn.2.gmail;
 Mon, 04 Jul 2022 08:06:34 -0700 (PDT)
X-Received: by 2002:a05:6512:3146:b0:482:e8c8:1a7f with SMTP id s6-20020a056512314600b00482e8c81a7fmr474650lfi.62.1656947194563;
        Mon, 04 Jul 2022 08:06:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947194; cv=none;
        d=google.com; s=arc-20160816;
        b=QV9pBec22bGiUDRo3YqKmP7orl5GcyIHG7uciOOhxFDBtfUmLvy0PvOwPtnPF+MBtR
         j72ChtaSPXrbO3qNJcSQqGqYHP4ABq97nJ0lzn3NEqTWDEEPApG5pFh0qSWVZW8vnh+E
         SMJZR11cOqXHbH9QZM1r3NCxrJxjIRtr6MltrdqV4bfH0FdqF7DObONEwWHT4f9I+mgS
         eezCMv7FnEmaUt296joNZUIDBLC12lq9yjz+qp7aA1a48wyt44fhU2Bn2MztjkOCm2u7
         /urCRrtykaxAxaPRBNyFcm8Spx400gbgv2nSDw6+2H2IYck1jy8o6kZf6YM2DD2RC0AM
         7ONw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=awwzJOIXuYTScESe+eB43r5mftw5KMgSj+HQD04XG+w=;
        b=Axz/9l6e1L/w3Lirp+Ys5wNdcICXk2YSm4UgjnQOHCXYE0xtsr+UwV7Nezpr70CQvA
         psHGMV9So56L55/BGDXuKHPbDG9S0sFplNd6urLmlQuIncGcHTDg6TYc24b4cs/YDv51
         tyv23d9EfOoQpXDk+wcOUXuGXkgoQoMtMe2oaMmTraCXoFZK/K2+Csnv3kNoK4iJ9qQi
         +luiFn6xB3kZKup+SJc3OzmB/rFt+IlgB2tW4/eb+nc2kdygfmuQj8HDq3vszNJ31j9B
         kFUB95FSIv+TSh2Uws446T7qVotdwneTSIjF98QUE+HzCImcwTcdaE/mdY85OiJSsx9b
         IQew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g2A+ZBHo;
       spf=pass (google.com: domain of 3-qhdygukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-QHDYgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id k27-20020a2ea27b000000b0025d2c310ccesi23061ljm.2.2022.07.04.08.06.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-qhdygukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id h125-20020a1c2183000000b003a03a8475c6so4188012wmh.8
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:34 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:adf:9cc7:0:b0:21d:642b:85f2 with SMTP id
 h7-20020adf9cc7000000b0021d642b85f2mr9614852wre.21.1656947193962; Mon, 04 Jul
 2022 08:06:33 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:14 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-15-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 14/14] perf/hw_breakpoint: Optimize toggle_bp_slot() for
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
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=g2A+ZBHo;       spf=pass
 (google.com: domain of 3-qhdygukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-QHDYgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-15-elver%40google.com.
