Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBVUQ6KQMGQEWUHSDNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 00280544A2A
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:19 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id y27-20020a056512045b00b00479570fbce4sf4846662lfk.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774279; cv=pass;
        d=google.com; s=arc-20160816;
        b=d1eKEl5Vr3DLBdsXBh010xmpTfYG+wiJcPaJ5SarvFuh2inrhVzQ2BJ4A3YpmEEaa5
         sOlTCWC8yQG8uNTeYgvbVeUOKMqr78R7G0YcjwEHzgTg3LtxVWhaUx6ef0f4gHdZRNW9
         7b1Ia1BiZK0uAtbzsIypDwQiaGGmizxXfowKLUu/F1gyM6U7vry1WloGSTItVJlGiE0D
         U+yzuE22d26DY3AgZOywGGvfFt3tJOxKS7FybXC0254hRYHAKI/YIM1u6+KZHAJ0QeBg
         TkekKGu/QaNr8IhfjnQk6wjQsD/1AU6p1Ri49+53cWj+pEYOeSEx3eRSgwIFY1qDGiit
         b4dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yUxukpOgq2T3s+XPKTVCGCpRw4DhN6+fdJ2N98If10c=;
        b=l7Cv3VQ9bSweomxca4hDUTVIWTAGVjm5SPWSV483vWxhcHSG3dROhxJtR5PQF8/ITe
         GKOV42npnbB5M+V60pNHxJsOq3QJ5RUm/fzImhXZWXz4khw6hlvF0wJTO15wkQeXvv+U
         lXL7C4//NBy9mIW6tpI1X1uA6rGAwIA7uzETzhSu5umCLGnCubcQLXU4A+z5rN50Kyae
         zaMrvVQZ1sdDs0JKeG8pu9tCOjHJfCtEDfZzzEFUAiwk0Gq8GBM3QHTu5/hruHxhqZWK
         nQtcJV57UzQHkki6qKaCLrnkBXyxSOlG+BUYW0ix0AsgeiWPzreGcvBPHEy2EKV5sIbk
         uCpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FUHqgrym;
       spf=pass (google.com: domain of 3bdqhygukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BdqhYgUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yUxukpOgq2T3s+XPKTVCGCpRw4DhN6+fdJ2N98If10c=;
        b=B4ncW+QLA/iVxQz9Iyz/i7x8K4MwuMFvyhxwY1V84R6A+mW/23hx5en3Kt+ga/i8JU
         cYgoIv9pWvopYFLO9tllowN2U9//5YYWrY7FMTi6vE+6/hPNXFxdAqtt5LRiStAnYnT0
         kZT+YtEZ4n/Y93EWaMCLO5dynMOv69GYNfs/aGpbUyH4ARtVOnKJ+f91cphtGppxlxr/
         Ninnu1xf4Ex0GOUmqpvKA0dRqakpBYsBJd/kFGkvlBUWao6Os+GaHVzfqmtA5ZDxTz35
         odcvItHfSgfBB9eNLis1A20m/WNl292SuBhXVps1qOfXLS6uHrVTS9GQ8Jts4e7fpXdo
         kqsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yUxukpOgq2T3s+XPKTVCGCpRw4DhN6+fdJ2N98If10c=;
        b=WPhqYbox6VJcBJsL3SCwAV5/1pNsLqNBUdEsy79fqI6xYe3uSdt8BAV1wk6NjWzfCf
         uSowPlSfHripWdtORGws93AB9w9AJs3Vx1d18Om8qPwX/AhIPO51wDZ45NxOGKSuiJYZ
         mEuk4zj0rr3ME2qTGWwI+KuUpSZrZMPNHE3Iip3KiKjgz+wbU12acbmbHmMyCQt17l/W
         Ga07xi0FLaYlKin5guZlDOSkQ4xXS8luLdBa0Gl/HB9UwU3VuQ1/1D6UI2hpxPyg2LSD
         oSzy33pwiJrVdTMjrAmuAKdMF1gH/0OnhUVacyBB+fMiIYcL5fM/pTPr5eWPxHSfW2Ar
         cVBQ==
X-Gm-Message-State: AOAM533+ScTKw3qmjkz2m1kvXh0ya8qNezyxiN3oreoXB0qRQZaw5pjh
	yYhLx54PPhp+2zdp9gVjEUM=
X-Google-Smtp-Source: ABdhPJw/IpkUXGKPIuGzvatoqC85fbTiyboefTpO/rFSomAJQeZfmKooXHGdaJmj4+a+cqJ/CQ8Pvg==
X-Received: by 2002:a2e:b168:0:b0:255:b134:99d9 with SMTP id a8-20020a2eb168000000b00255b13499d9mr6670736ljm.64.1654774279172;
        Thu, 09 Jun 2022 04:31:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls3322029lfu.0.gmail; Thu, 09 Jun 2022
 04:31:17 -0700 (PDT)
X-Received: by 2002:a19:f61a:0:b0:479:9c8:69b0 with SMTP id x26-20020a19f61a000000b0047909c869b0mr24433458lfe.140.1654774277707;
        Thu, 09 Jun 2022 04:31:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774277; cv=none;
        d=google.com; s=arc-20160816;
        b=O6hXaSmYboWepvHLqvVKnhvN3rq6PZO4OA31vBje3MyU59S9CKGD2ebyThDtVCNZRQ
         Fw1Ae2WmA5e1uMxH1v3ChEZnHNKnziM83LaU2kpHTLUxdeQKLhldpEvj32dipXgOpjz+
         +MJ0L+lxF4braDbIUPyk06JX6mKz0475+0hnp+DvMKV7mrTJeHpXBkm0waasH+BWD3un
         baeV0plWelWtssxUprMnOACU54CKluOJyEHwbjWPmw3r8iqSDXDJy3SKe94duBn/ORpo
         ljrBSg92HcrNS+8GK8nZd2vfz9F5b4vmp4YcSZrCL9MKbUstG56jcG1nJYufSc/g07sv
         7SDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=WcGBHtbaqL7btwnwCehWzC9DdtYID6QXS6Q+AzJHJpo=;
        b=uL0HjpqvoZP5HpqcxbZs1Uzxe8YU49QxYz1ZTd7lx0G0nHm2Nn8mJJYQQTHmqHQuQx
         2Cr93eZgJXZl+eqzD5hJZtR7pcMz3+uuRGMAQzm+4f4UmxrglQ6dGJhwPErrobwVI/nH
         O5Trr06QvxRvRxii9cLc1lAnr1v/O117pdoyrbR6ldJ4biDAnTgxiNkqIqrp7rrSIKjq
         wnP+0OpJpG4zWUPOvH1GILRPioBzGI72fPU5E5glpsPxaOWGUUe9mEReckE782pSv2KN
         Dj/8S3eVumGWvizudKw4TUtEht0QzYSTEqjp5gjF9lmSXMLnjqe6d5CGqj/MOQmIrwyn
         d8cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FUHqgrym;
       spf=pass (google.com: domain of 3bdqhygukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BdqhYgUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 6-20020a2eb946000000b00255889ba526si562979ljs.5.2022.06.09.04.31.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bdqhygukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id gh36-20020a1709073c2400b0070759e390fbso10678400ejc.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:17 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:aa7:c306:0:b0:42d:d4cc:c606 with SMTP id
 l6-20020aa7c306000000b0042dd4ccc606mr44735253edq.341.1654774277090; Thu, 09
 Jun 2022 04:31:17 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:45 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-8-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 7/8] perf/hw_breakpoint: Optimize task_bp_pinned() if CPU-independent
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FUHqgrym;       spf=pass
 (google.com: domain of 3bdqhygukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BdqhYgUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Running the perf benchmark with (note: more aggressive parameters vs.
preceding changes, but same host with 256 CPUs):

 | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
 |      Total time: 1.953 [sec]
 |
 |       38.146289 usecs/op
 |     4882.725000 usecs/op/cpu

    16.29%  [kernel]       [k] rhashtable_jhash2
    16.19%  [kernel]       [k] osq_lock
    14.22%  [kernel]       [k] queued_spin_lock_slowpath
     8.58%  [kernel]       [k] task_bp_pinned
     8.30%  [kernel]       [k] mutex_spin_on_owner
     4.03%  [kernel]       [k] smp_cfm_core_cond
     2.97%  [kernel]       [k] toggle_bp_slot
     2.94%  [kernel]       [k] bcmp

We can see that a majority of the time is now spent hashing task
pointers to index into task_bps_ht in task_bp_pinned().

However, if task_bp_pinned()'s computation is independent of any CPU,
i.e. always `iter->cpu < 0`, the result for each invocation will be
identical. With increasing CPU-count, this problem worsens.

Instead, identify if every call to task_bp_pinned() is CPU-independent,
and cache the result. Use the cached result instead of a call to
task_bp_pinned(), now __task_bp_pinned(), with task_bp_pinned() deciding
if the cached result can be used.

After this optimization:

    21.96%  [kernel]       [k] queued_spin_lock_slowpath
    16.39%  [kernel]       [k] osq_lock
     9.82%  [kernel]       [k] toggle_bp_slot
     9.81%  [kernel]       [k] find_next_bit
     4.93%  [kernel]       [k] mutex_spin_on_owner
     4.71%  [kernel]       [k] smp_cfm_core_cond
     4.30%  [kernel]       [k] __reserve_bp_slot
     2.65%  [kernel]       [k] cpumask_next

Showing that the time spent hashing keys has become insignificant.

With the given benchmark parameters, however, we see no statistically
significant improvement in performance on the test system with 256 CPUs.
This is very likely due to the benchmark parameters being too aggressive
and contention elsewhere becoming dominant.

Indeed, when using the less aggressive parameters from the preceding
changes, we now observe:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.071 [sec]
 |
 |       37.134896 usecs/op
 |     2376.633333 usecs/op/cpu

Which is an improvement of 12% compared to without this optimization
(baseline is 42 usecs/op). This is now only 5% slower than the
theoretical ideal (constraints disabled), and 18% slower than no
breakpoints at all.

[ While we're here, swap task_bp_pinned()'s bp and cpu arguments to be
  more consistent with other functions (which have bp first, before the
  cpu argument). ]

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/hw_breakpoint.c | 71 +++++++++++++++++++++++++----------
 1 file changed, 52 insertions(+), 19 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 08c9ed0626e4..3b33a4075104 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -242,11 +242,22 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
  * Count the number of breakpoints of the same type and same task.
  * The given event must be not on the list.
  */
-static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
+struct task_bp_pinned {
+	/*
+	 * If @cpu_independent is true, we can avoid calling __task_bp_pinned()
+	 * for each CPU, since @count will be the same for each invocation.
+	 */
+	bool cpu_independent;
+	int count;
+	struct perf_event *bp;
+	enum bp_type_idx type;
+};
+static struct task_bp_pinned
+__task_bp_pinned(struct perf_event *bp, int cpu, enum bp_type_idx type)
 {
+	struct task_bp_pinned ret = {true, 0, bp, type};
 	struct rhlist_head *head, *pos;
 	struct perf_event *iter;
-	int count = 0;
 
 	/*
 	 * We need a stable snapshot of the per-task breakpoint list.
@@ -259,14 +270,33 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 		goto out;
 
 	rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
-		if (find_slot_idx(iter->attr.bp_type) == type &&
-		    (iter->cpu < 0 || cpu == iter->cpu))
-			count += hw_breakpoint_weight(iter);
+		if (find_slot_idx(iter->attr.bp_type) == type) {
+			if (iter->cpu >= 0) {
+				ret.cpu_independent = false;
+				if (cpu != iter->cpu)
+					continue;
+			}
+			ret.count += hw_breakpoint_weight(iter);
+		}
 	}
 
 out:
 	rcu_read_unlock();
-	return count;
+	return ret;
+}
+
+static int
+task_bp_pinned(struct perf_event *bp, int cpu, enum bp_type_idx type,
+	       struct task_bp_pinned *cached_tbp_pinned)
+{
+	if (cached_tbp_pinned->cpu_independent) {
+		assert_bp_constraints_lock_held(bp);
+		if (!WARN_ON(cached_tbp_pinned->bp != bp || cached_tbp_pinned->type != type))
+			return cached_tbp_pinned->count;
+	}
+
+	*cached_tbp_pinned = __task_bp_pinned(bp, cpu, type);
+	return cached_tbp_pinned->count;
 }
 
 static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
@@ -281,8 +311,8 @@ static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
  * a given cpu (cpu > -1) or in all of them (cpu = -1).
  */
 static void
-fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
-		    enum bp_type_idx type)
+fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp, enum bp_type_idx type,
+		    struct task_bp_pinned *cached_tbp_pinned)
 {
 	const struct cpumask *cpumask = cpumask_of_bp(bp);
 	int cpu;
@@ -295,7 +325,7 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
 		if (!bp->hw.target)
 			nr += max_task_bp_pinned(cpu, type);
 		else
-			nr += task_bp_pinned(cpu, bp, type);
+			nr += task_bp_pinned(bp, cpu, type, cached_tbp_pinned);
 
 		if (nr > slots->pinned)
 			slots->pinned = nr;
@@ -314,10 +344,11 @@ fetch_this_slot(struct bp_busy_slots *slots, int weight)
 }
 
 /*
- * Add a pinned breakpoint for the given task in our constraint table
+ * Add a pinned breakpoint for the given task in our constraint table.
  */
-static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
-				enum bp_type_idx type, int weight)
+static void
+toggle_bp_task_slot(struct perf_event *bp, int cpu, enum bp_type_idx type, int weight,
+		    struct task_bp_pinned *cached_tbp_pinned)
 {
 	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int old_idx, new_idx;
@@ -331,7 +362,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 	 */
 	lockdep_assert_held_read(&bp_cpuinfo_lock);
 
-	old_idx = task_bp_pinned(cpu, bp, type) - 1;
+	old_idx = task_bp_pinned(bp, cpu, type, cached_tbp_pinned) - 1;
 	new_idx = old_idx + weight;
 
 	if (old_idx >= 0)
@@ -341,11 +372,11 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 }
 
 /*
- * Add/remove the given breakpoint in our constraint table
+ * Add/remove the given breakpoint in our constraint table.
  */
 static int
 toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
-	       int weight)
+	       int weight, struct task_bp_pinned *cached_tbp_pinned)
 {
 	const struct cpumask *cpumask = cpumask_of_bp(bp);
 	int cpu;
@@ -362,7 +393,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 
 	/* Pinned counter task profiling */
 	for_each_cpu(cpu, cpumask)
-		toggle_bp_task_slot(bp, cpu, type, weight);
+		toggle_bp_task_slot(bp, cpu, type, weight, cached_tbp_pinned);
 
 	/*
 	 * Readers want a stable snapshot of the per-task breakpoint list.
@@ -439,6 +470,7 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
  */
 static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 {
+	struct task_bp_pinned cached_tbp_pinned = {};
 	struct bp_busy_slots slots = {0};
 	enum bp_type_idx type;
 	int weight;
@@ -456,7 +488,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	type = find_slot_idx(bp_type);
 	weight = hw_breakpoint_weight(bp);
 
-	fetch_bp_busy_slots(&slots, bp, type);
+	fetch_bp_busy_slots(&slots, bp, type, &cached_tbp_pinned);
 	/*
 	 * Simulate the addition of this breakpoint to the constraints
 	 * and see the result.
@@ -471,7 +503,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	if (ret)
 		return ret;
 
-	return toggle_bp_slot(bp, true, type, weight);
+	return toggle_bp_slot(bp, true, type, weight, &cached_tbp_pinned);
 }
 
 int reserve_bp_slot(struct perf_event *bp)
@@ -485,6 +517,7 @@ int reserve_bp_slot(struct perf_event *bp)
 
 static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
 {
+	struct task_bp_pinned cached_tbp_pinned = {};
 	enum bp_type_idx type;
 	int weight;
 
@@ -492,7 +525,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
 
 	type = find_slot_idx(bp_type);
 	weight = hw_breakpoint_weight(bp);
-	WARN_ON(toggle_bp_slot(bp, false, type, weight));
+	WARN_ON(toggle_bp_slot(bp, false, type, weight, &cached_tbp_pinned));
 }
 
 void release_bp_slot(struct perf_event *bp)
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-8-elver%40google.com.
