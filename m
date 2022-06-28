Return-Path: <kasan-dev+bncBC7OBJGL2MHBB25B5OKQMGQE3J45Y5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 30EB655BFF5
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:08 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z19-20020a05640240d300b00437633081absf7529368edb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410348; cv=pass;
        d=google.com; s=arc-20160816;
        b=LqnnBLUeFyqcFG8Fk4rOszqTAV9qVXvhSTt26QPXuz38CAPR7Ecg2jmvbDK4DKue9G
         2hW2T2BbWjUUNISNHcn2TH+7vhhG3IVHe2cAZ+YrtUGhMKE1Wa8DUAPS/nRxv7tCTFTg
         L8HFDels7SJL0nuOy5ImdA1eeWoz9Jlb//WpAWBjvwoc/zjGLdWTTLwNDa8zfDtWTQgj
         ABKqPB0ig3ek1Ya/KPFOIG1AuhAn9fOLv0Lepvq4LPXQm/keBisoE101Xjr0FzlTPb9B
         GDrHlh8uZYnv8LGYPCvkKOBVlVermTjPaodLTie10Dygd0D33UBlayKJkKdy4e1LDuti
         EEYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=o67VIs2/hQWnNa37CXZT4z9MvTwhxz2Bmmmjjy77Ips=;
        b=0KkWmeN/kyuLtRQ8lQ6Mvlon4jbz7AhCySCXZLz73/6zor71bgX3l8Qd+fPvJXD1Hx
         jWgAmoStQS4di29l9sCbImE6bTOfOT2BDy+Kz6cHU4Wyl4k2aAgX0HJ+8/v1F66m//oh
         crb2Tp2sYIr9opMb2AsPg+3qrJ2PO9TtqmGjyPXO5adve7HWm3xl2iePYb6+r5+kE2B6
         azkKA/aGkoa3JvpLOuWPItLynq/XeChKgZblbpOlBxdrXquOwJ540bJV9v6D2GqcWWV9
         8azRCTVwy+1xpC98ipxm+H1a68IAtk17VuLPpke4gBWg1sI5f2Cb8roopsUELZUZh4Am
         nzOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qLGeHF0R;
       spf=pass (google.com: domain of 36tc6ygukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36tC6YgUKCZM18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o67VIs2/hQWnNa37CXZT4z9MvTwhxz2Bmmmjjy77Ips=;
        b=F1pQxjKZjZCHgz17qhc5WZ2gKKPxFwIrv+3cxWCSkHrGTEgkumjEX93eYE7porNDxT
         XrPAzCXZ91K+T8/MwrMY1DQzshO87yY1OcxfMu6UwEFdUmJ9U5Ab+WgViKoX1H3ATE7d
         YhWP+Ek7uOD+IenPAztKVUmn/InIRf11RDVps6HE2EkRQuAT4rRvOZA+RQW47wiB76NM
         CE2PJ5KNg0rQI20nqsyPcgD1Zyb0BnqMZYHBgOfAAswpdbJR8ERr7TJjBlU7dIjC3mm8
         0msYWfz3WkxEJBxT+C401Q4XGGSFgQFJm25GAMCAOKjuEb3tg/kSI717bvwR9DhdXZjv
         8f6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o67VIs2/hQWnNa37CXZT4z9MvTwhxz2Bmmmjjy77Ips=;
        b=yPeko1MS9BWbENPWyTCSSDb3nMh4BDADi3LbT9JILhde+yflOczI8WNc22WTSPwBwu
         3oqF93jydovgedq4csQ9prRrfSdce9idQFszqi23IYdBtywByOTfKRQa6uNSXQm/0Aeq
         grKtg/RRuOrlETyKLZXyUQ0acftF50qlHrANjZ25U6mnmHELHIweYfNP4okNy8PGKgdR
         Ozqp1rYBXoR7omesfYdimnmnRga3+cg8UgBgJGFi5+hNd8ROupprfWheWpJjrdZldp0w
         4b4uHHAGPXmd5ZGm5qqcwIuRnoUOSIFlNeuczthEyzP41xSjcBXM+DITz4n7l626Rs1n
         mvdA==
X-Gm-Message-State: AJIora9Men3CLjPhJmcgAv/fASChPzXzlzTbtc7ReCQf6UfLghDn/HMP
	1GpTvzCBKXFNzu03TR79abI=
X-Google-Smtp-Source: AGRyM1u9BdizSGSW+QhLkYuIm736GlJN9sG011URvz4jKUvvNzM5BPz7VWfm95MVYGE34VR/HOhXiA==
X-Received: by 2002:a05:6402:2752:b0:433:3a08:27b1 with SMTP id z18-20020a056402275200b004333a0827b1mr22017061edd.235.1656410347922;
        Tue, 28 Jun 2022 02:59:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls5620674ejs.6.gmail;
 Tue, 28 Jun 2022 02:59:06 -0700 (PDT)
X-Received: by 2002:a17:907:3f81:b0:6ff:1a3d:9092 with SMTP id hr1-20020a1709073f8100b006ff1a3d9092mr16831773ejc.319.1656410346668;
        Tue, 28 Jun 2022 02:59:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410346; cv=none;
        d=google.com; s=arc-20160816;
        b=gaLwjH6GeXef98uUfWvF2EDYhfyjgr89TD/ybtBHQEvEm7OwclJNqhqPlL7rtut/OT
         Od8J1pBk4uq8/jVR9Iahhai3dwCfFIBlwsF5s7bIgUv57srnh4AMK+xj0+O/DBf0DJSO
         4A7jD/a6KhIpitVsko4IyUzdnKhlLhnhajpkrh0mh5lpo+6tr+hxrPZZBYiCbXAfhEH9
         60WPUs4rJxw08iKiIf9uiJlwf2zlju2eio07x/gjuE3bSymfvOmnKHOq9zAk9aYJtLQW
         DFWVtPChkDB00yn1ewFhwD3LPqzEzSmKMyprrju3PwmQJDWl4O6gqLiquAPjlOChPWid
         4vXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=e+EIQiAUqemssDNIM5WUvkc+KdFQ1BIIF5nbA/MVrfg=;
        b=m6qy7ETKr/Se10nVz7n93rZavsOJwTlMdYthXxv6u67lOkdffyAJHogSz0tJroumrn
         v2JmqJhF0cMwwBOd7irI49pvw4hSNrT7mABo4KQpb4nHaqcANgx4SJD+m4bTZEmRMkL2
         QJYI5B1UrX7WHiABwt2kTho3/79jlET8wnlaoQcu4N1PIna2Ty9mOX/ktdwv5zGgDZu9
         TwF0cHS5PNVeQaocENFyi5vfGEm3alUn5G35HbgchhPMFEpzkBAY7eyvpsZYiSdLd8p5
         hzek+m9QtKliCvGfzLmquSZ8flneHr+4BZ4MzSOkC7AYkHWbOe1ngFJqRGuAsWiu4/5P
         Po9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qLGeHF0R;
       spf=pass (google.com: domain of 36tc6ygukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36tC6YgUKCZM18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id e24-20020a50fb98000000b00435a7649ad4si663712edq.5.2022.06.28.02.59.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36tc6ygukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hp8-20020a1709073e0800b0072629757566so3406050ejc.0
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:06 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a17:907:7b87:b0:726:c868:cf38 with SMTP id
 ne7-20020a1709077b8700b00726c868cf38mr4432036ejc.580.1656410346473; Tue, 28
 Jun 2022 02:59:06 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:23 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-4-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 03/13] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b=qLGeHF0R;       spf=pass
 (google.com: domain of 36tc6ygukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36tC6YgUKCZM18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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

On a machine with 256 CPUs, running the recently added perf breakpoint
benchmark results in:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 236.418 [sec]
 |
 |   123134.794271 usecs/op
 |  7880626.833333 usecs/op/cpu

The benchmark tests inherited breakpoint perf events across many
threads.

Looking at a perf profile, we can see that the majority of the time is
spent in various hw_breakpoint.c functions, which execute within the
'nr_bp_mutex' critical sections which then results in contention on that
mutex as well:

    37.27%  [kernel]       [k] osq_lock
    34.92%  [kernel]       [k] mutex_spin_on_owner
    12.15%  [kernel]       [k] toggle_bp_slot
    11.90%  [kernel]       [k] __reserve_bp_slot

The culprit here is task_bp_pinned(), which has a runtime complexity of
O(#tasks) due to storing all task breakpoints in the same list and
iterating through that list looking for a matching task. Clearly, this
does not scale to thousands of tasks.

Instead, make use of the "rhashtable" variant "rhltable" which stores
multiple items with the same key in a list. This results in average
runtime complexity of O(1) for task_bp_pinned().

With the optimization, the benchmark shows:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.208 [sec]
 |
 |      108.422396 usecs/op
 |     6939.033333 usecs/op/cpu

On this particular setup that's a speedup of ~1135x.

While one option would be to make task_struct a breakpoint list node,
this would only further bloat task_struct for infrequently used data.
Furthermore, after all optimizations in this series, there's no evidence
it would result in better performance: later optimizations make the time
spent looking up entries in the hash table negligible (we'll reach the
theoretical ideal performance i.e. no constraints).

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Commit message tweaks.
---
 include/linux/perf_event.h    |  3 +-
 kernel/events/hw_breakpoint.c | 56 ++++++++++++++++++++++-------------
 2 files changed, 37 insertions(+), 22 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 01231f1d976c..e27360436dc6 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -36,6 +36,7 @@ struct perf_guest_info_callbacks {
 };
 
 #ifdef CONFIG_HAVE_HW_BREAKPOINT
+#include <linux/rhashtable-types.h>
 #include <asm/hw_breakpoint.h>
 #endif
 
@@ -178,7 +179,7 @@ struct hw_perf_event {
 			 * creation and event initalization.
 			 */
 			struct arch_hw_breakpoint	info;
-			struct list_head		bp_list;
+			struct rhlist_head		bp_list;
 		};
 #endif
 		struct { /* amd_iommu */
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 1b013968b395..add1b9c59631 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -26,10 +26,10 @@
 #include <linux/irqflags.h>
 #include <linux/kdebug.h>
 #include <linux/kernel.h>
-#include <linux/list.h>
 #include <linux/mutex.h>
 #include <linux/notifier.h>
 #include <linux/percpu.h>
+#include <linux/rhashtable.h>
 #include <linux/sched.h>
 #include <linux/slab.h>
 
@@ -54,7 +54,13 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 }
 
 /* Keep track of the breakpoints attached to tasks */
-static LIST_HEAD(bp_task_head);
+static struct rhltable task_bps_ht;
+static const struct rhashtable_params task_bps_ht_params = {
+	.head_offset = offsetof(struct hw_perf_event, bp_list),
+	.key_offset = offsetof(struct hw_perf_event, target),
+	.key_len = sizeof_field(struct hw_perf_event, target),
+	.automatic_shrinking = true,
+};
 
 static int constraints_initialized;
 
@@ -103,17 +109,23 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
  */
 static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 {
-	struct task_struct *tsk = bp->hw.target;
+	struct rhlist_head *head, *pos;
 	struct perf_event *iter;
 	int count = 0;
 
-	list_for_each_entry(iter, &bp_task_head, hw.bp_list) {
-		if (iter->hw.target == tsk &&
-		    find_slot_idx(iter->attr.bp_type) == type &&
+	rcu_read_lock();
+	head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
+	if (!head)
+		goto out;
+
+	rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
+		if (find_slot_idx(iter->attr.bp_type) == type &&
 		    (iter->cpu < 0 || cpu == iter->cpu))
 			count += hw_breakpoint_weight(iter);
 	}
 
+out:
+	rcu_read_unlock();
 	return count;
 }
 
@@ -186,7 +198,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 /*
  * Add/remove the given breakpoint in our constraint table
  */
-static void
+static int
 toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 	       int weight)
 {
@@ -199,7 +211,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
 		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
-		return;
+		return 0;
 	}
 
 	/* Pinned counter task profiling */
@@ -207,9 +219,9 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 		toggle_bp_task_slot(bp, cpu, type, weight);
 
 	if (enable)
-		list_add_tail(&bp->hw.bp_list, &bp_task_head);
+		return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
 	else
-		list_del(&bp->hw.bp_list);
+		return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
 }
 
 __weak int arch_reserve_bp_slot(struct perf_event *bp)
@@ -307,9 +319,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	if (ret)
 		return ret;
 
-	toggle_bp_slot(bp, true, type, weight);
-
-	return 0;
+	return toggle_bp_slot(bp, true, type, weight);
 }
 
 int reserve_bp_slot(struct perf_event *bp)
@@ -334,7 +344,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
 
 	type = find_slot_idx(bp_type);
 	weight = hw_breakpoint_weight(bp);
-	toggle_bp_slot(bp, false, type, weight);
+	WARN_ON(toggle_bp_slot(bp, false, type, weight));
 }
 
 void release_bp_slot(struct perf_event *bp)
@@ -678,7 +688,7 @@ static struct pmu perf_breakpoint = {
 int __init init_hw_breakpoint(void)
 {
 	int cpu, err_cpu;
-	int i;
+	int i, ret;
 
 	for (i = 0; i < TYPE_MAX; i++)
 		nr_slots[i] = hw_breakpoint_slots(i);
@@ -689,18 +699,24 @@ int __init init_hw_breakpoint(void)
 
 			info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
 							GFP_KERNEL);
-			if (!info->tsk_pinned)
-				goto err_alloc;
+			if (!info->tsk_pinned) {
+				ret = -ENOMEM;
+				goto err;
+			}
 		}
 	}
 
+	ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
+	if (ret)
+		goto err;
+
 	constraints_initialized = 1;
 
 	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
 
 	return register_die_notifier(&hw_breakpoint_exceptions_nb);
 
- err_alloc:
+err:
 	for_each_possible_cpu(err_cpu) {
 		for (i = 0; i < TYPE_MAX; i++)
 			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
@@ -708,7 +724,5 @@ int __init init_hw_breakpoint(void)
 			break;
 	}
 
-	return -ENOMEM;
+	return ret;
 }
-
-
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-4-elver%40google.com.
