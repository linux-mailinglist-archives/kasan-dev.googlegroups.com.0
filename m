Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NTQ6KQMGQE5CIRFLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id CD31A544A1E
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:03 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id i19-20020aa79093000000b0050d44b83506sf12291239pfa.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774262; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sxs94CQ78c2STQwO5YxHJI9sk7UBVAtmjbRd+671xbz+p2PYBn//YDRbbTAmVDVBlW
         gTGSF5jlaTNsqwExHBo5bdCazOE/BrnWbBDFf+9swU/EdK4Xy+rIpSqQHOrcka+yM+ux
         37YLqbEefRH+27zsOSX2MKEiWfYXdtRp+mRdhCKCm9fdZ+SqEsv8/PM/ftI1uc4ZRYbC
         yb6BpK7N3b25PUqmqlo2zGxl9uFir3uq2aUcLoGJfMudl0GmI0enWZuNF6/OtLhz9qmS
         vkRHXYHx+KXck3V6hrmI5QJfyKOk9ivzfK41PyD4itRNVbWYnkUcL72KhOwmFG9NdBLB
         nhWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Zhf/CX2PTtr9dhsYxTYvSdrzja3giZ2utbXMJ5iFZQM=;
        b=Ika6Qj8fiEGFGBXDVJbSWXqYLZKp5UBnJiuYB0ptJUGGrIYgSMWB+onrTwADBEw941
         6ibt3DWSuTV3jIcv0DuwBzz2H4/igqEyiZZ9jX6f4ep5ODf9pMP7SrmEiRtJzUZG9EqD
         wRItva9ggKpUUHk3UKqiDEqwgaLN5mTUbx4KuBpxtAec/W0UkhgRRwFedj728oEcYEYc
         U7VBKPodgZg5gqikPhx6iexpEjLRXV6+RGjV4is/p2BQj8mF2i/dp/Z+GaHnxUOjSc/J
         ufx98STO9NlyTfe1TnrRCnB4FlnTN7xWVNfw3VrxBekKwEx4yCW4rTLWJF7D4Z3NwL4i
         v9NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rJ6pp5xo;
       spf=pass (google.com: domain of 39nmhygukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39NmhYgUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zhf/CX2PTtr9dhsYxTYvSdrzja3giZ2utbXMJ5iFZQM=;
        b=PwHrz5eO3dy7fYcDUvxXHvQSAD8J6DRZFvtKHaLBJmF9L1fJHz1hlOh90e/4joEacw
         7kAj7lfboFZg6IAWMnqfCN8YCnLCB1VWwVSeS112wYK57oYir+jGIqityzHd/ytfPYLp
         NPQ10C3sjAH2Ikmzpv3F/q9469XuVHc7DPkd7Fm2GKzk2rQG8nm51IO9LeFu1PQJJYfC
         d5GXwRAzLw3xUw8HFjHId5hty6m3pcSwQzyCKi2g2ImDcQUjWZ7eJ8ejfzh6ZQ4w/gid
         E/7efpXbRWZuFb4dPkh/46+C+x3r5MvM5UelgrcyLAJXpby02LLezS4ykoX9K8I4DArR
         BsMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zhf/CX2PTtr9dhsYxTYvSdrzja3giZ2utbXMJ5iFZQM=;
        b=X3lBiNeAMm9oGE0ZCoygCeTSlr+fTwYfosqbU0PGHf8/s3yPxP1Ija+qAK4ENa0mYH
         Q4jm8OihAgMv3bw5sAPTjTtBKyFwPZaiFUKFQ7lNEJPL+Fgt9mQePH1AalkZXAMAhe0n
         Y/wTPVzYEwk59SBZvXbg1laYvirLYlL3SEt+AKuJMy1Wywk/gLuoO63jJRKJ0tD63Xa7
         0statTVSqsOuv9h51y84n4Lh7uKxvi2JxpvxqMLA+3NLcnWIUvEA5CTV5DbZETc2qnm8
         gJxmBMu5wTiqPPn0SEkQzGSIwWGzm/2HsDSYrc5h0qyhcGCAle0E6EdcWV7VJUtgQrpJ
         Fw9Q==
X-Gm-Message-State: AOAM531VSFIdCEyYf9U6jBBNe6UQxU6B3yL4wmhUdEC5zEci2l85f1BN
	cDgrOdVzFz8bU6g2AjII56E=
X-Google-Smtp-Source: ABdhPJxkwd25nhBIlvGS5Ukq4n1sIRQz/nHPRK0svs4ccJSl7BwRMj/uwrpCfRSEIjvPs+CtIa5WtQ==
X-Received: by 2002:a05:6a00:1152:b0:4be:ab79:fcfa with SMTP id b18-20020a056a00115200b004beab79fcfamr106137529pfm.3.1654774261957;
        Thu, 09 Jun 2022 04:31:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5a81:b0:1dc:e81d:6bb1 with SMTP id
 n1-20020a17090a5a8100b001dce81d6bb1ls1454628pji.0.gmail; Thu, 09 Jun 2022
 04:31:01 -0700 (PDT)
X-Received: by 2002:a17:902:d54b:b0:164:bf9:3e1e with SMTP id z11-20020a170902d54b00b001640bf93e1emr40109905plf.58.1654774261179;
        Thu, 09 Jun 2022 04:31:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774261; cv=none;
        d=google.com; s=arc-20160816;
        b=a3IX3x8otBYuj1phusD8zJ5XAzVveLO2Zv88fdHsqOsSlkpZ9mebPMU8jJQLhJ3lIw
         giZBhkhsq/sTyLCBUuhuyaVTZB9zvfIjuOE5S86inZ9KdlwJtJY2POXhL0etFxACWQ57
         WUlUQiolT7An25aCcIQAPm+MMSeH8g5cnSC5TAvbvg/OJikMqmXWNB+AWIfklH0eVEcH
         S07NYaPus9kKjLIBfvCLhP8kvRn/UXWThCMDvfAN4LitNHC78g+w+RS2JUjxK8X/YB7T
         sZRihgRp32vHhfcO5q/SCf6pBe2EoT89919K7dVf+TjDgFmQ5KevgAgG43hooonkQZig
         nsng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vZHbZ1oi5OSjCMeU4/rneix3L5XarWjinLy785pgor0=;
        b=dFGTx0cCRi5EvDYsNKdViuFsp08KQPrjP04Lm6kPDl+Yrs4CF9mcUi1CPMSPtotLnE
         xC3ioJ3X0XqtyfBjG6eekJsGr5w39/krbyQH2ycgJzq44174f3tLazkVRxJMPCBcea7o
         jnFj1bFM4TMRgUMhoMZdHfkaMzLZPK3DPC+hCXX8vY20wPMdbguikq+UCZjdXHa9vrjO
         If4vt8nFcW6KzJMWVD/qRcuJnjGWO4qdXc+eiixQjaStf9RFFuH9DeulZl1/jsIfVNA7
         CDpgScFp1r31T0TKRFh122WFXDNHvjvIzBU80MPgSw8k9rofV6E/tNBKEt5p2xCaI4Df
         b3NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rJ6pp5xo;
       spf=pass (google.com: domain of 39nmhygukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39NmhYgUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y203-20020a6264d4000000b004e1a39c4e87si961215pfb.0.2022.06.09.04.31.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39nmhygukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id s22-20020a252d56000000b0065d1ef35f9dso20083612ybe.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:a25:dccd:0:b0:65c:bc72:75bf with SMTP id
 y196-20020a25dccd000000b0065cbc7275bfmr37441073ybe.315.1654774260428; Thu, 09
 Jun 2022 04:31:00 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:39 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-2-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b=rJ6pp5xo;       spf=pass
 (google.com: domain of 39nmhygukcusry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39NmhYgUKCUsry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

While one option would be to make task_struct a breakpoint list node,
this would only further bloat task_struct for infrequently used data.

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

Signed-off-by: Marco Elver <elver@google.com>
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
index f32320ac02fd..25c94c6e918d 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -28,7 +28,7 @@
 #include <linux/sched.h>
 #include <linux/init.h>
 #include <linux/slab.h>
-#include <linux/list.h>
+#include <linux/rhashtable.h>
 #include <linux/cpu.h>
 #include <linux/smp.h>
 #include <linux/bug.h>
@@ -55,7 +55,13 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
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
 
@@ -104,17 +110,23 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
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
 
@@ -187,7 +199,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 /*
  * Add/remove the given breakpoint in our constraint table
  */
-static void
+static int
 toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 	       int weight)
 {
@@ -200,7 +212,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
 		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
-		return;
+		return 0;
 	}
 
 	/* Pinned counter task profiling */
@@ -208,9 +220,9 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 		toggle_bp_task_slot(bp, cpu, type, weight);
 
 	if (enable)
-		list_add_tail(&bp->hw.bp_list, &bp_task_head);
+		return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
 	else
-		list_del(&bp->hw.bp_list);
+		return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
 }
 
 __weak int arch_reserve_bp_slot(struct perf_event *bp)
@@ -308,9 +320,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	if (ret)
 		return ret;
 
-	toggle_bp_slot(bp, true, type, weight);
-
-	return 0;
+	return toggle_bp_slot(bp, true, type, weight);
 }
 
 int reserve_bp_slot(struct perf_event *bp)
@@ -335,7 +345,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
 
 	type = find_slot_idx(bp_type);
 	weight = hw_breakpoint_weight(bp);
-	toggle_bp_slot(bp, false, type, weight);
+	WARN_ON(toggle_bp_slot(bp, false, type, weight));
 }
 
 void release_bp_slot(struct perf_event *bp)
@@ -679,7 +689,7 @@ static struct pmu perf_breakpoint = {
 int __init init_hw_breakpoint(void)
 {
 	int cpu, err_cpu;
-	int i;
+	int i, ret;
 
 	for (i = 0; i < TYPE_MAX; i++)
 		nr_slots[i] = hw_breakpoint_slots(i);
@@ -690,18 +700,24 @@ int __init init_hw_breakpoint(void)
 
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
@@ -709,7 +725,5 @@ int __init init_hw_breakpoint(void)
 			break;
 	}
 
-	return -ENOMEM;
+	return ret;
 }
-
-
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-2-elver%40google.com.
