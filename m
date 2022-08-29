Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCXLWKMAMGQEWCEF5RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CF8EC5A4C39
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:11 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id c18-20020a2ebf12000000b0025e5168c246sf1861413ljr.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777291; cv=pass;
        d=google.com; s=arc-20160816;
        b=RvxLaRC/Yy/G+/10tED4ST8WU2S4dKPHfnCeOBclALe4NC92lOs3ksy/iLthKjYHh7
         D4kCjkd4wmEsnzF9r560yGCSx2Yvh1LRrlbUNj86TU0djXUzJoXheWFxsHhnnApjFwn8
         nph1b6n4o9NiBbrYzORp+Ze9B3Uq/8g2oH2o0E7OwSMfVA8eIvyDMo/L3rhdV9tltknc
         Z1onaUfF47vr0e17NZnoVsHJLh+Nfsj1P8stPX3D2jPOXgfBSQNr0RkoHnhTF64alF3o
         0RUFBB+kt4wMpuAyIqAHpiBVoikEKlKsf0vuDyTAR0+CRzBpSKigW/v4A0uC5FFybxp5
         nDFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SrVNVB0lKJ+h5/4ooiOtqi+U/2b7Mg/irK56KONUNEg=;
        b=q/Xdy7krzekykbzzWD5x5QZBWc7tJ7Y0JUQbigv/K45wbSSO+FQm/KvrprtrWVPB1Y
         c+GHqoHlqeJ72by6tFbKCLHjux1cZJfAdM7nHQbcob41QFy7j1Lo012awM5BoC0H6mcS
         f1HZwBzGoSy1w77pzAHzp8Pg8n92xKgW0u7QdcCe/idE+pvG/sNpltYUUPVlAXIUSHv+
         eY1felEzrF0dr7M47MaIUdGd5eeBphm8Y2YBarlHYpl+TbsTiXoZgweWqohLAdBddUMx
         JJAXmOlxJRfmIXycebgTndhlR3tz4fhtK/JmTos+t09TXJX411p50jLFxTK45By24uGO
         EM4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="QxY/7D4H";
       spf=pass (google.com: domain of 3ibumywukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ibUMYwUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=SrVNVB0lKJ+h5/4ooiOtqi+U/2b7Mg/irK56KONUNEg=;
        b=CW9F692xc1/lR8d5oE+rCAu9YURZ6sfo2oqwEvyv6UgobfvfFdM7MR7yuOiw+Lfjr2
         35Dwwj+tWuI4qP3+ls9DfMtt1uDbOSyVV6uDJCVEQ9MRppULr3epjW/rUV7bg0Qbr/q/
         lBs7WT81HuTLsb6CQ1z9clMDvgyCA0mHK/lgbWbM6twD5KEZtBwUO0XdyTRNc2F4WxYE
         ofSGKYkU8B6f/Z7EB0DfzUNpkCQ8F3RTByjIme/HvgWq8UYTpJSoC/fQ1splv+c92Amd
         pmeXpW7+tQcywom/xRgeY3PofZdp30pbbUikdHGLZ3P5HOuCjznMhO6CVUL3GpuzVX6d
         7VOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=SrVNVB0lKJ+h5/4ooiOtqi+U/2b7Mg/irK56KONUNEg=;
        b=rglRAwm6fogH6poNEOPZopuJ2n5pYq7og3XiTwQSBmoibncdS1ClxyAJS2zL+JXuPz
         1rOZxoKYIcMH3fHRY+0lo1T+cB4rVvyjKn2kosGEKOYfEvGpz688+U80WyUBSmKNN854
         TiT/cy1Xl4OqkAdXhJXf/K64HwOn2tROxajLXpJ/4oARQJi4q3a6pE5kZOh3Q4LnfnYD
         UMkn9Gor0GwOvfeTp5oDCmKIe6XNYXb9Cz0KFgzr/c9nn8YwFk1ydM5Rd3hawDiHrA3Z
         Bmq1EENUV18ts+dztL0AMkJ2vB32A37NuYLqr5xqlyU7T9msh/0MKznAfkbty+sPwbbG
         jVog==
X-Gm-Message-State: ACgBeo05Ipgqz9qDc9jK8PVYnSj6q9QwnZR4QuwYQKCE8SkD/fkdS7YC
	xyfYUbAbOTZcClHgvmH9FPk=
X-Google-Smtp-Source: AA6agR6Zwh4h+sdbSOlUiXQeGcvL/6dzenwdoMQBfT9WIMxP/88cJMplM8Kv8wrJb/c00cJD9Edzew==
X-Received: by 2002:a05:651c:211d:b0:266:20b6:ae57 with SMTP id a29-20020a05651c211d00b0026620b6ae57mr688339ljq.108.1661777291175;
        Mon, 29 Aug 2022 05:48:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3588:b0:48b:3a68:3b0 with SMTP id
 m8-20020a056512358800b0048b3a6803b0ls4737022lfr.0.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:09 -0700 (PDT)
X-Received: by 2002:a05:6512:1285:b0:494:680f:390f with SMTP id u5-20020a056512128500b00494680f390fmr2188434lfs.601.1661777289731;
        Mon, 29 Aug 2022 05:48:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777289; cv=none;
        d=google.com; s=arc-20160816;
        b=Z1zZzfGMx9j78KFvrC/r+dZYb+rKO/uNSK/OGQ1IGRycsx9tsgYEtAuCDixSh0ZKNj
         GmAZn1IBCPahOw/HC4pmlua6XZa8TYeDHn6t6KQIk8zYqyZh1kM/JxAVUNXOv2nKZ6K+
         NGrA8xlsUaspE1iWsPUugydSk5k2/nsYGPk718tdCvU3urf9i+AsgYuk45S00r4U00gr
         qvssfJPKC6lAmNxBRWOU+XOKtJFTcj57vviMA5+/ao37je5ax/AmlBRd8lS+7PKukaku
         O5DUMX3aWX+jjrNEvnYjq/tyKimUrp55lhVoshJEBQAYncwg/UzB5NO/vt1s4XJ//SKB
         Xz/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Qud8pWzf3g4FVwsYBG/lvnDK9jpEJXDArWePZHukaec=;
        b=PkWytD6/oXO1WoZbYTwg/dEuoB1S7N3N45cfsW0HJnGmC9VKwUiIksGwnFSJXwtO58
         AfmCKARIktQmn5LoxxjxaL1PU+nh05c5wcGpZH0QLYWiTnE6d2epE3t+fhYcL2UR+Mvb
         T87Mx11oCjSNl8B8K6oMWNtSOa1HJev0w6k2/KiE34jpA8lk4Cbixt6DZjPwqximD9FA
         ATM/25yYy7BB1RH49ghkgD9hPDHbJdSZJIl6qyyYMQafV8kyXJMqbvZ4h9paisAqKtSl
         t5JLeDibrIs5MgXhABlmEVhsfmhq7p7KpJK5l03wgHWvr7zX8EwDBTR7TlLcDLEx3o6k
         0YzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="QxY/7D4H";
       spf=pass (google.com: domain of 3ibumywukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ibUMYwUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id p15-20020a2ea4cf000000b002652a5a5536si3769ljm.2.2022.08.29.05.48.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ibumywukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sh44-20020a1709076eac00b00741a01e2aafso942773ejc.22
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:09 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a17:906:cc13:b0:73d:d22d:63cd with SMTP id
 ml19-20020a170906cc1300b0073dd22d63cdmr13213673ejb.741.1661777289495; Mon, 29
 Aug 2022 05:48:09 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:09 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-5-elver@google.com>
Subject: [PATCH v4 04/14] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b="QxY/7D4H";       spf=pass
 (google.com: domain of 3ibumywukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ibUMYwUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v2:
* Commit message tweaks.
---
 include/linux/perf_event.h    |  3 +-
 kernel/events/hw_breakpoint.c | 56 ++++++++++++++++++++++-------------
 2 files changed, 37 insertions(+), 22 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index ee8b9ecdc03b..a784e055002e 100644
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
index 6076c6346291..6d09edc80d19 100644
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
@@ -707,7 +717,7 @@ static struct pmu perf_breakpoint = {
 int __init init_hw_breakpoint(void)
 {
 	int cpu, err_cpu;
-	int i;
+	int i, ret;
 
 	for (i = 0; i < TYPE_MAX; i++)
 		nr_slots[i] = hw_breakpoint_slots(i);
@@ -718,18 +728,24 @@ int __init init_hw_breakpoint(void)
 
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
@@ -737,7 +753,5 @@ int __init init_hw_breakpoint(void)
 			break;
 	}
 
-	return -ENOMEM;
+	return ret;
 }
-
-
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-5-elver%40google.com.
