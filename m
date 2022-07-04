Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYEDRSLAMGQECKTI2LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 63742565938
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:09 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id c13-20020a05651c014d00b0025bb794a55esf2836216ljd.10
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947169; cv=pass;
        d=google.com; s=arc-20160816;
        b=ggrPRFpLJj0tVq9af2bchA/hiuci2U0Ki5BijDaOqG7uTDxn+lADLmxddY2C50MPYa
         a4zhir4EtzsjzAIBL1UzIeGQKgIxlMNtCxGQ8q0LYkZVthuK6EXED1lj2oHseB7DaDHV
         gm0tZuSFkLJtYV89fXd0mPB3ZCtP7bjIp6fEccgaWAi/3Yu1OSCfx1J9fgqX3g2SAdAJ
         juR8xkLzs5aWSQh0VdyaoLrq7EdPqrwrTdXqUYLoP9xUl2MLYllelZKN+xlB2V27xFXV
         aWR7NzoieIlCzk3ZmpZbgUzPv/l+lG6euZmHdlcWMY01dQ3ocxVqIux8V7osCrcaxOdD
         uqFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=I+Zqscp4zftF1zvM50X9mRBofkNgm6LHUcvIiP17Ub4=;
        b=u06wnIMda67ojzEQipukrwGrXmK/FhaXHTDL8FHyCnT6zgYI3muOChqX6TnK8K2f00
         ljSUEpctuELFEQ1jjU4MoQJ1gbEZy8d3ic7uVWrMlifqr7cJdWrV26nbAvHEJy1x2Nzi
         hDgjqpTFB+ITocb4HfSlZEisOKxm6br3oyieC/vC1jrKtctqSq5POKoacCkQC1HQ00NE
         r5T4NCe5P9eECluxz/7j48cOKrzdxag7bxwu5+hQnSW8NlXohqf27abS/e1zE3yMX7OA
         H86L3wvcRFiSthx9okHCb9eJsglwISEWwtaKA2EeHPtyU74OoSIeQtd4hjS2hB7aVupM
         4ryA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bYGAltsL;
       spf=pass (google.com: domain of 33whdygukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=33wHDYgUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I+Zqscp4zftF1zvM50X9mRBofkNgm6LHUcvIiP17Ub4=;
        b=XlU0n60S92UnOJL8+8O3D13pBA4T9DwF6jSkuZoC+07Urd6UjsBHsfcE63OVmbboc5
         gB99RCMB/V9JCf5F8BdnzHNQVYsgTz+Kol3w9sb4/yB/OsBVMn+zWHEMj5WTylewUf+t
         ptgM6s16rGlH5r/WNndJaqwxGW84ztD9DWoHPr7iyVhl/EObbSVvERbOuUMHy5YiRYBt
         aGza0aBPNHx6mO900l/1wbbTlLsFKZCnWfXgCBDUo3UEXyY6zCgClv7g7G8jUEMzWToV
         zPdAEXNNzeMnm9y7rahngqpSoNJnpNfqUYKRflGhMMya26jDw8EjYOUceDNjz2YYHOTp
         +cDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I+Zqscp4zftF1zvM50X9mRBofkNgm6LHUcvIiP17Ub4=;
        b=ykl51eRpstmj+AXcBjBKZyq168F5P+JdTOvjnBk8mN66Ic68U9fDgesYWZ5Klvpa8g
         AwpDcn6C3cF5XEvv6XGqW5pQVJ+d92tY7Zl5WWvE0ZQHWf9bS7nhTfvq1XRYBD1eHsHT
         bfze0JcsPRSO6dK3iUo8wJIcpLcxAiVgb/Goc3ZotXA2KDpFBo9ChUf/nixlPS8zARJY
         DXDlnNe8HwFAPAUGjoWwD089l6p4bYplGxdSt/ZXQxWwcjoKoCzlU2/o5mOJPQV3fsUe
         iwy/riXe4BTN6cAfJ1TqOwz4FtQptiYhkZEyOedo+KMHhNFDd+mN95pNZ6k3/QOtmSMd
         ptew==
X-Gm-Message-State: AJIora/dVuYrQkHwmF7KsHzwJlaNwEk6f46S6if8RPCFg7n3CcSyzT6R
	muOJIQb4955Wd3NpoFHZ8v8=
X-Google-Smtp-Source: AGRyM1vatLyQyZCaRf2arRYEoZRceGzD3KCd9AnSwOVxKwC8NABHlqh50pBTDbG96+8ZDR4vXHWw/Q==
X-Received: by 2002:a05:6512:104b:b0:47f:68c7:4b1 with SMTP id c11-20020a056512104b00b0047f68c704b1mr19523997lfb.315.1656947168890;
        Mon, 04 Jul 2022 08:06:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls780729lfv.3.gmail; Mon, 04 Jul 2022
 08:06:07 -0700 (PDT)
X-Received: by 2002:ac2:4906:0:b0:47f:6c71:6de5 with SMTP id n6-20020ac24906000000b0047f6c716de5mr20295236lfi.137.1656947167496;
        Mon, 04 Jul 2022 08:06:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947167; cv=none;
        d=google.com; s=arc-20160816;
        b=O2NRNMxjPoBWrXb0jiO5HSoWG2N9wkzIMXdW2nz7cjA+hTWbu5VgsEHCaaegm7eE9a
         lJWElk/mtfsNiVlxXqMfKSBxbUH8uFtU/FVNhsSC7wtlrPubJ5xfaZ5cpRZnofICYjhg
         7MWZjnFgDhJ87rTXqyamTNKVdkg5ubMXFcLJq3bIJlhTYA6fSm6tWu80tZJxg9ubHjo3
         c+H5wDjoKVc1nO1BKXdnutoK7qll/E/YoXjSloABHFWHfDSpHllkftMU5TGUYgmtipqu
         YSd2u4igEnuBwqYGyKk8Spzh2NQCg9nZr8iUuQpOcsgL+RQlquN15NP/3+S6pGBDXTlh
         /kyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3Qgep28qH2mkV9jarBi4ciQq1DboNBSIg9Dd1YIv8wg=;
        b=jB/2mbQHGn3Mr6REt6AyAHinrND5aAPy6q5LzvMOv/5/ozm86jPpnk+WnmXof+Nv82
         L9YFvPd0DIuRuRSDydTyVaEmo47AKUaQGSs2WRqdwe51NENfhxO4GIEzOxqi/hEs0hMo
         S7BqUM+DGDmQPkOyJSOFWJyVQfbig0/6RgvXGnQlRlJQL/KiRydUJTmcjd+3qCHYkfzp
         TQdbAd40kZIqsaTAoTvC343UaykIwZfRiwTsvCzj4fBVg4dq+nHYjfh9yHUwOy098wgD
         tk1k6wJPqDhULl2zOIoFowJjTZakPAA5p46oQ0v8MK0xeTLXChVd7HKOKe+4dpSPmufs
         fgyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bYGAltsL;
       spf=pass (google.com: domain of 33whdygukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=33wHDYgUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id c38-20020a05651223a600b004811cb1ed75si950546lfv.13.2022.07.04.08.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33whdygukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z11-20020a056000110b00b0021b9c009d09so1468463wrw.17
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:07 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:adf:d1ea:0:b0:21b:a6cb:fcf6 with SMTP id
 g10-20020adfd1ea000000b0021ba6cbfcf6mr27579804wrd.477.1656947167004; Mon, 04
 Jul 2022 08:06:07 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:04 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-5-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 04/14] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b=bYGAltsL;       spf=pass
 (google.com: domain of 33whdygukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=33wHDYgUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-5-elver%40google.com.
