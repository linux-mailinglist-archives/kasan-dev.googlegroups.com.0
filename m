Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBNC5OKQMGQEH5KERVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id AAA7D55BFFF
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:33 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id az40-20020a05600c602800b003a048edf007sf2490915wmb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410373; cv=pass;
        d=google.com; s=arc-20160816;
        b=mOXnGIxlCTIW6UQ0yO2vfYfeUZtmpJEVtCtfXl+RyCK6Rhqq6gp73Mahpd/ssdZx1H
         oiECrgl+uwdPYxOtmFZU1anuy6Z0J19mtFvJpNCug2mvqxFIxoVSxsUJe7ptrKMZJlfr
         roobJRLJTnyWbwfAP5n6xShA5LNzn9eZ9UvfpqsJ2NwIyPZPeeJGpEWTVHLRYhzP19Tc
         5Gj/8Qe+uN8gNQCp4jWRtJv+mdMv7sE5OWL/+W3Vy5zzYIvRsHR7T8juO932oU3//y4j
         yldoIU6cTHd+YMBuI+zCobdAxUfnP5jlaUtybxNpkGizBY/KdIJEAUOvW0e4F06EiIa/
         q4JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Z6ku+efu8ZH0CVI1onKNfEUEHRhGh6vEt7rLB783MVM=;
        b=QAel0s7gq81Q/uV/RmmpuwEFXnmrsAkwkRPNFYCucWIcwdQnShOr7P6L9gu6FkTskJ
         /DkIwmOoU751Za8DZ4XNcr7OK+37HBxWZe9MM4yZwhV60mO8abHaK+TgCRC/IWVm/5A6
         43eU/VfkZBqr7xThsOeMHSLvrn3uDRJu+GvlzD3TYw/vFry26i/+9T7HJQQYK4UBg6Fd
         Z8WUyaCR/aKS3rONiEs6H43G3c23lpRwP0CQRbKDUg3NnVTA9T32LdbQC6iYAh0xPPTG
         t3b7OdZcHxIkEAnbcFAWNfsmLc0o5miD0uHkMdJnfLYd6uYphmfKxjKTdV81kbDwGoej
         E8jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="a9Qz/7hR";
       spf=pass (google.com: domain of 3a9g6ygukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3A9G6YgUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z6ku+efu8ZH0CVI1onKNfEUEHRhGh6vEt7rLB783MVM=;
        b=G3zpe/HASxuD8UCiO17QZ2QHCqp6h0EJWFd4GsqlxxHji1vPOtM1C3lMVYsdKrPKsv
         rJgFU+QV89XMt5WADmk7nQFmBf3aMkHvJR8Z9aeml58DDXOtuWMEkKhiW1ZJRxHB5O64
         GWZOS6B8dOTDzeIEnRxTR+T+pUyIHddHlCN9jgfxKLkOauNRqeuOhRnvPYhcofObKcFf
         UTAu96Gb4q1qmJjYN+aM1x/Bz+yfcx0/RmJikxqUWikBHv9lgjZukn7jycE1e3hlO4/E
         HqvJHkljOeFLy8hKR7IpdfW6i43MtflqOVJDubxtJfcj4O1MxlAysMB7Aby1wWgDhKzu
         bJwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z6ku+efu8ZH0CVI1onKNfEUEHRhGh6vEt7rLB783MVM=;
        b=N9MFmCt7fA5mm6jq7qbvIHggzQlKFYbyoTxCr2OXRTI04ztL6QtpWaXe8gc4SLuFAR
         OAsq2wORIFrk72LOPREGPgs3Bu3wCKQ2Qk9Y4q6kylm5oJ/sDlnXc31Q7+1LjDykJPbT
         nXf0Vzw8GtPQSmo4Yj3fVC66XJG8QITFyWcnU1MXoJ0+qBbPltQWumOHJcIPB+5PyByO
         dKSHGZOkjC1jY8B267mlZojF5iiXe1m2c6u3duy3YvZswL6IGl2fcnB9C9jcohdD5w+L
         f8r5iQjmWphI57H4LOrhY8AFXFE8hgqLl6Mu0aAiu8t7413rR5hmMrNY+x1AJ36OVvGi
         WGqg==
X-Gm-Message-State: AJIora8FWpSkG+ybZ5iFtJLnmhQnosG+VFy128taTM4H3R0LcxF4kQoW
	FKVpb1BUZvMv4leUdf589/g=
X-Google-Smtp-Source: AGRyM1sjgqf77sRjLTCngmP2D6wzOHp4nEwVhhTgC5QWNTcR3DVeiFuOdTOq6RugbqublNcP4nE1EA==
X-Received: by 2002:a05:600c:3516:b0:39c:8091:31b6 with SMTP id h22-20020a05600c351600b0039c809131b6mr27114139wmq.164.1656410373202;
        Tue, 28 Jun 2022 02:59:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb04:0:b0:21b:b3cc:1640 with SMTP id s4-20020adfeb04000000b0021bb3cc1640ls17368687wrn.1.gmail;
 Tue, 28 Jun 2022 02:59:32 -0700 (PDT)
X-Received: by 2002:a5d:5107:0:b0:21b:8c5d:1072 with SMTP id s7-20020a5d5107000000b0021b8c5d1072mr17714853wrt.378.1656410372094;
        Tue, 28 Jun 2022 02:59:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410372; cv=none;
        d=google.com; s=arc-20160816;
        b=tZwPNYLy3R83Iz93MFmgvkavyp9oXYVBxcdNYiC6CUueALIjJPIyihOhburrAYmtpz
         2MQrkpya77bOpiPBZNzp+zmNUN6pt/p9ZV7QPjyIbgJu+IZVXT1dH1Vq07GZtMs3Rsws
         RcwXFJ96lAtUr4OjqaVep3is1VakLOL+E5r5h2oaa5Arvflmfq/ZrwubU4/wn6A+pJff
         11s9QTJCSjIme0Mhl8ApNKzkGDW8ujzaVzEZghrIolOj6340BJwZFUlo3UKVVMlLk220
         kJGteAyBA4qyFvIC+sL/hr2iRIPTEMijNEtoXcCtz91oXIhlcDEUU/WAPt+ZPJ6g7JFE
         SKWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=YoFBOjNJrDqt8mzIFXF65D7zaWvuhvYLEYNKHK+PaLc=;
        b=FXkcYL9j9PPsrtY5Bj2UKRGlUm569q5QmB3Ek/moayhi4aQHbfIT/dZFHpX+ha2AaJ
         Dmqi1pJSHTS/PeaHwagdHY2vxKSKHH5o/qtRWPhX3LcJaH00jih2CqB5ZgjvgXiAfuGG
         qRHKcwzi5OWy7ALcKrquwmMyjUmA3qo1nMj3ykqtibSVPx01lIKf3kA8ROmY4Q1jCTB2
         1hiRKqV/rWWefueKB6kMLPsE66Ltrl84VEgtgX0LyfCy4LLb2DNc235TBdSsT0+BhsW8
         7S92za5bZeu93ZXW74aExtGXqOprOEN8jTpq5unWc6qBOV3SNPiskPB1aUlByQ1rAfIF
         LteA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="a9Qz/7hR";
       spf=pass (google.com: domain of 3a9g6ygukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3A9G6YgUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id m7-20020adffa07000000b0021a07a20517si436469wrr.7.2022.06.28.02.59.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a9g6ygukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id y8-20020ac24208000000b0047f9fc8f632so6006804lfh.11
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a05:6512:32c5:b0:481:1822:c41f with SMTP id
 f5-20020a05651232c500b004811822c41fmr7349560lfg.373.1656410371551; Tue, 28
 Jun 2022 02:59:31 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:32 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-13-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 12/13] perf/hw_breakpoint: Optimize max_bp_pinned_slots()
 for CPU-independent task targets
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
 header.i=@google.com header.s=20210112 header.b="a9Qz/7hR";       spf=pass
 (google.com: domain of 3a9g6ygukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3A9G6YgUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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
preceding changes, but same 256 CPUs host):

 | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
 |      Total time: 1.989 [sec]
 |
 |       38.854160 usecs/op
 |     4973.332500 usecs/op/cpu

    20.43%  [kernel]       [k] queued_spin_lock_slowpath
    18.75%  [kernel]       [k] osq_lock
    16.98%  [kernel]       [k] rhashtable_jhash2
     8.34%  [kernel]       [k] task_bp_pinned
     4.23%  [kernel]       [k] smp_cfm_core_cond
     3.65%  [kernel]       [k] bcmp
     2.83%  [kernel]       [k] toggle_bp_slot
     1.87%  [kernel]       [k] find_next_bit
     1.49%  [kernel]       [k] __reserve_bp_slot

We can see that a majority of the time is now spent hashing task
pointers to index into task_bps_ht in task_bp_pinned().

Obtaining the max_bp_pinned_slots() for CPU-independent task targets
currently is O(#cpus), and calls task_bp_pinned() for each CPU, even if
the result of task_bp_pinned() is CPU-independent.

The loop in max_bp_pinned_slots() wants to compute the maximum slots
across all CPUs. If task_bp_pinned() is CPU-independent, we can do so by
obtaining the max slots across all CPUs and adding task_bp_pinned().

To do so in O(1), use a bp_slots_histogram for CPU-pinned slots.

After this optimization:

 | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
 |      Total time: 1.930 [sec]
 |
 |       37.697832 usecs/op
 |     4825.322500 usecs/op/cpu

    19.13%  [kernel]       [k] queued_spin_lock_slowpath
    18.21%  [kernel]       [k] rhashtable_jhash2
    15.46%  [kernel]       [k] osq_lock
     6.27%  [kernel]       [k] toggle_bp_slot
     5.91%  [kernel]       [k] task_bp_pinned
     5.05%  [kernel]       [k] smp_cfm_core_cond
     1.78%  [kernel]       [k] update_sg_lb_stats
     1.36%  [kernel]       [k] llist_reverse_order
     1.34%  [kernel]       [k] find_next_bit
     1.19%  [kernel]       [k] bcmp

Suggesting that time spent in task_bp_pinned() has been reduced.
However, we're still hashing too much, which will be addressed in the
subsequent change.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 kernel/events/hw_breakpoint.c | 45 +++++++++++++++++++++++++++++++----
 1 file changed, 41 insertions(+), 4 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 18886f115abc..b5180a2ccfbf 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -64,6 +64,9 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 	return per_cpu_ptr(bp_cpuinfo + type, cpu);
 }
 
+/* Number of pinned CPU breakpoints globally. */
+static struct bp_slots_histogram cpu_pinned[TYPE_MAX];
+
 /* Keep track of the breakpoints attached to tasks */
 static struct rhltable task_bps_ht;
 static const struct rhashtable_params task_bps_ht_params = {
@@ -194,6 +197,10 @@ static __init int init_breakpoint_slots(void)
 				goto err;
 		}
 	}
+	for (i = 0; i < TYPE_MAX; i++) {
+		if (!bp_slots_histogram_alloc(&cpu_pinned[i], i))
+			goto err;
+	}
 
 	return 0;
 err:
@@ -203,6 +210,8 @@ static __init int init_breakpoint_slots(void)
 		if (err_cpu == cpu)
 			break;
 	}
+	for (i = 0; i < TYPE_MAX; i++)
+		bp_slots_histogram_free(&cpu_pinned[i]);
 
 	return -ENOMEM;
 }
@@ -270,6 +279,9 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 /*
  * Count the number of breakpoints of the same type and same task.
  * The given event must be not on the list.
+ *
+ * If @cpu is -1, but the result of task_bp_pinned() is not CPU-independent,
+ * returns a negative value.
  */
 static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 {
@@ -288,9 +300,18 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 		goto out;
 
 	rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
-		if (find_slot_idx(iter->attr.bp_type) == type &&
-		    (iter->cpu < 0 || cpu == iter->cpu))
-			count += hw_breakpoint_weight(iter);
+		if (find_slot_idx(iter->attr.bp_type) != type)
+			continue;
+
+		if (iter->cpu >= 0) {
+			if (cpu == -1) {
+				count = -1;
+				goto out;
+			} else if (cpu != iter->cpu)
+				continue;
+		}
+
+		count += hw_breakpoint_weight(iter);
 	}
 
 out:
@@ -316,6 +337,19 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 	int pinned_slots = 0;
 	int cpu;
 
+	if (bp->hw.target && bp->cpu < 0) {
+		int max_pinned = task_bp_pinned(-1, bp, type);
+
+		if (max_pinned >= 0) {
+			/*
+			 * Fast path: task_bp_pinned() is CPU-independent and
+			 * returns the same value for any CPU.
+			 */
+			max_pinned += bp_slots_histogram_max(&cpu_pinned[type], type);
+			return max_pinned;
+		}
+	}
+
 	for_each_cpu(cpu, cpumask) {
 		struct bp_cpuinfo *info = get_bp_info(cpu, type);
 		int nr;
@@ -366,8 +400,11 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 
 	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
+		struct bp_cpuinfo *info = get_bp_info(bp->cpu, type);
+
 		lockdep_assert_held_write(&bp_cpuinfo_sem);
-		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
+		bp_slots_histogram_add(&cpu_pinned[type], info->cpu_pinned, weight);
+		info->cpu_pinned += weight;
 		return 0;
 	}
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-13-elver%40google.com.
