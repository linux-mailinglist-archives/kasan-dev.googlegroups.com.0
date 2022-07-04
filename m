Return-Path: <kasan-dev+bncBC7OBJGL2MHBB54DRSLAMGQEQOBYKGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F50D565947
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:33 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 20-20020a9d0b94000000b00616c0b6b345sf3484159oth.10
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947192; cv=pass;
        d=google.com; s=arc-20160816;
        b=RU4bnv/amVERxvhkVSLN93bl9ZuTgwFIkHGYsEqZPLQqsF5qG0AGqMerjXtTcR8GjB
         Lg5M0ID/3iVHvIq95m6C12X+Y2VhuDL+aGAEb9YpILNQysnh6UXxz+cvjkuuOXujJ/1w
         LHIedtCrhEhbkzMfNTrz4QnjQZ7hOlq+7h+FxTGIOgFUQtfx0X4dXKh/bt1TLlfS/Den
         Vg7ZIk7S1MEerQbeNH0sFGNdm8NVXzMqPbp7TE0Ffoi6zrHyIPkZxuKjgDuUxV0coTHi
         T6/9yyDuv+XDGytGJJfMDQBwFVQeE1La+lyYZYKZ1oMwhKJBtfuxdq3KbNS3Svidf7b7
         49Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zRa4HroCW7Og4rSEgX5gRfbuSuWmFg5KZ8bXk1/APDE=;
        b=vBCUXxyWeNXc27cJm0E/34CE1mv5dErpLjO35VrzfSbRF4Gi8Bhyz0BWkmdFVDaoEZ
         m4kcU+143LQkQlNRDdvn3wq5ndg2a3OghHJyk8pp+B53Pg5a37bS1uc3Zdhu5oZes6BA
         kkNyhdzSLZTr5ukLRB5xPo/SqIIraOn/et0RxkkRyipMOZa/Qrp/jF7BpysfxiABsV3j
         wPwmAobBFadXWPEk4jDbaAK94dx48PX/kddog3y8IZdsXu329kdLo5ayZsLwwCZGETwg
         Lmr9ItxHdLzNQDQfbnscX/GAPnlGOve+//MlBnoamHg4nrwlQ/kclEVABQvzfSEIM1Bl
         4E7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pKioeff8;
       spf=pass (google.com: domain of 39whdygukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39wHDYgUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zRa4HroCW7Og4rSEgX5gRfbuSuWmFg5KZ8bXk1/APDE=;
        b=bPl8dGoeSvUzJzc020wbS00xrowrWnj4thoHnQHzGwV1tvMpQ5j/uOvZ/4wxsreLoJ
         yyjUvOcn91PZGGoR1kdTF0zdhqi9M2GOJ6e0vR7Hz8Lv3Lxb9ETFoFnz6EACmC6rVnJP
         6dz40h4eoC72F2lKCHGhXOMtQ8vUBAycg8wDwoBwOoZ3dLEL4ijIosJB3/iu5dHPXm8Y
         KiPLYuIKpeQdk/k07J71wCaP2HYDqM/OdRCjLBA6kCsXcmRZmCLCSIfLrFZHQ9BWa8r2
         sZ2lxp6lv2/xIbtqMr13f04pbV50UH/T894OdCwa8juzW5ReKDaj4Ud40/6fA0ophVEo
         onZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zRa4HroCW7Og4rSEgX5gRfbuSuWmFg5KZ8bXk1/APDE=;
        b=BgKYFiQNqrJLW6khWzmMuypINs2iQP55TXi8Eo8lx7Um6jplQNIQaiXQLfJBtKwplb
         vH6muJ1M4W8oVf73MHZ+0tO+ah7lkWAyAJFUQyC6WfEb64Qppgg4Z67MSgIRGbc1qcRn
         bgnHq/PTRZjHvihxoeJxxHhOwgDQRkecxEtcT/FEFwJxe/ztKghq0UWFZts0uxy+qI5u
         NfAssxpqKrsAYP0p0IIPyqJkNt96FHZkDAeiWZWwmre1Np4eZjRLM49XIa2sSF51UIuu
         nAS4mPIkXtGoaGDrRF+5eBreDJmI3uV1AzjIhsv9v0usPcuAizPh0t1885UlJIVG8eua
         W1LQ==
X-Gm-Message-State: AJIora95YvixE0nqUl+1SHLeGufz0GbatoH67Ny8swxvRS8fdNog5oxl
	tmeGT5ONyUE4XRIqKGJ1VxU=
X-Google-Smtp-Source: AGRyM1u85TJMZbsLb60KKfOcqsI0qVU0g/B89M01+2mE0WfGHsrKJyBCQkK25aW14Il4NGUXugFMPQ==
X-Received: by 2002:a05:6808:219:b0:337:bb4e:57ea with SMTP id l25-20020a056808021900b00337bb4e57eamr3523438oie.9.1656947192017;
        Mon, 04 Jul 2022 08:06:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b9d5:0:b0:32f:1186:e961 with SMTP id j204-20020acab9d5000000b0032f1186e961ls17220915oif.11.gmail;
 Mon, 04 Jul 2022 08:06:31 -0700 (PDT)
X-Received: by 2002:aca:1b03:0:b0:335:8faa:96c4 with SMTP id b3-20020aca1b03000000b003358faa96c4mr17298257oib.229.1656947191628;
        Mon, 04 Jul 2022 08:06:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947191; cv=none;
        d=google.com; s=arc-20160816;
        b=SdLQnl0iW+ZAyLdCwmkdrQ6x4zvb8fLpBoEVruBW2n0htE+xiB3wN8AH3fxFB7Zt3A
         LiGxwHfhJAMTr9xHWyaOxao46lyV35P0ShRUkzBys3TjJafjTWoTnIK+VZEpGz0UEHs1
         RNEfPHPksk36Tk8uAgKXQJoLa0dPBzoe1vdyziss+R0fcUcPDkHvhRuyV4NW+XHvdl0n
         OUyi0T1FDMCcVkek8bzbhN2Qqt2cb2JQe5EYNBtc2UKi779WgFrHcuQIxkfhv1AJnSsf
         k30qxZ5LNHKn17GTasEomm/2AhCKJPVHW/XaiZx/65ClkArQPJguH2hrnNrp9UO7m3q0
         dC0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=EpoFcAL2fWdwh8cZOIq67BCzlwBRSTcqZCW5NPscTUg=;
        b=NI4P/YPZiCSybDIgSdcWiNyBnb4vZqeIDvY8DKGiRPup+DunJebXDZXLeYBycyVawQ
         02c/WnGD6CTNwtuCQs6grzfet/JnN7Eqh/P6Zh1lcJJTt8VJngi67XP3g3F6wDI78iey
         nfkgr79005dn7yB0alX81TNmSKGLc2yuFDABMsnz72lXalnmtp6U141Kx7QtNSyIbJ4o
         RdgEKdH/7+kXhOPfrIYXd07EQ7g1uPtOaXn+35RF0YgntyIIb4R1HN0WUhDSRDiNQBg5
         Iy8oTq7FNrS+MAfJq6kr24PLJZOPmyoye3ryzgcHeBfk/8LfzLzHYhNn3NavKoRKpFMY
         vMMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pKioeff8;
       spf=pass (google.com: domain of 39whdygukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39wHDYgUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id o17-20020a056870969100b00101a5546931si3345780oaq.4.2022.07.04.08.06.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39whdygukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-2dc7bdd666fso68304637b3.7
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:31 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a81:a08d:0:b0:31c:b3d9:f93f with SMTP id
 x135-20020a81a08d000000b0031cb3d9f93fmr1684676ywg.492.1656947191436; Mon, 04
 Jul 2022 08:06:31 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:13 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-14-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 13/14] perf/hw_breakpoint: Optimize max_bp_pinned_slots()
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
 header.i=@google.com header.s=20210112 header.b=pKioeff8;       spf=pass
 (google.com: domain of 39whdygukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39wHDYgUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v3:
* Update hw_breakpoint_is_used() to include global cpu_pinned.

v2:
* New patch.
---
 kernel/events/hw_breakpoint.c | 57 ++++++++++++++++++++++++++++++++---
 1 file changed, 53 insertions(+), 4 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 03ebecf048c0..a489f31fe147 100644
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
 
@@ -804,6 +841,18 @@ bool hw_breakpoint_is_used(void)
 		}
 	}
 
+	for (int type = 0; type < TYPE_MAX; ++type) {
+		for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
+			/*
+			 * Warn, because if there are CPU pinned counters,
+			 * should never get here; bp_cpuinfo::cpu_pinned should
+			 * be consistent with the global cpu_pinned histogram.
+			 */
+			if (WARN_ON(atomic_read(&cpu_pinned[type].count[slot])))
+				return true;
+		}
+	}
+
 	return false;
 }
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-14-elver%40google.com.
