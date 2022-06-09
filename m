Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA5UQ6KQMGQEJLHAEFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1C6D544A25
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:16 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id bv8-20020a0560001f0800b002183c5d5c26sf3340946wrb.20
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774276; cv=pass;
        d=google.com; s=arc-20160816;
        b=YiAFb18DJ1ozaDTDMhV6EZ+7mDtkZ6E4fS3TlRMdwLxCK+hcK5DWhSDQJrNyZ5nuiA
         vLOGjI/psEQKV6RZ/fwww6XUP7s3hnjD/KaxY/N1poRgUTRoOk12HZ9BLRBNWj5Ytnxw
         03wwcpMKxr25S+5DsYTy5M2RQK/tXVRYAZLDoRDI51wh4pCAgzYrn5mC7gUAJhe/JYLg
         XnvXNjASWec8QwVTCRSARCPe6BnnUKEjtLwHb6xAhEtz4guELBmw3BbR2GSbUpfzhFMM
         WjdNGd1GMnNjO63RdcGqLGXtovW5s0AtpaseSyMEQ3ggqE4ONzZFTuOxoplJQRGWvMC0
         qSrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WlVbb5sSghDnOOXCAvuz3BGvPx4EuOjK4Ic6hzQagNI=;
        b=bPhCtoiKd9/hmmI29PfwplxMGbrZhw53BFaY6+ZlxheGTxbs1Bq5TwmdWjUrfiCSrs
         2pxxxBZ8Y97a0hZ+OkV2aJLSF0OWZon2tBIxHBL07VYxQf7sRevb3Dulb5p6BZvQC5kE
         07bq66tjesdqd9ySLlkGitEefGSJYLsnOp+Px2aoOv8fSVxf4WXYkykt0wINpypfoprZ
         DPTvu+fV5El9hB2bLff8RFIG9ZeNQUpU1ZQcdmbaZYO6KIJ7jnjbjF/O4R/GaMJLPVMt
         7AF2mgJexSmF0mK+kEPKzXr1t8GkxYYKIRAXfRocNudMehSNj2rWVAxZIx0dOweQA2bD
         Wb2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hrB6Z1QR;
       spf=pass (google.com: domain of 3atqhygukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3AtqhYgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WlVbb5sSghDnOOXCAvuz3BGvPx4EuOjK4Ic6hzQagNI=;
        b=HjD9mRhB1xhbo/Pe2epybJcP8T9wLcvejqFvstmb/QMHloNWMVvUwJDIz7t9Db3n8y
         1s6oJO+acckRxKWGKG1t6rLL8JelGCbtzYzjhUlvRkBKCYwwI8LnHrTI7tVekiiPK0ye
         oceK0YPz0Mbl/9HsvHELO9Ra4sQERVivcXvCl8BL4TN5hUCfWdIaE8MoJsmei49o5Rfn
         g6ByqVO+VoqPSWONcTDhmyLQrM9vwnYw3XydfeAcy25rLU2Ofuqbv7FsN/zUsAmsCAPF
         9korV/eRSOkyD4iFiTTiIWhuttFPwTw1LAp0r0d/cOqqSrBaSD9tzTH5j/61J+Auuv2t
         +Qcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WlVbb5sSghDnOOXCAvuz3BGvPx4EuOjK4Ic6hzQagNI=;
        b=KG/U8Lc9RSkhhQIgtZz1DLsXhjg3Hyxz26bYD8tXTIKQ03bGWLuY0jmkK52H404tf/
         8fA+8O0GC3JCZWIe12Wsll8sHBBWMFgzRu8CARr6TxLMG9QX7EKEHqM9LzKizs+skpjl
         0rd7aTQN/tIep84abNnWYWNvQHQcRO0tdSX9UPaoT9TNMc/5nltgFcF6SLJji9v6CI33
         WQqiPaWtSYoD3YqIslHwYTFUMgIDFdY3SdE3Gjqv0YLibl3DwzHIvH/KmFwqABnMTQmM
         W2V4kVWTplO0ENpbBY0RediOgLPMs0j29jY7F1Tr01pg1oqY/wbyxVS5ihHIcXY1SwGN
         3Z6Q==
X-Gm-Message-State: AOAM533CWXJJXY1TI+BDSmc9CLK778M+sLsQNM5CYLYPR+v1XhJhFqwa
	rN9T3COAC8Hp91WicW9vdi0=
X-Google-Smtp-Source: ABdhPJzt31aP/oEnzmRQf001ZnSwmJK4Z7nF8zSPdq4Hdyyor0T02d6DkvUpv04MFltTWFkV/ZGm5w==
X-Received: by 2002:adf:e181:0:b0:213:bbe1:ba66 with SMTP id az1-20020adfe181000000b00213bbe1ba66mr29939587wrb.325.1654774276136;
        Thu, 09 Jun 2022 04:31:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:350f:b0:397:475d:b954 with SMTP id
 h15-20020a05600c350f00b00397475db954ls738176wmq.0.canary-gmail; Thu, 09 Jun
 2022 04:31:14 -0700 (PDT)
X-Received: by 2002:a05:600c:34c6:b0:39a:c4e6:c316 with SMTP id d6-20020a05600c34c600b0039ac4e6c316mr2876850wmq.26.1654774274724;
        Thu, 09 Jun 2022 04:31:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774274; cv=none;
        d=google.com; s=arc-20160816;
        b=xIY3y2ubwA4/mcCrK2XdIgy1Sr0Dw+LHLYAur8BNTk5PZkp9QMtk6BstOq25v6C1Br
         AeJGbx13dNEZY4yc2npt6k4Oh8OsVu1bbS9ml05pa3RxGaOWYPLquNSxWbB92Oc49ZE9
         3mg2s8l8V0+C7CkMmuQc6RPuIr2kACaRKsmbTkpy34O/K2Mhl7PzR9boKUs0G0aWEFk+
         VXW0iBZJT/mmg6Pa57NxhtTlgT4wqCrZZpSTG51CAJmXy9HP/Lptb17FzcAEo7YNIFQ+
         WJyd5D63S9Bq8iDavqXgV7JkeVgGOSUtLHRp7sAwbtMuRgiecCbkkXUzwmbDDckRdspe
         AYAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Qrang/3zbd627ej4K3aX6CJRiMSrjsrxCenTVL581fY=;
        b=lspwg4QdwKVe3NJWHRzGJE4v2DWeqiq+m2xwQceAcelNVAHQh/3YMqQDHv3A/wXEw2
         eWTTBViHeAeZl7lTJhelbs9YlCJ2/JqzxLT2+jV+B/28zpSzd5NEWjxUD241C7Cw2tkP
         h7ESOw2RNVwRhj9iJ/PiVjhdfvr6F4etH8QfhhWVifsUO+NZ/LhrNu/Rv2rcWkMIjTup
         4csuRuNgbOpHosCRsCF44gGTbbSlokHhs8v0eQBKR3v/oW3CoHviGHaz9lRd282PRQr4
         mdwyFQTNwD7xYRUiwi/kihkfgXAqstUV1eoC3WThciRNhYgCy2kVPwjOELFOxq4Yt2E6
         zkpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hrB6Z1QR;
       spf=pass (google.com: domain of 3atqhygukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3AtqhYgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b00396f5233248si127037wmb.0.2022.06.09.04.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3atqhygukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id co13-20020a0564020c0d00b0042dc9ef4f01so16874801edb.16
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:14 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:aa7:c508:0:b0:42d:cc6b:df80 with SMTP id
 o8-20020aa7c508000000b0042dcc6bdf80mr44225331edq.393.1654774274424; Thu, 09
 Jun 2022 04:31:14 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:44 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-7-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 6/8] perf/hw_breakpoint: Reduce contention with large number
 of tasks
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
 header.i=@google.com header.s=20210112 header.b=hrB6Z1QR;       spf=pass
 (google.com: domain of 3atqhygukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3AtqhYgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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

While optimizing task_bp_pinned()'s runtime complexity to O(1) on
average helps reduce time spent in the critical section, we still suffer
due to serializing everything via 'nr_bp_mutex'. Indeed, a profile shows
that now contention is the biggest issue:

    95.93%  [kernel]       [k] osq_lock
     0.70%  [kernel]       [k] mutex_spin_on_owner
     0.22%  [kernel]       [k] smp_cfm_core_cond
     0.18%  [kernel]       [k] task_bp_pinned
     0.18%  [kernel]       [k] rhashtable_jhash2
     0.15%  [kernel]       [k] queued_spin_lock_slowpath

when running the breakpoint benchmark with (system with 256 CPUs):

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.207 [sec]
 |
 |      108.267188 usecs/op
 |     6929.100000 usecs/op/cpu

The main concern for synchronizing the breakpoint constraints data is
that a consistent snapshot of the per-CPU and per-task data is observed.

The access pattern is as follows:

 1. If the target is a task: the task's pinned breakpoints are counted,
    checked for space, and then appended to; only bp_cpuinfo::cpu_pinned
    is used to check for conflicts with CPU-only breakpoints;
    bp_cpuinfo::tsk_pinned are incremented/decremented, but otherwise
    unused.

 2. If the target is a CPU: bp_cpuinfo::cpu_pinned are counted, along
    with bp_cpuinfo::tsk_pinned; after a successful check, cpu_pinned is
    incremented. No per-task breakpoints are checked.

Since rhltable safely synchronizes insertions/deletions, we can allow
concurrency as follows:

 1. If the target is a task: independent tasks may update and check the
    constraints concurrently, but same-task target calls need to be
    serialized; since bp_cpuinfo::tsk_pinned is only updated, but not
    checked, these modifications can happen concurrently by switching
    tsk_pinned to atomic_t.

 2. If the target is a CPU: access to the per-CPU constraints needs to
    be serialized with other CPU-target and task-target callers (to
    stabilize the bp_cpuinfo::tsk_pinned snapshot).

We can allow the above concurrency by introducing a per-CPU constraints
data reader-writer lock (bp_cpuinfo_lock), and per-task mutexes
(task_sharded_mtx):

  1. If the target is a task: acquires its task_sharded_mtx, and
     acquires bp_cpuinfo_lock as a reader.

  2. If the target is a CPU: acquires bp_cpuinfo_lock as a writer.

With these changes, contention with thousands of tasks is reduced to the
point where waiting on locking no longer dominates the profile:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.080 [sec]
 |
 |       42.048437 usecs/op
 |     2691.100000 usecs/op/cpu

    21.31%  [kernel]       [k] task_bp_pinned
    17.49%  [kernel]       [k] rhashtable_jhash2
     5.29%  [kernel]       [k] toggle_bp_slot
     4.45%  [kernel]       [k] mutex_spin_on_owner
     3.72%  [kernel]       [k] bcmp

On this particular setup that's a speedup of 2.5x.

We're also getting closer to the theoretical ideal performance through
optimizations in hw_breakpoint.c -- constraints accounting disabled:

 | perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.067 [sec]
 |
 |       35.286458 usecs/op
 |     2258.333333 usecs/op/cpu

Which means the current implementation is ~19% slower than the
theoretical ideal.

For reference, performance without any breakpoints:

 | $> bench -r 30 breakpoint thread -b 0 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 0 breakpoints and 64 parallelism
 |      Total time: 0.060 [sec]
 |
 |       31.365625 usecs/op
 |     2007.400000 usecs/op/cpu

The theoretical ideal is only ~12% slower than no breakpoints at all.
The current implementation is ~34% slower than no breakpoints at all.
(On a system with 256 CPUs.)

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/hw_breakpoint.c | 155 ++++++++++++++++++++++++++++------
 1 file changed, 128 insertions(+), 27 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index afe0a6007e96..08c9ed0626e4 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -17,6 +17,7 @@
  * This file contains the arch-independent routines.
  */
 
+#include <linux/atomic.h>
 #include <linux/irqflags.h>
 #include <linux/kallsyms.h>
 #include <linux/notifier.h>
@@ -24,8 +25,10 @@
 #include <linux/kdebug.h>
 #include <linux/kernel.h>
 #include <linux/module.h>
+#include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/sched.h>
+#include <linux/spinlock.h>
 #include <linux/init.h>
 #include <linux/slab.h>
 #include <linux/rhashtable.h>
@@ -42,9 +45,9 @@ struct bp_cpuinfo {
 	unsigned int	cpu_pinned;
 	/* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
 #ifdef hw_breakpoint_slots
-	unsigned int	tsk_pinned[hw_breakpoint_slots(0)];
+	atomic_t	tsk_pinned[hw_breakpoint_slots(0)];
 #else
-	unsigned int	*tsk_pinned;
+	atomic_t	*tsk_pinned;
 #endif
 };
 
@@ -71,8 +74,81 @@ struct bp_busy_slots {
 	unsigned int pinned;
 };
 
-/* Serialize accesses to the above constraints */
-static DEFINE_MUTEX(nr_bp_mutex);
+/*
+ * Synchronizes accesses to the per-CPU constraints; users of data in bp_cpuinfo
+ * must acquire bp_cpuinfo_lock as writer to get a stable snapshot of all CPUs'
+ * constraints. Modifications without use may only acquire bp_cpuinfo_lock as a
+ * reader, but must otherwise ensure modifications are never lost.
+ */
+static DEFINE_RWLOCK(bp_cpuinfo_lock);
+
+/*
+ * Synchronizes accesses to the per-task breakpoint list in task_bps_ht. Since
+ * rhltable synchronizes concurrent insertions/deletions, independent tasks may
+ * insert/delete concurrently; therefore, a mutex per task would be sufficient.
+ *
+ * To avoid bloating task_struct with infrequently used data, use a sharded
+ * mutex that scales with number of CPUs.
+ */
+static DEFINE_PER_CPU(struct mutex, task_sharded_mtx);
+
+static struct mutex *get_task_sharded_mtx(struct perf_event *bp)
+{
+	int shard;
+
+	if (!bp->hw.target)
+		return NULL;
+
+	/*
+	 * Compute a valid shard index into per-CPU data.
+	 */
+	shard = task_pid_nr(bp->hw.target) % nr_cpu_ids;
+	shard = cpumask_next(shard - 1, cpu_possible_mask);
+	if (shard >= nr_cpu_ids)
+		shard = cpumask_first(cpu_possible_mask);
+
+	return per_cpu_ptr(&task_sharded_mtx, shard);
+}
+
+static struct mutex *bp_constraints_lock(struct perf_event *bp)
+{
+	struct mutex *mtx = get_task_sharded_mtx(bp);
+
+	if (mtx) {
+		mutex_lock(mtx);
+		read_lock(&bp_cpuinfo_lock);
+	} else {
+		write_lock(&bp_cpuinfo_lock);
+	}
+
+	return mtx;
+}
+
+static void bp_constraints_unlock(struct mutex *mtx)
+{
+	if (mtx) {
+		read_unlock(&bp_cpuinfo_lock);
+		mutex_unlock(mtx);
+	} else {
+		write_unlock(&bp_cpuinfo_lock);
+	}
+}
+
+static bool bp_constraints_is_locked(struct perf_event *bp)
+{
+	struct mutex *mtx = get_task_sharded_mtx(bp);
+
+	return (mtx ? mutex_is_locked(mtx) : false) ||
+	       rwlock_is_contended(&bp_cpuinfo_lock);
+}
+
+static inline void assert_bp_constraints_lock_held(struct perf_event *bp)
+{
+	lockdep_assert_held(&bp_cpuinfo_lock);
+	/* Don't call get_task_sharded_mtx() if lockdep is disabled. */
+	if (IS_ENABLED(CONFIG_LOCKDEP) && bp->hw.target)
+		lockdep_assert_held(get_task_sharded_mtx(bp));
+}
 
 #ifdef hw_breakpoint_slots
 /*
@@ -103,7 +179,7 @@ static __init int init_breakpoint_slots(void)
 		for (i = 0; i < TYPE_MAX; i++) {
 			struct bp_cpuinfo *info = get_bp_info(cpu, i);
 
-			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(int), GFP_KERNEL);
+			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(atomic_t), GFP_KERNEL);
 			if (!info->tsk_pinned)
 				goto err;
 		}
@@ -143,11 +219,19 @@ static inline enum bp_type_idx find_slot_idx(u64 bp_type)
  */
 static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 {
-	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
+	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int i;
 
+	/*
+	 * At this point we want to have acquired the bp_cpuinfo_lock as a
+	 * writer to ensure that there are no concurrent writers in
+	 * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
+	 */
+	lockdep_assert_held_write(&bp_cpuinfo_lock);
+
 	for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
-		if (tsk_pinned[i] > 0)
+		ASSERT_EXCLUSIVE_WRITER(tsk_pinned[i]); /* Catch unexpected writers. */
+		if (atomic_read(&tsk_pinned[i]) > 0)
 			return i + 1;
 	}
 
@@ -164,6 +248,11 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 	struct perf_event *iter;
 	int count = 0;
 
+	/*
+	 * We need a stable snapshot of the per-task breakpoint list.
+	 */
+	assert_bp_constraints_lock_held(bp);
+
 	rcu_read_lock();
 	head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
 	if (!head)
@@ -230,16 +319,25 @@ fetch_this_slot(struct bp_busy_slots *slots, int weight)
 static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 				enum bp_type_idx type, int weight)
 {
-	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
+	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int old_idx, new_idx;
 
+	/*
+	 * If bp->hw.target, tsk_pinned is only modified, but not used
+	 * otherwise. We can permit concurrent updates as long as there are no
+	 * other uses: having acquired bp_cpuinfo_lock as a reader allows
+	 * concurrent updates here. Uses of tsk_pinned will require acquiring
+	 * bp_cpuinfo_lock as a writer to stabilize tsk_pinned's value.
+	 */
+	lockdep_assert_held_read(&bp_cpuinfo_lock);
+
 	old_idx = task_bp_pinned(cpu, bp, type) - 1;
 	new_idx = old_idx + weight;
 
 	if (old_idx >= 0)
-		tsk_pinned[old_idx]--;
+		atomic_dec(&tsk_pinned[old_idx]);
 	if (new_idx >= 0)
-		tsk_pinned[new_idx]++;
+		atomic_inc(&tsk_pinned[new_idx]);
 }
 
 /*
@@ -257,6 +355,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 
 	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
+		lockdep_assert_held_write(&bp_cpuinfo_lock);
 		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
 		return 0;
 	}
@@ -265,6 +364,11 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 	for_each_cpu(cpu, cpumask)
 		toggle_bp_task_slot(bp, cpu, type, weight);
 
+	/*
+	 * Readers want a stable snapshot of the per-task breakpoint list.
+	 */
+	assert_bp_constraints_lock_held(bp);
+
 	if (enable)
 		return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
 	else
@@ -372,14 +476,10 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 
 int reserve_bp_slot(struct perf_event *bp)
 {
-	int ret;
-
-	mutex_lock(&nr_bp_mutex);
-
-	ret = __reserve_bp_slot(bp, bp->attr.bp_type);
-
-	mutex_unlock(&nr_bp_mutex);
+	struct mutex *mtx = bp_constraints_lock(bp);
+	int ret = __reserve_bp_slot(bp, bp->attr.bp_type);
 
+	bp_constraints_unlock(mtx);
 	return ret;
 }
 
@@ -397,12 +497,11 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
 
 void release_bp_slot(struct perf_event *bp)
 {
-	mutex_lock(&nr_bp_mutex);
+	struct mutex *mtx = bp_constraints_lock(bp);
 
 	arch_unregister_hw_breakpoint(bp);
 	__release_bp_slot(bp, bp->attr.bp_type);
-
-	mutex_unlock(&nr_bp_mutex);
+	bp_constraints_unlock(mtx);
 }
 
 static int __modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
@@ -429,11 +528,10 @@ static int __modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
 
 static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
 {
-	int ret;
+	struct mutex *mtx = bp_constraints_lock(bp);
+	int ret = __modify_bp_slot(bp, old_type, new_type);
 
-	mutex_lock(&nr_bp_mutex);
-	ret = __modify_bp_slot(bp, old_type, new_type);
-	mutex_unlock(&nr_bp_mutex);
+	bp_constraints_unlock(mtx);
 	return ret;
 }
 
@@ -444,7 +542,7 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
  */
 int dbg_reserve_bp_slot(struct perf_event *bp)
 {
-	if (mutex_is_locked(&nr_bp_mutex))
+	if (bp_constraints_is_locked(bp))
 		return -1;
 
 	return __reserve_bp_slot(bp, bp->attr.bp_type);
@@ -452,7 +550,7 @@ int dbg_reserve_bp_slot(struct perf_event *bp)
 
 int dbg_release_bp_slot(struct perf_event *bp)
 {
-	if (mutex_is_locked(&nr_bp_mutex))
+	if (bp_constraints_is_locked(bp))
 		return -1;
 
 	__release_bp_slot(bp, bp->attr.bp_type);
@@ -735,7 +833,10 @@ static struct pmu perf_breakpoint = {
 
 int __init init_hw_breakpoint(void)
 {
-	int ret;
+	int cpu, ret;
+
+	for_each_possible_cpu(cpu)
+		mutex_init(&per_cpu(task_sharded_mtx, cpu));
 
 	ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
 	if (ret)
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-7-elver%40google.com.
