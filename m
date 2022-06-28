Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75B5OKQMGQENHEX25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F2455BFFC
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:28 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 6-20020a1c0206000000b003a02cd754d1sf4867386wmc.9
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410367; cv=pass;
        d=google.com; s=arc-20160816;
        b=zCUsLheyQAlwDSuS77/k/10bKpdSuB9qbk+ncnYojz5VImM3Kjf2rbuWDH626EKGE+
         /4P1/oSVl6hvAfiifH7UsziLv0HBIcfVdM8TyWqHychcc2Cbp9H98x2+aPONJO2rSPqC
         DyGDbsiRmlO0MQQqsLjS5jcYUIYbznVOlrQfjOvNYxJnL3CuZawO2Xui3UWCd3XVeW+E
         VBL2RULxh6WUGNX5Wb05knbWtH7MVX93FJCNvBhlj9azaM2zrg6H3jP9Jv6JDWsyq5wj
         hWbtoX9LZH2tAwIVooDfEb7QTwlihkQNWZvHON8VDZOxnWo4YYEH2cbjcGYxbF8np4Zd
         2uTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lLUucf7yL/bPMmuLwJF6aUOJz4rq+sTmBMoWd5GRcRQ=;
        b=UUf/Ez5JmcpKMIJMOLwjTkRSNRQwEF75pvoH0pasvSBK71Y5gKhpw2hIeWLag9JL4p
         99GLot16Jcc2bwo8JU9BU1fSqA0iANaRZ1BcVzZIrS9hkByKIc3zkOxEd64DNYCj8Xv+
         +bZNvptHpaXjC938jfv/2vKQBA4Nj1dSpw7RosLxsbT78UDYL0DA+D5V+ruxVb4Df4IZ
         pnOaUpSoMrPefUtprZI0JWl9qK5nubcm/uILQAHG49+B1h7xJyVADwB45pC72mJ9tIrJ
         nbwojX/DPEqLPUKDyqLqnMchtzXijWhbr5q56JyLi6gjnO9scoTpl87rCstecbqVkROg
         JYug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=O4kzeA4u;
       spf=pass (google.com: domain of 3_dc6ygukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_dC6YgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lLUucf7yL/bPMmuLwJF6aUOJz4rq+sTmBMoWd5GRcRQ=;
        b=PIv3tsfT89HhbLUqg8wK4pyKSucVyMEsSJqO5pkFWGPFqeCBUF+TrsBvLHBVK8EhR6
         Mv5pgifPwUZ0Qi4T7fk8PKP6LYR9tdE3VPPErqUYNz58bG6YjT+089UykIPOZ1wspRFI
         O6kBOTxxFufG4rgKWMDWlYJGlOYuuIh0TfSZWtb9WaGiNb2OWV39aUPowNXlJRehmT9N
         cDX6CsGoJCgEKYyGp/yNeH7Dy0/Pt4qCVfnjfGJIcm6643NNR9QpE0/u56gIXX88AKDa
         ioJl5sjwxbrKTByq+ngke5QOhyhuVYZ1K58wtUnpZ8ijJj0Q0nHwe+Uva/Ts5qWs7ii1
         wZsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lLUucf7yL/bPMmuLwJF6aUOJz4rq+sTmBMoWd5GRcRQ=;
        b=0lts7DS6LjeGYs2ZVwlEM76Ac4i+gFh6c19MkQI+av6Rhys/Yq7o0+wUi5SI08hBtH
         +L/zIgTgSU8VXrw7zGS4mSGZfl0sKSu6wj2T8DGzhFZ8eCn8sOUtJvAJscfgEGT0UATN
         mAQd8SaLBGP4QeyfSXowUpkPrtTgv9PC6yBvBNJobfzJ50PZnIVwECcmAsL5bR1ZRkm6
         EWd9FOwSk4HH2K6VBa9wZHMhBNFfpiVrI09M16NDrjlaDOtPijNLe7yiUWJ2B706iX95
         qEn14zIxBlfnu8vnV+Lxqn5pqE4D0PYmZzsb+XBeGH5ZGOGz17OfB/NdKnRtfO6LSRhY
         uWYw==
X-Gm-Message-State: AJIora/wSaNHITtduVcZs9MkL3jURDbluBh5hyGANmbjIKvx6QGKqviM
	ztF3K538uI5yKRjtDuCuRyU=
X-Google-Smtp-Source: AGRyM1v89OmJ7HOpazbhopIbHGUHDZ7KjWLkB77UwABbeX6bKDMmBoG+lX57KcN1l1CIsRh4RuQHiQ==
X-Received: by 2002:a5d:470d:0:b0:21a:3dac:8bcf with SMTP id y13-20020a5d470d000000b0021a3dac8bcfmr17186020wrq.113.1656410367471;
        Tue, 28 Jun 2022 02:59:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb04:0:b0:21b:b3cc:1640 with SMTP id s4-20020adfeb04000000b0021bb3cc1640ls17368353wrn.1.gmail;
 Tue, 28 Jun 2022 02:59:26 -0700 (PDT)
X-Received: by 2002:a05:6000:1865:b0:21b:a408:b474 with SMTP id d5-20020a056000186500b0021ba408b474mr16807317wri.674.1656410366186;
        Tue, 28 Jun 2022 02:59:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410366; cv=none;
        d=google.com; s=arc-20160816;
        b=Uw5XGj4N+bYTvDWS4ABsf5M+Qez+vf8vbJ7HGrJ1nDnB4N22Ydx1tkh63NegrVT/T7
         GwzBc1VXq3bBgf8sMUz4Xy0EtmkZhNQMpOlxwrwAndp387na6QfVZf7hMycNwmsaEUDI
         mU07clr78HAUJITa5P7FBpjudZx6WNIER5MlijHje83zfZwRz2RT9L8GIQ4gqYDhLopB
         ZIFI/KYhjs7Ie8xTeku3igVWQs7JYRhtC6eHK7Z/3zNqZf5kd6LsNelZw9H0sPLhL6im
         a9qAlo1ZAn2nK7nuh5x39qCn427/viikFQJCCIf4M7x8Ib1NTKtvz3kz5PQ41Bp3QYCt
         ny7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Jb90vJz+Ljcdy/bwa5mhGZHGcIkLbD1O6C8oBBBl+eM=;
        b=He3CfZtVNpusEbNUNYPfGlyRXeocd9kqMrepKVXwm3bc3G7qz1zbrOM+x7OppNqqbM
         S1yQFMQRwP72tdsTqVDJ3cXyH0E/5lzyOxbdA9w0P7DM+FImABqqOLbQyNXqJ+smVIua
         w7wTxrTN7y1VmEtkVkpxaac7+8lieGGbH+xOPD13Wp4iTtmdcIk/BBzeUHUhiagHZGgM
         gjMThA3W5lsgxAiOau/JGESGBnQHjkTzH87GV2JU34RKm62awBe8VJE/O3mVC+FY7HnP
         ZdQtrW8fK0blTrI2JUpPBlCTwq2OdvqhIeyJ1vwuZM848QtOq4XUi3QjX3P9rqJQ76zb
         gZ1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=O4kzeA4u;
       spf=pass (google.com: domain of 3_dc6ygukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_dC6YgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x11-20020adfdccb000000b0021bbdc3209asi342500wrm.1.2022.06.28.02.59.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_dc6ygukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y18-20020adfdf12000000b0021b94ba4c37so1698614wrl.11
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:26 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a5d:6045:0:b0:21b:9397:41aa with SMTP id
 j5-20020a5d6045000000b0021b939741aamr17128186wrt.713.1656410365913; Tue, 28
 Jun 2022 02:59:25 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:30 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-11-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 10/13] perf/hw_breakpoint: Reduce contention with large
 number of tasks
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
 header.i=@google.com header.s=20210112 header.b=O4kzeA4u;       spf=pass
 (google.com: domain of 3_dc6ygukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3_dC6YgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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
data reader-writer lock (bp_cpuinfo_sem), and per-task mutexes (reuses
task_struct::perf_event_mutex):

  1. If the target is a task: acquires perf_event_mutex, and acquires
     bp_cpuinfo_sem as a reader. The choice of percpu-rwsem minimizes
     contention in the presence of many read-lock but few write-lock
     acquisitions: we assume many orders of magnitude more task target
     breakpoints creations/destructions than CPU target breakpoints.

  2. If the target is a CPU: acquires bp_cpuinfo_sem as a writer.

With these changes, contention with thousands of tasks is reduced to the
point where waiting on locking no longer dominates the profile:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.077 [sec]
 |
 |       40.201563 usecs/op
 |     2572.900000 usecs/op/cpu

    21.54%  [kernel]       [k] task_bp_pinned
    20.18%  [kernel]       [k] rhashtable_jhash2
     6.81%  [kernel]       [k] toggle_bp_slot
     5.47%  [kernel]       [k] queued_spin_lock_slowpath
     3.75%  [kernel]       [k] smp_cfm_core_cond
     3.48%  [kernel]       [k] bcmp

On this particular setup that's a speedup of 2.7x.

We're also getting closer to the theoretical ideal performance through
optimizations in hw_breakpoint.c -- constraints accounting disabled:

 | perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.067 [sec]
 |
 |       35.286458 usecs/op
 |     2258.333333 usecs/op/cpu

Which means the current implementation is ~12% slower than the
theoretical ideal.

For reference, performance without any breakpoints:

 | $> bench -r 30 breakpoint thread -b 0 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 0 breakpoints and 64 parallelism
 |      Total time: 0.060 [sec]
 |
 |       31.365625 usecs/op
 |     2007.400000 usecs/op/cpu

On a system with 256 CPUs, the theoretical ideal is only ~12% slower
than no breakpoints at all; the current implementation is ~28% slower.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use percpu-rwsem instead of rwlock.
* Use task_struct::perf_event_mutex. See code comment for reasoning.
==> Speedup of 2.7x (vs 2.5x in v1).
---
 kernel/events/hw_breakpoint.c | 159 ++++++++++++++++++++++++++++------
 1 file changed, 132 insertions(+), 27 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 63e39dc836bd..128ba3429223 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -19,6 +19,7 @@
 
 #include <linux/hw_breakpoint.h>
 
+#include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/cpu.h>
 #include <linux/export.h>
@@ -28,6 +29,7 @@
 #include <linux/kernel.h>
 #include <linux/mutex.h>
 #include <linux/notifier.h>
+#include <linux/percpu-rwsem.h>
 #include <linux/percpu.h>
 #include <linux/rhashtable.h>
 #include <linux/sched.h>
@@ -41,9 +43,9 @@ struct bp_cpuinfo {
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
 
@@ -65,8 +67,79 @@ static const struct rhashtable_params task_bps_ht_params = {
 
 static bool constraints_initialized __ro_after_init;
 
-/* Serialize accesses to the above constraints */
-static DEFINE_MUTEX(nr_bp_mutex);
+/*
+ * Synchronizes accesses to the per-CPU constraints; the locking rules are:
+ *
+ *  1. Atomic updates to bp_cpuinfo::tsk_pinned only require a held read-lock
+ *     (due to bp_slots_histogram::count being atomic, no update are lost).
+ *
+ *  2. Holding a write-lock is required for computations that require a
+ *     stable snapshot of all bp_cpuinfo::tsk_pinned.
+ *
+ *  3. In all other cases, non-atomic accesses require the appropriately held
+ *     lock (read-lock for read-only accesses; write-lock for reads/writes).
+ */
+DEFINE_STATIC_PERCPU_RWSEM(bp_cpuinfo_sem);
+
+/*
+ * Return mutex to serialize accesses to per-task lists in task_bps_ht. Since
+ * rhltable synchronizes concurrent insertions/deletions, independent tasks may
+ * insert/delete concurrently; therefore, a mutex per task is sufficient.
+ *
+ * Uses task_struct::perf_event_mutex, to avoid extending task_struct with a
+ * hw_breakpoint-only mutex, which may be infrequently used. The caveat here is
+ * that hw_breakpoint may contend with per-task perf event list management. The
+ * assumption is that perf usecases involving hw_breakpoints are very unlikely
+ * to result in unnecessary contention.
+ */
+static inline struct mutex *get_task_bps_mutex(struct perf_event *bp)
+{
+	struct task_struct *tsk = bp->hw.target;
+
+	return tsk ? &tsk->perf_event_mutex : NULL;
+}
+
+static struct mutex *bp_constraints_lock(struct perf_event *bp)
+{
+	struct mutex *tsk_mtx = get_task_bps_mutex(bp);
+
+	if (tsk_mtx) {
+		mutex_lock(tsk_mtx);
+		percpu_down_read(&bp_cpuinfo_sem);
+	} else {
+		percpu_down_write(&bp_cpuinfo_sem);
+	}
+
+	return tsk_mtx;
+}
+
+static void bp_constraints_unlock(struct mutex *tsk_mtx)
+{
+	if (tsk_mtx) {
+		percpu_up_read(&bp_cpuinfo_sem);
+		mutex_unlock(tsk_mtx);
+	} else {
+		percpu_up_write(&bp_cpuinfo_sem);
+	}
+}
+
+static bool bp_constraints_is_locked(struct perf_event *bp)
+{
+	struct mutex *tsk_mtx = get_task_bps_mutex(bp);
+
+	return percpu_is_write_locked(&bp_cpuinfo_sem) ||
+	       (tsk_mtx ? mutex_is_locked(tsk_mtx) :
+			  percpu_is_read_locked(&bp_cpuinfo_sem));
+}
+
+static inline void assert_bp_constraints_lock_held(struct perf_event *bp)
+{
+	struct mutex *tsk_mtx = get_task_bps_mutex(bp);
+
+	if (tsk_mtx)
+		lockdep_assert_held(tsk_mtx);
+	lockdep_assert_held(&bp_cpuinfo_sem);
+}
 
 #ifdef hw_breakpoint_slots
 /*
@@ -97,7 +170,7 @@ static __init int init_breakpoint_slots(void)
 		for (i = 0; i < TYPE_MAX; i++) {
 			struct bp_cpuinfo *info = get_bp_info(cpu, i);
 
-			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(int), GFP_KERNEL);
+			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(atomic_t), GFP_KERNEL);
 			if (!info->tsk_pinned)
 				goto err;
 		}
@@ -137,11 +210,19 @@ static inline enum bp_type_idx find_slot_idx(u64 bp_type)
  */
 static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 {
-	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
+	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int i;
 
+	/*
+	 * At this point we want to have acquired the bp_cpuinfo_sem as a
+	 * writer to ensure that there are no concurrent writers in
+	 * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
+	 */
+	lockdep_assert_held_write(&bp_cpuinfo_sem);
+
 	for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
-		if (tsk_pinned[i] > 0)
+		ASSERT_EXCLUSIVE_WRITER(tsk_pinned[i]); /* Catch unexpected writers. */
+		if (atomic_read(&tsk_pinned[i]) > 0)
 			return i + 1;
 	}
 
@@ -158,6 +239,11 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
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
@@ -214,16 +300,25 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 				enum bp_type_idx type, int weight)
 {
-	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
+	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int old_idx, new_idx;
 
+	/*
+	 * If bp->hw.target, tsk_pinned is only modified, but not used
+	 * otherwise. We can permit concurrent updates as long as there are no
+	 * other uses: having acquired bp_cpuinfo_sem as a reader allows
+	 * concurrent updates here. Uses of tsk_pinned will require acquiring
+	 * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
+	 */
+	lockdep_assert_held_read(&bp_cpuinfo_sem);
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
@@ -241,6 +336,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 
 	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
+		lockdep_assert_held_write(&bp_cpuinfo_sem);
 		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
 		return 0;
 	}
@@ -249,6 +345,11 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
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
@@ -354,14 +455,10 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 
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
 
@@ -379,12 +476,11 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
 
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
@@ -411,11 +507,10 @@ static int __modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
 
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
 
@@ -426,18 +521,28 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
  */
 int dbg_reserve_bp_slot(struct perf_event *bp)
 {
-	if (mutex_is_locked(&nr_bp_mutex))
+	int ret;
+
+	if (bp_constraints_is_locked(bp))
 		return -1;
 
-	return __reserve_bp_slot(bp, bp->attr.bp_type);
+	/* Locks aren't held; disable lockdep assert checking. */
+	lockdep_off();
+	ret = __reserve_bp_slot(bp, bp->attr.bp_type);
+	lockdep_on();
+
+	return ret;
 }
 
 int dbg_release_bp_slot(struct perf_event *bp)
 {
-	if (mutex_is_locked(&nr_bp_mutex))
+	if (bp_constraints_is_locked(bp))
 		return -1;
 
+	/* Locks aren't held; disable lockdep assert checking. */
+	lockdep_off();
 	__release_bp_slot(bp, bp->attr.bp_type);
+	lockdep_on();
 
 	return 0;
 }
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-11-elver%40google.com.
