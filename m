Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44DRSLAMGQEHXJWO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C0AB565945
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:28 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id w23-20020a2e9bd7000000b0025bd31b7fe7sf2863952ljj.16
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947188; cv=pass;
        d=google.com; s=arc-20160816;
        b=oMHaK4PyTmxUQhultiKbzflTz4DSqHUjjrOsHtwJmsrrCFaqZ7/jL4V/r7nNwNI2my
         lxJ5Xx40wjIWoEUxuV4mn5nIOEICAQDjshIqeTeQUq/H48VolBgr0C8+E8+rVfHaQlSs
         3xyTT3D3aGk8rgPI6fEwrM9PNSjrRrd7a9jSnN2qXGgXTG80+rDGInMLnAf4NlOaz0mY
         CJTmmIP2a1cXEAhimtNCxwzfoWTFG+kFaLhIyIn1KXUJZzn36uojhBPNjTjRqTIcpNH+
         nQzgLLOgIsa3MdcnVnAE4Uy6bW48nQMJiT0NN2HpnBg0wsDcpe+XknI0EtQ0RdqCBMmN
         ka+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zUsL5CiI/4lDfps05XNXDIIKpSMYs3U0TG5brxcIPEY=;
        b=CsXFl7gs7l/uiQzqPmCpFWve95aWiLqX51Ruiy3Ii+e6ze9Tq5JtYbdg7oyJlPx20/
         +pliGzLIP/yFNYm7p/z38+3cFlkM5RCK/YdF5jKB/rIIpIjsOPHiFMSHyDCYM6QG/xo/
         uVYhbF3XqV5dEAespbu8GN/EYeIpu3rdRh2AeCirlIH0CqAkdOUXv5bX3fkCvNmQaO7h
         eZ64+gM9ljy3KrEBahBNMwZ6JrZY2BvBqpzvEzs9iwu8sEEZIf4FTZ9g55twN3uUq+6Y
         dAI/HIe8aj+0WlGPFsJy2b3FiFuQRG9Lg5GiTtNbCYE3HbiO8tWczfEQeuaF58Fv0kWa
         e57Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="K6CNs/JC";
       spf=pass (google.com: domain of 38ghdygukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38gHDYgUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zUsL5CiI/4lDfps05XNXDIIKpSMYs3U0TG5brxcIPEY=;
        b=Us2+HxsfGQGzfv1/RJwQ0d1JChWYhIIqKuDo5TEERNdY8Dj4/0IY64ZpQ0INMo31Ap
         8PWAy2pvzrOAOZ6TLMBUxdxBYhxwzMyPl465XsnS5cRhBpGF8zoagaCFRJ80/ITuRxpk
         R15EeLWZIyV/+9APN09s3UzaJleo3OE21tUl2ck6wnfWvhylyAWtSbdkiCe2TKIRu813
         Yv/dgUP8lVaoYHwxqeJz74Mw7QsWO1pfHK4Cx4WhjH4Xg/2Xm8mJZEV/1PM/AM+SAJgS
         0x9t7KqNibpdQxL9Du66kt6sLBPiSSWQ3QFOdnqXV541AI3wgat0CXk5ujnlpWgV/POF
         ETuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zUsL5CiI/4lDfps05XNXDIIKpSMYs3U0TG5brxcIPEY=;
        b=sFnoDwJjG/ik6Z/QdeopGVsE25oQNJWfZ6GJMsmUMnO3KuUcUexeJCUU2NlKTsyZDU
         PQj16TLQ/m5gL6IS1Ev5iIht2XP982P8bxH7L4ooCq1amLMET+Di8hBE+5mW5QaKmt6L
         jVYn+mL0I2K1/hCO2vSVawPh+CKodPIvEBEJDjeRjdmk3Y9uglhkha6SokFzYTWvhHTW
         HL05wkLTj5tldXpDJgjKu9j8X2YLbPT6xA3U56yNDNRf9U2KesYq1SKcZS+TtYjFc7K7
         G1MxEEW9UDc+7MOIn6xIIpVoKrZJSdM+DzlTVKYTSlhrDc+ea18mhfqupc/9INX1Di4d
         znFQ==
X-Gm-Message-State: AJIora/OCFvSeClEEKdmQ9u5DkC4uoe27ue64rTcp5Yup0gLcXfUimpH
	FA/ynH9oVMtLoF+OYzmXvwU=
X-Google-Smtp-Source: AGRyM1u78eVCR8gDb1joKNdqcDuvsgcGsuAwEM8MpeJrX+q9HNRZTB56DCEooYDS3edYuya5RzQ0zA==
X-Received: by 2002:a2e:bd13:0:b0:246:1ff8:6da1 with SMTP id n19-20020a2ebd13000000b002461ff86da1mr16535256ljq.219.1656947188005;
        Mon, 04 Jul 2022 08:06:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls780729lfn.2.gmail;
 Mon, 04 Jul 2022 08:06:26 -0700 (PDT)
X-Received: by 2002:ac2:4e81:0:b0:47f:7ddf:a5a2 with SMTP id o1-20020ac24e81000000b0047f7ddfa5a2mr19443661lfr.690.1656947186512;
        Mon, 04 Jul 2022 08:06:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947186; cv=none;
        d=google.com; s=arc-20160816;
        b=z5V1wDY+pd+lwXbdJQFeF5xdRFRt5CnwhuPHWn1LClhcgzFziA4ymey4xaJ7Y+2KKE
         m4g3vk4/xlVQS6s3UbrxznidSX/tevG14pOEO6P0ECb4Vvg2BqJNdDtueagQ0vN5kMpD
         zhVnmSq/ATYqf0P1rPoc1PAxGKI3pnsvo/UMaVhWI972/lp9G0v2VjEi/FymxnnXnRxQ
         kW2dWolknLqoLWuEIlIVed94ZLQjT6BRx25zk6j5d/9FLRqXKUYuhINQLroWCHaOZ3KN
         N7BXXxA349se0YMN7Hif7qajlERc2OZ4WsXgbnEFCSsiGX8C8q0MKrVh0BmMEau9IenJ
         L7ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=F+y0VjUOf/KQ8kMAUmr6wHVQBOr1d3IzfRi1YZ7mk8I=;
        b=fFFA1KZugfYJVKIjgSxbXBdwzxm+x8iJO9llHRbWO/pAY/HC+b8OwX8d3hJ2OFeVBd
         7io4CBgAlx7QzKELFY4tYFmFWquHfgC9z1mcy7JE52Q90/VibZDU2vrFoXIse7pe0nxX
         LVhxAHRrLNREOUHs02uFcZlseuB84J5EtKYSX8EZ9LeT4v5KYDZWUhzfxYPY3GCDO0v2
         nZNHhOAomngTN6vmKMrg22lBMeevIkAoDjFXgcA0ZrhONToJlX7vzd6PKYrDPZ1Jumfk
         0gBmaJ45dHXEM1JxM+JujK+JS8VcpJnoJkEj4wOnWsmGlKjNJCJfxtVxrReiaGvLsVDV
         al3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="K6CNs/JC";
       spf=pass (google.com: domain of 38ghdygukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38gHDYgUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id v12-20020a056512348c00b00482b3534361si120821lfr.6.2022.07.04.08.06.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38ghdygukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id q18-20020a056402519200b004358ce90d97so7260486edd.4
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:26 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a05:6402:1e88:b0:435:bf05:f0f with SMTP id
 f8-20020a0564021e8800b00435bf050f0fmr39736606edf.2.1656947186068; Mon, 04 Jul
 2022 08:06:26 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:11 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-12-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 11/14] perf/hw_breakpoint: Reduce contention with large
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
 header.i=@google.com header.s=20210112 header.b="K6CNs/JC";       spf=pass
 (google.com: domain of 38ghdygukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38gHDYgUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Use percpu-rwsem instead of rwlock.
* Use task_struct::perf_event_mutex. See code comment for reasoning.
==> Speedup of 2.7x (vs 2.5x in v1).
---
 kernel/events/hw_breakpoint.c | 161 ++++++++++++++++++++++++++++------
 1 file changed, 133 insertions(+), 28 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8b40fca1a063..229c6f4fae75 100644
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
@@ -663,7 +768,7 @@ bool hw_breakpoint_is_used(void)
 				return true;
 
 			for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
-				if (info->tsk_pinned[slot])
+				if (atomic_read(&info->tsk_pinned[slot]))
 					return true;
 			}
 		}
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-12-elver%40google.com.
