Return-Path: <kasan-dev+bncBDPPFIEASMFBBAOD4CLAMGQEH5JEI3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2889257BA90
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:38:42 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id hr24-20020a1709073f9800b0072b57c28438sf4204973ejc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:38:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331522; cv=pass;
        d=google.com; s=arc-20160816;
        b=SPy7gfsU4RhoRJjD7lFQzc2eTQa0AxAgEguXMCTq7TLziGhnNfOJDVu23TVnpJCqVG
         sT4+h7woMfbT5/ahoD+W5cUENwVQAaxzu8UpdkNRsWGrxZYl7rjmFHxlu+cvmABLMfOE
         wLjbKBt1JCheKn/0/o70nbRJD9433o38tnxM7hJ5e5OkXvKuCASnY6UlAhNVr9AKZB7U
         OOExNvT7YQZ3YX4A1SJuoAriuthXJgjpvoD7Jj4QCJQC5XtTmPC/6CiwHYxeDrDXSmP+
         er8mZ4RzPQwSEEmzY/m5IeqlI73F9DvUBVR3YfQOodFt4h4r0g9lUBtEjcnFOhasozz9
         ZVOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TxBEtJAvKSOjIUeWju0x/+QmroaAQO2U24riqjnz2fI=;
        b=Q/vd3tviFdu3UnGTPXVK53hrvji8ZIh1co9FOkbdtUOtkomjgHDyih25iDb95fsro0
         rX3nqkrd+cLiPCZ6L1p1mhEa5pI5EFlRgqrDwPifLLGVmaYYxzKCqMP7USPq7o9+KCjo
         Vt7aSvgCe5A92h15Hyf2hwOJAX6iG/3CPsU3CnRbM8BOtDBvn0UQ6zrWmxnrG/pASxiZ
         /WriWARFb7HgaywyLDg/UB3nWvqaqBzB9LbKblRQSCQEfvLVRETdtlWtViv0sRYQMUvH
         8Jyst28wHLgPPNtI5BUlzotlV8a7VrCLx+3MCRev5Hr7Zzj7sjURL8yqSND7HOt5iI+u
         ZVOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WP2qB3iL;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TxBEtJAvKSOjIUeWju0x/+QmroaAQO2U24riqjnz2fI=;
        b=rMhKhTxt5YdyuWbncW5x+5bbzOHqNuJKEL+zR/j3vMBBaNpK102MocsJ+cimIpBC90
         Lno7QgbpuBwibf4XyLMU62LUJgmcaG0NOEPgEpUHpMctLr+fX8CdTAT8auYtS6dy20Lc
         GR0n7fGWzKnlPzLc2gyF4MEStf88PS+NspCw8RjPQz0eI7QrdgZtmYRk8tv4OOoCev5/
         XyRtQpsYItx0CGfW5Q0RIvFT+KUZxLImyuu8LcPqtZwSbzX27zLIWAfiHOYMDcNsNUvf
         St1U67qBWyKNKDAXs9oXP4+Szq5a1LbGxsXFRWXs0cLgHlu6AzQfmpH8m2NnIcZkF5CE
         eUnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TxBEtJAvKSOjIUeWju0x/+QmroaAQO2U24riqjnz2fI=;
        b=qOOaUmm6eLz5Nc01Z3d0kyv/8+Mz5azdDkmSbnJM3hKlu4di6cFKokCs8CHztVUZ3z
         NU1LWb6Uti1voy58PGdf2t0fVD0gu/JOTmC2MuIncsqTlbrF9rYrp9+xRtfIqLnp2VsR
         hS4TEnoPLQ+baIs8HpoCk75zTJPB1pRIT8va+T4RvhlyU2FY32LVBwMWoli7LlyHjpc5
         wFuwQXHENY+e6Ze49u9YuPpzkG19Tpn0aBZfEFGIKFEI/hV0GFLEQVJciGeC+BxIK2ib
         hgzOAI3hlDQ/gS7w2lQZIDd5K3Ik5kyQsE9JJZSsRD8uktel9kCi64dYCEbtTGNTlegK
         0kew==
X-Gm-Message-State: AJIora9Pg500yQoW+FUjX/MrJzLmS2OvnGghoHWehuamj/WX72TfkC6X
	JXyWJutt9QR2F1zZHSjWxRg=
X-Google-Smtp-Source: AGRyM1tIFP1h7riz3WENsSUHeHCKkdQssyiq8YCd/yKRaEiGYtWJETmpjvBwaMcR+f52vcGx4Trr5A==
X-Received: by 2002:a05:6402:278e:b0:43a:9cf5:6608 with SMTP id b14-20020a056402278e00b0043a9cf56608mr51334650ede.76.1658331521863;
        Wed, 20 Jul 2022 08:38:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a94b:b0:72b:564b:c25b with SMTP id
 hh11-20020a170906a94b00b0072b564bc25bls307933ejb.7.-pod-prod-gmail; Wed, 20
 Jul 2022 08:38:40 -0700 (PDT)
X-Received: by 2002:a17:907:2cf5:b0:72b:7656:f162 with SMTP id hz21-20020a1709072cf500b0072b7656f162mr33863491ejc.565.1658331520791;
        Wed, 20 Jul 2022 08:38:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331520; cv=none;
        d=google.com; s=arc-20160816;
        b=XiSJS05RcrDaxpUSINHUeZuaWzSpI7WeSc2dHjh/gJlSIkDQFc9oZFyWx1ROfoCwRD
         hBb+phhz8z1g+DANCb/8IqiZqWchNOnQXaD8IQaGeZJnBXZhh4Fi/FrKZIcmCFAIQBJb
         FBSKDTdQ2Nazq76syr+Xc1nBvSfKRA5PyR/f4IPOQKqW53Jc/G51pYrb9bI1WIKN1OJJ
         8RZ8Ptg+AOxx95BBsBfiaI+ubr8NTxyjeQbyi6lmF3ZyZhtRuhciSgI+VABuutUvf1Z8
         VxNnpxlGRCQlZBHlFau1aZEPurtzv2xYw5PndU5qOIXaq6skHgGCnhjSC16sZ8oKzX8k
         i/5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vg/L/5Ph5NMqge6CPKJ7rIzEwrI2CdrqRTD1mNbi3CM=;
        b=WAjdY6V6BD2ffDYpm3QC5uWMWDTbaeWpAEJGGsOV847DkkZ3NeoCUoMZFKXmkGWK+V
         Fd7ZIWe0+CBYvd+hx8lnRaJUvAgpM1I1q+MO0qlhjukPqDZuDhiY6/aY2jW+ea7oUqqh
         Lz/nq2dwdPfxzJDuEbwJvwprHe9Z7DlM9hFZcEZ/qyfMoSgRN8GlZKdJO6qdhIy2yZG2
         I69bCw608TRNGVCMGoNlf2z7pEzI/UHIq9SNz20NlRvLJYhr5IE9+oPzoMIse90y8CQb
         SbhVzygPrI1/QFYDuXHGc5mm+x4ZIgJCAdYYUmJvlAjMs1Pc3SZIYHh/aiEGPifIBkBk
         PPDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WP2qB3iL;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id r18-20020aa7cfd2000000b0043bbb9ccb80si57432edy.2.2022.07.20.08.38.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:38:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id x23-20020a05600c179700b003a30e3e7989so1536570wmo.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:38:40 -0700 (PDT)
X-Received: by 2002:a05:600c:4e8f:b0:3a1:8b21:ebbc with SMTP id
 f15-20020a05600c4e8f00b003a18b21ebbcmr4507339wmq.149.1658331520280; Wed, 20
 Jul 2022 08:38:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-12-elver@google.com>
In-Reply-To: <20220704150514.48816-12-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:38:28 -0700
Message-ID: <CAP-5=fWsCxFh4ajE9VH0eEkRk0K1agjCYmQySv4u+2p5on2cpg@mail.gmail.com>
Subject: Re: [PATCH v3 11/14] perf/hw_breakpoint: Reduce contention with large
 number of tasks
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WP2qB3iL;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:07 AM Marco Elver <elver@google.com> wrote:
>
> While optimizing task_bp_pinned()'s runtime complexity to O(1) on
> average helps reduce time spent in the critical section, we still suffer
> due to serializing everything via 'nr_bp_mutex'. Indeed, a profile shows
> that now contention is the biggest issue:
>
>     95.93%  [kernel]       [k] osq_lock
>      0.70%  [kernel]       [k] mutex_spin_on_owner
>      0.22%  [kernel]       [k] smp_cfm_core_cond
>      0.18%  [kernel]       [k] task_bp_pinned
>      0.18%  [kernel]       [k] rhashtable_jhash2
>      0.15%  [kernel]       [k] queued_spin_lock_slowpath
>
> when running the breakpoint benchmark with (system with 256 CPUs):
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.207 [sec]
>  |
>  |      108.267188 usecs/op
>  |     6929.100000 usecs/op/cpu
>
> The main concern for synchronizing the breakpoint constraints data is
> that a consistent snapshot of the per-CPU and per-task data is observed.
>
> The access pattern is as follows:
>
>  1. If the target is a task: the task's pinned breakpoints are counted,
>     checked for space, and then appended to; only bp_cpuinfo::cpu_pinned
>     is used to check for conflicts with CPU-only breakpoints;
>     bp_cpuinfo::tsk_pinned are incremented/decremented, but otherwise
>     unused.
>
>  2. If the target is a CPU: bp_cpuinfo::cpu_pinned are counted, along
>     with bp_cpuinfo::tsk_pinned; after a successful check, cpu_pinned is
>     incremented. No per-task breakpoints are checked.
>
> Since rhltable safely synchronizes insertions/deletions, we can allow
> concurrency as follows:
>
>  1. If the target is a task: independent tasks may update and check the
>     constraints concurrently, but same-task target calls need to be
>     serialized; since bp_cpuinfo::tsk_pinned is only updated, but not
>     checked, these modifications can happen concurrently by switching
>     tsk_pinned to atomic_t.
>
>  2. If the target is a CPU: access to the per-CPU constraints needs to
>     be serialized with other CPU-target and task-target callers (to
>     stabilize the bp_cpuinfo::tsk_pinned snapshot).
>
> We can allow the above concurrency by introducing a per-CPU constraints
> data reader-writer lock (bp_cpuinfo_sem), and per-task mutexes (reuses
> task_struct::perf_event_mutex):
>
>   1. If the target is a task: acquires perf_event_mutex, and acquires
>      bp_cpuinfo_sem as a reader. The choice of percpu-rwsem minimizes
>      contention in the presence of many read-lock but few write-lock
>      acquisitions: we assume many orders of magnitude more task target
>      breakpoints creations/destructions than CPU target breakpoints.
>
>   2. If the target is a CPU: acquires bp_cpuinfo_sem as a writer.
>
> With these changes, contention with thousands of tasks is reduced to the
> point where waiting on locking no longer dominates the profile:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.077 [sec]
>  |
>  |       40.201563 usecs/op
>  |     2572.900000 usecs/op/cpu
>
>     21.54%  [kernel]       [k] task_bp_pinned
>     20.18%  [kernel]       [k] rhashtable_jhash2
>      6.81%  [kernel]       [k] toggle_bp_slot
>      5.47%  [kernel]       [k] queued_spin_lock_slowpath
>      3.75%  [kernel]       [k] smp_cfm_core_cond
>      3.48%  [kernel]       [k] bcmp
>
> On this particular setup that's a speedup of 2.7x.
>
> We're also getting closer to the theoretical ideal performance through
> optimizations in hw_breakpoint.c -- constraints accounting disabled:
>
>  | perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.067 [sec]
>  |
>  |       35.286458 usecs/op
>  |     2258.333333 usecs/op/cpu
>
> Which means the current implementation is ~12% slower than the
> theoretical ideal.
>
> For reference, performance without any breakpoints:
>
>  | $> bench -r 30 breakpoint thread -b 0 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 0 breakpoints and 64 parallelism
>  |      Total time: 0.060 [sec]
>  |
>  |       31.365625 usecs/op
>  |     2007.400000 usecs/op/cpu
>
> On a system with 256 CPUs, the theoretical ideal is only ~12% slower
> than no breakpoints at all; the current implementation is ~28% slower.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v2:
> * Use percpu-rwsem instead of rwlock.
> * Use task_struct::perf_event_mutex. See code comment for reasoning.
> ==> Speedup of 2.7x (vs 2.5x in v1).
> ---
>  kernel/events/hw_breakpoint.c | 161 ++++++++++++++++++++++++++++------
>  1 file changed, 133 insertions(+), 28 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 8b40fca1a063..229c6f4fae75 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -19,6 +19,7 @@
>
>  #include <linux/hw_breakpoint.h>
>
> +#include <linux/atomic.h>
>  #include <linux/bug.h>
>  #include <linux/cpu.h>
>  #include <linux/export.h>
> @@ -28,6 +29,7 @@
>  #include <linux/kernel.h>
>  #include <linux/mutex.h>
>  #include <linux/notifier.h>
> +#include <linux/percpu-rwsem.h>
>  #include <linux/percpu.h>
>  #include <linux/rhashtable.h>
>  #include <linux/sched.h>
> @@ -41,9 +43,9 @@ struct bp_cpuinfo {
>         unsigned int    cpu_pinned;
>         /* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
>  #ifdef hw_breakpoint_slots
> -       unsigned int    tsk_pinned[hw_breakpoint_slots(0)];
> +       atomic_t        tsk_pinned[hw_breakpoint_slots(0)];
>  #else
> -       unsigned int    *tsk_pinned;
> +       atomic_t        *tsk_pinned;
>  #endif
>  };
>
> @@ -65,8 +67,79 @@ static const struct rhashtable_params task_bps_ht_params = {
>
>  static bool constraints_initialized __ro_after_init;
>
> -/* Serialize accesses to the above constraints */
> -static DEFINE_MUTEX(nr_bp_mutex);
> +/*
> + * Synchronizes accesses to the per-CPU constraints; the locking rules are:
> + *
> + *  1. Atomic updates to bp_cpuinfo::tsk_pinned only require a held read-lock
> + *     (due to bp_slots_histogram::count being atomic, no update are lost).
> + *
> + *  2. Holding a write-lock is required for computations that require a
> + *     stable snapshot of all bp_cpuinfo::tsk_pinned.
> + *
> + *  3. In all other cases, non-atomic accesses require the appropriately held
> + *     lock (read-lock for read-only accesses; write-lock for reads/writes).
> + */
> +DEFINE_STATIC_PERCPU_RWSEM(bp_cpuinfo_sem);
> +
> +/*
> + * Return mutex to serialize accesses to per-task lists in task_bps_ht. Since
> + * rhltable synchronizes concurrent insertions/deletions, independent tasks may
> + * insert/delete concurrently; therefore, a mutex per task is sufficient.
> + *
> + * Uses task_struct::perf_event_mutex, to avoid extending task_struct with a
> + * hw_breakpoint-only mutex, which may be infrequently used. The caveat here is
> + * that hw_breakpoint may contend with per-task perf event list management. The
> + * assumption is that perf usecases involving hw_breakpoints are very unlikely
> + * to result in unnecessary contention.
> + */
> +static inline struct mutex *get_task_bps_mutex(struct perf_event *bp)
> +{
> +       struct task_struct *tsk = bp->hw.target;
> +
> +       return tsk ? &tsk->perf_event_mutex : NULL;
> +}
> +
> +static struct mutex *bp_constraints_lock(struct perf_event *bp)
> +{
> +       struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> +
> +       if (tsk_mtx) {
> +               mutex_lock(tsk_mtx);
> +               percpu_down_read(&bp_cpuinfo_sem);
> +       } else {
> +               percpu_down_write(&bp_cpuinfo_sem);
> +       }
> +
> +       return tsk_mtx;
> +}
> +
> +static void bp_constraints_unlock(struct mutex *tsk_mtx)
> +{
> +       if (tsk_mtx) {
> +               percpu_up_read(&bp_cpuinfo_sem);
> +               mutex_unlock(tsk_mtx);
> +       } else {
> +               percpu_up_write(&bp_cpuinfo_sem);
> +       }
> +}
> +
> +static bool bp_constraints_is_locked(struct perf_event *bp)
> +{
> +       struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> +
> +       return percpu_is_write_locked(&bp_cpuinfo_sem) ||
> +              (tsk_mtx ? mutex_is_locked(tsk_mtx) :
> +                         percpu_is_read_locked(&bp_cpuinfo_sem));
> +}
> +
> +static inline void assert_bp_constraints_lock_held(struct perf_event *bp)
> +{
> +       struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> +
> +       if (tsk_mtx)
> +               lockdep_assert_held(tsk_mtx);
> +       lockdep_assert_held(&bp_cpuinfo_sem);
> +}
>
>  #ifdef hw_breakpoint_slots
>  /*
> @@ -97,7 +170,7 @@ static __init int init_breakpoint_slots(void)
>                 for (i = 0; i < TYPE_MAX; i++) {
>                         struct bp_cpuinfo *info = get_bp_info(cpu, i);
>
> -                       info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(int), GFP_KERNEL);
> +                       info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(atomic_t), GFP_KERNEL);
>                         if (!info->tsk_pinned)
>                                 goto err;
>                 }
> @@ -137,11 +210,19 @@ static inline enum bp_type_idx find_slot_idx(u64 bp_type)
>   */
>  static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>  {
> -       unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
> +       atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
>         int i;
>
> +       /*
> +        * At this point we want to have acquired the bp_cpuinfo_sem as a
> +        * writer to ensure that there are no concurrent writers in
> +        * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
> +        */
> +       lockdep_assert_held_write(&bp_cpuinfo_sem);
> +
>         for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
> -               if (tsk_pinned[i] > 0)
> +               ASSERT_EXCLUSIVE_WRITER(tsk_pinned[i]); /* Catch unexpected writers. */
> +               if (atomic_read(&tsk_pinned[i]) > 0)
>                         return i + 1;
>         }
>
> @@ -158,6 +239,11 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
>         struct perf_event *iter;
>         int count = 0;
>
> +       /*
> +        * We need a stable snapshot of the per-task breakpoint list.
> +        */
> +       assert_bp_constraints_lock_held(bp);
> +
>         rcu_read_lock();
>         head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
>         if (!head)
> @@ -214,16 +300,25 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
>  static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>                                 enum bp_type_idx type, int weight)
>  {
> -       unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
> +       atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
>         int old_idx, new_idx;
>
> +       /*
> +        * If bp->hw.target, tsk_pinned is only modified, but not used
> +        * otherwise. We can permit concurrent updates as long as there are no
> +        * other uses: having acquired bp_cpuinfo_sem as a reader allows
> +        * concurrent updates here. Uses of tsk_pinned will require acquiring
> +        * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
> +        */
> +       lockdep_assert_held_read(&bp_cpuinfo_sem);
> +
>         old_idx = task_bp_pinned(cpu, bp, type) - 1;
>         new_idx = old_idx + weight;
>
>         if (old_idx >= 0)
> -               tsk_pinned[old_idx]--;
> +               atomic_dec(&tsk_pinned[old_idx]);
>         if (new_idx >= 0)
> -               tsk_pinned[new_idx]++;
> +               atomic_inc(&tsk_pinned[new_idx]);
>  }
>
>  /*
> @@ -241,6 +336,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>
>         /* Pinned counter cpu profiling */
>         if (!bp->hw.target) {
> +               lockdep_assert_held_write(&bp_cpuinfo_sem);
>                 get_bp_info(bp->cpu, type)->cpu_pinned += weight;
>                 return 0;
>         }
> @@ -249,6 +345,11 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>         for_each_cpu(cpu, cpumask)
>                 toggle_bp_task_slot(bp, cpu, type, weight);
>
> +       /*
> +        * Readers want a stable snapshot of the per-task breakpoint list.
> +        */
> +       assert_bp_constraints_lock_held(bp);
> +
>         if (enable)
>                 return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
>         else
> @@ -354,14 +455,10 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>
>  int reserve_bp_slot(struct perf_event *bp)
>  {
> -       int ret;
> -
> -       mutex_lock(&nr_bp_mutex);
> -
> -       ret = __reserve_bp_slot(bp, bp->attr.bp_type);
> -
> -       mutex_unlock(&nr_bp_mutex);
> +       struct mutex *mtx = bp_constraints_lock(bp);
> +       int ret = __reserve_bp_slot(bp, bp->attr.bp_type);
>
> +       bp_constraints_unlock(mtx);
>         return ret;
>  }
>
> @@ -379,12 +476,11 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
>
>  void release_bp_slot(struct perf_event *bp)
>  {
> -       mutex_lock(&nr_bp_mutex);
> +       struct mutex *mtx = bp_constraints_lock(bp);
>
>         arch_unregister_hw_breakpoint(bp);
>         __release_bp_slot(bp, bp->attr.bp_type);
> -
> -       mutex_unlock(&nr_bp_mutex);
> +       bp_constraints_unlock(mtx);
>  }
>
>  static int __modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
> @@ -411,11 +507,10 @@ static int __modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
>
>  static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
>  {
> -       int ret;
> +       struct mutex *mtx = bp_constraints_lock(bp);
> +       int ret = __modify_bp_slot(bp, old_type, new_type);
>
> -       mutex_lock(&nr_bp_mutex);
> -       ret = __modify_bp_slot(bp, old_type, new_type);
> -       mutex_unlock(&nr_bp_mutex);
> +       bp_constraints_unlock(mtx);
>         return ret;
>  }
>
> @@ -426,18 +521,28 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
>   */
>  int dbg_reserve_bp_slot(struct perf_event *bp)
>  {
> -       if (mutex_is_locked(&nr_bp_mutex))
> +       int ret;
> +
> +       if (bp_constraints_is_locked(bp))
>                 return -1;
>
> -       return __reserve_bp_slot(bp, bp->attr.bp_type);
> +       /* Locks aren't held; disable lockdep assert checking. */
> +       lockdep_off();
> +       ret = __reserve_bp_slot(bp, bp->attr.bp_type);
> +       lockdep_on();
> +
> +       return ret;
>  }
>
>  int dbg_release_bp_slot(struct perf_event *bp)
>  {
> -       if (mutex_is_locked(&nr_bp_mutex))
> +       if (bp_constraints_is_locked(bp))
>                 return -1;
>
> +       /* Locks aren't held; disable lockdep assert checking. */
> +       lockdep_off();
>         __release_bp_slot(bp, bp->attr.bp_type);
> +       lockdep_on();
>
>         return 0;
>  }
> @@ -663,7 +768,7 @@ bool hw_breakpoint_is_used(void)
>                                 return true;
>
>                         for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
> -                               if (info->tsk_pinned[slot])
> +                               if (atomic_read(&info->tsk_pinned[slot]))
>                                         return true;
>                         }
>                 }
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfWsCxFh4ajE9VH0eEkRk0K1agjCYmQySv4u%2B2p5on2cpg%40mail.gmail.com.
