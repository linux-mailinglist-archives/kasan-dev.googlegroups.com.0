Return-Path: <kasan-dev+bncBCMIZB7QWENRB5V35SKQMGQEZAWFL6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3455855E5AC
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 17:27:51 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf6387520lfj.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 08:27:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656430070; cv=pass;
        d=google.com; s=arc-20160816;
        b=t/Fo66sPFJWYRjrMjngtv1IJLtw9xiJzQsHGpjiNp125DCit4bIohA2p0DGKU1jiYl
         UZ9LpkFXZ0O2NezQjFKYQ3daZkYC8D6EYOtXs1RugpR3j8gWxa7NmtRvXSDRHGuaVcS7
         q5u6z+qNb5Jn3oOMI+Gl0DCbuijUD8zhMGnMK47kKl7yfOzMvb8o0R7eR/5zL8BmOOVw
         kGxq7ks5NXtqMOO0hEA561mgv1HTDn4igl0Ry7Cgtfynp7UFdcQAnC+tNDAtYtejP6M9
         8f55RVc+9rUSt6d++Y+h0sBBBowEjI8dm3N0KC5qmhC+apYwqqvCJYm/ha6+7kTTmUHf
         jC/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kbsSgKCYxjXFuUwX8RbXrbjj+OIYwH2SNpVrSU8m/WE=;
        b=rpZVmMZ7YewomaInfrCX4ydOsgIosWII7xbC2donMnBLv5DK/pGF0mwp+gnnsvFdOW
         7jSuHn3DIhh4wfoqPXe/WBn2JLL8yj1eCUbwwCA91hZrswuDfa1DQMChSWNXkCKrklvg
         eqXuiTbCRq0b000vZ9iBT26ruBptcZuE0U2D/l04qUeLwS7XXaNPrvPRjSjkkfIqNv7G
         rYnYV+wDK296kYiIVtB8Lrd4qtOVCnn1/i7dFdiRly12/NUAAX0MBZp9JLgmhL5XvCSI
         hSSzkfPAjwDMYx0sNQ4PrLepkcbWsoMPFkwsUbz5MlJrA/CUGPih20giRAn/lk535hYt
         UNMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OwQ4ahQW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kbsSgKCYxjXFuUwX8RbXrbjj+OIYwH2SNpVrSU8m/WE=;
        b=Yu9kKKOsxMX3nWEGcAuz9fkmjaILFHiP+lQnje14ARgY8bKZdKdq/LY7PSbyd7Xyw6
         CmnH1rEEz64zxzFUJTo1plmfuYewaUwpkEuG+WaqQBSAj1U2xOE+IovDQEJHe0da/SQa
         7MweK7dLpAzew3KtbXaRNTdQmcDPFoHFqfOOQwYfREz/0PLu6xpxphGqwGbxnbmEZnaH
         4oEwjW3nT0tn2BqECnA9TzNDNlJrAbTFhIM0LuO5bN95AgsJzKzEGCInZna1NyoCvPyC
         yWvuOB8cDzWy5+oHMKRLdMRCswvxDXs6pjkvEHNYWdky1TaXfE4LAjpHgV3nRANJFsPn
         RTFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kbsSgKCYxjXFuUwX8RbXrbjj+OIYwH2SNpVrSU8m/WE=;
        b=XvnJspBKX/+DAYgeILAueiyezBuQOPrsCQFA7evzQtLuUmBhdPrbKaKZk++Py274a4
         XAY9SGP0IoTcTyO8HHvmPKBZpFHVhtHPVjtXob2/ABgejaWujQs5E1kTcoAOopRUPwV0
         9aWIU/Kmdc+uKr25FtMJm+YXOK8XJ3BXbg72kOyv4/KbcliKJkgZrYrjt9DkNmjHVfn9
         QJ77ln32+Kj8W++cHL3O4ItdNrY+3YoESR239cGH/0bFByoYEoRAbDxbb7OG+kYZLCJ2
         UYYQriOr9eZFOk6pVnBpkBu5h+8NGmIn5lJkeVijz/HRiAREAbHyrVJEhNOatgh8ATib
         N9NQ==
X-Gm-Message-State: AJIora/gasQtci9P7xsMZuOMC4bUxeS0R2cmb22QRcJl9O2YqmvjtHNh
	M8rb8oawoJwayzsDmPuFni8=
X-Google-Smtp-Source: AGRyM1uObZ68ey3NTqayxbSMbt+66N0G/oqGMM2yM/IrwRrl5Oa2w9rsF7wsvtxGqO6tkpgRo/lAvw==
X-Received: by 2002:a2e:6e19:0:b0:25a:7bb7:b133 with SMTP id j25-20020a2e6e19000000b0025a7bb7b133mr9852790ljc.374.1656430070606;
        Tue, 28 Jun 2022 08:27:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls39715lfn.2.gmail;
 Tue, 28 Jun 2022 08:27:49 -0700 (PDT)
X-Received: by 2002:a05:6512:a8c:b0:47f:749e:8de3 with SMTP id m12-20020a0565120a8c00b0047f749e8de3mr11305938lfu.568.1656430069417;
        Tue, 28 Jun 2022 08:27:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656430069; cv=none;
        d=google.com; s=arc-20160816;
        b=p/I8VoX7ZKIlUoGenTlOcrZBIZ2DN7zfvar63uc1m7OVksg3Syr9PWmkwzDxwadJ85
         yBDf0ocACt3kqCjK1DKc1brjLJIN3L4njsQBBNfcVaXXh9Lny86zyb5o0EqMNolnY6nF
         XoBMbuiEDYGFKdeamPj27MFsUH3nVGGt0xnR3EvGK26qanN3pFhILF9Iq+H08eBbCGOn
         59WAEm0qZlo2dP0Vutp9K82apINRgZ2DCrTkgUL4jFMWTsXFC1H82NPxxq13y2fSnJgm
         +KQc/KghegYG8D1OvLaPGWC+j3uajf+WgaNmY9S8inu71xvd0xlcTEv514KSSknxyF0p
         NXrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JcrXyHrbwCCKxz8IEipVzSt2camDv5QxjxkeQewO/T0=;
        b=EurgACLOLutdZiU4Jl9IglFMsZu7VOKOHZkyERnmsP4pHWHhEu6IT99cLFsYNiby/B
         yQmPDhOnAGLQ4PupdTuEMu1HKOYuDfMoHqnUwIDe7TGkU5w6MegX3+rAzA5H7EaQ4yqo
         1PquMw1I7/gFmpqrMNMfK3y3RKh23DJvSR8U/hZ1iBBxkkiaphrmAsJPEvAfiy5RrzUo
         hlg4RKVPtksm1C03nLVJ/YIInAw7n877RWUVjOGS4DgsuK0ouKwPqbghEfaJfQAiYXjt
         jrLVwxxGghk1Zo25L9UoLeLEfoN/UPBudjGeRt2lffXBpDHewr8XRF/E/wvdRkdDG9PZ
         obCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OwQ4ahQW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si570673ljg.4.2022.06.28.08.27.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 08:27:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id z21so22884694lfb.12
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 08:27:49 -0700 (PDT)
X-Received: by 2002:a05:6512:2520:b0:47f:8512:19c1 with SMTP id
 be32-20020a056512252000b0047f851219c1mr12110789lfb.540.1656430068858; Tue, 28
 Jun 2022 08:27:48 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-4-elver@google.com>
 <CACT4Y+bh06ZF5s4Mfq+CJ8RJ+Fm41NeXt=C8Kkx11t9hgABpYQ@mail.gmail.com> <CANpmjNOT=npm9Bu9QGNO=SgCJVB2fr8ojO4-u-Ffgw4gmRuSfw@mail.gmail.com>
In-Reply-To: <CANpmjNOT=npm9Bu9QGNO=SgCJVB2fr8ojO4-u-Ffgw4gmRuSfw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 17:27:37 +0200
Message-ID: <CACT4Y+YQibtAk0y=SVTSp27Ythjk4c1jCV2_BNAL5Uiw-fMo_w@mail.gmail.com>
Subject: Re: [PATCH v2 03/13] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OwQ4ahQW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 28 Jun 2022 at 16:54, Marco Elver <elver@google.com> wrote:
> > > On a machine with 256 CPUs, running the recently added perf breakpoint
> > > benchmark results in:
> > >
> > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > >  | # Running 'breakpoint/thread' benchmark:
> > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > >  |      Total time: 236.418 [sec]
> > >  |
> > >  |   123134.794271 usecs/op
> > >  |  7880626.833333 usecs/op/cpu
> > >
> > > The benchmark tests inherited breakpoint perf events across many
> > > threads.
> > >
> > > Looking at a perf profile, we can see that the majority of the time is
> > > spent in various hw_breakpoint.c functions, which execute within the
> > > 'nr_bp_mutex' critical sections which then results in contention on that
> > > mutex as well:
> > >
> > >     37.27%  [kernel]       [k] osq_lock
> > >     34.92%  [kernel]       [k] mutex_spin_on_owner
> > >     12.15%  [kernel]       [k] toggle_bp_slot
> > >     11.90%  [kernel]       [k] __reserve_bp_slot
> > >
> > > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > > O(#tasks) due to storing all task breakpoints in the same list and
> > > iterating through that list looking for a matching task. Clearly, this
> > > does not scale to thousands of tasks.
> > >
> > > Instead, make use of the "rhashtable" variant "rhltable" which stores
> > > multiple items with the same key in a list. This results in average
> > > runtime complexity of O(1) for task_bp_pinned().
> > >
> > > With the optimization, the benchmark shows:
> > >
> > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > >  | # Running 'breakpoint/thread' benchmark:
> > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > >  |      Total time: 0.208 [sec]
> > >  |
> > >  |      108.422396 usecs/op
> > >  |     6939.033333 usecs/op/cpu
> > >
> > > On this particular setup that's a speedup of ~1135x.
> > >
> > > While one option would be to make task_struct a breakpoint list node,
> > > this would only further bloat task_struct for infrequently used data.
> > > Furthermore, after all optimizations in this series, there's no evidence
> > > it would result in better performance: later optimizations make the time
> > > spent looking up entries in the hash table negligible (we'll reach the
> > > theoretical ideal performance i.e. no constraints).
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > v2:
> > > * Commit message tweaks.
> > > ---
> > >  include/linux/perf_event.h    |  3 +-
> > >  kernel/events/hw_breakpoint.c | 56 ++++++++++++++++++++++-------------
> > >  2 files changed, 37 insertions(+), 22 deletions(-)
> > >
> > > diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> > > index 01231f1d976c..e27360436dc6 100644
> > > --- a/include/linux/perf_event.h
> > > +++ b/include/linux/perf_event.h
> > > @@ -36,6 +36,7 @@ struct perf_guest_info_callbacks {
> > >  };
> > >
> > >  #ifdef CONFIG_HAVE_HW_BREAKPOINT
> > > +#include <linux/rhashtable-types.h>
> > >  #include <asm/hw_breakpoint.h>
> > >  #endif
> > >
> > > @@ -178,7 +179,7 @@ struct hw_perf_event {
> > >                          * creation and event initalization.
> > >                          */
> > >                         struct arch_hw_breakpoint       info;
> > > -                       struct list_head                bp_list;
> > > +                       struct rhlist_head              bp_list;
> > >                 };
> > >  #endif
> > >                 struct { /* amd_iommu */
> > > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > > index 1b013968b395..add1b9c59631 100644
> > > --- a/kernel/events/hw_breakpoint.c
> > > +++ b/kernel/events/hw_breakpoint.c
> > > @@ -26,10 +26,10 @@
> > >  #include <linux/irqflags.h>
> > >  #include <linux/kdebug.h>
> > >  #include <linux/kernel.h>
> > > -#include <linux/list.h>
> > >  #include <linux/mutex.h>
> > >  #include <linux/notifier.h>
> > >  #include <linux/percpu.h>
> > > +#include <linux/rhashtable.h>
> > >  #include <linux/sched.h>
> > >  #include <linux/slab.h>
> > >
> > > @@ -54,7 +54,13 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
> > >  }
> > >
> > >  /* Keep track of the breakpoints attached to tasks */
> > > -static LIST_HEAD(bp_task_head);
> > > +static struct rhltable task_bps_ht;
> > > +static const struct rhashtable_params task_bps_ht_params = {
> > > +       .head_offset = offsetof(struct hw_perf_event, bp_list),
> > > +       .key_offset = offsetof(struct hw_perf_event, target),
> > > +       .key_len = sizeof_field(struct hw_perf_event, target),
> > > +       .automatic_shrinking = true,
> > > +};
> > >
> > >  static int constraints_initialized;
> > >
> > > @@ -103,17 +109,23 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
> > >   */
> > >  static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
> > >  {
> > > -       struct task_struct *tsk = bp->hw.target;
> > > +       struct rhlist_head *head, *pos;
> > >         struct perf_event *iter;
> > >         int count = 0;
> > >
> > > -       list_for_each_entry(iter, &bp_task_head, hw.bp_list) {
> > > -               if (iter->hw.target == tsk &&
> > > -                   find_slot_idx(iter->attr.bp_type) == type &&
> > > +       rcu_read_lock();
> > > +       head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
> > > +       if (!head)
> > > +               goto out;
> > > +
> > > +       rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
> > > +               if (find_slot_idx(iter->attr.bp_type) == type &&
> > >                     (iter->cpu < 0 || cpu == iter->cpu))
> > >                         count += hw_breakpoint_weight(iter);
> > >         }
> > >
> > > +out:
> > > +       rcu_read_unlock();
> > >         return count;
> > >  }
> > >
> > > @@ -186,7 +198,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
> > >  /*
> > >   * Add/remove the given breakpoint in our constraint table
> > >   */
> > > -static void
> > > +static int
> > >  toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> > >                int weight)
> > >  {
> > > @@ -199,7 +211,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> > >         /* Pinned counter cpu profiling */
> > >         if (!bp->hw.target) {
> > >                 get_bp_info(bp->cpu, type)->cpu_pinned += weight;
> > > -               return;
> > > +               return 0;
> > >         }
> > >
> > >         /* Pinned counter task profiling */
> > > @@ -207,9 +219,9 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> > >                 toggle_bp_task_slot(bp, cpu, type, weight);
> > >
> > >         if (enable)
> > > -               list_add_tail(&bp->hw.bp_list, &bp_task_head);
> > > +               return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> > >         else
> > > -               list_del(&bp->hw.bp_list);
> > > +               return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> > >  }
> > >
> > >  __weak int arch_reserve_bp_slot(struct perf_event *bp)
> > > @@ -307,9 +319,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
> > >         if (ret)
> > >                 return ret;
> > >
> > > -       toggle_bp_slot(bp, true, type, weight);
> > > -
> > > -       return 0;
> > > +       return toggle_bp_slot(bp, true, type, weight);
> > >  }
> > >
> > >  int reserve_bp_slot(struct perf_event *bp)
> > > @@ -334,7 +344,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
> > >
> > >         type = find_slot_idx(bp_type);
> > >         weight = hw_breakpoint_weight(bp);
> > > -       toggle_bp_slot(bp, false, type, weight);
> > > +       WARN_ON(toggle_bp_slot(bp, false, type, weight));
> > >  }
> > >
> > >  void release_bp_slot(struct perf_event *bp)
> > > @@ -678,7 +688,7 @@ static struct pmu perf_breakpoint = {
> > >  int __init init_hw_breakpoint(void)
> > >  {
> > >         int cpu, err_cpu;
> > > -       int i;
> > > +       int i, ret;
> > >
> > >         for (i = 0; i < TYPE_MAX; i++)
> > >                 nr_slots[i] = hw_breakpoint_slots(i);
> > > @@ -689,18 +699,24 @@ int __init init_hw_breakpoint(void)
> > >
> > >                         info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
> > >                                                         GFP_KERNEL);
> > > -                       if (!info->tsk_pinned)
> > > -                               goto err_alloc;
> > > +                       if (!info->tsk_pinned) {
> > > +                               ret = -ENOMEM;
> > > +                               goto err;
> > > +                       }
> > >                 }
> > >         }
> > >
> > > +       ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
> > > +       if (ret)
> > > +               goto err;
> > > +
> > >         constraints_initialized = 1;
> > >
> > >         perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
> > >
> > >         return register_die_notifier(&hw_breakpoint_exceptions_nb);
> >
> > It seems there is a latent bug here:
> > if register_die_notifier() fails we also need to execute the err: label code.
>
> I think we should ignore it, because it's just a notifier when the
> kernel dies. I'd rather have working breakpoints (which we have if we
> made it to this point) when the kernel is live, and sacrifice some bad
> behaviour when the kernel dies.

I don't have a strong opinion either way. If ignoring such functions
is acceptable practice, it sounds fine.

> > Otherwise the patch looks good.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYQibtAk0y%3DSVTSp27Ythjk4c1jCV2_BNAL5Uiw-fMo_w%40mail.gmail.com.
