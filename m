Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAUARSKQMGQENJMGZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BF00545ECF
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 10:25:39 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id x24-20020ab07818000000b00378d73df633sf8273651uaq.10
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 01:25:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654849538; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWYRKrRXj5Os+WMtISe0jMINcioN/pQxamE4WSpdPKpwdhmfD7nkYQZF1SgXE77PrT
         ogtoAqFJhUGRqsA12aRBreIlYZ5sRpAtzDVDWrULFryyZ7HI546UVIoeVfitpiSCZn2q
         Hzpreb8eZZg4xuAXeHfPjU8G28E1ASBlhbf2XIPWQe6CkBswdHn8WN1XHsOzVf0sX1vf
         lcFIKV78YVWv0hCWwWoKB9+FfyQTa4ROipXnbcMT9YZYkYbXhTimEQFVw2hRK3C4GBvQ
         DmgEPa6RXX3fh2ZovJiMrdwFfy+kYUoXOzaXxz9dEPy440ONhJM3TSM48eKtxcnbholC
         qlkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PrQtkLQPB2Ots5t8NN8u20jjSK/NwJRq7rZPaPYZDok=;
        b=DdvEf+BSilfpSoW6cjvqS6lsgrVBY5aj+TtcZGK+UYBElMdHuQPlUSNtFc46m7tboy
         3z9p99SCuXy2B2X09ssAApv1Nd40Y+OqZXoGcQ+g89Az8WkDc/enARwYU0KcTQCBmDVk
         CgbpBvIMdSwuwq8Fuk7bTDCv1MZ8+o9755zMKq56SBpfsrkWadJNDRyn4whQoKfLd1D1
         /nOZ3UjphgAVmnnpRGKEDB/HX0YRMjaPDj+gvXK+xoQnTqcSaCsn/qZYAKeFEDIVzxXC
         32gaxN7ErYnTbgSmY127brFB0VBM+LW+b4OwPPrbBxvjKuw6QdbC44FbCcVPHQ7u/gmF
         jptQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qYH3eZm3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PrQtkLQPB2Ots5t8NN8u20jjSK/NwJRq7rZPaPYZDok=;
        b=npz6xsJDcndEFE6x/cvYx0P5FXGHgHCLHnPVMatLBX5VNoT8uh9bOiayZogl0BTiRQ
         E0qS4POH42jgXeNsTxt652slupQ8ZtK9pAGobVopJ5sZ/d3tQcdXmhfejbpftBsX2euc
         r0HIwvQ8+p03JahC/BzqjsCJvn6hftlCzPkgJb1hpR96bOKljLNZ6i/Z2SxFVDMEgNxg
         5iES/f/xZIX+2qYUkRs0sDcQAaTb47GaVUH0zZXfaLg7osvc38R5udpyI8jWKcFHl+s2
         UAhfrikv9m16WcYYGDoBInl43W9/cPIYUwb167CQZt5eDzt/09aK4wVXTfxhTHFwNYKc
         DcZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PrQtkLQPB2Ots5t8NN8u20jjSK/NwJRq7rZPaPYZDok=;
        b=tdI+TLO4ITTpKQR/2C+aqzlExsE40HDlLZnmwopifFpUdagjj8AHdu15Z3JiAsycxH
         gtm1gR6r9/pNhCuaNTKQuPdxxZsFGGRDQGjNpZuKa28hLq9xOGaqw01P4UrQVGNgAcRX
         wM4rKdebaFd2PKtDOjr7nfVucW8YrlO67IhnpiE5iwGiHCtjMQvytNHOVnp3r4f6VeLp
         xPyH3aPVX/hn/cCDpuf+d+dbOboaVfHgbWpehzF/FQTUZ/WljUh2FRAN6dlrAfrPjBdk
         Mo/k5lysHe9IRkQsdXh0hoQcwApfM3V0UqQhRwx7USBKzD8XTtzAfm8BsKIJYfbUsBC4
         h4SA==
X-Gm-Message-State: AOAM530lWEz4FOpAuZ4bzVuQApPLrnWMWi3MJu+NKRAdTGrq6cLJFACc
	iYgZMKREuwp17I8jZ+WspX0=
X-Google-Smtp-Source: ABdhPJyIv6fgu/xYFo76RMwIaX3NjShoNV/6APCzdpFcHzwuPJfEs1ikVXefJ3YvrBCm6uA5iZycyg==
X-Received: by 2002:a67:67c7:0:b0:34c:82b:93e0 with SMTP id b190-20020a6767c7000000b0034c082b93e0mr4644562vsc.84.1654849538188;
        Fri, 10 Jun 2022 01:25:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1746:0:b0:34b:8aa9:cbe8 with SMTP id 67-20020a671746000000b0034b8aa9cbe8ls1542736vsx.2.gmail;
 Fri, 10 Jun 2022 01:25:37 -0700 (PDT)
X-Received: by 2002:a05:6102:a84:b0:34b:b9a7:f174 with SMTP id n4-20020a0561020a8400b0034bb9a7f174mr11168176vsg.71.1654849537383;
        Fri, 10 Jun 2022 01:25:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654849537; cv=none;
        d=google.com; s=arc-20160816;
        b=Ic93YlD7CJn9Ch0nZ4E+FbLiOM4LP1z7RVCZ3VdMjd0XC16tPRHapIhASl9tVqZwFE
         iWcRXy0ycwlylcZS3pSAY+bqy82udK+K6J6R2pemvYSyflrjjuVti3Gd0z+xK4zkA53y
         TrGgVvgRsGLR6aV0FDR70vv6G5dUh+CZzL4j8xV0bsuHdnWonGELBXoUW7bXg7FFKrLG
         DFQo1qO0+iguFswZKaacGazRCwKu/A9d5iHB8j9KyH/iE34U1lKWZqo1rcKx7x0BLcXQ
         YfgZ9CFtGnK7BIX4HN70brk+W2D0QyTJMF1CVzBUrKf87sHEYY/FbQKDrO17wozuycrZ
         5uzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eLcNDbfanR+9OC/qj3TxYDSuqrtVsDPMKOVV+JQ2Ebk=;
        b=eFkJUsyeHQ4SXdJwvfqMxkkhC7S8PjKIsz3LjaOI0yVov3R5/iUs0ayqqqEFP7+uwp
         2t7YSLwXwVu/1Y1nhQiWmAMNscwfoMiZYCiWdoaDCoA+QXN79LZ3iOe1zlHUOubor0u+
         BapnRJ3rSPIkMzHv25pT32a3YY1QbCqe+Ctl7USjwShdiTIA5G3ndPo7jlHpojxsW5Xi
         HycSfnQKiYP6BuguySqwJbsKS+SYu2iEtFQucbBT61aRj1jOLOd1myR1LCtnysidPAWl
         vDaWQjSGmn1DJiYDNIcdbyi6jTEL51DHBgdOEXP2MCVR4Odvsa/ufJQguLpkH2+tBswZ
         D0Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qYH3eZm3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id r5-20020a05612206a500b0035df1d45071si595639vkq.1.2022.06.10.01.25.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jun 2022 01:25:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id k2so6440392ybj.3
        for <kasan-dev@googlegroups.com>; Fri, 10 Jun 2022 01:25:37 -0700 (PDT)
X-Received: by 2002:a25:d054:0:b0:664:49cb:410 with SMTP id
 h81-20020a25d054000000b0066449cb0410mr4709163ybg.609.1654849536816; Fri, 10
 Jun 2022 01:25:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-8-elver@google.com>
 <CACT4Y+bGPLampPm7JHJeXeK_CwQ2_=3mRktPCh7T9r3y8r02hw@mail.gmail.com>
In-Reply-To: <CACT4Y+bGPLampPm7JHJeXeK_CwQ2_=3mRktPCh7T9r3y8r02hw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jun 2022 10:25:00 +0200
Message-ID: <CANpmjNNwOOYxOXLixrUD25YoszYcy7SRwXMMfrj5zZvrETkp0g@mail.gmail.com>
Subject: Re: [PATCH 7/8] perf/hw_breakpoint: Optimize task_bp_pinned() if CPU-independent
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qYH3eZm3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 9 Jun 2022 at 17:00, 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
> >
> > Running the perf benchmark with (note: more aggressive parameters vs.
> > preceding changes, but same host with 256 CPUs):
> >
> >  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
> >  |      Total time: 1.953 [sec]
> >  |
> >  |       38.146289 usecs/op
> >  |     4882.725000 usecs/op/cpu
> >
> >     16.29%  [kernel]       [k] rhashtable_jhash2
> >     16.19%  [kernel]       [k] osq_lock
> >     14.22%  [kernel]       [k] queued_spin_lock_slowpath
> >      8.58%  [kernel]       [k] task_bp_pinned
> >      8.30%  [kernel]       [k] mutex_spin_on_owner
> >      4.03%  [kernel]       [k] smp_cfm_core_cond
> >      2.97%  [kernel]       [k] toggle_bp_slot
> >      2.94%  [kernel]       [k] bcmp
> >
> > We can see that a majority of the time is now spent hashing task
> > pointers to index into task_bps_ht in task_bp_pinned().
> >
> > However, if task_bp_pinned()'s computation is independent of any CPU,
> > i.e. always `iter->cpu < 0`, the result for each invocation will be
> > identical. With increasing CPU-count, this problem worsens.
> >
> > Instead, identify if every call to task_bp_pinned() is CPU-independent,
> > and cache the result. Use the cached result instead of a call to
> > task_bp_pinned(), now __task_bp_pinned(), with task_bp_pinned() deciding
> > if the cached result can be used.
> >
> > After this optimization:
> >
> >     21.96%  [kernel]       [k] queued_spin_lock_slowpath
> >     16.39%  [kernel]       [k] osq_lock
> >      9.82%  [kernel]       [k] toggle_bp_slot
> >      9.81%  [kernel]       [k] find_next_bit
> >      4.93%  [kernel]       [k] mutex_spin_on_owner
> >      4.71%  [kernel]       [k] smp_cfm_core_cond
> >      4.30%  [kernel]       [k] __reserve_bp_slot
> >      2.65%  [kernel]       [k] cpumask_next
> >
> > Showing that the time spent hashing keys has become insignificant.
> >
> > With the given benchmark parameters, however, we see no statistically
> > significant improvement in performance on the test system with 256 CPUs.
> > This is very likely due to the benchmark parameters being too aggressive
> > and contention elsewhere becoming dominant.
> >
> > Indeed, when using the less aggressive parameters from the preceding
> > changes, we now observe:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> >  |      Total time: 0.071 [sec]
> >  |
> >  |       37.134896 usecs/op
> >  |     2376.633333 usecs/op/cpu
> >
> > Which is an improvement of 12% compared to without this optimization
> > (baseline is 42 usecs/op). This is now only 5% slower than the
> > theoretical ideal (constraints disabled), and 18% slower than no
> > breakpoints at all.
> >
> > [ While we're here, swap task_bp_pinned()'s bp and cpu arguments to be
> >   more consistent with other functions (which have bp first, before the
> >   cpu argument). ]
>
> There are 3 main cases:
> 1. Per-cpu bp.

Yes, CPU-target breakpoint on just 1 CPU.

> 2. Per-task and per-cpu bp.

Task-target breakpoint but pinned to 1 CPU.

> 3. Per-task bp (on all cpus)

Task-target breakpoint that can run on all CPUs.

> right?
>
> For case 1 we still seem to do lots of unnecessary work in
> fetch_bp_busy_slots() by iterating over all CPUs. We are going to bump
> only the CPU's cpu_pinned, so that's the only CPU we need to
> fetch/check.

It'll just do 1 iteration, because cpumask_of_bp() will return a mask
with just the event's target CPU in it.

> For case 2 we also do lots of unnecessary work, again we also need to
> check only 1 CPU (don't need cached_tbp_pinned). Also don't need to do
> atomic_dec/inc on all other CPUs (they dec/inc the same variable).

Same as above, just 1 iteration because cpumask_of_bp() does the right
thing. cached_tbp_pinned may still be used if all existing task
breakpoints are CPU-independent (i.e. cpu==-1; granted, doing
task_bp_pinned() once or twice probably is irrelevant in this case).

> Case 3 is the only one when we need to check all CPUs and
> cached_tbp_pinned may be useful.
> But I wonder if we could instead add a per-task
> has_per_cpu_breakpoints flag. Then if the flag is set, we check all
> CPUs as we do now (don't need cached_tbp_pinned). And if it's not set,
> then we could optimize the code even more by making it O(1) instead of
> O(N).

> Namely, we add global tsk_pinned for tasks that don't have
> per-cpu breakpoints, and we update only that tsk_pinned instead of
> iterating over all CPUs.

That seems reasonable.

> I think this will require adding cpu_pinned as well (similar to
> tsk_pinned but aggregated over all CPUs).

> Then the fast path capacity check can become just:
>
> if (bp->hw.target && !bp->hw.target->has_per_cpu_breakpoints && bp->cpu < 0) {
>   if (max_cpu_bp_pinned(type) + task_bp_pinned(-1 /*cpu*/, bp, type) +
> hw_breakpoint_weight(bp) > nr_slots[type])
>     return -ENOSPC;
> }
>
> Does it make any sense?

Yes, I think this might work. I'll see if I can make it work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNwOOYxOXLixrUD25YoszYcy7SRwXMMfrj5zZvrETkp0g%40mail.gmail.com.
