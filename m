Return-Path: <kasan-dev+bncBCMIZB7QWENRBTEWRSKQMGQEWN3WYSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DD21546131
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 11:13:49 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id f32-20020a0565123b2000b004791bf1af10sf9491658lfv.1
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 02:13:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654852429; cv=pass;
        d=google.com; s=arc-20160816;
        b=bBeIl9gHfL5WAWCsQT645M8qTrf2zb1vYqEEyjSMtGEH2HcZpM4qXYSsBly6xO5WKj
         E3SaAX8NVHUvt9KTg+rorXqfP8Kw4YTLLFc6CJEH0Q4fH9B0RRrTDEqfWQDMM4dMOje9
         MZK2Vmj53kM+jcaq5ppO9rKlsp8vTdSV5Ab8w/RsY7fzZ/LMuii4QMPn7rTvQrCyaDKH
         p3vRSVaa8Q5gAFiO/BpulSPMbVf7q0+zvyoADxUZM0IgouLiBSp1coOFYQyNhm0/tBRj
         mRHVOmnA/IOO/XmKSd8klYk1V20t4ygVgR8g7HXU37Go1D1J8/ZSTTkQVTiUyHgRrvqb
         cBVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TnHlDBEYYuC4mH2nycyJwfbj3SAiWiRVM4X0Q3C4hhA=;
        b=uTtrDBCYIiCBWrI4GlOLZ4GmLS/mqKXj8e5+CUWIUWwMo2tUD0/8WS5eFCXDiK43t0
         QOXj/e7JPCXvskmK3iam2fAaX3KTk0btUpGD8tINADUsHT1wSwbGS5Kr2UOAy0FnJvv2
         lDjnQSgnZWMLd3i4C6Z39KdWGfSpo9zDP9t61fyFJSY/AUvnwZRf3lQjjIgPO86vboBa
         b4jZ+T5d/F33Ml2vF8/Fssonwl8HPnvSd4Ua+2EbLNv9GMEQzEw1BZB7Jeb2UQ8fZGes
         PniFVDCCF+SWlgGcnpSHJalGxdlR+5dUBvRHI68lrUL9qGgJtlivq+D6rz7y7jufaH5g
         QlLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NI1xIb4p;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TnHlDBEYYuC4mH2nycyJwfbj3SAiWiRVM4X0Q3C4hhA=;
        b=acU/ci6inwBeuAXFdEnWP2xyRUrUdzHGGz3Xr9VbxnN8c2c9AKkIW9yF50ZnfDOLMf
         V/oC2ux2aAW0GsJrh2I+D+jaHhhA75YBRZsTZhurhZxM4r2WZUncwbR1dZJ1XysMUPct
         BZuWgAZnJeCNceTnHB8SaEUWi0P/CYYQrplvf8zM+vqYjt5NcbTatBPGfuXYYciIJpn9
         eiph7Pw1Rwmq+UYmv/UCTqadk+mOqS4wesBRqBV880VcxqpU+S06/EeNMdWRKZ3eWJ6d
         SZmBHU78dTjkA5bhi/qmBLjkdEXoBBBwB+B9HHTv6KGoF/f+7uUHEhsW5vFDVkklEe7E
         8L5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TnHlDBEYYuC4mH2nycyJwfbj3SAiWiRVM4X0Q3C4hhA=;
        b=rOYCmU2fc7KwdFkNB5Bb5txYOUVpWf/vWa2UAn5cK6S/HoT1QaVucY4KIuMdoXuWuN
         U7POligBscW08WkUIugycHUimhfxYoHK3PT1QOoEm6vXGJwVR0j1QEpsqguk1qYcEEbP
         z/e2EP8joUQVw3YcZY38kbiLFRImAGdd3rNny4usjxo6zBsT30wSTkGTBq9RN+GuL026
         uZAPEyeVusrHIvtO8wcqhdjcRT/tuDV/NeA4AzY3q6d+2rGvGsPNkRZ2f98lTbQf9JcB
         gDEPRpsbcKlNyirXSk1+wqEeslIeAcB2CHdBIwSFy8Gu6Dhmqy1S0Arm0VAVsCv7Tgn7
         jpOA==
X-Gm-Message-State: AOAM530ZXMOmzh40MRx4DGSTaThcmoz8/7v1nV1l/wRSqgFfmagl8WoR
	0HE0L9bIFd5RxcMgmQ+fM9o=
X-Google-Smtp-Source: ABdhPJwxTSFnuPhfbUKCceT8+CJIx5AUO+Agt9J4b/dqqLusbtIE+qLTd8E9JSxw11+7SE0tVwsWeA==
X-Received: by 2002:a05:6512:13a4:b0:477:a28a:2280 with SMTP id p36-20020a05651213a400b00477a28a2280mr77307484lfa.689.1654852428763;
        Fri, 10 Jun 2022 02:13:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b95:b0:479:6748:7081 with SMTP id
 b21-20020a0565120b9500b0047967487081ls329324lfv.3.gmail; Fri, 10 Jun 2022
 02:13:47 -0700 (PDT)
X-Received: by 2002:a19:f61a:0:b0:479:9c8:69b0 with SMTP id x26-20020a19f61a000000b0047909c869b0mr27168642lfe.140.1654852427495;
        Fri, 10 Jun 2022 02:13:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654852427; cv=none;
        d=google.com; s=arc-20160816;
        b=kzzk0wQJQIpCUSg1hPxZCBCwPiqSEcjaKl5UtVbwi5mToocjcTtACb3zpzcUscNUcd
         cPhfcgwb1t0TDA63ND5aZDrDNGehTpPTXkCYAFzJqezYnhKkRjOQjnNi0DnFbxVBWeaJ
         2PBCvCrMcC0Y2Nqb7WzSecQ6x+WH+IsZ8r5lGFNg4oyit086UyfsR8+9xP07sA6UNHug
         B4G1atJ/eArzmM0nvE7tK59igNRyfD9bjdG1aTnQIARnNYZogmen5J8m9rHtqc5o0fQb
         9uLmPb8wpqY0redE5/KbcbS+8N0HlR0lXgT+TwD1rHA2LwrxA1QPzeSoI+2eS/6yKX/0
         MOwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6VipGKvXmUzgI6wJOysxL1F9dkG1/NuBz0MgOH/2bwo=;
        b=LADJ8VC4Pwj2hrPiDCyZJ4UJjTG0Oy1mV/MkFWPCURaHmJ6sfmRBTU/92Fs7QyF9Qt
         l7tX+uv2IVbVkYTf1f4gvJc0dpX9OjGh5RUxNrwDIpWb9JjZEbwaTPelHIcB9K7dV3iH
         5KKeQhcbmlorCURjMblYo6rOIp5AFZWmjLDUEnSxrZPQ2QuxAX1BEbO/iiz4rRjsQFNn
         Ew3OzMi2gXnXOWymR506uoNiaMrlYNccoUyPHos/pK2b2anq7h7rfqJ91GGvJXg0Su8B
         LJfPSaWSAA6QjIviG4r+hThXJ/06odYpk4KgcocEpuAU0W1IVIkAAUVht7PxrDZSblu6
         PrRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NI1xIb4p;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id x24-20020a056512131800b004786caccd4esi1373433lfu.4.2022.06.10.02.13.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jun 2022 02:13:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id c2so22433002lfk.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Jun 2022 02:13:47 -0700 (PDT)
X-Received: by 2002:a05:6512:1588:b0:477:a556:4ab2 with SMTP id
 bp8-20020a056512158800b00477a5564ab2mr27214759lfb.376.1654852426922; Fri, 10
 Jun 2022 02:13:46 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-8-elver@google.com>
 <CACT4Y+bGPLampPm7JHJeXeK_CwQ2_=3mRktPCh7T9r3y8r02hw@mail.gmail.com> <CANpmjNNwOOYxOXLixrUD25YoszYcy7SRwXMMfrj5zZvrETkp0g@mail.gmail.com>
In-Reply-To: <CANpmjNNwOOYxOXLixrUD25YoszYcy7SRwXMMfrj5zZvrETkp0g@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jun 2022 11:13:35 +0200
Message-ID: <CACT4Y+aJkk6BPYTT6abbem5Fx+9REuWDh8vjqg2HMSLr0MwAVg@mail.gmail.com>
Subject: Re: [PATCH 7/8] perf/hw_breakpoint: Optimize task_bp_pinned() if CPU-independent
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NI1xIb4p;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d
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

On Fri, 10 Jun 2022 at 10:25, Marco Elver <elver@google.com> wrote:
>
> On Thu, 9 Jun 2022 at 17:00, 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
> > >
> > > Running the perf benchmark with (note: more aggressive parameters vs.
> > > preceding changes, but same host with 256 CPUs):
> > >
> > >  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
> > >  | # Running 'breakpoint/thread' benchmark:
> > >  | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
> > >  |      Total time: 1.953 [sec]
> > >  |
> > >  |       38.146289 usecs/op
> > >  |     4882.725000 usecs/op/cpu
> > >
> > >     16.29%  [kernel]       [k] rhashtable_jhash2
> > >     16.19%  [kernel]       [k] osq_lock
> > >     14.22%  [kernel]       [k] queued_spin_lock_slowpath
> > >      8.58%  [kernel]       [k] task_bp_pinned
> > >      8.30%  [kernel]       [k] mutex_spin_on_owner
> > >      4.03%  [kernel]       [k] smp_cfm_core_cond
> > >      2.97%  [kernel]       [k] toggle_bp_slot
> > >      2.94%  [kernel]       [k] bcmp
> > >
> > > We can see that a majority of the time is now spent hashing task
> > > pointers to index into task_bps_ht in task_bp_pinned().
> > >
> > > However, if task_bp_pinned()'s computation is independent of any CPU,
> > > i.e. always `iter->cpu < 0`, the result for each invocation will be
> > > identical. With increasing CPU-count, this problem worsens.
> > >
> > > Instead, identify if every call to task_bp_pinned() is CPU-independent,
> > > and cache the result. Use the cached result instead of a call to
> > > task_bp_pinned(), now __task_bp_pinned(), with task_bp_pinned() deciding
> > > if the cached result can be used.
> > >
> > > After this optimization:
> > >
> > >     21.96%  [kernel]       [k] queued_spin_lock_slowpath
> > >     16.39%  [kernel]       [k] osq_lock
> > >      9.82%  [kernel]       [k] toggle_bp_slot
> > >      9.81%  [kernel]       [k] find_next_bit
> > >      4.93%  [kernel]       [k] mutex_spin_on_owner
> > >      4.71%  [kernel]       [k] smp_cfm_core_cond
> > >      4.30%  [kernel]       [k] __reserve_bp_slot
> > >      2.65%  [kernel]       [k] cpumask_next
> > >
> > > Showing that the time spent hashing keys has become insignificant.
> > >
> > > With the given benchmark parameters, however, we see no statistically
> > > significant improvement in performance on the test system with 256 CPUs.
> > > This is very likely due to the benchmark parameters being too aggressive
> > > and contention elsewhere becoming dominant.
> > >
> > > Indeed, when using the less aggressive parameters from the preceding
> > > changes, we now observe:
> > >
> > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > >  | # Running 'breakpoint/thread' benchmark:
> > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > >  |      Total time: 0.071 [sec]
> > >  |
> > >  |       37.134896 usecs/op
> > >  |     2376.633333 usecs/op/cpu
> > >
> > > Which is an improvement of 12% compared to without this optimization
> > > (baseline is 42 usecs/op). This is now only 5% slower than the
> > > theoretical ideal (constraints disabled), and 18% slower than no
> > > breakpoints at all.
> > >
> > > [ While we're here, swap task_bp_pinned()'s bp and cpu arguments to be
> > >   more consistent with other functions (which have bp first, before the
> > >   cpu argument). ]
> >
> > There are 3 main cases:
> > 1. Per-cpu bp.
>
> Yes, CPU-target breakpoint on just 1 CPU.
>
> > 2. Per-task and per-cpu bp.
>
> Task-target breakpoint but pinned to 1 CPU.
>
> > 3. Per-task bp (on all cpus)
>
> Task-target breakpoint that can run on all CPUs.
>
> > right?
> >
> > For case 1 we still seem to do lots of unnecessary work in
> > fetch_bp_busy_slots() by iterating over all CPUs. We are going to bump
> > only the CPU's cpu_pinned, so that's the only CPU we need to
> > fetch/check.
>
> It'll just do 1 iteration, because cpumask_of_bp() will return a mask
> with just the event's target CPU in it.

You are right. I missed the use of cpumask_of_bp().

> > For case 2 we also do lots of unnecessary work, again we also need to
> > check only 1 CPU (don't need cached_tbp_pinned). Also don't need to do
> > atomic_dec/inc on all other CPUs (they dec/inc the same variable).
>
> Same as above, just 1 iteration because cpumask_of_bp() does the right
> thing. cached_tbp_pinned may still be used if all existing task
> breakpoints are CPU-independent (i.e. cpu==-1; granted, doing
> task_bp_pinned() once or twice probably is irrelevant in this case).
>
> > Case 3 is the only one when we need to check all CPUs and
> > cached_tbp_pinned may be useful.
> > But I wonder if we could instead add a per-task
> > has_per_cpu_breakpoints flag. Then if the flag is set, we check all
> > CPUs as we do now (don't need cached_tbp_pinned). And if it's not set,
> > then we could optimize the code even more by making it O(1) instead of
> > O(N).
>
> > Namely, we add global tsk_pinned for tasks that don't have
> > per-cpu breakpoints, and we update only that tsk_pinned instead of
> > iterating over all CPUs.
>
> That seems reasonable.
>
> > I think this will require adding cpu_pinned as well (similar to
> > tsk_pinned but aggregated over all CPUs).
>
> > Then the fast path capacity check can become just:
> >
> > if (bp->hw.target && !bp->hw.target->has_per_cpu_breakpoints && bp->cpu < 0) {
> >   if (max_cpu_bp_pinned(type) + task_bp_pinned(-1 /*cpu*/, bp, type) +
> > hw_breakpoint_weight(bp) > nr_slots[type])
> >     return -ENOSPC;
> > }
> >
> > Does it make any sense?
>
> Yes, I think this might work. I'll see if I can make it work.

Actually!
This is somewhat orthogonal to the optimizations you are doing, but
the most interesting case for us is inherited events. And it seems
that an inherited event can't possibly overflow the capacity.
Inherited events are a subset of the parent events and all parent
events have already passed validation and the child can't have its own
new events when inherited events are created.
So couldn't we somehow detect that reserve_bp_slot() is called from
inherit_event() and skip fetch_bp_busy_slots() altogether? Maybe that
can be detected by looking at bp->attr.inherit and presence of parent
context? Capacity validation may be kept as a debug-only check.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaJkk6BPYTT6abbem5Fx%2B9REuWDh8vjqg2HMSLr0MwAVg%40mail.gmail.com.
