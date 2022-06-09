Return-Path: <kasan-dev+bncBCMIZB7QWENRBFEWRCKQMGQE4DJNF6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E209154500B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 17:00:36 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id i26-20020a0565123e1a00b004792c615104sf6766995lfv.12
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 08:00:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654786836; cv=pass;
        d=google.com; s=arc-20160816;
        b=aPTCkT8BRuyU9LKGS1wQ2+R1OJ+UUudpz10zWoMbElOuMNM9Lyf94QGyEXYbk7trZM
         MPP+Lcxl2+yhtdMhZ5/scdlc+dnf39OjlSMeuZm3de1vJSD0mvCjq2MxNsG4nDhONDGU
         wfzQtxg7nR8qDgRAYoyC4POKOdaxnG2eiw+n5aMv4Na0G65rBTrOHCEsDgBMQKbA8JXc
         f4yv5Xj0GrkjCXVvpgmAJWUokEK4bfckYqNEegJYk70XESJa7eTvy/hdkBk5v/ha++nY
         SzwkZas2uyFS6IYC09Whilh/RQZtwl+CaTMr2VZpzFU6UrfwIodHma9qk3mFH/rTZLj4
         TJtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=48J2gxTQ5vUr7xFgEaNcNSuZH8KrmJgzn3P2gDiDtvA=;
        b=Kb8HyzGTWa7qf8SlUUyFNyWKcQ1M3JIx2F7wrNmuNiaIba4t5Adwsb6Z7xsC0hYD18
         a7NsXnM77ceCGrCcZY0jCTEI+OM5Oh0n1vIB1yiTaoFx6xoCQK9dwKTJRWAXOZDzCjIU
         WYTFbMIJ0DkITw/+gy4Ik94bsG9th8fPn9mjWiPOJMRCxqZYOfl3egiGfJEitGTO3hSQ
         F/wwdCdxNj9YYi21NTgIEY/NuvsUdFCRKhmk5ky+sf158mXCYL+wvp1WlZdHiZSZP+bw
         w+y0F4Lp+aKj2grbMzRks91xX5F364qkTCJqVOmJG5xDQuGtWHGVyzxT1prelH2lYvEE
         tb/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kICnwHg+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=48J2gxTQ5vUr7xFgEaNcNSuZH8KrmJgzn3P2gDiDtvA=;
        b=dBSZRd1oO46VWMhrZvytUWwFWe6+0obOAn/LnSyCw0pbeqSaeGWAs2ONlGoQuPLIUq
         KQIBHQuzSp6pDQI9gKaeHLE8VxSpDEfhDyKIrOG8rnPgIGLvnhWwK+f3ZzLp+pCymUHA
         84LloVbfDzZaOSzd+UeOOewHTTWZTAZw8gH5UQ/JiOghF1nL3YL/HytaVQ0CnGU2FAdR
         ulQaN+UUyLBNZslCNTJFr+UNMR9XBoUPZriSQjf+kfIp8vrwzOwgDvEJ62rW/7F6zuAx
         zeB5+RfhBGJHIG0zU2irTFllgJZ3IuzH6qXL3PXJ/V89KV+gelLY0Iw2roY1/ZQ7TmTw
         kc4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=48J2gxTQ5vUr7xFgEaNcNSuZH8KrmJgzn3P2gDiDtvA=;
        b=c7fR0uUIJ0on3jTyOGE6L9JC5Q1t5A4uA9PoZobfHMpHseg/tGww5TQncSXPDj3YNO
         QIK0kD3RCZXhqqNoiy80215lP6xEZqn17tzDKwHMwZQSCiPUTUzK1QFjniCR+j1rSK/K
         spoxb3w1rZHz4Yl9RYo8IeTZVHT+u2opUzdtadpbM23N3Gd/CdpYqWQbhsWJ9P7rqQX8
         B6euoT7GlovKKyXD/M+fHjNqm2kgn8BGS1oyHyc2yyxIhCBJ+jiIkP4O+iKARWXPudqo
         OxyzTSdR+o7kf8JYqEcl/jHcyBVxIGd12rBVk/w6+wesF8Ysq84fOPELM5C5AwAg604n
         Msow==
X-Gm-Message-State: AOAM5326L5YHf+N2UBDz1uYxfK9heX3cPuH7VIHdthB1X7IISIVgBPJQ
	L7+MOghLA311HxxztNBDxZk=
X-Google-Smtp-Source: ABdhPJz0Jkx10h+nsFozPLixd3h9TXgeWslN2QD4+of4x8hvNctkCtmEQT+sICkzGg8YVAG8+m/adw==
X-Received: by 2002:a19:6407:0:b0:479:3fd4:6a02 with SMTP id y7-20020a196407000000b004793fd46a02mr14324960lfb.116.1654786836323;
        Thu, 09 Jun 2022 08:00:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc24:0:b0:256:c8db:bc69 with SMTP id b36-20020a2ebc24000000b00256c8dbbc69ls807753ljf.6.gmail;
 Thu, 09 Jun 2022 08:00:35 -0700 (PDT)
X-Received: by 2002:a05:651c:1501:b0:255:9588:98a6 with SMTP id e1-20020a05651c150100b00255958898a6mr12226159ljf.306.1654786835110;
        Thu, 09 Jun 2022 08:00:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654786835; cv=none;
        d=google.com; s=arc-20160816;
        b=08P1oB9madqpHashteXR0uxgKin6Bx3aH5XmPm7WI4Xl5kyugWkvuWNWlv4OGJ2ymw
         LVQPg/f5qjkXB1NJ3cdS/THHErVNdWjwmN0Q2joMm+lk5xRFSqOOaWAcH07pZ7uRJ220
         Y1CFA0I1pGCEYuyleKyVg74lcK5DoAKhFYwb//dt/JyX0qI8y6sE7gxKKmp0mUoBBG1s
         RSzxyPzrV0kyX6NZD6EAdqNbijLrASeFt8l7Ot42nLLHn71taJb3EJew490gK3jwVkhU
         YVdU/CJ2+RJ6UAsjDSjX8AHadSstuDrmairzLHA2DFmjhe0+eG3ZqomuwmXmVhYeQB7M
         tDlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NsfmNOfUlC+V3z4AhfvGEnurL/kWR5dN7NT7SPzXTek=;
        b=mt7a5asPNZKHzt5xmrwZjDyI801ADPFx1ft0lhd6RI6/pqsI3YSngdSzrmSlNctKKn
         wpwtrLyBfGB0exTDPv+RlpKA32C3DZUj5Q3suKR8tHL04IgQ1saxzXsTGX/54hK1N6NS
         Tqblej0V28cFiRilRgdn7MqILirvsAmPc1JPWIuXG6pAXdrcyJKgb4C0e3A2OQGD9k9P
         fRcAP4tdfyYEteXymjTf1w+tlU+b3MeoFXOfO1NMlYG2yhFr9vh+wB/R6r05AclY6421
         zzcXt0uN9ED6qOxNdZua2aXlLKZQssyEb4dh68RuLfqrme5J91kpT9yP1XNPG1qa+DBH
         A0uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kICnwHg+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id o3-20020a198c03000000b0047ad98bddbasi232340lfd.0.2022.06.09.08.00.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 08:00:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id be31so38441972lfb.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 08:00:35 -0700 (PDT)
X-Received: by 2002:a05:6512:3f13:b0:464:f55f:7806 with SMTP id
 y19-20020a0565123f1300b00464f55f7806mr25654590lfa.598.1654786834533; Thu, 09
 Jun 2022 08:00:34 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-8-elver@google.com>
In-Reply-To: <20220609113046.780504-8-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 17:00:22 +0200
Message-ID: <CACT4Y+bGPLampPm7JHJeXeK_CwQ2_=3mRktPCh7T9r3y8r02hw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=kICnwHg+;       spf=pass
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

On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
>
> Running the perf benchmark with (note: more aggressive parameters vs.
> preceding changes, but same host with 256 CPUs):
>
>  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
>  |      Total time: 1.953 [sec]
>  |
>  |       38.146289 usecs/op
>  |     4882.725000 usecs/op/cpu
>
>     16.29%  [kernel]       [k] rhashtable_jhash2
>     16.19%  [kernel]       [k] osq_lock
>     14.22%  [kernel]       [k] queued_spin_lock_slowpath
>      8.58%  [kernel]       [k] task_bp_pinned
>      8.30%  [kernel]       [k] mutex_spin_on_owner
>      4.03%  [kernel]       [k] smp_cfm_core_cond
>      2.97%  [kernel]       [k] toggle_bp_slot
>      2.94%  [kernel]       [k] bcmp
>
> We can see that a majority of the time is now spent hashing task
> pointers to index into task_bps_ht in task_bp_pinned().
>
> However, if task_bp_pinned()'s computation is independent of any CPU,
> i.e. always `iter->cpu < 0`, the result for each invocation will be
> identical. With increasing CPU-count, this problem worsens.
>
> Instead, identify if every call to task_bp_pinned() is CPU-independent,
> and cache the result. Use the cached result instead of a call to
> task_bp_pinned(), now __task_bp_pinned(), with task_bp_pinned() deciding
> if the cached result can be used.
>
> After this optimization:
>
>     21.96%  [kernel]       [k] queued_spin_lock_slowpath
>     16.39%  [kernel]       [k] osq_lock
>      9.82%  [kernel]       [k] toggle_bp_slot
>      9.81%  [kernel]       [k] find_next_bit
>      4.93%  [kernel]       [k] mutex_spin_on_owner
>      4.71%  [kernel]       [k] smp_cfm_core_cond
>      4.30%  [kernel]       [k] __reserve_bp_slot
>      2.65%  [kernel]       [k] cpumask_next
>
> Showing that the time spent hashing keys has become insignificant.
>
> With the given benchmark parameters, however, we see no statistically
> significant improvement in performance on the test system with 256 CPUs.
> This is very likely due to the benchmark parameters being too aggressive
> and contention elsewhere becoming dominant.
>
> Indeed, when using the less aggressive parameters from the preceding
> changes, we now observe:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.071 [sec]
>  |
>  |       37.134896 usecs/op
>  |     2376.633333 usecs/op/cpu
>
> Which is an improvement of 12% compared to without this optimization
> (baseline is 42 usecs/op). This is now only 5% slower than the
> theoretical ideal (constraints disabled), and 18% slower than no
> breakpoints at all.
>
> [ While we're here, swap task_bp_pinned()'s bp and cpu arguments to be
>   more consistent with other functions (which have bp first, before the
>   cpu argument). ]

There are 3 main cases:
1. Per-cpu bp.
2. Per-task and per-cpu bp.
3. Per-task bp (on all cpus)
right?

For case 1 we still seem to do lots of unnecessary work in
fetch_bp_busy_slots() by iterating over all CPUs. We are going to bump
only the CPU's cpu_pinned, so that's the only CPU we need to
fetch/check.

For case 2 we also do lots of unnecessary work, again we also need to
check only 1 CPU (don't need cached_tbp_pinned). Also don't need to do
atomic_dec/inc on all other CPUs (they dec/inc the same variable).

Case 3 is the only one when we need to check all CPUs and
cached_tbp_pinned may be useful.
But I wonder if we could instead add a per-task
has_per_cpu_breakpoints flag. Then if the flag is set, we check all
CPUs as we do now (don't need cached_tbp_pinned). And if it's not set,
then we could optimize the code even more by making it O(1) instead of
O(N). Namely, we add global tsk_pinned for tasks that don't have
per-cpu breakpoints, and we update only that tsk_pinned instead of
iterating over all CPUs.
I think this will require adding cpu_pinned as well (similar to
tsk_pinned but aggregated over all CPUs).
Then the fast path capacity check can become just:

if (bp->hw.target && !bp->hw.target->has_per_cpu_breakpoints && bp->cpu < 0) {
  if (max_cpu_bp_pinned(type) + task_bp_pinned(-1 /*cpu*/, bp, type) +
hw_breakpoint_weight(bp) > nr_slots[type])
    return -ENOSPC;
}

Does it make any sense?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbGPLampPm7JHJeXeK_CwQ2_%3D3mRktPCh7T9r3y8r02hw%40mail.gmail.com.
