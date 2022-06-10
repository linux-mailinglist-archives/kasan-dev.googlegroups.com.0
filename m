Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXVBRSKQMGQESD2FUSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id A3EE55462A0
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 11:37:35 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id q200-20020a252ad1000000b006632baa38desf15880003ybq.15
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 02:37:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654853854; cv=pass;
        d=google.com; s=arc-20160816;
        b=JHQFEtNb854ZznnZ4xgvP6zWk4AICv8Zllc1oK8sL5sy6b8LHjA+5lErbsRFGRBKI+
         DHkoYaGppCjc7Ay5EvZ5QXIFVkH1MmagkgLsZ88Daz0qdL1jYLACqsh4Kke+qCnPqnp4
         BE5sGFuFHn/42zypIt9FHCwlGvWONcrd29+n0U2AI+hu99700Iak2kDMWQ/50ImOrBK1
         z1FIWK5mLHDZiwenstHA47Ox+fgucWzOihFScdtSbBgwrLcb7m5GY8snNkYpmWv0lZb7
         ISRfAlo6dT5uD5piGvIo5OXx88oNgbPgKdz6uoX7DCEYW4MesQFMJPzIbahBxt7+O9C5
         w9hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OobC7Jh0OwtCCNxE37SUq23vxvoyrftM6JBTvi20h94=;
        b=AqacxItVV8orTC62EGam7uYrG4PTZcztLnh4ICHldtGacWLvM/SCqX8b40MzmAgKMR
         kybEKaBF/Cl0kxPHlcdKvBG1j7GcC0EnLUZT51cu37l5e0lwkCTHuGzBHxtGNXH73wUM
         13G/d+3WjFxANtsWsnjU2B9tBgad+KDzp2va6RE/hrj1nbvRPLE7Sih4xLHaesd/Kc+1
         DwZwCnSTNxVGDkNBoajYkbRpRk8D3mAwJy3jy/vx8zSJtxXiOoXYQFNHqM56++ICR6nV
         UJzI1cQcbUCB7aerv61iBTB3ai7Ry07oc94XAY4qPIFn9IRhq0yMUp5TZoRp+oEn2whu
         8zrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nO+Vc9Qp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OobC7Jh0OwtCCNxE37SUq23vxvoyrftM6JBTvi20h94=;
        b=edBkgplNYgnVvntuKiOySN6dot3sGEKmu0IhkkJQIRfLaRAiQbW35nnllINv81gwUZ
         VWmzjtpRWPb8QYvMEYa8tZ/PxmQtlRTL39Iv5GyzvqowkVbsoVdj8UC5y8fq7oFzuFiS
         /E0Eea50t22KywkJXxriD/TfZGRt9ZkEUpT1fieIYqS+rP5jRkv6edX53MP/+rlHPqa8
         8osG1EmApGoRifjX/27s4BlCyYlrPSMbVakT4OyJczrJshtY1GeaVkgqJd+jsEzRRSJO
         IYpTs86hpkKDNk+othyggjNLaArjwgbo6OW8P6WVDVGJAeGh2vpy0G4xZNvdReFMADwr
         vm1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OobC7Jh0OwtCCNxE37SUq23vxvoyrftM6JBTvi20h94=;
        b=Wkti5FcRbaX0Z0q1upsRWFl2rVwuKTu8NQi0RIWs8Iph8n9KX/q9HW36J9ycQrZmPP
         40kiIisk2UCh0EC0fHIGCN59255GDBEtQ3X0+OxDz8KrtaHWai+QrksAQNo31dj4El0n
         5bPVj5DerR16yrXCiyDMQi9UH9b8JxQqf/bRhJ1lfK2jxj6eB6CmspCkkQSC/Jn9yz/X
         DLtJo7HB3XxmE15s4r2A11jqxPnixRh7HnyBgIQGVQhAg7dCGr14Cgtl9Z5vOWi0FrzX
         hsWmqvK7f6F/NVz51/gC1bP3Zu9yFgN07H02GyxLn3NtoYCWfECzsdirM7SUKBz0hG7f
         J5BA==
X-Gm-Message-State: AOAM532y3mg4N4sXyvyZcFa9kSB84NehalU1oNubE/LeEcOm8Af4YfiZ
	JulzZNbt869ul+yA1OYQR1g=
X-Google-Smtp-Source: ABdhPJyfBQo6b9j/tFB1JlAFCs4E+n98Sg61qc1es3WA/cSIytrCIcsQh/ey5swA9hu4KKgH9DvsGA==
X-Received: by 2002:a25:a227:0:b0:663:5bea:8954 with SMTP id b36-20020a25a227000000b006635bea8954mr28914900ybi.513.1654853854208;
        Fri, 10 Jun 2022 02:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3d84:0:b0:648:cabd:538f with SMTP id k126-20020a253d84000000b00648cabd538fls5079427yba.3.gmail;
 Fri, 10 Jun 2022 02:37:33 -0700 (PDT)
X-Received: by 2002:a25:5688:0:b0:660:1ffb:78b6 with SMTP id k130-20020a255688000000b006601ffb78b6mr42696929ybb.194.1654853853531;
        Fri, 10 Jun 2022 02:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654853853; cv=none;
        d=google.com; s=arc-20160816;
        b=mIHO/yxh2Yx1TzFBN76672sKguDBTgFupOlOzHmXlCc05y/KyvGP22rdvgxIK2SfK3
         ZFS5ekpTjeGmgvphQ8fOC1qHi3MHCUkkCufSfKJCcl7fCmeR444WPVkuA6pIvCnO2h1u
         86Jdu1YLG3+iz83CF00TAQ27tNJWxbJoLXSDN2ziwkibF+Ee3iUChKa4lp0u1OwewlG3
         Idcq+HR93eZVKXjzBqKbVVFzn2yc5UnXkRQd9S8pj8LSfKPoyIBl9Tn4PappIsUCmrHF
         enucXoZ2FrJTBnDbmSwKE/4hKR5aFHuFf64a8vHSbBEJ10DAFfSY2z3BsQuB7f5chdsN
         uSqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R0yCkjQP9dSep6/xo5aErRNWl4SfOJuW2ssFAWrT83k=;
        b=CARZhNpSmDLjQfxNRshHJwNrGX7GlTpW6WXGRZAY34ubPjNSE8nqZYuYcBfECCzd+V
         SbgPKaDtb30OLoIlEdR3u0iiE1k5c9zyv/IEiiUd5K87kyjXEm02BOnmGxcBTv+BG1pR
         lxUtqXAVcIWN8K19eJ9ZxzMZWoItrPhYAR8Nz8+vedD1T4VqrKtH4Rv1L4ypkk2VgO0A
         I3jUy1jSiYZTyYxtUE9wrUrPyzpLyXmwPTorJ+X4dzpTyWktFGUzNLmxwQyHVfpT4Z0r
         SdSHj2DCx1kvIgP4Lw1SBd9Drz91rBwesNPjYq2Pm5yZjDuY+3YDkG5DrtDShb5CbUeO
         O53w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nO+Vc9Qp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id w192-20020a25dfc9000000b00663e34089d0si869964ybg.4.2022.06.10.02.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jun 2022 02:37:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id r3so11919702ybr.6
        for <kasan-dev@googlegroups.com>; Fri, 10 Jun 2022 02:37:33 -0700 (PDT)
X-Received: by 2002:a5b:49:0:b0:656:151d:a1e3 with SMTP id e9-20020a5b0049000000b00656151da1e3mr12972356ybp.425.1654853853082;
 Fri, 10 Jun 2022 02:37:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
 <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com>
 <CANpmjNNtV_6kgoLv=VX3z_oM6ZEvWJNAOj9z4ADcymqmhc+crw@mail.gmail.com>
 <CACT4Y+Zq-1nczM2JH7Sr4mZo84gsCRd83RAwwnHwmap-wCOLTQ@mail.gmail.com>
 <CANpmjNNC7ry59OXsJrPMf56Xi63chexaDfnP4t8_4MG7S5ZgCg@mail.gmail.com> <CACT4Y+ZyrWuZxqpO_fKBjdXbTY-GJu6M7GARVk7YQnyv790mFw@mail.gmail.com>
In-Reply-To: <CACT4Y+ZyrWuZxqpO_fKBjdXbTY-GJu6M7GARVk7YQnyv790mFw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jun 2022 11:36:56 +0200
Message-ID: <CANpmjNNyyFuozLmqyuQ3u1LLjc4-1STq5EyV9=WHhyc2Z9OUEQ@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b=nO+Vc9Qp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Fri, 10 Jun 2022 at 11:04, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, 9 Jun 2022 at 20:37, Marco Elver <elver@google.com> wrote:
> > > /On Thu, 9 Jun 2022 at 16:56, Marco Elver <elver@google.com> wrote:
> > > > > > On a machine with 256 CPUs, running the recently added perf breakpoint
> > > > > > benchmark results in:
> > > > > >
> > > > > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > > > > >  | # Running 'breakpoint/thread' benchmark:
> > > > > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > > > > >  |      Total time: 236.418 [sec]
> > > > > >  |
> > > > > >  |   123134.794271 usecs/op
> > > > > >  |  7880626.833333 usecs/op/cpu
> > > > > >
> > > > > > The benchmark tests inherited breakpoint perf events across many
> > > > > > threads.
> > > > > >
> > > > > > Looking at a perf profile, we can see that the majority of the time is
> > > > > > spent in various hw_breakpoint.c functions, which execute within the
> > > > > > 'nr_bp_mutex' critical sections which then results in contention on that
> > > > > > mutex as well:
> > > > > >
> > > > > >     37.27%  [kernel]       [k] osq_lock
> > > > > >     34.92%  [kernel]       [k] mutex_spin_on_owner
> > > > > >     12.15%  [kernel]       [k] toggle_bp_slot
> > > > > >     11.90%  [kernel]       [k] __reserve_bp_slot
> > > > > >
> > > > > > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > > > > > O(#tasks) due to storing all task breakpoints in the same list and
> > > > > > iterating through that list looking for a matching task. Clearly, this
> > > > > > does not scale to thousands of tasks.
> > > > > >
> > > > > > While one option would be to make task_struct a breakpoint list node,
> > > > > > this would only further bloat task_struct for infrequently used data.
> > > > >
> > > > > task_struct already has:
> > > > >
> > > > > #ifdef CONFIG_PERF_EVENTS
> > > > >   struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
> > > > >   struct mutex perf_event_mutex;
> > > > >   struct list_head perf_event_list;
> > > > > #endif
> > > > >
> > > > > Wonder if it's possible to use perf_event_mutex instead of the task_sharded_mtx?
> > > > > And possibly perf_event_list instead of task_bps_ht? It will contain
> > > > > other perf_event types, so we will need to test type as well, but on
> > > > > the positive side, we don't need any management of the separate
> > > > > container.
> > > >
> > > > Hmm, yes, I looked at that but then decided against messing the
> > > > perf/core internals. The main issue I have with using perf_event_mutex
> > > > is that we might interfere with perf/core's locking rules as well as
> > > > interfere with other concurrent perf event additions. Using
> > > > perf_event_list is very likely a no-go because it requires reworking
> > > > perf/core as well.
> > > >
> > > > I can already hear Peter shouting, but maybe I'm wrong. :-)
> > >
> > > Let's wait for Peter to shout then :)
> > > A significant part of this change is having per-task data w/o having
> > > per-task data.
> > >
> > > The current perf-related data in task_struct is already multiple words
> > > and it's also not used in lots of production cases.
> > > Maybe we could have something like:
> > >
> > >   struct perf_task_data* lazily_allocated_perf_data;
> > >
> > > that's lazily allocated on first use instead of the current
> > > perf_event_ctxp/perf_event_mutex/perf_event_list.
> > > This way we could both reduce task_size when perf is not used and have
> > > more perf-related data (incl breakpoints) when it's used.
> >
> > I don't mind either option, so keeping task_struct bloat in mind, we have:
> >
> >   1. rhashtable option, no changes to task_struct.
> >
> >   2. add the breakpoint mutex + list to task_struct.
> >
> >   3. add something like hw_breakpoint_task_data* and allocate lazily.
> >
> >   4. (your proposal) move all of perf data into a new struct (+add
> > hw_breakpoint things in there) that is lazily allocated.
> >
> > I don't think perf is that infrequently used, and I can't estimate
> > performance impact, so I don't like #4 too much personally. My
> > preferred compromise would be #3, but at the same time I'd rather not
> > bloat task_struct even with 8 extra infrequently used bytes. Am I too
> > paranoid?
> >
> > Preferences?
>
>
> There is also this "could eventually get its own" comment:
>
> static struct pmu perf_breakpoint = {
>   .task_ctx_nr = perf_sw_context, /* could eventually get its own */
> https://elixir.bootlin.com/linux/v5.19-rc1/source/kernel/events/hw_breakpoint.c#L669
>
> If it gets its own, then it also gets a perf_event_context pointer in
> task_struct:
> https://elixir.bootlin.com/linux/v5.19-rc1/source/include/linux/sched.h#L1229
> And perf_event_context has its own mutex and lots of other stuff.
> But I don't know what other implications it has.

Relying on perf events to be the only way that instantiates
breakpoints does not work, because hw_breakpoint is also used by
ptrace independently.

On a whole, adding lazily allocated data to task_struct is not as
simple as the rhashtable option (need to take care of  fork and exit
and make sure the lazily allocated data lives long enough etc.). I
question the added complexity vs. the benefit, when using the
rhashtable avoids all that. If I get rid of the O(#cpu) loops it also
doesn't show up in profiles anymore and any efforts to optimize here
are not buying us much in terms of performance.

If the main issue is the mutex, I suppose we can find a hole in
task_struct and stick it there (there's a massive 32-byte hole above
task_struct::stats).

Was the mutex the only benefit?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyyFuozLmqyuQ3u1LLjc4-1STq5EyV9%3DWHhyc2Z9OUEQ%40mail.gmail.com.
