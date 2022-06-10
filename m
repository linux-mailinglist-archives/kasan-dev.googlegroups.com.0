Return-Path: <kasan-dev+bncBCMIZB7QWENRBLUSRSKQMGQEZYCRR3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id CDB7D5460C4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 11:04:46 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id x8-20020a056402414800b0042d8498f50asf18788462eda.23
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 02:04:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654851886; cv=pass;
        d=google.com; s=arc-20160816;
        b=tMCYtHPdyPpZsSU/YsvXUHUj2LqU9ECUmKtL60pxe62aG6c/YwrELZRvlsC8NtQmok
         5h8MH1s4l+6PSq21HOReia6DcBsA0gj8cp8GaHvEitqbPJ2WUmKBEt3RSTFMPL0UlmtY
         5j6p7pJVBZTCZnID1qCWD+g0Xl2z+YWuIzQ2m0rZz46AruTn+1yPb60AQb7zS4J49wRD
         B8/njLUOp/w7MPAENlUGHdeKvMLz0E3NbdmRj48xmxXqEiL6y51w1UrCQTObOl7ignTR
         RKgvlkyJU+2/WQjF8VXHR1iqL8sJ6YxFVm4qZGl1+kvOTTC9ZPuCOpsmSHz9VrbxZLOo
         EGZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HGfXQPDAzIshIbSoOx0zG/lQPRMVC77BtvvlFtsxacs=;
        b=L455WpqngUcCTeNYbd+Gayz052VgsUUlm19aGc9KebqIhoJfu0xnNv7Uhu0jD0ZgGn
         Qv8mc/wcKTG0T2GWljeJxfXHVGeEufMvlxBHTWlrIzHyvHlXHZT4uB/Rwsgn/UAMjuKj
         PR3+0532bF+N+IiJ0Ho7rORsWJo9gNqxy6LPl3+G3ZNtYI9Qts+1HyDfIiiJEKnuZKS4
         FBgpiPQJfMX20cZHMiOUGfe8lrFul4PhY72QzXjMVnwXzILuz8opNYJNb39ZQrY0Juou
         +XGTeLpkRGmeT4x1PhbgqdmHu9ijjem3YAeJUSr2yBST3Hjrk1Q1IZu7NWxvhxncXrIH
         Hmcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JB1ke9QQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGfXQPDAzIshIbSoOx0zG/lQPRMVC77BtvvlFtsxacs=;
        b=MNN09Yh7cnS+delTwYv4XJLJvTiNoauEv1lCHYyKFQejfdSfLQIcEeHlT6CR81u/RQ
         lIM+WAWR745vf4uSyCYKHo1qmkhIXKIp6h01RI8lCdSav06cxHm71SOCLzc9yaWyoQgz
         10iCHr0bxgUCdAQXvPmtnZUENHBfauFHmALWq6s6ZI7spSc4p+Y2Civ2Ow7L0ZX2MoaW
         kyRM6xaLgOhFYoX5yoAzE7QM3oXmGqxokwTBkjrm3sHwfkt/WRmDKedWy8lwY8M5nPh9
         S+LPdZFJEwGwWA49+1ifZm+mUGbsNSKvT02qN/cFD4HZqkvxUzxYzcvGvhvxP9Z7wWMO
         64XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGfXQPDAzIshIbSoOx0zG/lQPRMVC77BtvvlFtsxacs=;
        b=O+lhUv58EqWkKOL+0BkMdUVcSkM56rxAmRp1o8D0yDwOIFzEjExxciNpTiS/kuZBZH
         OoqChNON8Dd58UCqxZi2ZxnJsw2jNKaejq1uEJEqp/snz4jQatITnBrbnJUYm8JFIvZZ
         EqKEZRhiPQ0p8FZDHR8CoUviatiT1O3pWFRYEp8zvvSa6neLgvE/tGQiydDTYLTm0qYZ
         Nk5+Rc4GkJGLxcvM9V3+dJPocZvHU9u/i+oVPwuUmvG+JLqsur/KyVR8m6C6d1SLmpXr
         OocJ9/NJaf+ZMMCWWJ6mH2i6kkcDyCpPjekPiKJKk4NB/3wE01AVvv7LBQpOAfkcLmBh
         YrvQ==
X-Gm-Message-State: AOAM531wlDSNR05l5hhCu35eqogwzCzEvbMz/7iC9NqqZqrRAV8tn8tt
	esqZ6bHHDVn4gKjm40Awef0=
X-Google-Smtp-Source: ABdhPJx7WxUQV5V6uyui1AhH+rwkF8h53xP2tmTTegN2+ciBda6tlQsM+djPVYvynAXYExPG3fHAgw==
X-Received: by 2002:a05:6402:f17:b0:42d:d3f3:244c with SMTP id i23-20020a0564020f1700b0042dd3f3244cmr50005888eda.52.1654851886221;
        Fri, 10 Jun 2022 02:04:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3fc5:b0:6fe:fc5b:a579 with SMTP id
 k5-20020a1709063fc500b006fefc5ba579ls921664ejj.10.gmail; Fri, 10 Jun 2022
 02:04:45 -0700 (PDT)
X-Received: by 2002:a17:907:c24:b0:711:d4c6:9161 with SMTP id ga36-20020a1709070c2400b00711d4c69161mr21471522ejc.760.1654851885159;
        Fri, 10 Jun 2022 02:04:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654851885; cv=none;
        d=google.com; s=arc-20160816;
        b=ySEDogPb2DuKAR8Ko6DFTQFR8HQejNRFyUVNEKG8EHPOhSJMDP318xuy+V4KBZXqAC
         MrWxW4YazY2/VcwZ3ZUfnXa9FNsAH3p7s29G6Cg/bydu2xj9faw6feIem3iTEgMNt2tS
         xbqqE+uuy07Ea9t1sB87emmQVZ5l0dKDlCh1sYqki7X8MtoUMh1StsNtBw82+OjjcIQ+
         y1/wP/G9F2KtqUPgEijtG4hOg8W3fR2wxnia+N9wDd797/BjzUMgj7/jBlQtb8aXkDjK
         0UHJL09Z0I2/yhsmSQWG8J31xwXDs63HTlTe+BEVs8JItq3NBEAZzJU1kWUZkyr8Jg9p
         +4JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fGZRSNtjYVE5/AFVVZNo9Q/VK/BnWz0MKKsJwglLOK0=;
        b=cI6zof9kRkMtQMgEHT2ey4e11+4xKqxeWrSckxTRA+WC8XzFmKG1t7nQsP/chKV6oS
         239yp3MT61kVuGGTHh9S7Fnf6knJvj4ddV2CNoRiVuhqbORaDq7IWSf/Z2izvwXEUKhs
         Ptn40wwvklDd/YU3Q6tfNxS+2SGOgUIbD5OIJOWDJ//otK5C1AmktcDhwRa8VZR3H/vQ
         OL0MHz0JWdTa0gq5rCAGEKmtv4ZWxLKC92Ect1h0yUDZuFB9etSC6eiVO8U8lGhjl5pA
         x/p4hv8C0pdyhN9ziJhl0lA2KIwO81u2c4p8H/+ZDcJKXqbrwrThtmzZstP74mh20jjQ
         amTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JB1ke9QQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id a26-20020a170906245a00b007104df95c8bsi890696ejb.2.2022.06.10.02.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jun 2022 02:04:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id s10so4473592ljh.12
        for <kasan-dev@googlegroups.com>; Fri, 10 Jun 2022 02:04:45 -0700 (PDT)
X-Received: by 2002:a05:651c:1612:b0:253:d535:d7c0 with SMTP id
 f18-20020a05651c161200b00253d535d7c0mr59255207ljq.33.1654851884560; Fri, 10
 Jun 2022 02:04:44 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
 <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com>
 <CANpmjNNtV_6kgoLv=VX3z_oM6ZEvWJNAOj9z4ADcymqmhc+crw@mail.gmail.com>
 <CACT4Y+Zq-1nczM2JH7Sr4mZo84gsCRd83RAwwnHwmap-wCOLTQ@mail.gmail.com> <CANpmjNNC7ry59OXsJrPMf56Xi63chexaDfnP4t8_4MG7S5ZgCg@mail.gmail.com>
In-Reply-To: <CANpmjNNC7ry59OXsJrPMf56Xi63chexaDfnP4t8_4MG7S5ZgCg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jun 2022 11:04:33 +0200
Message-ID: <CACT4Y+ZyrWuZxqpO_fKBjdXbTY-GJu6M7GARVk7YQnyv790mFw@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b=JB1ke9QQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Thu, 9 Jun 2022 at 20:37, Marco Elver <elver@google.com> wrote:
> > /On Thu, 9 Jun 2022 at 16:56, Marco Elver <elver@google.com> wrote:
> > > > > On a machine with 256 CPUs, running the recently added perf breakpoint
> > > > > benchmark results in:
> > > > >
> > > > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > > > >  | # Running 'breakpoint/thread' benchmark:
> > > > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > > > >  |      Total time: 236.418 [sec]
> > > > >  |
> > > > >  |   123134.794271 usecs/op
> > > > >  |  7880626.833333 usecs/op/cpu
> > > > >
> > > > > The benchmark tests inherited breakpoint perf events across many
> > > > > threads.
> > > > >
> > > > > Looking at a perf profile, we can see that the majority of the time is
> > > > > spent in various hw_breakpoint.c functions, which execute within the
> > > > > 'nr_bp_mutex' critical sections which then results in contention on that
> > > > > mutex as well:
> > > > >
> > > > >     37.27%  [kernel]       [k] osq_lock
> > > > >     34.92%  [kernel]       [k] mutex_spin_on_owner
> > > > >     12.15%  [kernel]       [k] toggle_bp_slot
> > > > >     11.90%  [kernel]       [k] __reserve_bp_slot
> > > > >
> > > > > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > > > > O(#tasks) due to storing all task breakpoints in the same list and
> > > > > iterating through that list looking for a matching task. Clearly, this
> > > > > does not scale to thousands of tasks.
> > > > >
> > > > > While one option would be to make task_struct a breakpoint list node,
> > > > > this would only further bloat task_struct for infrequently used data.
> > > >
> > > > task_struct already has:
> > > >
> > > > #ifdef CONFIG_PERF_EVENTS
> > > >   struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
> > > >   struct mutex perf_event_mutex;
> > > >   struct list_head perf_event_list;
> > > > #endif
> > > >
> > > > Wonder if it's possible to use perf_event_mutex instead of the task_sharded_mtx?
> > > > And possibly perf_event_list instead of task_bps_ht? It will contain
> > > > other perf_event types, so we will need to test type as well, but on
> > > > the positive side, we don't need any management of the separate
> > > > container.
> > >
> > > Hmm, yes, I looked at that but then decided against messing the
> > > perf/core internals. The main issue I have with using perf_event_mutex
> > > is that we might interfere with perf/core's locking rules as well as
> > > interfere with other concurrent perf event additions. Using
> > > perf_event_list is very likely a no-go because it requires reworking
> > > perf/core as well.
> > >
> > > I can already hear Peter shouting, but maybe I'm wrong. :-)
> >
> > Let's wait for Peter to shout then :)
> > A significant part of this change is having per-task data w/o having
> > per-task data.
> >
> > The current perf-related data in task_struct is already multiple words
> > and it's also not used in lots of production cases.
> > Maybe we could have something like:
> >
> >   struct perf_task_data* lazily_allocated_perf_data;
> >
> > that's lazily allocated on first use instead of the current
> > perf_event_ctxp/perf_event_mutex/perf_event_list.
> > This way we could both reduce task_size when perf is not used and have
> > more perf-related data (incl breakpoints) when it's used.
>
> I don't mind either option, so keeping task_struct bloat in mind, we have:
>
>   1. rhashtable option, no changes to task_struct.
>
>   2. add the breakpoint mutex + list to task_struct.
>
>   3. add something like hw_breakpoint_task_data* and allocate lazily.
>
>   4. (your proposal) move all of perf data into a new struct (+add
> hw_breakpoint things in there) that is lazily allocated.
>
> I don't think perf is that infrequently used, and I can't estimate
> performance impact, so I don't like #4 too much personally. My
> preferred compromise would be #3, but at the same time I'd rather not
> bloat task_struct even with 8 extra infrequently used bytes. Am I too
> paranoid?
>
> Preferences?


There is also this "could eventually get its own" comment:

static struct pmu perf_breakpoint = {
  .task_ctx_nr = perf_sw_context, /* could eventually get its own */
https://elixir.bootlin.com/linux/v5.19-rc1/source/kernel/events/hw_breakpoint.c#L669

If it gets its own, then it also gets a perf_event_context pointer in
task_struct:
https://elixir.bootlin.com/linux/v5.19-rc1/source/include/linux/sched.h#L1229
And perf_event_context has its own mutex and lots of other stuff.
But I don't know what other implications it has.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZyrWuZxqpO_fKBjdXbTY-GJu6M7GARVk7YQnyv790mFw%40mail.gmail.com.
