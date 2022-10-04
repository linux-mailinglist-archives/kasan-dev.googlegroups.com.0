Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKO56GMQMGQEEAA633Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7385D5F488D
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 19:34:36 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id c12-20020a170903234c00b0017f695bf8f0sf3158495plh.6
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 10:34:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664904873; cv=pass;
        d=google.com; s=arc-20160816;
        b=m6iCIqXS0EqONfrY2QUZMFzudYd8Kh0eWi9wZlnIbFqrE5LzFZ5jKXX1MaME9nkyG8
         MgWCh4P5+5UC9XIrwwm5yaGbdlRGVzlJndM+mMy9H8q/9bBOgUiSmkQxfMrGxP2HP4EC
         s8Qxxcunync/blO9LIt+042aMX9jeEL61JRI7btbazYa4ddmPfCMVF6yqoo47pTaYQ+R
         8/KARCalI2dsXj0aw3FvqTZViAmSd9povCriQaCAt+X7OANQ1stIf8PMYl4spjW41/+b
         M/uBuzygY/6f6uQ4yN7ojthKYshQNKYiFaxuFdTV9tTif89nUROLHt0eT9YiGGVY77Gd
         G1oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=93ldYph8FvVv9+J5PBK99PqyOXF4Trs8iviQBSLDlqk=;
        b=rWlzbmulbLk9ksnkAMgrwVl1dfq6YGQYJ3Y2PDeI8OajFi/dUq7GmrlSN57wW3i7J8
         FsIfJGYBcmgyrFblkHwY7ly/g8UoUq/eyjfytM6WVeYuU0d/pQ2t3xStNblTEeApG8cB
         lkYWur5Aj+TsORr3NyrDs9XsJ1HGeZKnrf0RBHBVTthGI/LXnyiRUPqZPC2GQf1ba3Yf
         vD0xIcHhzoOVbwlY2BQCHc2Iy3jXBvJuIC/lIKinhgBlCNETOjTYBT4i5QkdlNU8RGH/
         YRAvjTZ+JDK2D7RSGLcVdA1O9rL8CRGt9uPRPizgMqaQ3HnWYXIHTuLozar+Dl/i1byB
         VZJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ymg9ZZ0r;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=93ldYph8FvVv9+J5PBK99PqyOXF4Trs8iviQBSLDlqk=;
        b=mpMAEyGAClGi82gD5uW4ENivl4K0ouWiE5/IUULBkHcnouNIdCL8wODjvCWJEAwU6E
         esil5P52XH3CY4FVUNzrp/JI/PncdbrhAXZpEamycXC1+r9R7yCuOaPVoCvcF9+iEyAM
         llOeeS4KtTjh++/NTXf2cRVvzTPKAtbKQc9nOQiSfVv6gFk7f7YLuHNgr1JjuYwdAOb6
         JkU914NWlCFyk97fy+KH35jIm0ukxEoi9PQaXP7YlbKR2ZFjjsGh0Vu5n9s4gOgnAnFz
         rn+mbqbBGM2enhCF0OW87OlMtMN4rBZNMBaNSF933XqLYYQyJqRVHOnlL9+heqOBvAGv
         tchw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=93ldYph8FvVv9+J5PBK99PqyOXF4Trs8iviQBSLDlqk=;
        b=y+akrx0VAHooupZp6C3mMBPr883VfnvdnbpkfXB63DwZQrda9ffw/6rx3ASJqdBLsF
         PWbp82WJtm/g9liNTiSyYpEFMCzILY/yKsDPKhTSCHTZv7phg0pDqY5F/u7EVBvbNveq
         CVboJJQQvrIQGQYLIGuHZXGID/wRWODeq29SAAUwjbWFfzCBVuToxva4X9Me0WwmCHCC
         ZmvXJgnxu4Laik47Fw/hDBecOzRLBQ3eFuPUpKfWo9YlWAgeKaP2SPXghbDr99InKEdc
         s7X0cta+iCrgqjDupC27gFkIYZqdy9+n5M5/unJacZQsIFiCfL/sL5OF60iar1lVAFyz
         LS7A==
X-Gm-Message-State: ACrzQf2mcH9utdhdLSUswzvBHACKF/UB3795dEkn/3cKVBeqk1R2wgaj
	6kqyk050JimOoUZl/iVws28=
X-Google-Smtp-Source: AMsMyM7u1+VyW9wNC0sNTK7NI/YySoVPXO8eaWeGEtprvsrJ2JAKcLjk17sy3Z/eELe1BawQDQnStg==
X-Received: by 2002:a63:6b09:0:b0:453:88a9:1d18 with SMTP id g9-20020a636b09000000b0045388a91d18mr5665011pgc.41.1664904873154;
        Tue, 04 Oct 2022 10:34:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a92:0:b0:438:96ac:b3c1 with SMTP id q140-20020a632a92000000b0043896acb3c1ls8062479pgq.7.-pod-prod-gmail;
 Tue, 04 Oct 2022 10:34:32 -0700 (PDT)
X-Received: by 2002:a05:6a00:17a1:b0:542:be09:7b23 with SMTP id s33-20020a056a0017a100b00542be097b23mr28518884pfg.12.1664904872298;
        Tue, 04 Oct 2022 10:34:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664904872; cv=none;
        d=google.com; s=arc-20160816;
        b=iQhGmhqCXd3jtrWkgJ4RwOO0sesr4Tcox85SokhNq2nnpnhXmG2XY1mhJy+6ET2qjw
         Or5XU1sdxd0WEw7JKhy50FpVIWvud9SbHBwaiDFdfbdOvv0gvSa6K8qxRXspPza4WIwn
         rm2eKpuNspYN6Go/oV66A6xmjLyB7jCOmHkfVIXsEvRNRKf2mJqBHfFQP7tcXzNFTTq2
         Fhvs5/eqeqs+V9E6163DIK5HuoziL/BgiWNzzijGOkIXdbHJBBJmYNYzOE74/qF1SMVL
         zL8Gq1lzawAJ4/vJp0SUThN37BVeeqz0K8kHYykHBGwsGOV0mxVuv1Cctm/+k2dDtQgy
         0M+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uB+xgYQO/9hSmh+whT13wcnQWr/VgecN0kcqIDAF7KU=;
        b=031WiqLQYG8qqUGlLF2xrFwOtzd8tcB46w2C2vqcTOM6KZiYsf766pmQ1ERsbiSw1j
         9c1yIzWoS8FGgGkXpw37fEyxfJsfWr6/qMc32MUL1K3pzmbG9c+a4i1QUSI9n+wuF+Dl
         ES7cXZ4OiT3ZTr5xmvB2PQXILYUG4btjw3E1Tt/8/jcUjrguou9y3F8AOMz+wvTCPxSH
         5BUFK+uwXafZpSSTT70IIvXeEk3h9pypSHWC6+mUjAL0liEtM5rTGPho8HDFubX+TocX
         rqV9WreXu5GbfDTuFeuaEwpNt/+rIje8LMwzXxo0lsRnCX22Taw9c9URoVpfU5tIaS4Y
         TT7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ymg9ZZ0r;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id o10-20020a170902d4ca00b0016d5fc78c8esi631796plg.7.2022.10.04.10.34.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 10:34:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-357208765adso100867787b3.12
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 10:34:32 -0700 (PDT)
X-Received: by 2002:a81:6dc5:0:b0:358:6a18:b73d with SMTP id
 i188-20020a816dc5000000b003586a18b73dmr14847990ywc.267.1664904871847; Tue, 04
 Oct 2022 10:34:31 -0700 (PDT)
MIME-Version: 1.0
References: <20220927121322.1236730-1-elver@google.com> <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com> <YzQcqe9p9C5ZbjZ1@elver.google.com>
 <YzRgcnMXWuUZ4rlt@elver.google.com> <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
In-Reply-To: <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Oct 2022 19:33:55 +0200
Message-ID: <CANpmjNPwiL279B5id5dPF821aXYdTUqsfDNAtB4q7jXX+41Qgg@mail.gmail.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ymg9ZZ0r;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Tue, 4 Oct 2022 at 19:09, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Sep 28, 2022 at 04:55:46PM +0200, Marco Elver wrote:
> > On Wed, Sep 28, 2022 at 12:06PM +0200, Marco Elver wrote:
> >
> > > My second idea about introducing something like irq_work_raw_sync().
> > > Maybe it's not that crazy if it is actually safe. I expect this case
> > > where we need the irq_work_raw_sync() to be very very rare.
> >
> > The previous irq_work_raw_sync() forgot about irq_work_queue_on(). Alas,
> > I might still be missing something obvious, because "it's never that
> > easy". ;-)
> >
> > And for completeness, the full perf patch of what it would look like
> > together with irq_work_raw_sync() (consider it v1.5). It's already
> > survived some shorter stress tests and fuzzing.
>
> So.... I don't like it. But I cooked up the below, which _almost_ works :-/
>
> For some raisin it sometimes fails with 14999 out of 15000 events
> delivered and I've not yet figured out where it goes sideways. I'm
> currently thinking it's that sigtrap clear on OFF.
>
> Still, what do you think of the approach?

It looks reasonable, but obviously needs to pass tests. :-)
Also, see comment below (I think you're still turning signals
asynchronous, which we shouldn't do).

> ---
>  include/linux/perf_event.h |  8 ++--
>  kernel/events/core.c       | 92 +++++++++++++++++++++++++---------------------
>  2 files changed, 55 insertions(+), 45 deletions(-)
>
> diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> index ee8b9ecdc03b..c54161719d37 100644
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -736,9 +736,11 @@ struct perf_event {
>         struct fasync_struct            *fasync;
>
>         /* delayed work for NMIs and such */
> -       int                             pending_wakeup;
> -       int                             pending_kill;
> -       int                             pending_disable;
> +       unsigned int                    pending_wakeup  :1;
> +       unsigned int                    pending_disable :1;
> +       unsigned int                    pending_sigtrap :1;
> +       unsigned int                    pending_kill    :3;
> +
>         unsigned long                   pending_addr;   /* SIGTRAP */
>         struct irq_work                 pending;
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 2621fd24ad26..8e5dbe971d9e 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -2268,11 +2268,15 @@ event_sched_out(struct perf_event *event,
>         event->pmu->del(event, 0);
>         event->oncpu = -1;
>
> -       if (READ_ONCE(event->pending_disable) >= 0) {
> -               WRITE_ONCE(event->pending_disable, -1);
> +       if (event->pending_disable) {
> +               event->pending_disable = 0;
>                 perf_cgroup_event_disable(event, ctx);
>                 state = PERF_EVENT_STATE_OFF;
>         }
> +
> +       if (event->pending_sigtrap && state == PERF_EVENT_STATE_OFF)
> +               event->pending_sigtrap = 0;
> +
>         perf_event_set_state(event, state);
>
>         if (!is_software_event(event))
> @@ -2463,8 +2467,7 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
>
>  void perf_event_disable_inatomic(struct perf_event *event)
>  {
> -       WRITE_ONCE(event->pending_disable, smp_processor_id());
> -       /* can fail, see perf_pending_event_disable() */
> +       event->pending_disable = 1;
>         irq_work_queue(&event->pending);
>  }
>
> @@ -2527,6 +2530,9 @@ event_sched_in(struct perf_event *event,
>         if (event->attr.exclusive)
>                 cpuctx->exclusive = 1;
>
> +       if (event->pending_disable || event->pending_sigtrap)
> +               irq_work_queue(&event->pending);
> +
>  out:
>         perf_pmu_enable(event->pmu);
>
> @@ -6440,47 +6446,40 @@ static void perf_sigtrap(struct perf_event *event)
>                       event->attr.type, event->attr.sig_data);
>  }
>
> -static void perf_pending_event_disable(struct perf_event *event)
> +/*
> + * Deliver the pending work in-event-context or follow the context.
> + */
> +static void __perf_pending_event(struct perf_event *event)
>  {
> -       int cpu = READ_ONCE(event->pending_disable);
> +       int cpu = READ_ONCE(event->oncpu);
>
> +       /*
> +        * If the event isn't running; we done. event_sched_in() will restart
> +        * the irq_work when needed.
> +        */
>         if (cpu < 0)
>                 return;
>
> +       /*
> +        * Yay, we hit home and are in the context of the event.
> +        */
>         if (cpu == smp_processor_id()) {
> -               WRITE_ONCE(event->pending_disable, -1);
> -
> -               if (event->attr.sigtrap) {
> +               if (event->pending_sigtrap) {
> +                       event->pending_sigtrap = 0;
>                         perf_sigtrap(event);
> -                       atomic_set_release(&event->event_limit, 1); /* rearm event */
> -                       return;
>                 }
> -
> -               perf_event_disable_local(event);
> -               return;
> +               if (event->pending_disable) {
> +                       event->pending_disable = 0;
> +                       perf_event_disable_local(event);
> +               }
>         }
>
>         /*
> -        *  CPU-A                       CPU-B
> -        *
> -        *  perf_event_disable_inatomic()
> -        *    @pending_disable = CPU-A;
> -        *    irq_work_queue();
> -        *
> -        *  sched-out
> -        *    @pending_disable = -1;
> -        *
> -        *                              sched-in
> -        *                              perf_event_disable_inatomic()
> -        *                                @pending_disable = CPU-B;
> -        *                                irq_work_queue(); // FAILS
> -        *
> -        *  irq_work_run()
> -        *    perf_pending_event()
> -        *
> -        * But the event runs on CPU-B and wants disabling there.
> +        * Requeue if there's still any pending work left, make sure to follow
> +        * where the event went.
>          */
> -       irq_work_queue_on(&event->pending, cpu);
> +       if (event->pending_disable || event->pending_sigtrap)
> +               irq_work_queue_on(&event->pending, cpu);

I considered making the irq_work "chase" the right CPU but it doesn't
work for sigtrap. This will make the signal asynchronous (it should be
synchronous), and the reason why I had to do irq_work_raw_sync().

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPwiL279B5id5dPF821aXYdTUqsfDNAtB4q7jXX%2B41Qgg%40mail.gmail.com.
