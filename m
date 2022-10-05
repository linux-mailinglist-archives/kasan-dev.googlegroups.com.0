Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNHO6SMQMGQE26BPYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 88E635F5073
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Oct 2022 09:50:14 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id k19-20020a056a00135300b0054096343fc6sf10467340pfu.10
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 00:50:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664956213; cv=pass;
        d=google.com; s=arc-20160816;
        b=etAHAdH7l8FRgNF8vL7CY3yYtmzBqCZf0PUgN3w8HOkkUW4X/z12rpXXpSsBGmsipl
         plzre8/dpwy/uAhNE5ic3Zklf3QGwVH2SJCXP7LQ7Lfw4NTNUw5zi2em8OQQRvCdSsmO
         fQgz2iu4aL4Uf5JXvMa6OXPZE/azNbPBNlkbOEy0BzxdzFsXAfIrdLcXyaRTopMeYVGK
         f+KJ5yyQheIGMR2lEaJ75BJaD92xdpOE1eiJXQxpBqFIfWGtcuNSd7y7Tnvnv1rJ4uUi
         2jQD/NEWX57S+Irp7PB22dIf9zFUeES0kdsH2QV9FmdETjjqmbfeTMKKBCzpgAjbX4uy
         I5PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BBY5pgKNz0+kgfBNst+DkTkCqv6++rLJJUULSYlkajA=;
        b=Lz4XhC060iFSqq//DPwmpDIwERVgm55UyUGXqN+PyUXlFBtX0Tup3WMAHIauhpRnRi
         2E8BouIEwMW18XcrbTuTbHp4m4L6lHPrTR3zKUxOT/ABbls1CifWwl7DfeEg5GUUI88S
         F7R9CDag5TF+Rm0Gi2vg3aO6kWpQjbMT0ullNpoNnbI4frWsx5viU72/j1gmDtiQuIU4
         hUjq8Hh+aCbRm0kRxeq3lHsetHCHNXfeGIHDch2OQXtSAOHzNhHGmsULfM6G+5YVmCsj
         kNmfCGWtX9rdlQ/YtIfyDBfj5/5UGBgvBPKiPKl5k9t/bIHvtCe/GhMjbiPzVpl4cFeu
         0Mzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PxghZPSa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=BBY5pgKNz0+kgfBNst+DkTkCqv6++rLJJUULSYlkajA=;
        b=TuhPV0NijDi1DshXm4zjHpW/5rTg7QanhpD+Enxr+OObCMB5Nu/EkC/UIoe4tQ2qCD
         Dr7ouGEIqmHnEPoIvWFdW7F8WlLRUfuqWmm/DZCEw2y2XwMotwxzaDzJebmd7SKp0Qey
         yN46PBM1Bkq8kAYewIVnz2Qv3pGU52NqtOgKtiZ93hxpksNxvCmEL9hfjMR9GlLl+c/G
         2cS2NxsZbHbzFXoPFojxBOWwDYwloGbx+BRp6bpbeWN/A+QIDwkqhEw0WglpFOUiIvL+
         0tz9bhW+bzd1kaJnmcQd/dIm6ZVBSkHuQoTAd4uwn6jF6aN763aQYjOE32m8Mi/QhvYp
         UfEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=BBY5pgKNz0+kgfBNst+DkTkCqv6++rLJJUULSYlkajA=;
        b=TmPvuo/6Gtjpc+lz6l1RwSN6F1umM7K7QosSwaHIzKwbCiYpkiEJk8liZ/E3OSMYIE
         o0lolMu3fAf9zTYfZLOEA/MTygm0lHVqH1MmfeRVN2Rka9J8U4jpTcAIXbD7l9W673IM
         DxcXjMjkS+1tSL/eTOWscbTMuVsMPMIQLqHudjhZlAhGG/0eGD8YkMkjeD7Rw24Z2n/V
         lshfYgY+/uE1RrGNvDblscQdSEv9HVskCShn268CmLLJhbRqO8eaDY9WaJWaxCUFIOGw
         0RaAiubhAKpuFXgSt6qP/yASRhYOdHdNrZ6QOguLquInmRy6QbTd58/fjFjjwYS5PYcX
         P5dQ==
X-Gm-Message-State: ACrzQf3bQL1HS+bRB273a/UE4MFEZhM8TGB1sKVc7RTvlSTV3Eeldtg0
	9vonMnqBsPP33F1aHMed+c4=
X-Google-Smtp-Source: AMsMyM4C/ir0kGV0w33dxef5xYXuu3WW2WKW6WLZ3ABLet/mz0sES/zQqtRT+gKhzW2ptPsRVr7+WA==
X-Received: by 2002:a17:90b:3a90:b0:202:d341:bf81 with SMTP id om16-20020a17090b3a9000b00202d341bf81mr3769354pjb.179.1664956212805;
        Wed, 05 Oct 2022 00:50:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f081:b0:178:3881:c7e3 with SMTP id
 p1-20020a170902f08100b001783881c7e3ls13683281pla.11.-pod-prod-gmail; Wed, 05
 Oct 2022 00:50:12 -0700 (PDT)
X-Received: by 2002:a17:902:db12:b0:178:1f91:74e6 with SMTP id m18-20020a170902db1200b001781f9174e6mr31367075plx.100.1664956211920;
        Wed, 05 Oct 2022 00:50:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664956211; cv=none;
        d=google.com; s=arc-20160816;
        b=enl3uEmdv9DwqyLGwdQeNThtQCrO5pw1IFXKUabTreGeRGx8Ob3Peo/So2KliARjfZ
         bWNsiQbeSvW+ybP24XGCR1Y161ReNes4VGyH71V71xU9WqvpYP67inTmNxZgs5G2E+if
         lhQCe7/U00wvj+IbWMlxWzX5e0C9rU/wyi5wQ51I5cQaQ1qZJIUK3AmMCXc57wnDy6p4
         F/1s5TUc6yGSYtRAHH3dW+mYVE/LoYkNs465bGyFEki+qqN8Yq8z0aurlVxAq9PGQl8n
         dnhVmuUwqWuqk2QK2jfhhBpUGXr6/KtuHBDGppY6pvzm437qrriO2RAEgzAtKynDrKN8
         dkLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UzQmyinUVh0gYIU7G22SjWrGZvbDKlQeEbxckrHhAUQ=;
        b=pSDvX6G2WaTSgfpxGOAViuviYPn1EcPvLUp8b+tLmU0seSpgQ3Spp+0hLIOTZG75WW
         5El/Wm+73/frYyCqgR6G1vEW6wamtu1I7TjolzCVSJWzxi/uaeR56n0ez7yQQexeL92O
         N0chK0g3jw818eU8KNbtA4JIMaeV7MlmaP1/vFZgx6b9OrzFeG1LQF1iPrAwo575PC2O
         FBmtf8ZLhbEg9YbsRGWJlWevD0/nIUPzGLIv3aRuciIR82MYkuSc1WTEEO5aLvRHK8Q8
         Bdd1tJS5+ivIOcRcn/kP9aL6Jxc6+VURzmxvvNoubQT1CoionW6KkG8PcuTVhvBKZ5cL
         oyug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PxghZPSa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id x14-20020a170902ec8e00b0017848b6f590si658553plg.6.2022.10.05.00.50.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 00:50:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-35befab86a4so35864697b3.8
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 00:50:11 -0700 (PDT)
X-Received: by 2002:a81:7787:0:b0:349:8bbe:64b with SMTP id
 s129-20020a817787000000b003498bbe064bmr29166335ywc.465.1664956211013; Wed, 05
 Oct 2022 00:50:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220927121322.1236730-1-elver@google.com> <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com> <YzQcqe9p9C5ZbjZ1@elver.google.com>
 <YzRgcnMXWuUZ4rlt@elver.google.com> <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
 <CANpmjNPwiL279B5id5dPF821aXYdTUqsfDNAtB4q7jXX+41Qgg@mail.gmail.com> <Yz00IjTZjlsKlNvy@hirez.programming.kicks-ass.net>
In-Reply-To: <Yz00IjTZjlsKlNvy@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Oct 2022 09:49:34 +0200
Message-ID: <CANpmjNNWWBs97tXzjnzR8NitN9L6WH=yjbpQRVKWKS7t=0wAww@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=PxghZPSa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as
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

On Wed, 5 Oct 2022 at 09:37, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Oct 04, 2022 at 07:33:55PM +0200, Marco Elver wrote:
> > It looks reasonable, but obviously needs to pass tests. :-)
>
> Ikr :-)
>
> > Also, see comment below (I think you're still turning signals
> > asynchronous, which we shouldn't do).
>
> Indeed so; I tried fixing that this morning, but so far that doesn't
> seem to want to actually cure things :/ I'll need to stomp on this
> harder.
>
> Current hackery below. The main difference is that instead of trying to
> restart the irq_work on sched_in, sched_out will now queue a task-work.
>
> The event scheduling is done from 'regular' IRQ context and as such
> there should be a return-to-userspace for the relevant task in the
> immediate future (either directly or after scheduling).

Does this work if we get a __perf_event_enable() IPI as described in
the commit message of the patch I sent? I.e. it does a sched-out
immediately followed by a sched-in aka resched; presumably in that
case it should still have the irq_work on the same CPU, but the
task_work will be a noop?

> Alas, something still isn't right...
>
> ---
>  include/linux/perf_event.h |   9 ++--
>  kernel/events/core.c       | 115 ++++++++++++++++++++++++++++-----------------
>  2 files changed, 79 insertions(+), 45 deletions(-)
>
> diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> index 853f64b6c8c2..f15726a6c127 100644
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -756,11 +756,14 @@ struct perf_event {
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
> +       struct callback_head            pending_sig;
>
>         atomic_t                        event_limit;
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index b981b879bcd8..e28257fb6f00 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -54,6 +54,7 @@
>  #include <linux/highmem.h>
>  #include <linux/pgtable.h>
>  #include <linux/buildid.h>
> +#include <linux/task_work.h>
>
>  #include "internal.h"
>
> @@ -2276,11 +2277,19 @@ event_sched_out(struct perf_event *event,
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
> +       if (event->pending_sigtrap) {
> +               if (state != PERF_EVENT_STATE_OFF)
> +                       task_work_add(current, &event->pending_sig, TWA_NONE);
> +               else
> +                       event->pending_sigtrap = 0;
> +       }
> +
>         perf_event_set_state(event, state);
>
>         if (!is_software_event(event))
> @@ -2471,8 +2480,7 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
>
>  void perf_event_disable_inatomic(struct perf_event *event)
>  {
> -       WRITE_ONCE(event->pending_disable, smp_processor_id());
> -       /* can fail, see perf_pending_event_disable() */
> +       event->pending_disable = 1;
>         irq_work_queue(&event->pending);
>  }
>
> @@ -6448,47 +6456,40 @@ static void perf_sigtrap(struct perf_event *event)
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

This probably should not queue an irq_work if pending_sigtrap, given
it just doesn't work. It probably should just ignore?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNWWBs97tXzjnzR8NitN9L6WH%3DyjbpQRVKWKS7t%3D0wAww%40mail.gmail.com.
