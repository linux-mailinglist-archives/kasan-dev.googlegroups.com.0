Return-Path: <kasan-dev+bncBCMIZB7QWENRBTVP2SAQMGQEIKXIDDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id C4DFD322CF5
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:57:19 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id t193sf1148387vkd.4
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:57:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614092238; cv=pass;
        d=google.com; s=arc-20160816;
        b=qG2I5SSEgCPAxTFBh+hgRq2XJ5XJlZ4O9fn2cxgOiA1fOIvcZaQRcn36xvdWv+znk/
         r3rP93bcUFKn5a3AbvREdLMhf+j1NR/oTiWBKz6iJVFfb7HcXabkj6Bw/VBlv5JcnbgN
         JwHDPd1K1H9hBtbfZ0bhKvxVDwwnt06fVoEyKEJTWSHFN2NuJ6loQ586l80i9pXnz8zf
         VO5LkfHUAKu3ZR4c3JF6vaQ8VGRAjuoNNaa7Mmdod2R/JJzPMShPdr+/Z2btlE8I+sDG
         De0lNYhKPQas6SpHmAYCOr/d0K27s0HKjjCh6ySNqkh1iX8oXt8VOyF5ycNBnaseCkGK
         Z9qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pemFy8zRh8HAOHC/x1H+5zZwXOSQI93g1n96QhH73DQ=;
        b=AyLsUTI078unLGTZHwuBP0Gmzo2xs36bt2FZbaPR0bFv52i5hEoGyoLo3AiPpcHf9n
         ZmwHHPlvSvl8QLWp8uq15e74ICSEKr+wo+8eZNd4umC+tK7bU1r2VsFVwARC8b00dPHd
         k2Zxx7GIbBrv/k4mbQuQxO9BBx17VTWtT6REIYl4COac7F/oQELVafGtS66gf0+chcAK
         wefdT77voH4VYI3WQ3RJ/cFfDxhZig7Bg7EOttOYmsNatDRCgU9a3o17kyxXovwPsSP1
         BR+EeCDa8JziO0eqQREf2jPN+ee4DXhwhzHUxXmIwSldXF2dqzEk9LQKwRqTqxflYz/F
         Ah+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lPGcs8+X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pemFy8zRh8HAOHC/x1H+5zZwXOSQI93g1n96QhH73DQ=;
        b=Bmwc4XQxfDXfiCVBTTimg2tA6AMmv2iHJm7+sJmcTjiObugzzk7dYz/p+TufXjuLPu
         y4RKNGcnGfPvqiV1ksAwFAXYiFXCYXINwndqHMBBtIzq4MWlIgsB/rOnmCjb2o1xblsk
         fzk93wSt70S412XIK7QjPxjO03ZCTyNLZB+mcb0JlVaVLeM7GabOZWR4hCwlY85Ifj2p
         +EdFMzRx9Rg64zksBSc513fPJhTRwCOqrkI27PJrtFcJ7PYMpKumUmRALQ/eBI8Q7CTj
         gTF0is8U72Gm6OT35LLgUdpw8YYkBTXNj/5YCHFU6cYrrGiiB98c0OjU1Ux5ofU+AyYE
         B9Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pemFy8zRh8HAOHC/x1H+5zZwXOSQI93g1n96QhH73DQ=;
        b=eH9hWnSOU7+v1EK7MjcNc8JBtM6iIkx5kaZIi+GjU42O04vRdBjqAKECaaevAfl4ko
         1mZCwfTM2ndlQlGjRBtiiFa1Mgo5P+M1inAMfJLdf8yKtR/2pPGlSsYc+4HdNpSo6Px5
         38VYbTNu6HJSOA/uEXjsbYbCv7NZmMtNwbYaD3AnfzG97NrwfIidF9maxzv0hjKUv+n9
         07wXSpUe82G8KnFFLISPjAI5JqLXsKH8qkBr+mvFFctRdbiqv66zA5WHSCky/Jz60UAx
         74CHLpT0Nuq1YC2NaW3wqrmDl+Z1EScjydk+ddGi1ejhhA1KC7qShGWf47AZBRxaRieo
         eJMw==
X-Gm-Message-State: AOAM532IfratoD2iUY1qshlW1m/c/HJDgWgOOT6HCIOpjIhxLjxCYP+3
	vooYLvZ/ZQwhkAArXjR5SzI=
X-Google-Smtp-Source: ABdhPJz5itQMy1EZr/uwYeGrlSgDljvmoh8lX3F6vwMjCjJ4kuTL0vKG8M+tkPClAr35nxaTMsRnXw==
X-Received: by 2002:a1f:bd08:: with SMTP id n8mr16977375vkf.1.1614092238672;
        Tue, 23 Feb 2021 06:57:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ce91:: with SMTP id c17ls2342523vse.1.gmail; Tue, 23 Feb
 2021 06:57:18 -0800 (PST)
X-Received: by 2002:a67:8a8a:: with SMTP id m132mr15841423vsd.31.1614092238165;
        Tue, 23 Feb 2021 06:57:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614092238; cv=none;
        d=google.com; s=arc-20160816;
        b=jBxJ0IOjDgwgGOgtdGQhyT8DKkUrBBN0vxQqcPb+nbpd76zhVfJxHMx2QMRFdCBwMr
         ghwbw+OSU4jaIIyNScCcJYedVH79/8eIfJ3MeKx2v2rgfuUW8DQAoZgpgdAPzyv8a7hn
         fkOlIHY2x1uEdZi7XEeyxSnl4itg0Z0/JvdOPycl8E5JVF8cIOt8+T7qJGS+wTTo6XGn
         9KnanMf4owsOFRyAlBnmyxxeLdObxH0Ga8GWgzrSPKPr0zjBr78HWkEJf+zFOLCDnnH0
         k6lQJY/JHVuhsyHo9QsZHfuXeH+kofqHiEdXBOAYwzOaQoiEi61WsyauEoLb2GOKTBNW
         OgAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LmrazInE9lkHVfTVT/c9ri5uOiLTKO8Po9aKcmrNBAY=;
        b=mWDRgY+4vo2mUVOd0uhcUcq+k/jwUPufKY6OobIwuaM6e2E71UaeqVdpK6MqyDgOS+
         UvoLHWUjzYWHF12tmVA13IfwT4LpPXKKGXfUG44EvYbSBHZy5vZ+03nVhGxMSBLmzqfZ
         O+euP8kX8cvfxNnLCxCpR3kD1aJPt1liZ0FVfTWkJzSmDc2TUtAhyfgE1bfgz21Nc9tl
         2FbSg2oBX/f+P9CmNynhlXG4fqrlwiz/QOpMSdYCy84d4/PdbN2//FH50wpgYF9QNu3k
         cbY2yIfwjbQrFX88hxmoSpKKQE+X7DIXKfAVnJ2IjRDV3+hBhXoiRSRcXdlDrrCIAsSu
         Cn+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lPGcs8+X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id y127si896990vsc.0.2021.02.23.06.57.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:57:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id h8so16342030qkk.6
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:57:18 -0800 (PST)
X-Received: by 2002:a37:a757:: with SMTP id q84mr25540114qke.501.1614092237384;
 Tue, 23 Feb 2021 06:57:17 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-4-elver@google.com>
In-Reply-To: <20210223143426.2412737-4-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 15:57:06 +0100
Message-ID: <CACT4Y+aEZ5_KFf8Uj-J6uLCdZcB_r5+tSpw8KhGg0PoBn_eMFQ@mail.gmail.com>
Subject: Re: [PATCH RFC 3/4] perf/core: Add support for SIGTRAP on perf events
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lPGcs8+X;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729
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

On Tue, Feb 23, 2021 at 3:34 PM Marco Elver <elver@google.com> wrote:
>
> Adds bit perf_event_attr::sigtrap, which can be set to cause events to
> send SIGTRAP (with si_code TRAP_PERF) to the task where the event
> occurred. To distinguish perf events and allow user space to decode
> si_perf (if set), the event type is set in si_errno.
>
> The primary motivation is to support synchronous signals on perf events
> in the task where an event (such as breakpoints) triggered.
>
> Link: https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/uapi/linux/perf_event.h |  3 ++-
>  kernel/events/core.c            | 21 +++++++++++++++++++++
>  2 files changed, 23 insertions(+), 1 deletion(-)
>
> diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
> index ad15e40d7f5d..b9cc6829a40c 100644
> --- a/include/uapi/linux/perf_event.h
> +++ b/include/uapi/linux/perf_event.h
> @@ -389,7 +389,8 @@ struct perf_event_attr {
>                                 cgroup         :  1, /* include cgroup events */
>                                 text_poke      :  1, /* include text poke events */
>                                 build_id       :  1, /* use build id in mmap2 events */
> -                               __reserved_1   : 29;
> +                               sigtrap        :  1, /* send synchronous SIGTRAP on event */
> +                               __reserved_1   : 28;
>
>         union {
>                 __u32           wakeup_events;    /* wakeup every n events */
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 37a8297be164..8718763045fd 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6288,6 +6288,17 @@ void perf_event_wakeup(struct perf_event *event)
>         }
>  }
>
> +static void perf_sigtrap(struct perf_event *event)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = SIGTRAP;
> +       info.si_code = TRAP_PERF;
> +       info.si_errno = event->attr.type;
> +       force_sig_info(&info);
> +}
> +
>  static void perf_pending_event_disable(struct perf_event *event)
>  {
>         int cpu = READ_ONCE(event->pending_disable);
> @@ -6297,6 +6308,13 @@ static void perf_pending_event_disable(struct perf_event *event)
>
>         if (cpu == smp_processor_id()) {
>                 WRITE_ONCE(event->pending_disable, -1);
> +
> +               if (event->attr.sigtrap) {
> +                       atomic_inc(&event->event_limit); /* rearm event */

Can/should this be atomic_set(&event->event_limit, 1)? It should only
go between 1 and 0, right?
Otherwise:

Acked-by: Dmitry Vyukov <dvyukov@google.com>


> +                       perf_sigtrap(event);
> +                       return;
> +               }
> +
>                 perf_event_disable_local(event);
>                 return;
>         }
> @@ -11325,6 +11343,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
>
>         event->state            = PERF_EVENT_STATE_INACTIVE;
>
> +       if (event->attr.sigtrap)
> +               atomic_set(&event->event_limit, 1);
> +
>         if (task) {
>                 event->attach_state = PERF_ATTACH_TASK;
>                 /*
> --
> 2.30.0.617.g56c4b15f3c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaEZ5_KFf8Uj-J6uLCdZcB_r5%2BtSpw8KhGg0PoBn_eMFQ%40mail.gmail.com.
