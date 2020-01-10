Return-Path: <kasan-dev+bncBC7OBJGL2MHBB74A4PYAKGQE2UUGK5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC4D71375F8
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 19:20:50 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id u14sf1711021pgq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 10:20:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578680447; cv=pass;
        d=google.com; s=arc-20160816;
        b=RoBTXwejmSj0C3hTQZXRnndseE6fePO02TQOnwc9cKTsxU4zZj1yk4zC9+I6LcnhFb
         sTZyEPOPEjcHbEJ9bFaVrWaJdy1frCuHU8gUFphB40D4B8wYcwOLUa4/kJuJIoDzOFn7
         iTqlpSiwm1IR3jpIbV2bPYPLDkw7M1qCl2dlaJ8sdwx9jgJb54ukpWGue2QCLl2VT559
         B3GBH2rsnESKh9poqPbwIsb8B8xQG5bXHo3WLfmiXqrlUSxLdyFRV/6NMpWKtMr/drdS
         nHiddjn6ltSL5/5ylqqBYiYSScQZc08P94wbsQKGfA95GFPxV7dpobkiJkJlO3iOkSeS
         u48A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E2ByH7RWvBaIZWfOX/MOQlExOXjLoCOU69laU6kt54w=;
        b=IaXGHWoDWeh6F9cfHgBElAKu7aRpDujEyMDRO1qpSgUtQcdmQqC+Fbdtxy8Ildf42K
         nko9uN6gEkuLT52ZXJYRzHW3DbCccCu+zeVQMp+GfMraovkXtSWASNLi++sFBIdK2rKD
         iWUDFTreRk9EULb3jmu2qqwRi6ZwP4YKSGa9ZeE8M0zh4ksf921X7C0O1DkJORb+OYmb
         j9b3ziP2yZTx94VTZ2NF5liJnqmpWSIBnpYbGRcbepOR5D6H4OSrOCBGzFgRapAXa7/8
         NWef+Ti94LYhTQxwOatAUYNk4+ER9xfMk2MyLTCSj6tvIipRy5UQJ9zBuABj4+NEE4ow
         mkvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W+bQEbU2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2ByH7RWvBaIZWfOX/MOQlExOXjLoCOU69laU6kt54w=;
        b=FuqQAaY7zv4lCMgrZe9FYJ/ZJDgrw/JI2iQszLJMzW52Gh1lh1AiQURf6GzaltIlcv
         1TkwWZR5N0dkNzDpYaIO1Bh7OiDdMOI9hGSPgMgqE+XIcqKix/AWNDoDzovQBsBtvaXs
         WYxWdXk6jhSfzv9xyOQ0qkQ3HYy7jX3OtHYd7cajglRrGXeVirCzX7q4diiFwx0gqPwB
         XU4jbOKNqPvku+D9G3NOvN2JeZ8CeZMgFOY9zlUWwy5fEvDokNKq8l53XRlIDuPTBnqL
         HUoWHgPc6RLDRhE5xI0xBMssJ0xC4UXk7W+TBt9syI8iiJfXOXAaH2YUBGePuaZIz4bg
         x5uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2ByH7RWvBaIZWfOX/MOQlExOXjLoCOU69laU6kt54w=;
        b=WfDlL92430JgrlYX3fx/qVKoIXflMPw+ubiBa5IHhnYBg1AB8ye+XUhi1FP+LKNLJz
         tR9d9aPufPzaZ53NPrA8EpcQnuv6c1MK9RZZPwx3QLnEBiAbGlxs/9qHIKNgzO7OPZXD
         pNE44B0wSN2U/12Rj4Jz9xZMIspOzCsnY00GGAGrDO4voxDNEyWDup+Lkjeg+eyICjTi
         4puohSiLN83PrxAjcVbUub7FiaTyZ6QRs++rysQ6dQdF0g40GGPRcS2aEpDexNSNYZnR
         C1/7BQ8wcl1A68ri9W7ZgfqPTF710B+HijySoymoN96dGyl/UVMLcT5VLhJUvzSJj5X9
         hoEQ==
X-Gm-Message-State: APjAAAWaQyH0V3n13OEZHT1Wli/i5UuIqZiUnYduM0INXpwq1oYRj+Dl
	gCT8qRj9RAvit5BcKKCOSWQ=
X-Google-Smtp-Source: APXvYqwWYQ2//ZHqxtYuwiOXep2EdVsIdZv9p1wpLtWYBv4wDAkKKcg4aU+rHhXWmwFZSKx/4NTZJQ==
X-Received: by 2002:a17:90a:20c4:: with SMTP id f62mr6692751pjg.70.1578680447264;
        Fri, 10 Jan 2020 10:20:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d207:: with SMTP id a7ls1567565pgg.1.gmail; Fri, 10 Jan
 2020 10:20:46 -0800 (PST)
X-Received: by 2002:a63:181a:: with SMTP id y26mr6057530pgl.423.1578680446749;
        Fri, 10 Jan 2020 10:20:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578680446; cv=none;
        d=google.com; s=arc-20160816;
        b=YkhGmOazDR4zrhkziDejjl55xp9RN57SnoLiL4bGcGN+mmDRjs6uvfhMJJQzMXmynO
         WztgTd94QDNcvUtp7qtuQu+oAB89h8VXXOxuGJtEBVBPCGcHCjp4vjG8mQ3ubPg/1oIP
         JUHxnsOPwrmg4/7Bb1ibzBQLylv2hNGpVmmX32JSucKchLogI1il3ZIBV4DGMWTMGoJV
         SJEkS0dVuzBo+6C+ok6LYp3hu/8lAM8CX2D4D2yqPIW4Z4qW8S+lSVhkUEVIVb8R+5Qr
         7cehroZMdLqRgKsvza325kXcx2ngLjsQ5CpVtVLKxRd0PhBgCkyDoqsOqdDvExWCK/Sc
         Tmxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=he8cV4Je1YO1zSBdo6zOJypAxMQ+pWm4+ZlJU93BV+E=;
        b=AGwmDLeHs49z8kYqR5YchfIY7Tcsfrv9lNSgotE7CVIY09RrOobMw+ZziZFMQFXTxa
         I/3qq3zH8l1SCHiQc7sHygQlI9o9TKBHE2S5jWZyAbsyd/rfu4dXlHTdlL2ZzXU5Jt5i
         yk4OwtKICZRDMWDiWhkfetycxDdvQwIKnh6nmWLae+9m1jR2obX1szMpw+gxci9/1OFe
         bXUIMkM9QKbmjGEDNwdlo0+xMEuhPJzwKVC7UR9wsA0ttAB8LY8eHv4L8efAhkarzr5l
         s9Qjd50wttOG0J6Zq+814OHOTdGBRJuMxnlsj5Cj8jJEgAkr/ZL+fk5Tw/m81/Xcq1Ba
         Jtmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W+bQEbU2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id d9si148870pls.5.2020.01.10.10.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 10:20:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id k4so2688162oik.2
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 10:20:46 -0800 (PST)
X-Received: by 2002:aca:36c1:: with SMTP id d184mr3344121oia.70.1578680445877;
 Fri, 10 Jan 2020 10:20:45 -0800 (PST)
MIME-Version: 1.0
References: <20200109152322.104466-1-elver@google.com> <20200109152322.104466-3-elver@google.com>
In-Reply-To: <20200109152322.104466-3-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2020 19:20:34 +0100
Message-ID: <CANpmjNNt_+EQHLFZyV5_Wq1frU3A=Rh8y5P7Zjp-0cAU2X7N6w@mail.gmail.com>
Subject: Re: [PATCH -rcu 2/2] kcsan: Rate-limit reporting per data races
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W+bQEbU2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Thu, 9 Jan 2020 at 16:23, Marco Elver <elver@google.com> wrote:
>
> Adds support for rate limiting reports. This uses a time based rate
> limit, that limits any given data race report to no more than one in a
> fixed time window (default is 3 sec). This should prevent the console
> from being spammed with data race reports, that would render the system
> unusable.
>
> The implementation assumes that unique data races and the rate at which
> they occur is bounded, since we cannot store arbitrarily many past data
> race report information: we use a fixed-size array to store the required
> information. We cannot use kmalloc/krealloc and resize the list when
> needed, as reporting is triggered by the instrumentation calls; to
> permit using KCSAN on the allocators, we cannot (re-)allocate any memory
> during report generation (data races in the allocators lead to
> deadlock).
>
> Reported-by: Qian Cai <cai@lca.pw>
> Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/report.c | 112 ++++++++++++++++++++++++++++++++++++++----
>  lib/Kconfig.kcsan     |  10 ++++
>  2 files changed, 112 insertions(+), 10 deletions(-)
>
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 9f503ca2ff7a..e324af7d14c9 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,6 +1,7 @@
>  // SPDX-License-Identifier: GPL-2.0
>
>  #include <linux/kernel.h>
> +#include <linux/ktime.h>
>  #include <linux/preempt.h>
>  #include <linux/printk.h>
>  #include <linux/sched.h>
> @@ -31,12 +32,101 @@ static struct {
>         int                     num_stack_entries;
>  } other_info = { .ptr = NULL };
>
> +/*
> + * Information about reported data races; used to rate limit reporting.
> + */
> +struct report_time {
> +       /*
> +        * The last time the data race was reported.
> +        */
> +       ktime_t time;
> +
> +       /*
> +        * The frames of the 2 threads; if only 1 thread is known, one frame
> +        * will be 0.
> +        */
> +       unsigned long frame1;
> +       unsigned long frame2;
> +};
> +
> +/*
> + * Since we also want to be able to debug allocators with KCSAN, to avoid
> + * deadlock, report_times cannot be dynamically resized with krealloc in
> + * rate_limit_report.
> + *
> + * Therefore, we use a fixed-size array, which at most will occupy a page. This
> + * still adequately rate limits reports, assuming that a) number of unique data
> + * races is not excessive, and b) occurrence of unique data races within the
> + * same time window is limited.
> + */
> +#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
> +#define REPORT_TIMES_SIZE                                                      \
> +       (CONFIG_KCSAN_REPORT_ONCE_IN_MS > REPORT_TIMES_MAX ?                   \
> +                REPORT_TIMES_MAX :                                            \
> +                CONFIG_KCSAN_REPORT_ONCE_IN_MS)
> +static struct report_time report_times[REPORT_TIMES_SIZE];
> +
>  /*
>   * This spinlock protects reporting and other_info, since other_info is usually
>   * required when reporting.
>   */
>  static DEFINE_SPINLOCK(report_lock);
>
> +/*
> + * Checks if the data race identified by thread frames frame1 and frame2 has
> + * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
> + */
> +static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
> +{
> +       struct report_time *use_entry = &report_times[0];
> +       ktime_t now;
> +       ktime_t invalid_before;
> +       int i;
> +
> +       BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 && REPORT_TIMES_SIZE == 0);
> +
> +       if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
> +               return false;
> +
> +       now = ktime_get();
> +       invalid_before = ktime_sub_ms(now, CONFIG_KCSAN_REPORT_ONCE_IN_MS);

Been thinking about this a bit more, and wondering if we should just
use jiffies here?  Don't think we need the precision.

Thanks,
-- Marco

> +       /* Check if a matching data race report exists. */
> +       for (i = 0; i < REPORT_TIMES_SIZE; ++i) {
> +               struct report_time *rt = &report_times[i];
> +
> +               /*
> +                * Must always select an entry for use to store info as we
> +                * cannot resize report_times; at the end of the scan, use_entry
> +                * will be the oldest entry, which ideally also happened before
> +                * KCSAN_REPORT_ONCE_IN_MS ago.
> +                */
> +               if (ktime_before(rt->time, use_entry->time))
> +                       use_entry = rt;
> +
> +               /*
> +                * Initially, no need to check any further as this entry as well
> +                * as following entries have never been used.
> +                */
> +               if (rt->time == 0)
> +                       break;
> +
> +               /* Check if entry expired. */
> +               if (ktime_before(rt->time, invalid_before))
> +                       continue; /* before KCSAN_REPORT_ONCE_IN_MS ago */
> +
> +               /* Reported recently, check if data race matches. */
> +               if ((rt->frame1 == frame1 && rt->frame2 == frame2) ||
> +                   (rt->frame1 == frame2 && rt->frame2 == frame1))
> +                       return true;
> +       }
> +
> +       use_entry->time = now;
> +       use_entry->frame1 = frame1;
> +       use_entry->frame2 = frame2;
> +       return false;
> +}
> +
>  /*
>   * Special rules to skip reporting.
>   */
> @@ -132,7 +222,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>         unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
>         int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
>         int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
> -       int other_skipnr;
> +       unsigned long this_frame = stack_entries[skipnr];
> +       unsigned long other_frame = 0;
> +       int other_skipnr = 0; /* silence uninit warnings */
>
>         /*
>          * Must check report filter rules before starting to print.
> @@ -143,34 +235,34 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>         if (type == KCSAN_REPORT_RACE_SIGNAL) {
>                 other_skipnr = get_stack_skipnr(other_info.stack_entries,
>                                                 other_info.num_stack_entries);
> +               other_frame = other_info.stack_entries[other_skipnr];
>
>                 /* @value_change is only known for the other thread */
> -               if (skip_report(other_info.access_type, value_change,
> -                               other_info.stack_entries[other_skipnr]))
> +               if (skip_report(other_info.access_type, value_change, other_frame))
>                         return false;
>         }
>
> +       if (rate_limit_report(this_frame, other_frame))
> +               return false;
> +
>         /* Print report header. */
>         pr_err("==================================================================\n");
>         switch (type) {
>         case KCSAN_REPORT_RACE_SIGNAL: {
> -               void *this_fn = (void *)stack_entries[skipnr];
> -               void *other_fn = (void *)other_info.stack_entries[other_skipnr];
>                 int cmp;
>
>                 /*
>                  * Order functions lexographically for consistent bug titles.
>                  * Do not print offset of functions to keep title short.
>                  */
> -               cmp = sym_strcmp(other_fn, this_fn);
> +               cmp = sym_strcmp((void *)other_frame, (void *)this_frame);
>                 pr_err("BUG: KCSAN: data-race in %ps / %ps\n",
> -                      cmp < 0 ? other_fn : this_fn,
> -                      cmp < 0 ? this_fn : other_fn);
> +                      (void *)(cmp < 0 ? other_frame : this_frame),
> +                      (void *)(cmp < 0 ? this_frame : other_frame));
>         } break;
>
>         case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
> -               pr_err("BUG: KCSAN: data-race in %pS\n",
> -                      (void *)stack_entries[skipnr]);
> +               pr_err("BUG: KCSAN: data-race in %pS\n", (void *)this_frame);
>                 break;
>
>         default:
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 3f78b1434375..3552990abcfe 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -81,6 +81,16 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
>           KCSAN_WATCH_SKIP. If false, the chosen value is always
>           KCSAN_WATCH_SKIP.
>
> +config KCSAN_REPORT_ONCE_IN_MS
> +       int "Duration in milliseconds, in which any given data race is only reported once"
> +       default 3000
> +       help
> +         Any given data race is only reported once in the defined time window.
> +         Different data races may still generate reports within a duration
> +         that is smaller than the duration defined here. This allows rate
> +         limiting reporting to avoid flooding the console with reports.
> +         Setting this to 0 disables rate limiting.
> +
>  # Note that, while some of the below options could be turned into boot
>  # parameters, to optimize for the common use-case, we avoid this because: (a)
>  # it would impact performance (and we want to avoid static branch for all
> --
> 2.25.0.rc1.283.g88dfdc4193-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNt_%2BEQHLFZyV5_Wq1frU3A%3DRh8y5P7Zjp-0cAU2X7N6w%40mail.gmail.com.
