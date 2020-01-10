Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMA4PYAKGQE4XLOZBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id ECDC81375F4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 19:19:42 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id v24sf1569854plo.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 10:19:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578680381; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/0nXJUArioV6PCoKIywIxIEwsybpAmPmdjcQFod4XZuPf9nwYKBLHKUHtYJr0y4GD
         E78ngE52gKEskfN/caw7sFwt7iWJUmrpsxaGNP6AlkfJMI8XifmR25wYN6j7S+GvvSd6
         mHsVg1RIZGc0JOjNXKwDmor/RdpP9zM/Tda3bJF8kThzgSVq0o8kKINT8+98PbViZltB
         joMM2XK7BZipMvTEGocu5OqITdrjkR+wWyKI54iuWln5N/3lNbcJhMiRNuVQHxBolkHv
         MH58Kf4I8kLRsGfiDTw67iqDyuQZnAnfRwbCgkIlFwLxsihm6r2aBTymOBboN8re6dG/
         +8kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4iVAT7b7/z6V7mv4q+6TIR8R8wV9dwQsCaqfJO9bpCE=;
        b=rQpeAnY9bzTXptsDCEEGe1FsG2A7wfRkGMjzQFdC2ENK3JjKTfX0tjxDA3PYEKbv8E
         qOOk4mm//j80n3VT1nnVrdvYrHknPJrM+qMF7Kvim4oW63ka8JEzUrDb12DBCvKIDHjZ
         MqEV6YVjlRQl2eI7FhNOss9N7ce53Q+B6MJ5N3g9WeM7DR2/jg9/WwV4HI9Y6H9zgf1j
         XC6LcqiuQL8drpDSDAwKN9NB1kyGBCK42IkSz6hWePSTSWadcm1LvhWqiMuOicHH20La
         +cyv8fMtUC0UmHpl5oL1ZxjgAK4L2E5sUC6wFOOseNItF2GzI38lkDBTsJYwWkZkmYfF
         lruw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vWdDNT1c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4iVAT7b7/z6V7mv4q+6TIR8R8wV9dwQsCaqfJO9bpCE=;
        b=FCXhEjMVZNhF6wJEjnz+GEVDNct0qzsxXqlDDB1vBXMOSQS1Nplr0OmqOwyigaFX+G
         m1tRnh1vG8w7E1YVJAPCwtoS+P0rVmS+9dWeteoLy+DHz8gNu6M3I4yrl3ivpd5A/zZ0
         YM599/SSjfq3Q0uwvRwpuJwIqOBi7Kx8/qTU/oJJxq6yFxprE8xaCjVTyS5xpsoFsjsO
         IhOso9LWL5G4a5sPm3swPFviNpa1BdL+a9JCiqWFUiPxr19rfttT/0ixR1R2+fwXV4LH
         5HdM9LK5fPos7p8rwJSBEhKZo93RPU+4az0fytv+hXC1qnMnSMEBtb28xBx71bx3f5iS
         0b+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4iVAT7b7/z6V7mv4q+6TIR8R8wV9dwQsCaqfJO9bpCE=;
        b=Y8iM7Z6Tit9wp2fUpKTWLCoRnaCnVMWSTbb/fBf4Qdf0a0yKtp1gZfVbOUzEn4uqi2
         yDXAeNMo9Sg3K3k2s6RdlldMTNOyVMsYhu/DIBmGDNE4JjVNURIrsnytq6ZaqYzuwd3v
         uUBHuq5ZDzJKErkPuDjrxyafdOCNWB2lifM+G1Y2fXbkEfNTPfAi7TUnbR9eV37mCxHy
         Pfq1FJBGB9q080JXUvaUidYjCfwFNuE/KUjkc051KaMjExGmi8Wx22L7Uy+O146lxdFr
         0AXuK/z/2k8IxS/f06i/yW91fZV+rHIumnMoGRIsQd5+ssELGcQYRrU+nI6E3RlH7R2R
         m64A==
X-Gm-Message-State: APjAAAWcPwfBmMwRCGL2r4F3eZxuH8HjDIhdAm43vLpHzpI9evRuTmiy
	uBmztGhUGTsKv4MynLHBAxU=
X-Google-Smtp-Source: APXvYqzMoT61cR3S8RmlXiNIyD4vKscRF/+Z18IwfylreS7trfCWiyKSvjuY6OhM0nlJcrKGl0gvjg==
X-Received: by 2002:aa7:87cf:: with SMTP id i15mr5596917pfo.114.1578680381506;
        Fri, 10 Jan 2020 10:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:864b:: with SMTP id y11ls1636340plt.2.gmail; Fri, 10
 Jan 2020 10:19:41 -0800 (PST)
X-Received: by 2002:a17:902:6501:: with SMTP id b1mr5939265plk.121.1578680380491;
        Fri, 10 Jan 2020 10:19:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578680380; cv=none;
        d=google.com; s=arc-20160816;
        b=SGkde3SKXwJxQGkIns3SArw7Ehv0TTU/8lEEVZ/0aXkhxAlowRgTbEV4tar3v2WGVc
         hw6+SkHWTMw2gLSKlr1LmDdpQy9Q0fQRHAs/FeBG3LTAypOYmel47Vn1qrz5inUXqeak
         Lw/kdzE1k+lC5cVJ+qopSfrvKRDwKJoYRJeLu1Lr/luYu2C2pwSe+AhB2O6Ek/VRiXPR
         DSZ+YSWfxLgQF2MzOjhAafXwryQkOhScSa/9/jevDHGeKuNOr0hfYbDf8cw352R3inkQ
         3uIfnokJf6+Kx1gI99XuJf/80zIDbT+iCfLu3jW6yj20ee0AJpWD13BmpGWLA0AY/Nby
         o6Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YIVMByshgU+GZmYsdxjKz53iEsTl2gm3eDz8KItITko=;
        b=W+ESZc27AtrUT7VVDSkPYrU6Ri6MRhAxZmP2nY9hi3itsKLb+mAoPx35bipIxCqfH4
         U12SN6KAGBsSF4CIeNe1wSK7Eh2RPnfPBw5P0Q/eKSg3yWqR+idO3dKA6zOsQhtOGiuy
         mV1ohWA3MrRthTSjKiZ4hXNtsQdJwvRCUZpEcLchRnnWy9v5Te18SGU4envmtyuyVRT5
         xiLpyZ+6x5YZWfHg589Tgic2/PjjHZ+kduJLB/DG6PImnoIe2+y87j2QcMefsoIWF078
         SQlLZSPqaNMeRiLpjhmh78F1T1+RaAsIxMeT1gTtcYYqv2YJg7rzvVGJBOEKXDR0WR9k
         1h0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vWdDNT1c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id d9si148683pls.5.2020.01.10.10.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 10:19:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id d62so2628207oia.11
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 10:19:40 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr3054689oiz.155.1578680379834;
 Fri, 10 Jan 2020 10:19:39 -0800 (PST)
MIME-Version: 1.0
References: <20200109152322.104466-1-elver@google.com> <20200109152322.104466-3-elver@google.com>
In-Reply-To: <20200109152322.104466-3-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2020 19:19:28 +0100
Message-ID: <CANpmjNMa5EEC-qojZGw_3zYdoXJjg5CqBVrWyDNOhYt4YZ3CiQ@mail.gmail.com>
Subject: Re: [PATCH -rcu 2/2] kcsan: Rate-limit reporting per data races
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Qian Cai <cai@lca.pw>
Content-Type: multipart/alternative; boundary="0000000000004150d8059bcd2b3b"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vWdDNT1c;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as
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

--0000000000004150d8059bcd2b3b
Content-Type: text/plain; charset="UTF-8"

On Thu, 9 Jan 2020 at 16:23, Marco Elver <elver@google.com> wrote:

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
> +        * The frames of the 2 threads; if only 1 thread is known, one
> frame
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
> + * Therefore, we use a fixed-size array, which at most will occupy a
> page. This
> + * still adequately rate limits reports, assuming that a) number of
> unique data
> + * races is not excessive, and b) occurrence of unique data races within
> the
> + * same time window is limited.
> + */
> +#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
> +#define REPORT_TIMES_SIZE
>       \
> +       (CONFIG_KCSAN_REPORT_ONCE_IN_MS > REPORT_TIMES_MAX ?
>      \
> +                REPORT_TIMES_MAX :
>     \
> +                CONFIG_KCSAN_REPORT_ONCE_IN_MS)
> +static struct report_time report_times[REPORT_TIMES_SIZE];
> +
>  /*
>   * This spinlock protects reporting and other_info, since other_info is
> usually
>   * required when reporting.
>   */
>  static DEFINE_SPINLOCK(report_lock);
>
> +/*
> + * Checks if the data race identified by thread frames frame1 and frame2
> has
> + * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
> + */
> +static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
> +{
> +       struct report_time *use_entry = &report_times[0];
> +       ktime_t now;
> +       ktime_t invalid_before;
> +       int i;
> +
> +       BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 &&
> REPORT_TIMES_SIZE == 0);
> +
> +       if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
> +               return false;
> +
> +       now = ktime_get();
> +       invalid_before = ktime_sub_ms(now, CONFIG_KCSAN_REPORT_ONCE_IN_MS);
>

Been thinking about this a bit more, and wondering if we should just use
jiffies here?  Don't think we need the precision.

Thanks,
-- Marco


> +       /* Check if a matching data race report exists. */
> +       for (i = 0; i < REPORT_TIMES_SIZE; ++i) {
> +               struct report_time *rt = &report_times[i];
> +
> +               /*
> +                * Must always select an entry for use to store info as we
> +                * cannot resize report_times; at the end of the scan,
> use_entry
> +                * will be the oldest entry, which ideally also happened
> before
> +                * KCSAN_REPORT_ONCE_IN_MS ago.
> +                */
> +               if (ktime_before(rt->time, use_entry->time))
> +                       use_entry = rt;
> +
> +               /*
> +                * Initially, no need to check any further as this entry
> as well
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
> @@ -132,7 +222,9 @@ static bool print_report(const volatile void *ptr,
> size_t size, int access_type,
>         unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
>         int num_stack_entries = stack_trace_save(stack_entries,
> NUM_STACK_ENTRIES, 1);
>         int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
> -       int other_skipnr;
> +       unsigned long this_frame = stack_entries[skipnr];
> +       unsigned long other_frame = 0;
> +       int other_skipnr = 0; /* silence uninit warnings */
>
>         /*
>          * Must check report filter rules before starting to print.
> @@ -143,34 +235,34 @@ static bool print_report(const volatile void *ptr,
> size_t size, int access_type,
>         if (type == KCSAN_REPORT_RACE_SIGNAL) {
>                 other_skipnr = get_stack_skipnr(other_info.stack_entries,
>
> other_info.num_stack_entries);
> +               other_frame = other_info.stack_entries[other_skipnr];
>
>                 /* @value_change is only known for the other thread */
> -               if (skip_report(other_info.access_type, value_change,
> -                               other_info.stack_entries[other_skipnr]))
> +               if (skip_report(other_info.access_type, value_change,
> other_frame))
>                         return false;
>         }
>
> +       if (rate_limit_report(this_frame, other_frame))
> +               return false;
> +
>         /* Print report header. */
>
> pr_err("==================================================================\n");
>         switch (type) {
>         case KCSAN_REPORT_RACE_SIGNAL: {
> -               void *this_fn = (void *)stack_entries[skipnr];
> -               void *other_fn = (void
> *)other_info.stack_entries[other_skipnr];
>                 int cmp;
>
>                 /*
>                  * Order functions lexographically for consistent bug
> titles.
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
> +               pr_err("BUG: KCSAN: data-race in %pS\n", (void
> *)this_frame);
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
> +       int "Duration in milliseconds, in which any given data race is
> only reported once"
> +       default 3000
> +       help
> +         Any given data race is only reported once in the defined time
> window.
> +         Different data races may still generate reports within a duration
> +         that is smaller than the duration defined here. This allows rate
> +         limiting reporting to avoid flooding the console with reports.
> +         Setting this to 0 disables rate limiting.
> +
>  # Note that, while some of the below options could be turned into boot
>  # parameters, to optimize for the common use-case, we avoid this because:
> (a)
>  # it would impact performance (and we want to avoid static branch for all
> --
> 2.25.0.rc1.283.g88dfdc4193-goog
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMa5EEC-qojZGw_3zYdoXJjg5CqBVrWyDNOhYt4YZ3CiQ%40mail.gmail.com.

--0000000000004150d8059bcd2b3b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Thu, 9 Jan 2020 at 16:23, Marco El=
ver &lt;<a href=3D"mailto:elver@google.com">elver@google.com</a>&gt; wrote:=
<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8=
ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">Adds support fo=
r rate limiting reports. This uses a time based rate<br>
limit, that limits any given data race report to no more than one in a<br>
fixed time window (default is 3 sec). This should prevent the console<br>
from being spammed with data race reports, that would render the system<br>
unusable.<br>
<br>
The implementation assumes that unique data races and the rate at which<br>
they occur is bounded, since we cannot store arbitrarily many past data<br>
race report information: we use a fixed-size array to store the required<br=
>
information. We cannot use kmalloc/krealloc and resize the list when<br>
needed, as reporting is triggered by the instrumentation calls; to<br>
permit using KCSAN on the allocators, we cannot (re-)allocate any memory<br=
>
during report generation (data races in the allocators lead to<br>
deadlock).<br>
<br>
Reported-by: Qian Cai &lt;<a href=3D"mailto:cai@lca.pw" target=3D"_blank">c=
ai@lca.pw</a>&gt;<br>
Suggested-by: Paul E. McKenney &lt;<a href=3D"mailto:paulmck@kernel.org" ta=
rget=3D"_blank">paulmck@kernel.org</a>&gt;<br>
Signed-off-by: Marco Elver &lt;<a href=3D"mailto:elver@google.com" target=
=3D"_blank">elver@google.com</a>&gt;<br>
---<br>
=C2=A0kernel/kcsan/report.c | 112 ++++++++++++++++++++++++++++++++++++++---=
-<br>
=C2=A0lib/Kconfig.kcsan=C2=A0 =C2=A0 =C2=A0|=C2=A0 10 ++++<br>
=C2=A02 files changed, 112 insertions(+), 10 deletions(-)<br>
<br>
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c<br>
index 9f503ca2ff7a..e324af7d14c9 100644<br>
--- a/kernel/kcsan/report.c<br>
+++ b/kernel/kcsan/report.c<br>
@@ -1,6 +1,7 @@<br>
=C2=A0// SPDX-License-Identifier: GPL-2.0<br>
<br>
=C2=A0#include &lt;linux/kernel.h&gt;<br>
+#include &lt;linux/ktime.h&gt;<br>
=C2=A0#include &lt;linux/preempt.h&gt;<br>
=C2=A0#include &lt;linux/printk.h&gt;<br>
=C2=A0#include &lt;linux/sched.h&gt;<br>
@@ -31,12 +32,101 @@ static struct {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 int=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0num_stack_entries;<br>
=C2=A0} other_info =3D { .ptr =3D NULL };<br>
<br>
+/*<br>
+ * Information about reported data races; used to rate limit reporting.<br=
>
+ */<br>
+struct report_time {<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 * The last time the data race was reported.<br=
>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0ktime_t time;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 * The frames of the 2 threads; if only 1 threa=
d is known, one frame<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 * will be 0.<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned long frame1;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned long frame2;<br>
+};<br>
+<br>
+/*<br>
+ * Since we also want to be able to debug allocators with KCSAN, to avoid<=
br>
+ * deadlock, report_times cannot be dynamically resized with krealloc in<b=
r>
+ * rate_limit_report.<br>
+ *<br>
+ * Therefore, we use a fixed-size array, which at most will occupy a page.=
 This<br>
+ * still adequately rate limits reports, assuming that a) number of unique=
 data<br>
+ * races is not excessive, and b) occurrence of unique data races within t=
he<br>
+ * same time window is limited.<br>
+ */<br>
+#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))<br>
+#define REPORT_TIMES_SIZE=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 \<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0(CONFIG_KCSAN_REPORT_ONCE_IN_MS &gt; REPORT_TIM=
ES_MAX ?=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0\<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 REPORT_TIMES_MAX :=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 \<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 CONFIG_KCSAN_REPOR=
T_ONCE_IN_MS)<br>
+static struct report_time report_times[REPORT_TIMES_SIZE];<br>
+<br>
=C2=A0/*<br>
=C2=A0 * This spinlock protects reporting and other_info, since other_info =
is usually<br>
=C2=A0 * required when reporting.<br>
=C2=A0 */<br>
=C2=A0static DEFINE_SPINLOCK(report_lock);<br>
<br>
+/*<br>
+ * Checks if the data race identified by thread frames frame1 and frame2 h=
as<br>
+ * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).<br>
+ */<br>
+static bool rate_limit_report(unsigned long frame1, unsigned long frame2)<=
br>
+{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0struct report_time *use_entry =3D &amp;report_t=
imes[0];<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0ktime_t now;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0ktime_t invalid_before;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0int i;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS !=
=3D 0 &amp;&amp; REPORT_TIMES_SIZE =3D=3D 0);<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (CONFIG_KCSAN_REPORT_ONCE_IN_MS =3D=3D 0)<br=
>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return false;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0now =3D ktime_get();<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0invalid_before =3D ktime_sub_ms(now, CONFIG_KCS=
AN_REPORT_ONCE_IN_MS);<br></blockquote><div><br></div><div>Been thinking ab=
out this a bit more, and wondering if we should just use jiffies here?=C2=
=A0 Don&#39;t think we need the precision.</div><div><br></div><div>Thanks,=
</div><div>-- Marco</div><div>=C2=A0</div><blockquote class=3D"gmail_quote"=
 style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);p=
adding-left:1ex">
+=C2=A0 =C2=A0 =C2=A0 =C2=A0/* Check if a matching data race report exists.=
 */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0for (i =3D 0; i &lt; REPORT_TIMES_SIZE; ++i) {<=
br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0struct report_time =
*rt =3D &amp;report_times[i];<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * Must always sele=
ct an entry for use to store info as we<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * cannot resize re=
port_times; at the end of the scan, use_entry<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * will be the olde=
st entry, which ideally also happened before<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * KCSAN_REPORT_ONC=
E_IN_MS ago.<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (ktime_before(rt=
-&gt;time, use_entry-&gt;time))<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0use_entry =3D rt;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * Initially, no ne=
ed to check any further as this entry as well<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * as following ent=
ries have never been used.<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (rt-&gt;time =3D=
=3D 0)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0break;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/* Check if entry e=
xpired. */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (ktime_before(rt=
-&gt;time, invalid_before))<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0continue; /* before KCSAN_REPORT_ONCE_IN_MS ago */<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/* Reported recentl=
y, check if data race matches. */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if ((rt-&gt;frame1 =
=3D=3D frame1 &amp;&amp; rt-&gt;frame2 =3D=3D frame2) ||<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0(rt-&=
gt;frame1 =3D=3D frame2 &amp;&amp; rt-&gt;frame2 =3D=3D frame1))<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0return true;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0use_entry-&gt;time =3D now;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0use_entry-&gt;frame1 =3D frame1;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0use_entry-&gt;frame2 =3D frame2;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0return false;<br>
+}<br>
+<br>
=C2=A0/*<br>
=C2=A0 * Special rules to skip reporting.<br>
=C2=A0 */<br>
@@ -132,7 +222,9 @@ static bool print_report(const volatile void *ptr, size=
_t size, int access_type,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 unsigned long stack_entries[NUM_STACK_ENTRIES] =
=3D { 0 };<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 int num_stack_entries =3D stack_trace_save(stac=
k_entries, NUM_STACK_ENTRIES, 1);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 int skipnr =3D get_stack_skipnr(stack_entries, =
num_stack_entries);<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0int other_skipnr;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned long this_frame =3D stack_entries[skip=
nr];<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned long other_frame =3D 0;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0int other_skipnr =3D 0; /* silence uninit warni=
ngs */<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 /*<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0* Must check report filter rules before s=
tarting to print.<br>
@@ -143,34 +235,34 @@ static bool print_report(const volatile void *ptr, si=
ze_t size, int access_type,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (type =3D=3D KCSAN_REPORT_RACE_SIGNAL) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 other_skipnr =3D ge=
t_stack_skipnr(other_info.stack_entries,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 other_info.num_stack_entries);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0other_frame =3D oth=
er_info.stack_entries[other_skipnr];<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 /* @value_change is=
 only known for the other thread */<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (skip_report(oth=
er_info.access_type, value_change,<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0other_info.stack_entries[other_skipnr=
]))<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (skip_report(oth=
er_info.access_type, value_change, other_frame))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 return false;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (rate_limit_report(this_frame, other_frame))=
<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return false;<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 /* Print report header. */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D\n&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 switch (type) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 case KCSAN_REPORT_RACE_SIGNAL: {<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0void *this_fn =3D (=
void *)stack_entries[skipnr];<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0void *other_fn =3D =
(void *)other_info.stack_entries[other_skipnr];<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 int cmp;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 /*<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0* Order funct=
ions lexographically for consistent bug titles.<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0* Do not prin=
t offset of functions to keep title short.<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0*/<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0cmp =3D sym_strcmp(=
other_fn, this_fn);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0cmp =3D sym_strcmp(=
(void *)other_frame, (void *)this_frame);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;BUG: K=
CSAN: data-race in %ps / %ps\n&quot;,<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 cmp &lt; 0 ? other_fn : this_fn,<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 cmp &lt; 0 ? this_fn : other_fn);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 (void *)(cmp &lt; 0 ? other_frame : this_frame),<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 (void *)(cmp &lt; 0 ? this_frame : other_frame));<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } break;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;BUG: K=
CSAN: data-race in %pS\n&quot;,<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 (void *)stack_entries[skipnr]);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;BUG: K=
CSAN: data-race in %pS\n&quot;, (void *)this_frame);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 break;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 default:<br>
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan<br>
index 3f78b1434375..3552990abcfe 100644<br>
--- a/lib/Kconfig.kcsan<br>
+++ b/lib/Kconfig.kcsan<br>
@@ -81,6 +81,16 @@ config KCSAN_SKIP_WATCH_RANDOMIZE<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 KCSAN_WATCH_SKIP. If false, the chosen v=
alue is always<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 KCSAN_WATCH_SKIP.<br>
<br>
+config KCSAN_REPORT_ONCE_IN_MS<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0int &quot;Duration in milliseconds, in which an=
y given data race is only reported once&quot;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0default 3000<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0help<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Any given data race is only reported onc=
e in the defined time window.<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Different data races may still generate =
reports within a duration<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0that is smaller than the duration define=
d here. This allows rate<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0limiting reporting to avoid flooding the=
 console with reports.<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Setting this to 0 disables rate limiting=
.<br>
+<br>
=C2=A0# Note that, while some of the below options could be turned into boo=
t<br>
=C2=A0# parameters, to optimize for the common use-case, we avoid this beca=
use: (a)<br>
=C2=A0# it would impact performance (and we want to avoid static branch for=
 all<br>
-- <br>
2.25.0.rc1.283.g88dfdc4193-goog<br>
<br>
</blockquote></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CANpmjNMa5EEC-qojZGw_3zYdoXJjg5CqBVrWyDNOhYt4YZ3CiQ%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CANpmjNMa5EEC-qojZGw_3zYdoXJjg5CqBVrWyDNOhYt4YZ3CiQ=
%40mail.gmail.com</a>.<br />

--0000000000004150d8059bcd2b3b--
