Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIWBYHZAKGQEF7SQV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C5C24168A25
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 23:58:43 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id x69sf4114472ill.14
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 14:58:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582325922; cv=pass;
        d=google.com; s=arc-20160816;
        b=nMDCN9Y3h0oOxTUl62NYzX0gWhsJJrHebXK4dSiJqPe/G+XuUSLOSxANWnnnUrM+Fk
         LrTrHGACITpFYboDtTzXYyh2uyAQynYoToIWfX7uBbpUS+T+4tx+CUx0Krzcr+zicEjj
         aaI5yIosVQkJfiy5iiU/+XPDjaJzODqXkIPyGEA2kW1rsGw5qfFpAoWcMEXs3sUrIx03
         GP0xIli0qlgCNBaZuYU5q6W9ZmOgaY+2vAT59HFtGGOVYTnp1iRABlCQTte7XTsKVyo6
         hPLbI0+E/mOIkIji1pmS5EJr0DVvNg1991DbbHIcnhnXI+frLLwWF2t/RoX6tGDH2o2A
         /wIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EB8dDkE0vWA9bxGr7sZjPcia8wE7MvTQweC3YALyPu0=;
        b=nTSHbCKI1DcIEyLq0IYLEl0rcV71wnbOwdk9X3Kx+bnoh5b3ahrdDarwrS5JDDO/4O
         paFsxTxzBF/TTh44gcAZhwkvDJyZe/Ry+Ms4xLSnw8kGaGvTcjItUtz0xsL1bXjf0UR4
         XH6ZjAViFcTYnJsujOQ3u8oMCSFa0pq7crduJv7BKuW2TF+t8hdAJ5sMXReoboU8iQRf
         UiVhG1XyyfZfyK6lH69Udf/A51ILHnNZ1CtrpDoj7ekMozisOl1Im3aPhDB02IEcIrFy
         WKMYPr+LtZcy+l1dCA341fgH6V05K5gq+OxKqSGE+y6WOiuItDrOG+eW01tGfBSS4mB9
         hYkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I+NTz+bB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EB8dDkE0vWA9bxGr7sZjPcia8wE7MvTQweC3YALyPu0=;
        b=ehac3Wv1wrZe2mLIvYHZ5XNxfEOzZGcu1ftix8c2Fzp7VorwaDLb5cwtajyREASlrk
         Z8t9ntrziYY+kbqkP2gatF8NcEi+WORRx52PlokUNLg7+x/0z0zB4Ft6WuQQZutOyXfR
         ixlNnPJ8auNYNnf8s+mBZYcbo6WgobcVVzgKuLJEiuOKD9BFT4Qfyivuh3zKWywvFeYB
         iOPTQE4dwC6KOIJqGOuvv6zVoz2RgaMYJ+jNMe4gsOlAEqeXjxTWkhax206oz4jG82At
         kGUK4zkl/nziH23GUsgwLA645JGcOrUwgq4rpvCGBeSizzfxYmS90fPNfSpGrtQhJyoz
         Pv3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EB8dDkE0vWA9bxGr7sZjPcia8wE7MvTQweC3YALyPu0=;
        b=C578vepUm1VpUqIMJssxHzttRXJjzol1GU/zYQxhMpcD66oLN6BoDb5fOw78XyI8zt
         tFkc6/xA4IJT4h3b1vpM3yGJkZJZiaA073HE64rgsbA5K8N9YgEMxou7leuecJawWWen
         tLUHKfdNFzcp5ANXLN9DxvmBmzlU6+LdyhomHNVjIBIsPXVwYdq4Lqh6SfCqfIc0ol1Y
         aDepZ2qF+3iN4ylLbZqvBIG2B4fQq/rcflM3uLIYZ9Gnc3Neft6UQLXWQejY0SyXaJdx
         s5CR2FW0DI5tvmkGqsPftKIJ0gmsYjsmXVLdsbLijhPF45b+hGx3vK9PXH5wlxUuS0ub
         9WDA==
X-Gm-Message-State: APjAAAWldW6XOJkkz4k9P4ByzRq9ctsHfTby+qTS1JyEJBLgism/dTW5
	YVYom7RL3tl65jCQWBQ243E=
X-Google-Smtp-Source: APXvYqwBpMkG9g58wUFUv/nYQYDUFiUYW0JdB0ZGcsH/hzK7ajYbdTlXWnA4TFhe4wFB3rK3jCTr0w==
X-Received: by 2002:a92:d3c6:: with SMTP id c6mr41140966ilh.228.1582325922384;
        Fri, 21 Feb 2020 14:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3d8b:: with SMTP id k11ls787851ilf.10.gmail; Fri, 21 Feb
 2020 14:58:42 -0800 (PST)
X-Received: by 2002:a92:60f:: with SMTP id x15mr38379105ilg.181.1582325921974;
        Fri, 21 Feb 2020 14:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582325921; cv=none;
        d=google.com; s=arc-20160816;
        b=UqULhG8k5PbCCGv753tlV5w9OI0HXq1cvrFZ+CTD7Trg5CSujB8rRSMUW9bLZRmOAg
         sSYPA7ZcKzdDdqAU0QqukB7zV1Y93d1mMriFw6mtbsxycX+P+zEVCyYYG3R+2fE6Y2PV
         uQVoLvVMzr4wnggybVUlPlU9xOmWKT6jXMQX5oVhpxsAwnCL1ZYoQsmmAbF0B9roQth9
         CF3zr9bFnhSxvMTSFs1/X0tpmLZKZUERNUhGLqYzcobOOjUl6iVbblwBKwplKg7LQAqM
         11IkhmE8L3DmyZhzXToxoxMIBTCNaiPzxP/y72f1VdkovAGZD1tZcRPM5TKOqZEikV6u
         Rfvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZbyeYRXgDIes5s9xa5B9SEl5uluy49ubtkBwGsyY6g4=;
        b=YC3Stm3VlDINxKAZIwawFrH11jecxJVwD2gABhYPfv2QGLa3uBcNKHvfx36Ci//6oj
         904I9xPRgEICnLJeTkdHkjSnqmij5h+TsFeXJZ199QHmfiZy3AhXLgZLE/JYVFcEUfu9
         TvCPew5euAZsyarHD8TBE11cDL6OsyuL0BVOiLZjh8s+3T9U9fnChNR5PeiSNYzR29mA
         KL0jAE+hp7vm85qbWF5fFgLcl4Qo23F6ey184hpTZNpBTFGef6nbh8h1KGiR+byTPAz8
         3QPBgInYgHExF3mIgDzM7f+PLDhzyQRr55xX+JpyQhGJuvG92rmqYOcsE4l52dmU5/OB
         Ufkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I+NTz+bB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id z20si311614ill.5.2020.02.21.14.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 14:58:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id j20so3568314otq.3
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 14:58:41 -0800 (PST)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr31177927otk.23.1582325921271;
 Fri, 21 Feb 2020 14:58:41 -0800 (PST)
MIME-Version: 1.0
References: <20200221220209.164772-1-elver@google.com>
In-Reply-To: <20200221220209.164772-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Feb 2020 23:58:30 +0100
Message-ID: <CANpmjNOnXhX_Edc7=7L072TB5-uv-4nivPEUYNh-=-1EFkYJbw@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: Add option to allow watcher interruptions
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I+NTz+bB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 21 Feb 2020 at 23:02, Marco Elver <elver@google.com> wrote:
>
> Add option to allow interrupts while a watchpoint is set up. This can be
> enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> parameter 'kcsan.interrupt_watcher=1'.
>
> Note that, currently not all safe per-CPU access primitives and patterns
> are accounted for, which could result in false positives. For example,
> asm-generic/percpu.h uses plain operations, which by default are
> instrumented. On interrupts and subsequent accesses to the same
> variable, KCSAN would currently report a data race with this option.
>
> Therefore, this option should currently remain disabled by default, but
> may be enabled for specific test scenarios.
>
> To avoid new warnings, changes all uses of smp_processor_id() to use the
> raw version (as already done in kcsan_found_watchpoint()). The exact SMP
> processor id is for informational purposes in the report, and
> correctness is not affected.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Change smp_processor_id() to raw_smp_processor_id() as already used in
>   kcsan_found_watchpoint() to avoid warnings.

Just noticed this one should probably go before v2 of "kcsan: Add
option for verbose reporting" as otherwise there may be a minor
conflict (adjacent lines touched). (Sorry)

Thanks,
-- Marco

> ---
>  kernel/kcsan/core.c | 34 ++++++++++------------------------
>  lib/Kconfig.kcsan   | 11 +++++++++++
>  2 files changed, 21 insertions(+), 24 deletions(-)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 589b1e7f0f253..e7387fec66795 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -21,6 +21,7 @@ static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
>  static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
>  static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
>  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> +static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
>
>  #ifdef MODULE_PARAM_PREFIX
>  #undef MODULE_PARAM_PREFIX
> @@ -30,6 +31,7 @@ module_param_named(early_enable, kcsan_early_enable, bool, 0);
>  module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
>  module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
>  module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
> +module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
>
>  bool kcsan_enabled;
>
> @@ -354,7 +356,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>         unsigned long access_mask;
>         enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
>         unsigned long ua_flags = user_access_save();
> -       unsigned long irq_flags;
> +       unsigned long irq_flags = 0;
>
>         /*
>          * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> @@ -370,26 +372,9 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>                 goto out;
>         }
>
> -       /*
> -        * Disable interrupts & preemptions to avoid another thread on the same
> -        * CPU accessing memory locations for the set up watchpoint; this is to
> -        * avoid reporting races to e.g. CPU-local data.
> -        *
> -        * An alternative would be adding the source CPU to the watchpoint
> -        * encoding, and checking that watchpoint-CPU != this-CPU. There are
> -        * several problems with this:
> -        *   1. we should avoid stealing more bits from the watchpoint encoding
> -        *      as it would affect accuracy, as well as increase performance
> -        *      overhead in the fast-path;
> -        *   2. if we are preempted, but there *is* a genuine data race, we
> -        *      would *not* report it -- since this is the common case (vs.
> -        *      CPU-local data accesses), it makes more sense (from a data race
> -        *      detection point of view) to simply disable preemptions to ensure
> -        *      as many tasks as possible run on other CPUs.
> -        *
> -        * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
> -        */
> -       raw_local_irq_save(irq_flags);
> +       if (!kcsan_interrupt_watcher)
> +               /* Use raw to avoid lockdep recursion via IRQ flags tracing. */
> +               raw_local_irq_save(irq_flags);
>
>         watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
>         if (watchpoint == NULL) {
> @@ -507,7 +492,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>                 if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
>                         kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
>
> -               kcsan_report(ptr, size, type, value_change, smp_processor_id(),
> +               kcsan_report(ptr, size, type, value_change, raw_smp_processor_id(),
>                              KCSAN_REPORT_RACE_SIGNAL);
>         } else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
>                 /* Inferring a race, since the value should not have changed. */
> @@ -518,13 +503,14 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>
>                 if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
>                         kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
> -                                    smp_processor_id(),
> +                                    raw_smp_processor_id(),
>                                      KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
>         }
>
>         kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>  out_unlock:
> -       raw_local_irq_restore(irq_flags);
> +       if (!kcsan_interrupt_watcher)
> +               raw_local_irq_restore(irq_flags);
>  out:
>         user_access_restore(ua_flags);
>  }
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index f0b791143c6ab..081ed2e1bf7b1 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -88,6 +88,17 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
>           KCSAN_WATCH_SKIP. If false, the chosen value is always
>           KCSAN_WATCH_SKIP.
>
> +config KCSAN_INTERRUPT_WATCHER
> +       bool "Interruptible watchers"
> +       help
> +         If enabled, a task that set up a watchpoint may be interrupted while
> +         delayed. This option will allow KCSAN to detect races between
> +         interrupted tasks and other threads of execution on the same CPU.
> +
> +         Currently disabled by default, because not all safe per-CPU access
> +         primitives and patterns may be accounted for, and therefore could
> +         result in false positives.
> +
>  config KCSAN_REPORT_ONCE_IN_MS
>         int "Duration in milliseconds, in which any given race is only reported once"
>         default 3000
> --
> 2.25.0.265.gbab2e86ba0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnXhX_Edc7%3D7L072TB5-uv-4nivPEUYNh-%3D-1EFkYJbw%40mail.gmail.com.
