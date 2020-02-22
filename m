Return-Path: <kasan-dev+bncBAABBTMHYLZAKGQED6NRQ2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A041168B90
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2020 02:28:47 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id x10sf3745856iob.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 17:28:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582334926; cv=pass;
        d=google.com; s=arc-20160816;
        b=qfI+IXNTPJEigJFYBN3h5l3PAsOyOoZ5ZNwaSzMGPnC0AYljvVTbtB6Uw5JMwyKsDt
         TfD8BoM5+/BX77mn/BWXvyd9Xs1/WyVxZs6R92cfqjvWXuS7Kb4fjNV4OEhcEd5ZFlbj
         RxA+ThmMFHFsAHZZb9E0KgoM/oMjaLF2DkIJS/3SDnzdsZz7rRd5BHjlrAqIWyssAwof
         M5yRt+zsnVv6XWPU7A2blCsOrJnciyfpQoGnQerTyIcvaIuhIpXi9xSpET0qC9krUf54
         aVjmeh8A1aYvixPKrjPpSsPAeadCWxSFWSyYVXzxosxSJVNMwiO5rvQ4fitpyIUd8xYO
         A6zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=3Am34nd7/8DFAt5nKpkyBa2t8wF3nIubKupTz4BZZ/g=;
        b=RbPtP/TPyxCyqskebBJ/YMPVhCJU9YmYy2n2u61F9Mvfqw3iDDdFueY7w0rOZsacjb
         mgpE2P2Z/BIq5EZ1koSKmoRe1yjSSR86/S1q/0I8wYSRtk6opZY/ytT61FJ+BwXQZnfF
         vY23RlM9yeQ+7DF5Br/D9Lyg6P37cgGNXEFnCRbxDcW0ejn3DP5avXtPJE80/WjhgAxt
         uzdXaBldy4C58bfBhH/mtY7V59h44sc5+uhlKBORdJya8ayaZmwjopysEgerNyyDech2
         wdBEp/26PnQtKBeETeLtq3qJ1PqX0kiE+foq+HHvcrjfs0upIH3QJ+ZQKeEQVisx7rHB
         tNug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xjKM7DAI;
       spf=pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Am34nd7/8DFAt5nKpkyBa2t8wF3nIubKupTz4BZZ/g=;
        b=qKehOHXpRzhp247VJ07blHFu/cA4y/2tEklCE5daCnZV0Y+tyJ2u2rZrJilb5QmXhx
         S2XGT2cZfKKdLYqD63KVffrUrgKDDOlCxxScE1FdZ50v0CCF4CsTraR10vP09EXnVjBH
         240KlOyflUvlLpJO97dbDeYbZop+XYhRLfs2MyiTZDO3X8TcqnS/vX4dlXoViFOHxCpt
         rZJ7xLJoEGIPWEJ8eWMODtMZNMtat4oxBXZ302JEyNX5p03xrbSJ9kbXJoB4Vz6zUx/d
         J2oD9e+3rT6sTLWOXA4nRDNA8Svgz0qHiVCPqKnF8Zfvp7vzOSsJ/V2o6xm2UtD/tH/a
         rKig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Am34nd7/8DFAt5nKpkyBa2t8wF3nIubKupTz4BZZ/g=;
        b=I5w5M/7ZTJulJLMeGb2LB0hw28OUDKGchI9lcL8QOFMacf6LD8m2yUBkurJw3K6+rZ
         LRN0d0YE5CTXE2hjTrP3o/t0lx9T1l5w0Ptdso5eW2wFOVdUSMynnCQYOmDtUGDjfHUW
         1chXgPjbELTQSyw/TcbDJqAk9z8iR44QyCq18Zaur9TGqe9BSdaf7yXrHbOlzfoE9N5P
         8SI4bgvp7W7Oy2vbBmhdrV/xnuM9wVBt6xKZuaQ9y6UPv4qLz9wSTnMFGdkh5MebWnlM
         X6gYYz00Z8UrmPRS1/jGiaIkx4AFezGMN6yI5gHuqCr8U52wj4hQe/kmVoSClqyQ7acU
         tdkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVojYZUmBxVobda1oLlhbw0RSOoZOBZJo6kLd6eEhLhgNcBgtnc
	6eOuDzvhNS1xvSuIUkUP3Cw=
X-Google-Smtp-Source: APXvYqwVOwV3Xjihl9C1x7YwG7hzSo0F/yw1XB6B5QJGJxQKBhmmzJnH5a+3tPFDq6cXeCGA6LL04A==
X-Received: by 2002:a92:d608:: with SMTP id w8mr39057103ilm.95.1582334925995;
        Fri, 21 Feb 2020 17:28:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f13:: with SMTP id x19ls862687ilj.0.gmail; Fri, 21
 Feb 2020 17:28:45 -0800 (PST)
X-Received: by 2002:a92:d5c3:: with SMTP id d3mr39893301ilq.250.1582334925628;
        Fri, 21 Feb 2020 17:28:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582334925; cv=none;
        d=google.com; s=arc-20160816;
        b=sPP1MnAV34Jz7AafW6Msc6MOe92NX4p0NGCzob1cnEkyfiJl1gQCIS7na8c/ju02rm
         THWOZMs14MV/2Auuc3k9EHECEODroU9G0RC5AMYdl3C5JgguGjBKe4XTLu1Iiyy6E8Nr
         Q5HWQyB198Hy9SyM4X8qhmgG04jjwc3OzRAsox49BZU5cDT2YQvXy5EvCR2d1g00ozbd
         0GYaKQeJlzZX0B3mLjdG1Wb/z40/uMqY1MgauvxNJDFg8nziTXnIZTR88UHquVcQ6/8+
         eB43Q1sDM/Z92tHdmyLdDzExLtBVPYE9to4hkwBY5u66mS3C7Sy4UQpiGj+vPOsbxd9F
         S6gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=bf5kzm3R9o6FwPUxtnBNxvnWIF6yTpIlBnCSfZjk8aA=;
        b=WiCL1vIbg3RbA7x5tcCpxY3cQlfzBr8PjJRtKVsw/v8onTgFuJy2ftfbpPk2Z5TAij
         oxscSr1tpQNf24aj/jjoMeXQ2OaROI8qnF4YCWlu/aDxPd1G4irBesQiAjC5k0gJVHjr
         rwKgNf1923q3RVyRX5GGYt/JTPD0B2FpUpiyLUZZ63xyodH9tsDZFNeada9PSfuaP5KG
         b+b9ueYTyBHYWJxmN4gr78ic5jf09mPpFyA2FsgVwTHUWX2OINTK2wfeHIGaxBh1U5kR
         eEYDF2a79li8P7X/O2rHrL2wF42FHfXWH0D0F64HcS6+D5Dz5LRcr0YN+HGBuiEm8PvU
         NFww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xjKM7DAI;
       spf=pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b16si241025ion.0.2020.02.21.17.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Feb 2020 17:28:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B631320722;
	Sat, 22 Feb 2020 01:28:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 56BA835226DB; Fri, 21 Feb 2020 17:28:44 -0800 (PST)
Date: Fri, 21 Feb 2020 17:28:44 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v2] kcsan: Add option to allow watcher interruptions
Message-ID: <20200222012844.GN2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200221220209.164772-1-elver@google.com>
 <CANpmjNOnXhX_Edc7=7L072TB5-uv-4nivPEUYNh-=-1EFkYJbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOnXhX_Edc7=7L072TB5-uv-4nivPEUYNh-=-1EFkYJbw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=xjKM7DAI;       spf=pass
 (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Feb 21, 2020 at 11:58:30PM +0100, Marco Elver wrote:
> On Fri, 21 Feb 2020 at 23:02, Marco Elver <elver@google.com> wrote:
> >
> > Add option to allow interrupts while a watchpoint is set up. This can be
> > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > parameter 'kcsan.interrupt_watcher=1'.
> >
> > Note that, currently not all safe per-CPU access primitives and patterns
> > are accounted for, which could result in false positives. For example,
> > asm-generic/percpu.h uses plain operations, which by default are
> > instrumented. On interrupts and subsequent accesses to the same
> > variable, KCSAN would currently report a data race with this option.
> >
> > Therefore, this option should currently remain disabled by default, but
> > may be enabled for specific test scenarios.
> >
> > To avoid new warnings, changes all uses of smp_processor_id() to use the
> > raw version (as already done in kcsan_found_watchpoint()). The exact SMP
> > processor id is for informational purposes in the report, and
> > correctness is not affected.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Change smp_processor_id() to raw_smp_processor_id() as already used in
> >   kcsan_found_watchpoint() to avoid warnings.
> 
> Just noticed this one should probably go before v2 of "kcsan: Add
> option for verbose reporting" as otherwise there may be a minor
> conflict (adjacent lines touched). (Sorry)

Not a problem, "git revert" followed by applying the patches in the
requested order.  ;-)

							Thanx, Paul

> Thanks,
> -- Marco
> 
> > ---
> >  kernel/kcsan/core.c | 34 ++++++++++------------------------
> >  lib/Kconfig.kcsan   | 11 +++++++++++
> >  2 files changed, 21 insertions(+), 24 deletions(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 589b1e7f0f253..e7387fec66795 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -21,6 +21,7 @@ static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> >  static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> >  static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> >  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> > +static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
> >
> >  #ifdef MODULE_PARAM_PREFIX
> >  #undef MODULE_PARAM_PREFIX
> > @@ -30,6 +31,7 @@ module_param_named(early_enable, kcsan_early_enable, bool, 0);
> >  module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
> >  module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
> >  module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
> > +module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
> >
> >  bool kcsan_enabled;
> >
> > @@ -354,7 +356,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >         unsigned long access_mask;
> >         enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
> >         unsigned long ua_flags = user_access_save();
> > -       unsigned long irq_flags;
> > +       unsigned long irq_flags = 0;
> >
> >         /*
> >          * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> > @@ -370,26 +372,9 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >                 goto out;
> >         }
> >
> > -       /*
> > -        * Disable interrupts & preemptions to avoid another thread on the same
> > -        * CPU accessing memory locations for the set up watchpoint; this is to
> > -        * avoid reporting races to e.g. CPU-local data.
> > -        *
> > -        * An alternative would be adding the source CPU to the watchpoint
> > -        * encoding, and checking that watchpoint-CPU != this-CPU. There are
> > -        * several problems with this:
> > -        *   1. we should avoid stealing more bits from the watchpoint encoding
> > -        *      as it would affect accuracy, as well as increase performance
> > -        *      overhead in the fast-path;
> > -        *   2. if we are preempted, but there *is* a genuine data race, we
> > -        *      would *not* report it -- since this is the common case (vs.
> > -        *      CPU-local data accesses), it makes more sense (from a data race
> > -        *      detection point of view) to simply disable preemptions to ensure
> > -        *      as many tasks as possible run on other CPUs.
> > -        *
> > -        * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
> > -        */
> > -       raw_local_irq_save(irq_flags);
> > +       if (!kcsan_interrupt_watcher)
> > +               /* Use raw to avoid lockdep recursion via IRQ flags tracing. */
> > +               raw_local_irq_save(irq_flags);
> >
> >         watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> >         if (watchpoint == NULL) {
> > @@ -507,7 +492,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >                 if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
> >                         kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
> >
> > -               kcsan_report(ptr, size, type, value_change, smp_processor_id(),
> > +               kcsan_report(ptr, size, type, value_change, raw_smp_processor_id(),
> >                              KCSAN_REPORT_RACE_SIGNAL);
> >         } else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
> >                 /* Inferring a race, since the value should not have changed. */
> > @@ -518,13 +503,14 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >
> >                 if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
> >                         kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
> > -                                    smp_processor_id(),
> > +                                    raw_smp_processor_id(),
> >                                      KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
> >         }
> >
> >         kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> >  out_unlock:
> > -       raw_local_irq_restore(irq_flags);
> > +       if (!kcsan_interrupt_watcher)
> > +               raw_local_irq_restore(irq_flags);
> >  out:
> >         user_access_restore(ua_flags);
> >  }
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index f0b791143c6ab..081ed2e1bf7b1 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -88,6 +88,17 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
> >           KCSAN_WATCH_SKIP. If false, the chosen value is always
> >           KCSAN_WATCH_SKIP.
> >
> > +config KCSAN_INTERRUPT_WATCHER
> > +       bool "Interruptible watchers"
> > +       help
> > +         If enabled, a task that set up a watchpoint may be interrupted while
> > +         delayed. This option will allow KCSAN to detect races between
> > +         interrupted tasks and other threads of execution on the same CPU.
> > +
> > +         Currently disabled by default, because not all safe per-CPU access
> > +         primitives and patterns may be accounted for, and therefore could
> > +         result in false positives.
> > +
> >  config KCSAN_REPORT_ONCE_IN_MS
> >         int "Duration in milliseconds, in which any given race is only reported once"
> >         default 3000
> > --
> > 2.25.0.265.gbab2e86ba0-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200222012844.GN2935%40paulmck-ThinkPad-P72.
