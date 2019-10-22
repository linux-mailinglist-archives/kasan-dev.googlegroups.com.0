Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQPHXTWQKGQEULGYSHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 483CFE09B3
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 18:52:19 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id d11sf5563565ioc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 09:52:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571763138; cv=pass;
        d=google.com; s=arc-20160816;
        b=o37eYRmfs8dTMDXCS5Z5LEizkeO4PjFpTQcCz6RykUrIcp0CvivkaSwVylskV65MME
         qVSs8DbkQY6LfMaYQb0n3Xc4Lklm6TKosi1l/e6meWvXhVmaxQ0/JcvjL4WfgMLOOPez
         g/zq3sGouRr8lRQLbuDsIJDtVwAd5qpNMhFdiNUgD0Vg7QavRS4Nslo4wtmRBhz1mGYd
         cNR0QJeT26MoxbbsyreeNZjt3/F7qVXtWQFD8YC8AHFfxTyPYdQJZjMWu6YTYUu+EFFR
         C5Bm1csV4M0Wdfib7y3zcfoJypXul/RCP7LahMJcrjasGRi2xD9hrI/olPpmLpSMHmMe
         nEbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ed/aGAYgizVlHOzOaSnJ7LQoSxmz4783DhwGgSJEJyc=;
        b=fX7hu4QpQstwiCWFpChNsk9gujs0aVgqL8B4x70QAVMqhOOAheqbByS5yJU/7DVVJT
         WkoZKYNE/ML2e+qvNKzSWa1LpXr9ioARKJRgdLXv42lVECldaeI9wk/9keHbXcf/wPcU
         F9Ysu3Sds95qD4+VYvr6+JXK+HYjwht90dg80fOdcTSxoi53OVJszhMxe6luvfJNa95T
         hPwIG3KX52jVvFEUOv+yAzE9+N32n2nhaKZKrTopCF+xFgMfpaVgsVHgGMk2Zy/bdyX3
         KUKy7jG1iKUvnIiIu1vl3FtuAqHy5/XQ2ShOL11tQBU/rBk+4ahNsXuWJ6NAPYBtM34E
         Dccg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W7dwyFSZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ed/aGAYgizVlHOzOaSnJ7LQoSxmz4783DhwGgSJEJyc=;
        b=Ni9uuxvFHJyUas6BWcbXfCYgtTDn3Rg4ufR9JY1Anw6kWrqMFRLfRjZ3SgbWegwnza
         7CGpA+bpyoaaMKKO1Im3PnKbzqGw18O0bTjMq1X/frkSN8F570L0kz+hCZnpnzI59V+f
         /SnbGtIq9npx91K8z+8uNUdDLvqracDVknAmo5fwoMSCiipJQZ+qdNSR65uxQ3IGgH9t
         DSrLKvpkBIBAP5QeNqH6dHUbISTIuIeTSedObc8NOyZeaUIS2nRTWNYUi7GLtw/ZWhOU
         uj5Xd0EnVAwDATmfW03iRm8bG9CZ6D5WQs2/NWp4Hp+fWUJiH0Yho8hc15LN/h+rbEyH
         2s7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ed/aGAYgizVlHOzOaSnJ7LQoSxmz4783DhwGgSJEJyc=;
        b=RNJh6aRssq3HisRqKJbNgVF8qkSh9kLVuS0PqxRC92j636MlDJ9AuhvPvx9gPX5D5I
         vEYbiRBSzACfHLdk8diA9wKYyg/ssOQJXtH+2ukplcYFFc28L8t6LMcQwHwZSR3h7B34
         sVbZscdBV+oWLZGHOuVwQKMCXwFwmA5mALBpjFjPQx0jcbm21xTPPydFmvSJOQFZtDJP
         Ks4PN+qCcFLHBZ7wB0nS9WNNL86NDrkw80o6Pp7eU7S0oAIifr3DDkJSgztLe41HU/Ba
         +MApvRTrbIBSPMdYlblJO33TfYeZTa3cNoFywLEWRWQwsYbocwHiAFogCNRHc7wOz7vK
         XnjA==
X-Gm-Message-State: APjAAAXR8Yl5Gm0V/2sjgkuiMWx2VGY2VoeDkQp/U+YQGCinkVLnNdMv
	181MVyKsjMK8wgc+RAHT2+s=
X-Google-Smtp-Source: APXvYqwY3aC0LykS8GvDuRlYijbCl/F4KB6+KxbiMaBREwVSYlh9J+u51DulKx9ubF+7R7clkkSDkw==
X-Received: by 2002:a92:1642:: with SMTP id r63mr6501604ill.83.1571763137849;
        Tue, 22 Oct 2019 09:52:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b104:: with SMTP id t4ls3833442ilh.1.gmail; Tue, 22 Oct
 2019 09:52:17 -0700 (PDT)
X-Received: by 2002:a92:9f02:: with SMTP id u2mr4945760ili.241.1571763137439;
        Tue, 22 Oct 2019 09:52:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571763137; cv=none;
        d=google.com; s=arc-20160816;
        b=PTWf3FzP3SOjQ6V8ZR4HqaS7p1Bie/w9YKJVkF2pUvftfP/khxevacDlWVwDKnWNKq
         5GNsuN/ONMNRlYbk+qwv8fxPbpVSjuY9dnk91OClVF/ru4xrGAcBgB9IwrSrC0ehb//e
         SA04W2wACbDC8qD3Fj+3gRJ7QCeIoVvJAOoKne1nzpFH0Y4yfq/Yo5hxgJAJ6X6YrOuP
         qoK0ALDQSZ7TIAjeiO4/O3+XRglXMw0V9w9054BsslyWn5jEpU0f2fGzI7+4GNuoAZTQ
         aTJCyGx5pwSMXEzCg8Bn0KTb5gkwdxe/33nBqEy58WoGTb+/DVCmnomb0PQx6Uzft1SP
         bWjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C8Rn6LDgQaZ0OS/R+WSy3tEdJu49xR/zZV4L+3dNvaA=;
        b=Etts3PvLMrAn2xD26Gu4ugZlSmxQNfgmhAFNR1uJufRNjF/0O5+SOoXet/tWkWaxwv
         s3MhFKG6tNZN//iBrovIBtCk/630SPigYUQzSZBRdh/9MSqfCLlOAGWy91desx6dFDbj
         XXsfOUQmn9sU+iQ+kU1OPM9N+8fDjDTV+WfHF9SgSIp+rpqVWnS2Gou/GQqDUlDB76Zj
         u9TxLIG6VWdC44eVEul1FdexdRTHWZJXsAHpzI/FVebRLmNnI0o1xRyRjOkk4ZJVQxm1
         MTxUID3uhaqCDiXYunX4QHmiH4PoOGF6KYYL2q28sUX4YgK/y4XB2g0a0qgNRfGHqvan
         yfAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W7dwyFSZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id k11si357673ilg.4.2019.10.22.09.52.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Oct 2019 09:52:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id s71so1924431oih.11
        for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2019 09:52:17 -0700 (PDT)
X-Received: by 2002:aca:f1a:: with SMTP id 26mr3773484oip.172.1571763136488;
 Tue, 22 Oct 2019 09:52:16 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-2-elver@google.com>
 <20191022141103.GE11583@lakrids.cambridge.arm.com>
In-Reply-To: <20191022141103.GE11583@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2019 18:52:03 +0200
Message-ID: <CANpmjNPO7hn6cEQp9BXZByvE6WVkUVUEjO6AKpDPYYcwtbhBwQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W7dwyFSZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

Hi Mark,

Thanks for you comments; see inline comments below.

On Tue, 22 Oct 2019 at 16:11, Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Marco,
>
> On Thu, Oct 17, 2019 at 04:12:58PM +0200, Marco Elver wrote:
> > Kernel Concurrency Sanitizer (KCSAN) is a dynamic data-race detector for
> > kernel space. KCSAN is a sampling watchpoint-based data-race detector.
> > See the included Documentation/dev-tools/kcsan.rst for more details.
> >
> > This patch adds basic infrastructure, but does not yet enable KCSAN for
> > any architecture.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Elaborate comment about instrumentation calls emitted by compilers.
> > * Replace kcsan_check_access(.., {true, false}) with
> >   kcsan_check_{read,write} for improved readability.
> > * Change bug title of race of unknown origin to just say "data-race in".
> > * Refine "Key Properties" in kcsan.rst, and mention observed slow-down.
> > * Add comment about safety of find_watchpoint without user_access_save.
> > * Remove unnecessary preempt_disable/enable and elaborate on comment why
> >   we want to disable interrupts and preemptions.
> > * Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
> >   contexts [Suggested by Mark Rutland].
>
> This is generally looking good to me.
>
> I have a few comments below. Those are mostly style and naming things to
> minimize surprise, though I also have a couple of queries (nested vs
> flat atomic regions and the number of watchpoints).
>
> [...]
>
> > diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
> > new file mode 100644
> > index 000000000000..fd5de2ba3a16
> > --- /dev/null
> > +++ b/include/linux/kcsan.h
> > @@ -0,0 +1,108 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +#ifndef _LINUX_KCSAN_H
> > +#define _LINUX_KCSAN_H
> > +
> > +#include <linux/types.h>
> > +#include <linux/kcsan-checks.h>
> > +
> > +#ifdef CONFIG_KCSAN
> > +
> > +/*
> > + * Context for each thread of execution: for tasks, this is stored in
> > + * task_struct, and interrupts access internal per-CPU storage.
> > + */
> > +struct kcsan_ctx {
> > +     int disable; /* disable counter */
>
> Can we call this disable_count? That would match the convention used for
> preempt_count, and make it clear this isn't a boolean.

Done for v3.

> > +     int atomic_next; /* number of following atomic ops */
>
> I'm a little unclear on why we need this given the begin ... end
> helpers -- isn't knowing that we're in an atomic region sufficient?

Sadly no, this is all due to seqlock usage. See seqlock patch for explanation.

> > +
> > +     /*
> > +      * We use separate variables to store if we are in a nestable or flat
> > +      * atomic region. This helps make sure that an atomic region with
> > +      * nesting support is not suddenly aborted when a flat region is
> > +      * contained within. Effectively this allows supporting nesting flat
> > +      * atomic regions within an outer nestable atomic region. Support for
> > +      * this is required as there are cases where a seqlock reader critical
> > +      * section (flat atomic region) is contained within a seqlock writer
> > +      * critical section (nestable atomic region), and the "mismatching
> > +      * kcsan_end_atomic()" warning would trigger otherwise.
> > +      */
> > +     int atomic_region;
> > +     bool atomic_region_flat;
> > +};
>
> I think we need to introduce nestability and flatness first. How about:

Thanks, updated wording to read better hopefully.

>         /*
>          * Some atomic sequences are flat, and cannot contain another
>          * atomic sequence. Other atomic sequences are nestable, and may
>          * contain other flat and/or nestable sequences.
>          *
>          * For example, a seqlock writer critical section is nestable
>          * and may contain a seqlock reader critical section, which is
>          * flat.
>          *
>          * To support this we track the depth of nesting, and whether
>          * the leaf level is flat.
>          */
>         int atomic_nest_count;
>         bool in_flat_atomic;
>
> That said, I'm not entirely clear on the distinction. Why would nesting
> a reader within another reader not be legitimate?

It is legitimate, however, seqlock reader critical sections do not
always have a balance begin/end. I ran into trouble initially when
readers were still nestable, as e.g. read_seqcount_retry can be called
multiple times. See seqlock patch for more explanations.

> > +
> > +/**
> > + * kcsan_init - initialize KCSAN runtime
> > + */
> > +void kcsan_init(void);
> > +
> > +/**
> > + * kcsan_disable_current - disable KCSAN for the current context
> > + *
> > + * Supports nesting.
> > + */
> > +void kcsan_disable_current(void);
> > +
> > +/**
> > + * kcsan_enable_current - re-enable KCSAN for the current context
> > + *
> > + * Supports nesting.
> > + */
> > +void kcsan_enable_current(void);
> > +
> > +/**
> > + * kcsan_begin_atomic - use to denote an atomic region
> > + *
> > + * Accesses within the atomic region may appear to race with other accesses but
> > + * should be considered atomic.
> > + *
> > + * @nest true if regions may be nested, or false for flat region
> > + */
> > +void kcsan_begin_atomic(bool nest);
> > +
> > +/**
> > + * kcsan_end_atomic - end atomic region
> > + *
> > + * @nest must match argument to kcsan_begin_atomic().
> > + */
> > +void kcsan_end_atomic(bool nest);
> > +
>
> Similarly to the check_{read,write}() naming, could we get rid of the
> bool argument and split this into separate nestable and flat functions?
>
> That makes it easier to read in-context, e.g.
>
>         kcsan_nestable_atomic_begin();
>         ...
>         kcsan_nestable_atomic_end();
>
> ... has a more obvious meaning than:
>
>         kcsan_begin_atomic(true);
>         ...
>         kcsan_end_atomic(true);
>
> ... and putting the begin/end at the end of the name makes it easier to
> spot the matching pair.

Thanks, done for v3.

> [...]
>
> > +static inline bool is_enabled(void)
> > +{
> > +     return READ_ONCE(kcsan_enabled) && get_ctx()->disable == 0;
> > +}
>
> Can we please make this kcsan_is_enabled(), to avoid confusion with
> IS_ENABLED()?

Done for v3.

> > +static inline unsigned int get_delay(void)
> > +{
> > +     unsigned int max_delay = in_task() ? CONFIG_KCSAN_UDELAY_MAX_TASK :
> > +                                          CONFIG_KCSAN_UDELAY_MAX_INTERRUPT;
> > +     return IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
> > +                    ((prandom_u32() % max_delay) + 1) :
> > +                    max_delay;
> > +}
> > +
> > +/* === Public interface ===================================================== */
> > +
> > +void __init kcsan_init(void)
> > +{
> > +     BUG_ON(!in_task());
> > +
> > +     kcsan_debugfs_init();
> > +     kcsan_enable_current();
> > +#ifdef CONFIG_KCSAN_EARLY_ENABLE
> > +     /*
> > +      * We are in the init task, and no other tasks should be running.
> > +      */
> > +     WRITE_ONCE(kcsan_enabled, true);
> > +#endif
>
> Where possible, please use IS_ENABLED() rather than ifdeffery for
> portions of functions like this, e.g.
>
>         /*
>          * We are in the init task, and no other tasks should be running.
>          */
>         if (IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE))
>                 WRITE_ONCE(kcsan_enabled, true);
>
> That makes code a bit easier to read, and ensures that the code always
> gets build coverage, so it's less likely that code changes will
> introduce a build failure when the option is enabled.

Thanks, done for v3.

> [...]
>
> > +#ifdef CONFIG_KCSAN_DEBUG
> > +     kcsan_disable_current();
> > +     pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
> > +            is_write ? "write" : "read", size, ptr,
> > +            watchpoint_slot((unsigned long)ptr),
> > +            encode_watchpoint((unsigned long)ptr, size, is_write));
> > +     kcsan_enable_current();
> > +#endif
>
> This can use IS_ENABLED(), e.g.
>
>         if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
>                 kcsan_disable_current();
>                 pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
>                        is_write ? "write" : "read", size, ptr,
>                        watchpoint_slot((unsigned long)ptr),
>                        encode_watchpoint((unsigned long)ptr, size, is_write));
>                 kcsan_enable_current();
>         }
>
> [...]
> > +#ifdef CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> > +             kcsan_report(ptr, size, is_write, smp_processor_id(),
> > +                          kcsan_report_race_unknown_origin);
> > +#endif
>
> This can also use IS_ENABLED().

Done for v3.

> [...]
>
> > diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> > new file mode 100644
> > index 000000000000..429479b3041d
> > --- /dev/null
> > +++ b/kernel/kcsan/kcsan.h
> > @@ -0,0 +1,140 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +#ifndef _MM_KCSAN_KCSAN_H
> > +#define _MM_KCSAN_KCSAN_H
> > +
> > +#include <linux/kcsan.h>
> > +
> > +/*
> > + * Total number of watchpoints. An address range maps into a specific slot as
> > + * specified in `encoding.h`. Although larger number of watchpoints may not even
> > + * be usable due to limited thread count, a larger value will improve
> > + * performance due to reducing cache-line contention.
> > + */
> > +#define KCSAN_NUM_WATCHPOINTS 64
>
> Is there any documentation as to how 64 was chosen? It's fine if it's
> arbitrary, but it would be good to know either way.

It was arbitrary in the sense that I chose the largest value that I
think is an acceptable overhead in terms of storage, i.e. on 64-bit
watchpoints consume 512 bytes. It should always be large enough so
that "no_capacity" counter does not increase frequently.

> I wonder if this is something that might need to scale with NR_CPUS (or
> nr_cpus).

I think this is hard to say. I've decided to make it configurable in
v3, with a BUILD_BUG_ON to ensure its value is within expected bounds.

> > +enum kcsan_counter_id {
> > +     /*
> > +      * Number of watchpoints currently in use.
> > +      */
> > +     kcsan_counter_used_watchpoints,
>
> Nit: typically enum values are capitalized (as coding-style.rst says).
> That helps to make it clear each value is a constant rather than a
> variable. Likewise for the other enums here.

Done for v3.

Thanks,
-- Marco

> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPO7hn6cEQp9BXZByvE6WVkUVUEjO6AKpDPYYcwtbhBwQ%40mail.gmail.com.
