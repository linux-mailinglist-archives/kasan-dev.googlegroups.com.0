Return-Path: <kasan-dev+bncBCMIZB7QWENRBY6B4DUQKGQEWH47CJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A4FB72B2D
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 11:12:05 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id 75sf34005831ywb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 02:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563959524; cv=pass;
        d=google.com; s=arc-20160816;
        b=hwyhhTa0YfloYpC5DJGRQjt8A+BqyUMLiycYaZYxHWzOyZC93cTBYu9cDsdEZOiatb
         uF1pob4wKhf40Supb4lcY7xKS+iHDs3q7e3AVoneXSl66jB4e/QlPIajHdrEghzfSbhY
         nQf3qmR52x938FLDKslKhV9KaxJgLsIo8YhtfqzoenU/unPbe3K80fK8LlYiiGaVhIpj
         1dUHo2hvWdW7c0Momdr140YQHtS39oBT/utrRxa+vULWlFgDg4Yyy6ewOuHcIVA7jzII
         CLl93MQvfNY4j3+u0GGrVTC/5dFaJQaHXzso2l+vn8c6sMNz+2JjakcQmpkIo+lGyBF6
         X2/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WP6OpCEENjf+Seeqh1OyTXqklRCjouEwZ8jGw9ApeLI=;
        b=pPgK61YR8dmDRXXF8CIld8cmfhQyiZ8bFkBY3h+drLvn4pP9JDSI5jTBzwEy1arAzM
         T38Kr3FVBuH2DWdTsgB8SX7RUkek9N00L7pVRi/nsw2puSj+m1IDwgMvNJDTIQc47oNc
         xdIYVeGOOhTz7ix0NtFFHMAKvgahdIWyBY1VKUB4euKY6Krlcp71dlUCSyf6czJSFVGC
         torEn4ITMs+c/tgjGd8qiVE40tGhAJ2JUfn3BAQnGOvLcWpXdm/yK4MC2KVQF1YnRaEK
         NTWeUVxEhhNA/unVcgFuV9wWDHbpbh8hgSWEEBk34Chrslr4+IX6g/7EIMNKD6aEE0ES
         89KQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fiyK4t8L;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WP6OpCEENjf+Seeqh1OyTXqklRCjouEwZ8jGw9ApeLI=;
        b=c4uvoC+FPFgxrt/xUGS4OcsRMbN8nF4bNMnKWNxVC9PjS6xTo99XvNeQVKIZ+jLKM+
         TB1upTVCXY8vioH6bBoLoSWiT62SXRcQCFQUSN8e4+if27eD05heKjnl6N+z9omPqNCM
         rE319XCIGG4w74LgcIZNWgpeLy6oizcz+UQw/UFx6r3I0JnefKUSqoOmZDh3vTZSUPX0
         PnvFd5VCkPXvL2g2CaXl4iPSIOiLMz+EPWdXmshY8L5yHD7YhjThSj4zGLK4W0ScFIFm
         Zn2vUzYT+bkmjeYRSMkZqyzoA8IoYL4y7Ux0T6XHzxNPp2wJePcAEmqgO1FWHeF8BYkb
         G6+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WP6OpCEENjf+Seeqh1OyTXqklRCjouEwZ8jGw9ApeLI=;
        b=XM0WXWwL9TlGyHJs3Ja8CXBQUrXAK75RKjX4KS/PQ4arbwDrTZ3xOvU406KE4cjj0X
         yFINp1Kb3CEhGFDj4Oo+Ok8VoJBvqJta6mMWT+0FcnXwsZ77Rj1eL7unW45bRB/Ffbz8
         N2QYkyC+o/wqUY/bJ/fNnBgW310s67wdGj+BytOD3XPfU0+ynKUJVToF7b85dDO61kyK
         TCjrNOncPbuZJ1Yst9JUrvPiLmR/9djhXZmvX/8UmVUFEIY8xqmwM9aBw3oulNIS+nBs
         v7V/qxyT6lXsbbtKrzfkg6S3K5ywScuXM2HgRpyOP4HJKTemWrX7V1wxLDKbRGpfWMZw
         CyUA==
X-Gm-Message-State: APjAAAXab1QxF+8iZRhrb4pNtR2NLG16h8x8CHYtgO3telHKhPsP2PJ3
	3AZc5/Q8oO+MAXYVG3W9r04=
X-Google-Smtp-Source: APXvYqzEikMcd8nWr7aCjTuOHqRUlG1wO3KOnMTR3lOr/BBcBXOkL7fuSO/dHguah1D2NES8Hbj1Eg==
X-Received: by 2002:a25:59c6:: with SMTP id n189mr49483583ybb.306.1563959523779;
        Wed, 24 Jul 2019 02:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d257:: with SMTP id j84ls6283919ybg.10.gmail; Wed, 24
 Jul 2019 02:12:03 -0700 (PDT)
X-Received: by 2002:a25:7156:: with SMTP id m83mr49412004ybc.163.1563959523506;
        Wed, 24 Jul 2019 02:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563959523; cv=none;
        d=google.com; s=arc-20160816;
        b=tXzq5+4kQG2vGyhlLyTgdDDlrVBm2SrCPTJSFbSiWIJPWJBJOSxw1v5smoRjx0mU7R
         u+vR3fYJekW5suZtM7S37jRTIHeI0MxMRiDG3lIBl0xQFRhKDdpSPa7+ypivJJnela0u
         /+aX511wqt8pRH45vfOKsKUW4yLof5L37kBersAlnUyqElkpZU3VTjSWpyisEJexOYOA
         F+Yy659PmPPPdZiWTkEiOYNvsm4Gn2hnDYo+SQSJnTMW+kZ1IzrmCAwf6dy8mr1Djfe/
         VU6ig4Vrj0VbBzJVwN5A1TanpYh/0IK2e22Bkm0R0Z6+Ayj8Vk6HaiCKPcMSV5CSQhH0
         V9HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6sRlylSNczuEnN2aNH3I85pbG0P7MfDaMqfGAEipuRs=;
        b=uac2nBBUhRTaqflAhCR+hX8g4YjJ1AepH+4+S2k+GyV71ruyr1KizvYlgjwgcvGBp7
         jCbBAPSxv4ZO4LtMc3zPd1MxHyT3J1h7R/V6dGNtWDhJ3CwOpelKUkRVtlItNR77pmxS
         YMcvGPj6QX9dmUeeNLr7TShydWsbWB5ZHK69xb0ZM3YuZoV1+u1Eh8Q2RR/VYMadfLOC
         VnFtTcpzKjK3MoDDS6kaP2hAEM5/7pO8/qsiaT8KQJMLiBEt5dsJE4yCbRnNqENrVsxn
         5bKZiacVyXu6ud5nPYJYK30gKLY36Faen27k5TEOdZ5L6pZWuux0/gIb88dUSD+DepMc
         7wTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fiyK4t8L;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id r1si2649495ywg.4.2019.07.24.02.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jul 2019 02:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id j6so12882838ioa.5
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2019 02:12:03 -0700 (PDT)
X-Received: by 2002:a5e:c241:: with SMTP id w1mr70964257iop.58.1563959522535;
 Wed, 24 Jul 2019 02:12:02 -0700 (PDT)
MIME-Version: 1.0
References: <20190719132818.40258-1-elver@google.com> <20190723164115.GB56959@lakrids.cambridge.arm.com>
In-Reply-To: <20190723164115.GB56959@lakrids.cambridge.arm.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Jul 2019 11:11:49 +0200
Message-ID: <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com>
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fiyK4t8L;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43
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

On Tue, Jul 23, 2019 at 6:41 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Jul 19, 2019 at 03:28:17PM +0200, Marco Elver wrote:
> > Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
> > rather than causing difficult-to-diagnose corruption. Note that, unlike
> > virtually-mapped kernel stacks, this will effectively waste an entire page of
> > memory; however, this feature may provide extra protection in cases that cannot
> > use virtually-mapped kernel stacks, at the cost of a page.
> >
> > The motivation for this patch is that KASAN cannot use virtually-mapped kernel
> > stacks to detect stack overflows. An alternative would be implementing support
> > for vmapped stacks in KASAN, but would add significant extra complexity.
>
> Do we have an idea as to how much additional complexity?

We would need to map/unmap shadow for vmalloc region on stack
allocation/deallocation. We may need to track shadow pages that cover
both stack and an unused memory, or 2 different stacks, which are
mapped/unmapped at different times. This may have some concurrency
concerns.  Not sure what about page tables for other CPU, I've seen
some code that updates pages tables for vmalloc region lazily on page
faults. Not sure what about TLBs. Probably also some problems that I
can't thought about now.


> > While the stack-end guard page approach here wastes a page, it is
> > significantly simpler than the alternative.  We assume that the extra
> > cost of a page can be justified in the cases where STACK_GUARD_PAGE
> > would be enabled.
> >
> > Note that in an earlier prototype of this patch, we used
> > 'set_memory_{ro,rw}' functions, which flush the TLBs. This, however,
> > turned out to be unacceptably expensive, especially when run with
> > fuzzers such as Syzkaller, as the kernel would encounter frequent RCU
> > timeouts. The current approach of not flushing the TLB is therefore
> > best-effort, but works in the test cases considered -- any comments on
> > better alternatives or improvements are welcome.
>
> Ouch. I don't think that necessarily applies to other architectures, and
> from my PoV it would be nicer if we could rely on regular vmap'd stacks.
> That way we have one code path, and we can rely on the fault.
>
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Cc: Thomas Gleixner <tglx@linutronix.de>
> > Cc: Ingo Molnar <mingo@redhat.com>
> > Cc: Borislav Petkov <bp@alien8.de>
> > Cc: "H. Peter Anvin" <hpa@zytor.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Mark Rutland <mark.rutland@arm.com>
> > Cc: Peter Zijlstra <peterz@infradead.org>
> > Cc: x86@kernel.org
> > Cc: linux-kernel@vger.kernel.org
> > Cc: kasan-dev@googlegroups.com
> > ---
> >  arch/Kconfig                         | 15 +++++++++++++++
> >  arch/x86/include/asm/page_64_types.h |  8 +++++++-
> >  include/linux/sched/task_stack.h     | 11 +++++++++--
> >  kernel/fork.c                        | 22 +++++++++++++++++++++-
> >  4 files changed, 52 insertions(+), 4 deletions(-)
> >
> > diff --git a/arch/Kconfig b/arch/Kconfig
> > index e8d19c3cb91f..cca3258fff1f 100644
> > --- a/arch/Kconfig
> > +++ b/arch/Kconfig
> > @@ -935,6 +935,21 @@ config LOCK_EVENT_COUNTS
> >         the chance of application behavior change because of timing
> >         differences. The counts are reported via debugfs.
> >
> > +config STACK_GUARD_PAGE
> > +     default n
> > +     bool "Use stack-end page as guard page"
> > +     depends on !VMAP_STACK && ARCH_HAS_SET_DIRECT_MAP && THREAD_INFO_IN_TASK && !STACK_GROWSUP
> > +     help
> > +       Enable this if you want to use the stack-end page as a guard page.
> > +       This causes kernel stack overflows to be caught immediately rather
> > +       than causing difficult-to-diagnose corruption. Note that, unlike
> > +       virtually-mapped kernel stacks, this will effectively waste an entire
> > +       page of memory; however, this feature may provide extra protection in
> > +       cases that cannot use virtually-mapped kernel stacks, at the cost of
> > +       a page. Note that, this option does not implicitly increase the
> > +       default stack size. The main use-case is for KASAN to avoid reporting
> > +       misleading bugs due to stack overflow.
>
> These dependencies can also be satisfied on arm64, but I don't believe
> this will work correctly there, and we'll need something like a
> ARCH_HAS_STACK_GUARD_PAGE symbol so that x86 can opt-in.
>
> On arm64 our exception vectors don't specify an alternative stack, so we
> don't have a direct equivalent to x86 double-fault handler. Our kernel
> stack overflow handling requires explicit tests in the entry assembly
> that are only built (or valid) when VMAP_STACK is selected.
>
> > +
> >  source "kernel/gcov/Kconfig"
> >
> >  source "scripts/gcc-plugins/Kconfig"
> > diff --git a/arch/x86/include/asm/page_64_types.h b/arch/x86/include/asm/page_64_types.h
> > index 288b065955b7..b218b5713c02 100644
> > --- a/arch/x86/include/asm/page_64_types.h
> > +++ b/arch/x86/include/asm/page_64_types.h
> > @@ -12,8 +12,14 @@
> >  #define KASAN_STACK_ORDER 0
> >  #endif
> >
> > +#ifdef CONFIG_STACK_GUARD_PAGE
> > +#define STACK_GUARD_SIZE PAGE_SIZE
> > +#else
> > +#define STACK_GUARD_SIZE 0
> > +#endif
> > +
> >  #define THREAD_SIZE_ORDER    (2 + KASAN_STACK_ORDER)
> > -#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
> > +#define THREAD_SIZE  ((PAGE_SIZE << THREAD_SIZE_ORDER) - STACK_GUARD_SIZE)
>
> I'm pretty sure that common code relies on THREAD_SIZE being a
> power-of-two. I also know that if we wanted to enable this on arm64 that
> would very likely be a requirement.
>
> For example, in kernel/trace/trace_stack.c we have:
>
> | this_size = ((unsigned long)stack) & (THREAD_SIZE-1);
>
> ... and INIT_TASK_DATA() allocates the initial task stack using
> THREAD_SIZE, so that may require special care, as it might not be sized
> or aligned as you expect.


We've built it, booted it, stressed it, everything looked fine... that
should have been a build failure.
Is it a property that we need to preserve? Or we could fix the uses
that assume power-of-2?


> >  #define EXCEPTION_STACK_ORDER (0 + KASAN_STACK_ORDER)
> >  #define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)
> > diff --git a/include/linux/sched/task_stack.h b/include/linux/sched/task_stack.h
> > index 2413427e439c..7ee86ad0a282 100644
> > --- a/include/linux/sched/task_stack.h
> > +++ b/include/linux/sched/task_stack.h
> > @@ -11,6 +11,13 @@
> >
> >  #ifdef CONFIG_THREAD_INFO_IN_TASK
> >
> > +#ifndef STACK_GUARD_SIZE
> > +#ifdef CONFIG_STACK_GUARD_PAGE
> > +#error "Architecture not compatible with STACK_GUARD_PAGE"
> > +#endif
> > +#define STACK_GUARD_SIZE 0
> > +#endif
>
> The core code you add assumes that when enabled, this is PAGE_SIZE, so
> I think the definition should live in a common header.
>
> As above, it should not be possible to select CONFIG_STACK_GUARD_PAGE
> unless the architecture supports it. If nothing else, this avoids
> getting bug reports on randconfigs.
>
> Thanks,
> Mark.
>
> > +
> >  /*
> >   * When accessing the stack of a non-current task that might exit, use
> >   * try_get_task_stack() instead.  task_stack_page will return a pointer
> > @@ -18,14 +25,14 @@
> >   */
> >  static inline void *task_stack_page(const struct task_struct *task)
> >  {
> > -     return task->stack;
> > +     return task->stack + STACK_GUARD_SIZE;
> >  }
> >
> >  #define setup_thread_stack(new,old)  do { } while(0)
> >
> >  static inline unsigned long *end_of_stack(const struct task_struct *task)
> >  {
> > -     return task->stack;
> > +     return task->stack + STACK_GUARD_SIZE;
> >  }
> >
> >  #elif !defined(__HAVE_THREAD_FUNCTIONS)
> > diff --git a/kernel/fork.c b/kernel/fork.c
> > index d8ae0f1b4148..22033b03f7da 100644
> > --- a/kernel/fork.c
> > +++ b/kernel/fork.c
> > @@ -94,6 +94,7 @@
> >  #include <linux/livepatch.h>
> >  #include <linux/thread_info.h>
> >  #include <linux/stackleak.h>
> > +#include <linux/set_memory.h>
> >
> >  #include <asm/pgtable.h>
> >  #include <asm/pgalloc.h>
> > @@ -249,6 +250,14 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
> >                                            THREAD_SIZE_ORDER);
> >
> >       if (likely(page)) {
> > +             if (IS_ENABLED(CONFIG_STACK_GUARD_PAGE)) {
> > +                     /*
> > +                      * Best effort: do not flush TLB to avoid the overhead
> > +                      * of flushing all TLBs.
> > +                      */
> > +                     set_direct_map_invalid_noflush(page);
> > +             }
> > +
> >               tsk->stack = page_address(page);
> >               return tsk->stack;
> >       }
> > @@ -258,6 +267,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
> >
> >  static inline void free_thread_stack(struct task_struct *tsk)
> >  {
> > +     struct page* stack_page;
> >  #ifdef CONFIG_VMAP_STACK
> >       struct vm_struct *vm = task_stack_vm_area(tsk);
> >
> > @@ -285,7 +295,17 @@ static inline void free_thread_stack(struct task_struct *tsk)
> >       }
> >  #endif
> >
> > -     __free_pages(virt_to_page(tsk->stack), THREAD_SIZE_ORDER);
> > +     stack_page = virt_to_page(tsk->stack);
> > +
> > +     if (IS_ENABLED(CONFIG_STACK_GUARD_PAGE)) {
> > +             /*
> > +              * Avoid flushing TLBs, and instead rely on spurious fault
> > +              * detection of stale TLBs.
> > +              */
> > +             set_direct_map_default_noflush(stack_page);
> > +     }
> > +
> > +     __free_pages(stack_page, THREAD_SIZE_ORDER);
> >  }
> >  # else
> >  static struct kmem_cache *thread_stack_cache;
> > --
> > 2.22.0.657.g960e92d24f-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3%2Bw%40mail.gmail.com.
