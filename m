Return-Path: <kasan-dev+bncBCMIZB7QWENRB4F74XUQKGQEPWEHOTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FC7274877
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 09:53:21 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id i132sf19228486oif.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 00:53:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564041200; cv=pass;
        d=google.com; s=arc-20160816;
        b=TgvnfpfnpgukZ/m3elqbuoESWMcS+ggrONEeNc4ywkTFTRxAS8wVsskRMkfGlJ1pBP
         FXW1ryA6WiaQjxjdq8GbEXF/Vn5X0u1hsVR+FRvQcot9oTqyVfkxaUy9+FHR6VWRL46p
         lFR4J/n7G66Bkmf9dMzCjr83v2KblDmPG1yQcz+RMDxF9Z0XDmFume+LTcTfYLrxJs5G
         OqEMzctwL9jJ1ClIwHFHnx6WRoSgyRPMIlOtdNGhLiOMh3fhdLXYc/x96oynznzEMjnp
         oaFcnYNXEA8wShCCYcvFr8SsFDeyazfPYMSSkWKDGzTrWH5JRMeS52tFrAQxdR9L9edI
         DbMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zV1si+BbnJpRI2LpRuVeipeQcTZxoDm1ROZFcvNCBZA=;
        b=R06mA3K/YEQqaOZQ34HPF48wJl2ON2oeexlE0qadolZMEANSJuS3OS+VjxQhAZJXhu
         hH+TmA+IBl8LUP2KlVwlixwwfG7qLn0oCxS7zQHGYoTaknwnIdaYz2WDTDGQAIOwku/s
         hJ2rg4AfkcxC7BnuZr4oPpBaUBjM8FpEIwY+m+f/AvHY+Gb/UuelVTpTPpLaRtkIWpbN
         uxnmbPO3OcFESx8dcM2f7J9pl1DFJiKF+K+ZTQAWBB3gTTCDy9q3zEvtKUP3l+j06RJF
         1zb3uSpCYLHUSjgOaE9w/uZdbXc6QJKyVX8JHHzXVCz3ZpV3n1QvxLZezFr1yYTSUQ9r
         PuYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bfITDNTZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zV1si+BbnJpRI2LpRuVeipeQcTZxoDm1ROZFcvNCBZA=;
        b=o2otfSQqnQ3RLzvdojFq/efBgiBgDvMW081Jre/JUxp4F12lKCzbxPtX62KzJSfXZ+
         6hSyoNyGIbrPElhliPCDn3KsP4kO7WnfIDmyaufcH5lvRASq1ynmhEFuPo8EH7wi+462
         Ztf7I4E+izY+HYiGAnOIxy0Hwe2tuR84s1EQqVEMxlpSibOMiB5eNsvWLK8pPvThrwcv
         fHnYSr6+97qQ9HlvgvFW8nCxfAzKe0k7OEq3pILKQaHR8FPUNrGcOyPogBrpBUXVb05/
         CZETFOFJipKl2m1Lo7N8e0Vp0Sluw3k3KCcDhU9xDx5IeNy9uVf15h+8mHAdMu10OTOW
         TBow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zV1si+BbnJpRI2LpRuVeipeQcTZxoDm1ROZFcvNCBZA=;
        b=q75dWylQFPZpxLjo+xO398iQtzA6SoBSvumeohmyvZYjvp4n3koGS3qCwGTMpQqBMj
         1eu0R502BMgloemkZWbWc58WCgndV9u1LgMXFllyjpFTLcJvQGkKaWc5uDcueR725ChP
         /c6kJ04PqFqwsRpzMkKV8A6ATkLQJYginFm7D10DqpvoxjBiz9FcEFKztU/A0MoYzfmY
         7MvxFtZPMBx3W96nvgXu3uKYjOEBnUJX7COFnowCn9cAh6V5pBKrxbf403fBnkMMGcQw
         +/V0MCXreHxWPiahRP0OMJz6Ioh9MoAr8aKqDUa8xAab7hJaAE6vY1cG6sukjiWkdCVD
         NSAw==
X-Gm-Message-State: APjAAAUV3K4JcbVFCOceqiAIw0x05IzUuffAIk+yTydoPhCBlFZ6PA1/
	8pgnJvAyEKP3AMFaMTScs04=
X-Google-Smtp-Source: APXvYqzgXK60PpyhEBD9rgHvCLQk29q5jUz2hQbIXDKxEVVwoxIYVcNrsuqNukWQBNZ6Pyo6wMCvKw==
X-Received: by 2002:a9d:7c8f:: with SMTP id q15mr36683008otn.24.1564041200152;
        Thu, 25 Jul 2019 00:53:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:afd2:: with SMTP id y201ls6384164oie.7.gmail; Thu, 25
 Jul 2019 00:53:19 -0700 (PDT)
X-Received: by 2002:aca:b788:: with SMTP id h130mr44948053oif.85.1564041199845;
        Thu, 25 Jul 2019 00:53:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564041199; cv=none;
        d=google.com; s=arc-20160816;
        b=IZDTU8Bo0rcM6mh0VLxxpFHmAPhmY8L7kY262qjN+DU7NE6wOg2XH5BpnSECNHRAVe
         BKT2eageXrzX+Mm+kNeV4Ji1ocCHSYjijAqJZPCTF5tPwuo5yvI9J8GfeTlkKMPJUGry
         3loHJQRiT3FECRMfs1a5hMywyphs0E30r9jejaOfNbiU9jy50wCBkZKO9jUuGW8hMvCf
         703oDUdkdepEWvAk2T3D4KFv++9olEjGCj4JtZXSDUIr6wIR3aRVZubb0lva13mM1fxt
         Cwxwg9kox3oco1LCyD6qAY/JXqvQ3X3pneLm6yqlawHat3Y5oZuRc2Rr6o9hvXAitxpn
         8cxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4EYQg8FUzP6g7x2kdeJSMJwD/d2JUeynf50PgVDomsY=;
        b=hRapzp1QoxfAObPUGEqu+fTm6NZFVywNdWphpTpY/fGUikJ02MI8IpCs6cm3yqKHe/
         5pk1ynnB7Nstgnuf9StzNnBXQpo58sTWP9HtTaaNTCxeqAGAghWEe+zT6bsPy+Phxg6K
         RQUQPoYsxVWvJWYhtLlgkpNPaQx3YSAhnX7qOWvYzwFOX0Uu95YBhQ3btx3Ph5vqm2ji
         rF84Kxv6LndKxcYcbtu4os+syNyZa/R7JuiE3SHEoKd7ZolHPl+RGe/SY3jhP6xebIU2
         xHQntlCTeAgbmAvT/WUVXPMpKJP4fII4smUVGJSXf+8OG20Mu6oeA4/c4hqWtgev+8el
         jihg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bfITDNTZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id i6si2047271oii.0.2019.07.25.00.53.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 00:53:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id j6so20141534ioa.5
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 00:53:19 -0700 (PDT)
X-Received: by 2002:a5d:80d6:: with SMTP id h22mr57856594ior.231.1564041199254;
 Thu, 25 Jul 2019 00:53:19 -0700 (PDT)
MIME-Version: 1.0
References: <20190719132818.40258-1-elver@google.com> <20190723164115.GB56959@lakrids.cambridge.arm.com>
 <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com> <20190724112101.GB2624@lakrids.cambridge.arm.com>
In-Reply-To: <20190724112101.GB2624@lakrids.cambridge.arm.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2019 09:53:08 +0200
Message-ID: <CACT4Y+Zai+4VwNXS_a417M2m0DbtNhjTVdYga178ZDkvNnP4CQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Daniel Axtens <dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bfITDNTZ;       spf=pass
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

On Wed, Jul 24, 2019 at 1:21 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Wed, Jul 24, 2019 at 11:11:49AM +0200, Dmitry Vyukov wrote:
> > On Tue, Jul 23, 2019 at 6:41 PM Mark Rutland <mark.rutland@arm.com> wrote:
> > >
> > > On Fri, Jul 19, 2019 at 03:28:17PM +0200, Marco Elver wrote:
> > > > Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
> > > > rather than causing difficult-to-diagnose corruption. Note that, unlike
> > > > virtually-mapped kernel stacks, this will effectively waste an entire page of
> > > > memory; however, this feature may provide extra protection in cases that cannot
> > > > use virtually-mapped kernel stacks, at the cost of a page.
> > > >
> > > > The motivation for this patch is that KASAN cannot use virtually-mapped kernel
> > > > stacks to detect stack overflows. An alternative would be implementing support
> > > > for vmapped stacks in KASAN, but would add significant extra complexity.
> > >
> > > Do we have an idea as to how much additional complexity?
> >
> > We would need to map/unmap shadow for vmalloc region on stack
> > allocation/deallocation. We may need to track shadow pages that cover
> > both stack and an unused memory, or 2 different stacks, which are
> > mapped/unmapped at different times. This may have some concurrency
> > concerns.  Not sure what about page tables for other CPU, I've seen
> > some code that updates pages tables for vmalloc region lazily on page
> > faults. Not sure what about TLBs. Probably also some problems that I
> > can't thought about now.
>
> Ok. So this looks big, we this hasn't been prototyped, so we don't have
> a concrete idea. I agree that concurrency is likely to be painful. :)
>
> [...]
>
> > > > diff --git a/arch/x86/include/asm/page_64_types.h b/arch/x86/include/asm/page_64_types.h
> > > > index 288b065955b7..b218b5713c02 100644
> > > > --- a/arch/x86/include/asm/page_64_types.h
> > > > +++ b/arch/x86/include/asm/page_64_types.h
> > > > @@ -12,8 +12,14 @@
> > > >  #define KASAN_STACK_ORDER 0
> > > >  #endif
> > > >
> > > > +#ifdef CONFIG_STACK_GUARD_PAGE
> > > > +#define STACK_GUARD_SIZE PAGE_SIZE
> > > > +#else
> > > > +#define STACK_GUARD_SIZE 0
> > > > +#endif
> > > > +
> > > >  #define THREAD_SIZE_ORDER    (2 + KASAN_STACK_ORDER)
> > > > -#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
> > > > +#define THREAD_SIZE  ((PAGE_SIZE << THREAD_SIZE_ORDER) - STACK_GUARD_SIZE)
> > >
> > > I'm pretty sure that common code relies on THREAD_SIZE being a
> > > power-of-two. I also know that if we wanted to enable this on arm64 that
> > > would very likely be a requirement.
> > >
> > > For example, in kernel/trace/trace_stack.c we have:
> > >
> > > | this_size = ((unsigned long)stack) & (THREAD_SIZE-1);
> > >
> > > ... and INIT_TASK_DATA() allocates the initial task stack using
> > > THREAD_SIZE, so that may require special care, as it might not be sized
> > > or aligned as you expect.
> >
> > We've built it, booted it, stressed it, everything looked fine... that
> > should have been a build failure.
>
> I think it's been an implicit assumption for so long that no-one saw the need
> for built-time assertions where they depend on it.
>
> I also suspect that in practice there are paths that you won't have
> stressed in your environment, e.g. in the ACPI wakeup path where we end
> up calling:
>
> /* Unpoison the stack for the current task beyond a watermark sp value. */
> asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
> {
>         /*
>          * Calculate the task stack base address.  Avoid using 'current'
>          * because this function is called by early resume code which hasn't
>          * yet set up the percpu register (%gs).
>          */
>         void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
>
>         kasan_unpoison_shadow(base, watermark - base);
> }
>
> > Is it a property that we need to preserve? Or we could fix the uses
> > that assume power-of-2?
>
> Generally, I think that those can be fixed up. Someone just needs to dig
> through how THREAD_SIZE and THREAD_SIZE_ORDER are used to generate or
> manipulate addresses.
>
> For local-task stuff, I think it's easy to rewrite in terms of
> task_stack_page(), but I'm not entirely sure what we'd do for cases
> where we look at another task, e.g.
>
> static int proc_stack_depth(struct seq_file *m, struct pid_namespace *ns,
>                                 struct pid *pid, struct task_struct *task)
> {
>         unsigned long prev_depth = THREAD_SIZE -
>                                 (task->prev_lowest_stack & (THREAD_SIZE - 1));
>         unsigned long depth = THREAD_SIZE -
>                                 (task->lowest_stack & (THREAD_SIZE - 1));
>
>         seq_printf(m, "previous stack depth: %lu\nstack depth: %lu\n",
>                                                         prev_depth, depth);
>         return 0;
> }
>
> ... as I'm not sure of the lifetime of task->stack relative to task. I
> know that with THREAD_INFO_IN_TASK the stack can be freed while the task
> is still live.
>
> Thanks,
> Mark.

FTR, Daniel just mailed:

[PATCH 0/3] kasan: support backing vmalloc space with real shadow memory
https://groups.google.com/forum/#!topic/kasan-dev/YuwLGJYPB4I
Which presumably will supersede this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZai%2B4VwNXS_a417M2m0DbtNhjTVdYga178ZDkvNnP4CQ%40mail.gmail.com.
