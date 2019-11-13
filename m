Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4V5WDXAKGQE3ZOWCIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B3B2BFB38E
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2019 16:19:15 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id w16sf1851820pfq.14
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2019 07:19:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573658354; cv=pass;
        d=google.com; s=arc-20160816;
        b=l71G+8yEPpJ7JZZSG+EekWiDw5XGsWbI/EwlllgbYj7cKKwKY9vzTibV/gZjHaErhJ
         e5RK9ydvMk09yzElrGKyLpp0/kRCRztTlOnUTJqVrigegRdxeWPxssfF/tGBBXj3lhzf
         l+cf0MJKJCvl+qR2wx+OAwvIyAS4LnIyh8sEUj4+ozhZTdhW08udEyl66rtDIVEm+f7C
         NNp61i+u9BIWtxXqc9wxU2yG0vb1QxV9widvMwGjddZXTfj1Ph0DQks9Lgw5UOHJXtTa
         AQU3kPSrYACmtFOrSPqoKwO9WkgOIEaX2DPe6+Aa7XEHdteWhYRmzr/GW8/GX/hHv83W
         u0VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wzp0IvHlCH+XK3236M/utrWVNDZP/3xYOnQg+utp8VM=;
        b=U4l7HSiYi/BBB1oHJTO6X5y7go+CUjrTp5m+NcESgiOS4d4DggxohBA66MrYS9q/yR
         LyTOJfyLmPBoWiVvhCcatxSG6fEqTHYseUqZX2qN1Q908F+inE7vB7cGlDK4lKto6JX7
         3BJ+5MfMYui+rOnSe7fWlvtWE4wBIzNRgtIvNCIHfRsshL44iZVXDSVRKIeg13uErOPc
         0q13KJASHhXncjneeeMy8z/DSK6G3mf0EQ5tffCgv4OP4Xaz+++l+wghQhGfMv+/XSnE
         xIGsRNreiqJU7nCFqWK4jZvAJY+drnEzIbP3O8gKySkMcWwLL/bQO0lqv4OBSYwkXQco
         oHNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P58mPzYU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzp0IvHlCH+XK3236M/utrWVNDZP/3xYOnQg+utp8VM=;
        b=Gf0kvaZahax44w+HT+L2khJxxvCMtEA7wg6w6DfjGzj1kYhA0S4t3JKqg+0Z6qc5S9
         yxLZPD30JD7P0CZJ9O6o4WJ1NDNH2oZJb1HuMietcw++tzyeSQBZSz3vHrPsSUBGzt8G
         OrCMdf5W6VHSkHecBL45RiqSYin+GIPQZZOyWF1o0FDvk71K78JoxodMjq+tF4KnIVsr
         b3Lvhs6Zp4ZECYGeGjX5pfa59tAzXhxzGXDHz9bckRUJiJUFVOO8OqQ2wrjyfXWFvh+V
         chcu/tGKntjPl/sS7r3eF2ixkcrP1Pvzs+5o0Qg9p5wAikSvxWWKcwyNRAYzNA/Jl2vy
         4Jtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzp0IvHlCH+XK3236M/utrWVNDZP/3xYOnQg+utp8VM=;
        b=YcU+UqswzotLO2+Ixaw1nc4O/4Lo2s/Jj2+33A4ySIXC9gLQAkM9HrTOqOMnAjHdYt
         0VEtjjP992xD8So50S/hj4cCukzAu7roU3zjrpm4HtR0/mOPOkRHEX94kRnAzeidI0X8
         lXHsDL9tUosU8+9Jd45l8g2smGMHQnjZAd0sh2Y8Y4fApvgN93X1cCEb7B4m0mm+0A6y
         JU7EZBomDnvo1OPgG238RYOaFhFOV9DWBm2V1484Cv28o3uJgQPv37jxEKsp6jCo6YaY
         sfKNvCQvawDSkzsS63p07fHIk4Swe9cmsQ6wpTYc5ZcXnoUms/o4JT3BtNv1R8KDS8jB
         RRag==
X-Gm-Message-State: APjAAAU0ykoTpuSOJy2tSqe6lg0ECxe6Gn9QzDeLaFG8ff1rvskofGGW
	3D57gNyYwFe+4hYGDihvJF4=
X-Google-Smtp-Source: APXvYqyKXIN7oBLCV22J05W/oM34TFBZAIfAQCxOll5dP5S8trG1iwkLxEOocO5NNtGZmPhcFMXFfA==
X-Received: by 2002:a17:902:7205:: with SMTP id ba5mr4217212plb.95.1573658354129;
        Wed, 13 Nov 2019 07:19:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a70b:: with SMTP id w11ls690955plq.3.gmail; Wed, 13
 Nov 2019 07:19:13 -0800 (PST)
X-Received: by 2002:a17:902:8343:: with SMTP id z3mr4405444pln.200.1573658353628;
        Wed, 13 Nov 2019 07:19:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573658353; cv=none;
        d=google.com; s=arc-20160816;
        b=oMQzbp20GD2uV0VOH/IDRQ7R4l/ConAOwEnWcEjjJzYAkDtsIHb0TqY+K7REkgqTZw
         KLtAC6EVPl7IO3OFMaPFMVjKfouZPwOpgPs2zJn2jCauyVeZG/g70SgwnFLtjoe2lBZ/
         XYlh0WJTp9ZUsSxC8khIX+H7kRAEPm4+dFHw48D7YOzmLXb0EvyqQUu1qWv9eJPjXzdd
         GX+29hRrS3WqRH42jZQmn7uat7X9RdeiCJ2CClFd8OFr1aKZCi4VhD5JLk4mHdu4cyIC
         /Uycm8/Z70MUjxlaBiXFTKTr57XITyTcqaXVOIxgu3pRJ56vMOpzjilJJC/QJpmlNiYk
         x+Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KAzyCDiMhQgDTvcJf/hx8upE6E8G92HV2i4vTyZKSjU=;
        b=O+p0CkAP4T3PxqAK8Wy1WkC3GWKsvAAbyQvzha2fi2IABbyzsmecmS6mMK4E6H0GhH
         B8akZI8su5kAIsHUn//udvpqlQq9tbrSwsEzhJx7RJKHmfZHnkE0A0TlOElSYp+cPT/d
         ImpHVagR7Me9cUeKrsET9IeCh/xjgnSSGjgK8eMCbkaSGlNOD33nZ0oE3+315dSm3Nqk
         W6liOeu2Op9cDfP7YOzct8K4xm5oEERvMJRjOUFGWVfh/IZIrcNeXZJO8FW2CdhziMbq
         NRmKi2Oo1mWxq6LrDYyA92d4nnjLHMJhCSq8NeyDhHkTMPsxfehTmqibg1Qgx0YnEXT8
         ODJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P58mPzYU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id c101si83405pje.1.2019.11.13.07.19.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Nov 2019 07:19:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id 3so1853733pfb.10
        for <kasan-dev@googlegroups.com>; Wed, 13 Nov 2019 07:19:13 -0800 (PST)
X-Received: by 2002:aa7:9806:: with SMTP id e6mr5123522pfl.25.1573658352964;
 Wed, 13 Nov 2019 07:19:12 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-3-jannh@google.com>
 <CACT4Y+aojSsss3+Y2FB9Rw=OPxXgsFrGF0YiAJ9eo2wJM0ruWg@mail.gmail.com>
In-Reply-To: <CACT4Y+aojSsss3+Y2FB9Rw=OPxXgsFrGF0YiAJ9eo2wJM0ruWg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Nov 2019 16:19:01 +0100
Message-ID: <CAAeHK+zy1dTvn-VSGYjoNKcp1jHS65ZAoM5M259T1_OE411WUg@mail.gmail.com>
Subject: Re: [PATCH 3/3] x86/kasan: Print original address on #GP
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P58mPzYU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Nov 13, 2019 at 11:11 AM 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Nov 12, 2019 at 10:10 PM 'Jann Horn' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
> > to understand by computing the address of the original access and
> > printing that. More details are in the comments in the patch.
> >
> > This turns an error like this:
> >
> >     kasan: CONFIG_KASAN_INLINE enabled
> >     kasan: GPF could be caused by NULL-ptr deref or user memory access
> >     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
> >     general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI
> >
> > into this:
> >
> >     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
> >     kasan: maybe dereferencing invalid pointer in range
> >             [0x00badbeefbadbee8-0x00badbeefbadbeef]
> >     general protection fault: 0000 [#3] PREEMPT SMP KASAN PTI
> >     [...]

Would it make sense to use the common "BUG: KASAN: <bug-type>" report
format here? Something like:

BUG: KASAN: invalid-ptr-deref in range ...

Otherwise this looks amazing, distinguishing NULL pointer accesses
from wild memory accesses is much more convenient with this. Thanks
Jann!

>
> Nice!
>
> +Andrey, do you see any issues for TAGS mode? Or, Jann, did you test
> it by any chance?

Hm, this looks like x86-specific change, so I don't think it
interferes with the TAGS mode.

>
>
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> >  arch/x86/include/asm/kasan.h |  6 +++++
> >  arch/x86/kernel/traps.c      |  2 ++
> >  arch/x86/mm/kasan_init_64.c  | 52 +++++++++++++++++++++++++-----------
> >  3 files changed, 44 insertions(+), 16 deletions(-)
> >
> > diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> > index 13e70da38bed..eaf624a758ed 100644
> > --- a/arch/x86/include/asm/kasan.h
> > +++ b/arch/x86/include/asm/kasan.h
> > @@ -25,6 +25,12 @@
> >
> >  #ifndef __ASSEMBLY__
> >
> > +#ifdef CONFIG_KASAN_INLINE
> > +void kasan_general_protection_hook(unsigned long addr);
> > +#else
> > +static inline void kasan_general_protection_hook(unsigned long addr) { }
> > +#endif
> > +
> >  #ifdef CONFIG_KASAN
> >  void __init kasan_early_init(void);
> >  void __init kasan_init(void);
> > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > index 479cfc6e9507..e271a5a1ddd4 100644
> > --- a/arch/x86/kernel/traps.c
> > +++ b/arch/x86/kernel/traps.c
> > @@ -58,6 +58,7 @@
> >  #include <asm/umip.h>
> >  #include <asm/insn.h>
> >  #include <asm/insn-eval.h>
> > +#include <asm/kasan.h>
> >
> >  #ifdef CONFIG_X86_64
> >  #include <asm/x86_init.h>
> > @@ -544,6 +545,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
> >                 return;
> >
> >         pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> > +       kasan_general_protection_hook(addr_ref);
> >  #endif
> >  }
> >
> > diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> > index 296da58f3013..9ef099309489 100644
> > --- a/arch/x86/mm/kasan_init_64.c
> > +++ b/arch/x86/mm/kasan_init_64.c
> > @@ -246,20 +246,44 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
> >  }
> >
> >  #ifdef CONFIG_KASAN_INLINE
> > -static int kasan_die_handler(struct notifier_block *self,
> > -                            unsigned long val,
> > -                            void *data)
> > +/*
> > + * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> > + * canonical half of the address space) cause out-of-bounds shadow memory reads
> > + * before the actual access. For addresses in the low canonical half of the
> > + * address space, as well as most non-canonical addresses, that out-of-bounds
> > + * shadow memory access lands in the non-canonical part of the address space,
> > + * causing #GP to be thrown.
> > + * Help the user figure out what the original bogus pointer was.
> > + */
> > +void kasan_general_protection_hook(unsigned long addr)
> >  {
> > -       if (val == DIE_GPF) {
> > -               pr_emerg("CONFIG_KASAN_INLINE enabled\n");
> > -               pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
> > -       }
> > -       return NOTIFY_OK;
> > -}
> > +       unsigned long orig_addr;
> > +       const char *addr_type;
> > +
> > +       if (addr < KASAN_SHADOW_OFFSET)
> > +               return;
>
> Thinking how much sense it makes to compare addr with KASAN_SHADOW_END...
> If the addr is > KASAN_SHADOW_END, we know it's not a KASAN access,
> but do we ever get GP on canonical addresses?
>
> >
> > -static struct notifier_block kasan_die_notifier = {
> > -       .notifier_call = kasan_die_handler,
> > -};
> > +       orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
> > +       /*
> > +        * For faults near the shadow address for NULL, we can be fairly certain
> > +        * that this is a KASAN shadow memory access.
> > +        * For faults that correspond to shadow for low canonical addresses, we
> > +        * can still be pretty sure - that shadow region is a fairly narrow
> > +        * chunk of the non-canonical address space.
> > +        * But faults that look like shadow for non-canonical addresses are a
> > +        * really large chunk of the address space. In that case, we still
> > +        * print the decoded address, but make it clear that this is not
> > +        * necessarily what's actually going on.
> > +        */
> > +       if (orig_addr < PAGE_SIZE)
> > +               addr_type = "dereferencing kernel NULL pointer";
> > +       else if (orig_addr < TASK_SIZE_MAX)
> > +               addr_type = "probably dereferencing invalid pointer";
>
> This is access to user memory, right? In outline mode we call it
> "user-memory-access". We could say about "user" part here as well.

I think we should use the same naming scheme here as in
get_wild_bug_type(): null-ptr-deref, user-memory-access and
wild-memory-access.

>
> > +       else
> > +               addr_type = "maybe dereferencing invalid pointer";
> > +       pr_alert("%s in range [0x%016lx-0x%016lx]\n", addr_type,
> > +                orig_addr, orig_addr + (1 << KASAN_SHADOW_SCALE_SHIFT) - 1);
>
> "(1 << KASAN_SHADOW_SCALE_SHIFT) - 1)" part may be replaced with
> KASAN_SHADOW_MASK.
> Overall it can make sense to move this mm/kasan/report.c b/c we are
> open-coding a number of things here (e.g. reverse address mapping). If
> another arch will do the same, it will need all of this code too (?).
>
> But in general I think it's a very good usability improvement for KASAN.
>
> > +}
> >  #endif
> >
> >  void __init kasan_early_init(void)
> > @@ -298,10 +322,6 @@ void __init kasan_init(void)
> >         int i;
> >         void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
> >
> > -#ifdef CONFIG_KASAN_INLINE
> > -       register_die_notifier(&kasan_die_notifier);
> > -#endif
> > -
> >         memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
> >
> >         /*
> > --
> > 2.24.0.432.g9d3f5f5b63-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112211002.128278-3-jannh%40google.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaojSsss3%2BY2FB9Rw%3DOPxXgsFrGF0YiAJ9eo2wJM0ruWg%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzy1dTvn-VSGYjoNKcp1jHS65ZAoM5M259T1_OE411WUg%40mail.gmail.com.
