Return-Path: <kasan-dev+bncBCMIZB7QWENRBPGJWDXAKGQE5TF6Z7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id ACBCCFB3FA
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2019 16:43:57 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id c68sf313661vsc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2019 07:43:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573659836; cv=pass;
        d=google.com; s=arc-20160816;
        b=XwPfsejh8EWQyeE8+sllj0Sjh+xDb4GNTc5W3Lj/8ijS2L6vFL2QDW/8XF5xKb9ExL
         dEVH80ecarv0/NB3NNRCaGGX+mrx0vYQXbTYYzMbvZUXeKYlWluLRYWK3RQuTd4vO/pM
         wqlRNTIXLQa/8uqOPupQ8mpSvi2NtYDJUw468lCqpNXnKduRFGk6xSiGsLw4gAYk9qBd
         JG3u56z3XwIYm8LCMvD++1bR6Biz09eEi9zQIWyucnVfXzQ8vYFe6bOj3JyNll6ttvNZ
         DrioNNM0YHzZES5UukBu7SqOHr5jmTbKA2SRbKiZ88UJdw4lk2HZ/5ad+k8zOIwPH2dp
         H9uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GrwbWvJdxNhK7aqEBuqDEwYynIUy+zUlf9wFJ0r9SZA=;
        b=AMf0hmeIJuN2mi8AsL8MWGPhb+/KWerYgkKfcWj0dOaEtxw24vpyyyHtUi7W5F7HAx
         WcHIf+YfzGD3A1N3jLRQ3FWQDT5ukAK99Y71/JB9CE3LY1rWiNQKq7hKGsGenC3OONXr
         9YWzsu/Hmz0vM5Ovyd0tPZJ9VwF8uoGJ0xQVgq67OR8+gOfQEq2QUyguduRHdfaT07F4
         YbvVqez/KF8vdILBYP9jwhrR4vdfrYHWXv7v/CcW4mv98CJPZUPNvRtPqn3hqn2NPazG
         Pj9dj+y9hGbHlxYNFPnOXgRmUOGVBiveGgHgNEX2xI+jyZTvMxkMKIix4KCFlY8fBvlP
         n7aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MelMg6UT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GrwbWvJdxNhK7aqEBuqDEwYynIUy+zUlf9wFJ0r9SZA=;
        b=CAHE0SYI2/TsTPstl3W3pOugi4pxCXlJXWaxJhI70eBX2l6ErqJTdW4lPhOh/AkuSJ
         qFodGJFRGLkZNBjxKhssnJHEWOrKAMZHg5ZaRR8Dgx41VVvTW0Pa/wMPVyY68X47A4T+
         XJ7QvfkI41A/SFZU50zQ29+SYNnF2n7K2UqqQF6oEjueDjna9QAXbwUcfp9+ja81idkK
         QF/6Rgv6JscG5yuqwYBqptjYpxXLBsiAP8yAcJYwkt2NvLJEHS1wgZfxyXkDd9Zd/PdY
         dKLVIctoXC/6D0Em8Pf+SoDJ5OQeFeplsGSYOlGovLlQPIuu4a5x8zWa6IbovH1hpI+G
         W3uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GrwbWvJdxNhK7aqEBuqDEwYynIUy+zUlf9wFJ0r9SZA=;
        b=ZJvXN/Zep5UPOBqEfuPKeNlnnnY3cBIGpQvN/J7rK87Q4O5YlXX4PjKgS0RCb52nN2
         3Ykpc1LQwAYiIOWhgeSXvQg2cAW7POpPkkaE8N9P54qSBSdWK6LGqnfhjcFc5uYT+kT6
         JrxjLtPWbe86jANS0ZBbM+6LGwsr2KME8dmJCFddeq/ix5iTv7q3NUj29sRNb7+UnlLQ
         QSqQElAEWo5evQ3W+gvQecTvKe+bMe7nGgNURfFmvjxpbdKLfRHe0OvHdr9BF/dTZJtq
         DX8t559khMCqjB0f+QLSZe0DbvHWOp4lojZ3cX4IpEiDpFJM6cjR7WF4GOenHYX0m3fz
         K7Kw==
X-Gm-Message-State: APjAAAWHxLnLyYvKhLAwcGx7D0gMq7wmzZGT9z9bnJuejRQtKsTDdBbF
	pNmZdylkA8/YLj3wHDpDbgI=
X-Google-Smtp-Source: APXvYqwP3LkdTf6EIysYoFxHPXfKitJrEwkUSjZW+7SmCKXThITK5bDVscdwFDfyghSVJuIf13TyBQ==
X-Received: by 2002:ac5:cd87:: with SMTP id i7mr2126078vka.72.1573659836547;
        Wed, 13 Nov 2019 07:43:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7cc8:: with SMTP id x191ls216724vsc.15.gmail; Wed, 13
 Nov 2019 07:43:56 -0800 (PST)
X-Received: by 2002:a67:6917:: with SMTP id e23mr2355283vsc.143.1573659836202;
        Wed, 13 Nov 2019 07:43:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573659836; cv=none;
        d=google.com; s=arc-20160816;
        b=S7/54iK5vtYALA4VvT1EvxRfPx9y4vQi02z4qMG1irfZhUK4KQyi8OUPDTr1ZImYNw
         sbq5+TCLVUOh3frpREBV91Q2ybn6oQy6poNvy+4yPFieGM2fJKCBNs18Kb06gbFtY+Gd
         hiLCGQ0MmhNTFLTEBxrqv/C9QE03FhBqIh8lP56Q8ViYTl+iBqUWdlFyvTP3h4/hOW1d
         OehcoWADAFeFyBMCY5mr/mpG+unG/PPK4LHT8XCvp5lptr4qso6R0mxLLYx6WT/0p7tB
         qbK2MKemTtyim1nYdAqZQThzzU4mrWKDm0XG1Ax7PCbTreAuZmrapbb3xZj0013ei/Op
         KQrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XcXWmlt05QR18owK+MGeLb0ZPAuT9teI4dlutv4UOY4=;
        b=ZXj4VXtpPgL7xAHuEKD/VwDsbdO6zdU0Xedf3OqQbtSi3zjz0M7LzGw2EQ2UV50BgS
         mi7x2ViWSeSVaoD8LHZP9TQ/QKM7uus3A3umEIk59gcIavmK0fue1hXW6APUnZAcUZ+l
         SWyRbeyWRq5jIeZORzWy2z9LmZGO4hy8JkN3VMbymuxvkiE3lbD67hVgTJKOnS639kl7
         dVn3p6ia91Wpuh0IHLxoCjE8UUmYMlcw6xDtU0MoipRjg5jB7xaxWWEWjM7FHghNCUit
         SLdvJAA3H/KaWHIJgtMG1+rPN492WZQHMfkp0IVX0lEmsq4U5JQnqBGIkk4+mxy85zKc
         twUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MelMg6UT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id p195si198092vkp.1.2019.11.13.07.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Nov 2019 07:43:56 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id 71so2134424qkl.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Nov 2019 07:43:56 -0800 (PST)
X-Received: by 2002:a05:620a:14b9:: with SMTP id x25mr3145990qkj.8.1573659835263;
 Wed, 13 Nov 2019 07:43:55 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-3-jannh@google.com>
 <CACT4Y+aojSsss3+Y2FB9Rw=OPxXgsFrGF0YiAJ9eo2wJM0ruWg@mail.gmail.com> <CAAeHK+zy1dTvn-VSGYjoNKcp1jHS65ZAoM5M259T1_OE411WUg@mail.gmail.com>
In-Reply-To: <CAAeHK+zy1dTvn-VSGYjoNKcp1jHS65ZAoM5M259T1_OE411WUg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Nov 2019 16:43:43 +0100
Message-ID: <CACT4Y+ay_0e6GSsaYXwLGRkBmmBGSA-gy_TEUu+FsL8JfRHG9g@mail.gmail.com>
Subject: Re: [PATCH 3/3] x86/kasan: Print original address on #GP
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MelMg6UT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Wed, Nov 13, 2019 at 4:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Wed, Nov 13, 2019 at 11:11 AM 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Tue, Nov 12, 2019 at 10:10 PM 'Jann Horn' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
> > > to understand by computing the address of the original access and
> > > printing that. More details are in the comments in the patch.
> > >
> > > This turns an error like this:
> > >
> > >     kasan: CONFIG_KASAN_INLINE enabled
> > >     kasan: GPF could be caused by NULL-ptr deref or user memory access
> > >     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
> > >     general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI
> > >
> > > into this:
> > >
> > >     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
> > >     kasan: maybe dereferencing invalid pointer in range
> > >             [0x00badbeefbadbee8-0x00badbeefbadbeef]
> > >     general protection fault: 0000 [#3] PREEMPT SMP KASAN PTI
> > >     [...]
>
> Would it make sense to use the common "BUG: KASAN: <bug-type>" report
> format here? Something like:
>
> BUG: KASAN: invalid-ptr-deref in range ...


Currently this line is not the official bug title. The official bug
title is "general protection fault:" line that follows.
If we add "BUG: KASAN:" before that we need to be super careful wrt
effect on syzbot but parsing/reporting.



> Otherwise this looks amazing, distinguishing NULL pointer accesses
> from wild memory accesses is much more convenient with this. Thanks
> Jann!
>
> >
> > Nice!
> >
> > +Andrey, do you see any issues for TAGS mode? Or, Jann, did you test
> > it by any chance?
>
> Hm, this looks like x86-specific change, so I don't think it
> interferes with the TAGS mode.
>
> >
> >
> > > Signed-off-by: Jann Horn <jannh@google.com>
> > > ---
> > >  arch/x86/include/asm/kasan.h |  6 +++++
> > >  arch/x86/kernel/traps.c      |  2 ++
> > >  arch/x86/mm/kasan_init_64.c  | 52 +++++++++++++++++++++++++-----------
> > >  3 files changed, 44 insertions(+), 16 deletions(-)
> > >
> > > diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> > > index 13e70da38bed..eaf624a758ed 100644
> > > --- a/arch/x86/include/asm/kasan.h
> > > +++ b/arch/x86/include/asm/kasan.h
> > > @@ -25,6 +25,12 @@
> > >
> > >  #ifndef __ASSEMBLY__
> > >
> > > +#ifdef CONFIG_KASAN_INLINE
> > > +void kasan_general_protection_hook(unsigned long addr);
> > > +#else
> > > +static inline void kasan_general_protection_hook(unsigned long addr) { }
> > > +#endif
> > > +
> > >  #ifdef CONFIG_KASAN
> > >  void __init kasan_early_init(void);
> > >  void __init kasan_init(void);
> > > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > > index 479cfc6e9507..e271a5a1ddd4 100644
> > > --- a/arch/x86/kernel/traps.c
> > > +++ b/arch/x86/kernel/traps.c
> > > @@ -58,6 +58,7 @@
> > >  #include <asm/umip.h>
> > >  #include <asm/insn.h>
> > >  #include <asm/insn-eval.h>
> > > +#include <asm/kasan.h>
> > >
> > >  #ifdef CONFIG_X86_64
> > >  #include <asm/x86_init.h>
> > > @@ -544,6 +545,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
> > >                 return;
> > >
> > >         pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> > > +       kasan_general_protection_hook(addr_ref);
> > >  #endif
> > >  }
> > >
> > > diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> > > index 296da58f3013..9ef099309489 100644
> > > --- a/arch/x86/mm/kasan_init_64.c
> > > +++ b/arch/x86/mm/kasan_init_64.c
> > > @@ -246,20 +246,44 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
> > >  }
> > >
> > >  #ifdef CONFIG_KASAN_INLINE
> > > -static int kasan_die_handler(struct notifier_block *self,
> > > -                            unsigned long val,
> > > -                            void *data)
> > > +/*
> > > + * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> > > + * canonical half of the address space) cause out-of-bounds shadow memory reads
> > > + * before the actual access. For addresses in the low canonical half of the
> > > + * address space, as well as most non-canonical addresses, that out-of-bounds
> > > + * shadow memory access lands in the non-canonical part of the address space,
> > > + * causing #GP to be thrown.
> > > + * Help the user figure out what the original bogus pointer was.
> > > + */
> > > +void kasan_general_protection_hook(unsigned long addr)
> > >  {
> > > -       if (val == DIE_GPF) {
> > > -               pr_emerg("CONFIG_KASAN_INLINE enabled\n");
> > > -               pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
> > > -       }
> > > -       return NOTIFY_OK;
> > > -}
> > > +       unsigned long orig_addr;
> > > +       const char *addr_type;
> > > +
> > > +       if (addr < KASAN_SHADOW_OFFSET)
> > > +               return;
> >
> > Thinking how much sense it makes to compare addr with KASAN_SHADOW_END...
> > If the addr is > KASAN_SHADOW_END, we know it's not a KASAN access,
> > but do we ever get GP on canonical addresses?
> >
> > >
> > > -static struct notifier_block kasan_die_notifier = {
> > > -       .notifier_call = kasan_die_handler,
> > > -};
> > > +       orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
> > > +       /*
> > > +        * For faults near the shadow address for NULL, we can be fairly certain
> > > +        * that this is a KASAN shadow memory access.
> > > +        * For faults that correspond to shadow for low canonical addresses, we
> > > +        * can still be pretty sure - that shadow region is a fairly narrow
> > > +        * chunk of the non-canonical address space.
> > > +        * But faults that look like shadow for non-canonical addresses are a
> > > +        * really large chunk of the address space. In that case, we still
> > > +        * print the decoded address, but make it clear that this is not
> > > +        * necessarily what's actually going on.
> > > +        */
> > > +       if (orig_addr < PAGE_SIZE)
> > > +               addr_type = "dereferencing kernel NULL pointer";
> > > +       else if (orig_addr < TASK_SIZE_MAX)
> > > +               addr_type = "probably dereferencing invalid pointer";
> >
> > This is access to user memory, right? In outline mode we call it
> > "user-memory-access". We could say about "user" part here as well.
>
> I think we should use the same naming scheme here as in
> get_wild_bug_type(): null-ptr-deref, user-memory-access and
> wild-memory-access.
>
> >
> > > +       else
> > > +               addr_type = "maybe dereferencing invalid pointer";
> > > +       pr_alert("%s in range [0x%016lx-0x%016lx]\n", addr_type,
> > > +                orig_addr, orig_addr + (1 << KASAN_SHADOW_SCALE_SHIFT) - 1);
> >
> > "(1 << KASAN_SHADOW_SCALE_SHIFT) - 1)" part may be replaced with
> > KASAN_SHADOW_MASK.
> > Overall it can make sense to move this mm/kasan/report.c b/c we are
> > open-coding a number of things here (e.g. reverse address mapping). If
> > another arch will do the same, it will need all of this code too (?).
> >
> > But in general I think it's a very good usability improvement for KASAN.
> >
> > > +}
> > >  #endif
> > >
> > >  void __init kasan_early_init(void)
> > > @@ -298,10 +322,6 @@ void __init kasan_init(void)
> > >         int i;
> > >         void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
> > >
> > > -#ifdef CONFIG_KASAN_INLINE
> > > -       register_die_notifier(&kasan_die_notifier);
> > > -#endif
> > > -
> > >         memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
> > >
> > >         /*
> > > --
> > > 2.24.0.432.g9d3f5f5b63-goog
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112211002.128278-3-jannh%40google.com.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaojSsss3%2BY2FB9Rw%3DOPxXgsFrGF0YiAJ9eo2wJM0ruWg%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bay_0e6GSsaYXwLGRkBmmBGSA-gy_TEUu%2BFsL8JfRHG9g%40mail.gmail.com.
