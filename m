Return-Path: <kasan-dev+bncBDEPT3NHSUCBBUVMW3XAKGQE76P55AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A1EFCC6A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:00:53 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id f7sf4317962plj.12
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:00:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754450; cv=pass;
        d=google.com; s=arc-20160816;
        b=I9bYzw3sJ4D+QDgnqny91CyjBvBD1FGmm+MJQ+GiTbVDSCvp5skjPh1SHk6fCkQ/uo
         PQ4xrNZ6HrlR5KY0JKDDvDOaEB7n1YTIS51Z9sbq5Ge4yDpr0obnJ3aotZC3w4/GiHRs
         o3OyjpQZmrM/pa/YlucZc847yKsolzunc0wy9XyRLrgiVcLRPnhE632U+y4vW5xec3FY
         pyNNJGrrv9b1VK9o57jHg0mgyDo0IdFVLw0LA21WeIsEj9u58cAKSQiMf7enNroHesMF
         D+pU4wNCumvwcLybKPvWFbKqWC5cHWcmC4d5dt0fkrV+ZHvhIlA4et7op5TERl83frLy
         2nQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=2qNWTtJOfo/0ifbgeS8XnSs4hJeMU9p675POVb44KN4=;
        b=ZkD3xv+r9KVLpjaPIz0rnh2ze3GJKPyfz33fznsSOaprftgt2iyK9tdwCgXgBT/0nc
         /xTrrRWD2l7ciu2nK4jZGIFw/WyIMOPmgTtPiua2NH0DJIJdeqldUZAgOnA0FIjOTLdY
         coZjCisHfYYy129Xa7FgshsneyoUcEpBBJ4v5cVrAZqKu4dyiDPU0kTrQdQo+DSXGh/N
         YSpSbXMiZadmDfUl1d6E1uztMIFb0d454+GbFJzuS6NtUv3ETv7OHS3K8b87cqSO8HRn
         tTPy0Nhzl9OVj8gSTj/rcR6GKA+h4NXvsOrhgHzojiWXPLb1JxZu1D8Z1GnRQv11wDTC
         c8pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Ax+5fcJF;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2qNWTtJOfo/0ifbgeS8XnSs4hJeMU9p675POVb44KN4=;
        b=rM+fnYiZ/4N+vxnMJuWpRWtT6o6G9C88glvSi8T5i9haLndkMd6QG3s7BZr4dc8ri0
         2pEyV861WxqzkMfVbn1zR3bKyjMYpt3/j8R1jKsD4PqKDoouLzQB7ocmsnQVxt+eQ1+Y
         DTIXREpdLtcltH2bK6XwzR2yLfpYUPSc5eK3a3Zxe5JVoJuADXxWdexoJiR9xwW3wYnD
         fqzAE1u793X+xpv2szDg+hG+E9+wtiT1ixtYUo949zswk2Tc1GwRTwtSId+xZQjKm62V
         9am5zftRhIu7aSmGcctL+rdOMPuZEfGZTlDQoisQ5tohyAfal3QQrIIaiZqIWODsTYPg
         0OcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2qNWTtJOfo/0ifbgeS8XnSs4hJeMU9p675POVb44KN4=;
        b=LZQNhKJ/muj2SDHF+bdB1Djn7dvhcxPxLIgIUHew6uRcbx1qz+kkCh8JEK6yNyx529
         L/S5pNnUdgn7ryNXeHl7nLvoKWcXfYaNdIxu2WQIEVKXtAuy49bs5Bj+GGfad/FcAQLa
         dH8HvaNhtOri62R4pxspvBisIFHkwD0KN/2P/dqXMd0unwjGQz2WgZDmBBpa+4aofBnF
         mHKjxzy2iW1pyaSEHXZcqodkWs84uPaDDPoWwsaEDoPS1ey66UbidRZC7NL7hYf9tuFR
         bBJ+/p4X15w7I3VAyeQDECtEny7vFXLrcK/ndGkhhLo/ZpeWZ8BOmOr1A3+8+sVvF4Pa
         M6MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVwh3W4h311iLGk/HHyBsn/J+31eqIkazlR2pA2IpBOpK9psuK8
	5HXiy/HU4A270EuRdqaJcDA=
X-Google-Smtp-Source: APXvYqz2kihQElo25/dUO+XV7GFTpoVEOeNfWnu6dNoYe9iWUYjRkcHJLx6mMfQu5siZkdfxi1sIvA==
X-Received: by 2002:a17:902:d917:: with SMTP id c23mr10716612plz.199.1573754450437;
        Thu, 14 Nov 2019 10:00:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb98:: with SMTP id a24ls878780pju.4.canary-gmail;
 Thu, 14 Nov 2019 10:00:50 -0800 (PST)
X-Received: by 2002:a17:902:9882:: with SMTP id s2mr2247552plp.101.1573754450006;
        Thu, 14 Nov 2019 10:00:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754450; cv=none;
        d=google.com; s=arc-20160816;
        b=X5eY+TBgA8PB8LksHaj764uY6mwjJD9bHFYLvlmDrcTpijqqWUTtVFBNeJqyZChrfq
         u4ldAFYi5jXWZ2rJJRgYeyjz1l2PruX0lkkKOkVkkgqHtb+JcLhqcrY/rPVmaFKm6vod
         gYPayrqs5KL/zu3emq0rTutFwz00BVMuNgAAmhTJTEwOuiyovCiKlw9BcXMY23v1qb8F
         exOcZ5FTQlZfAF1u+w6z22P39PRG8QBb1CYwcfyFkcdez9oZrw0IdQGn1rpOAEUPI00h
         6lAnK1Etys4tf8lm6TvISY90E1Q2x0y28XAXIWq5l2oTt3AqewGxkDBUTLSzM2JrRq0/
         /WpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/RT+b9OoZ2ycIG8i0xGKAcVdve78ciuE/kLigIiRD1c=;
        b=FIkuKRzV4wamQDW+u+VIrFkrcKzjKpPoSmlvQW6/5TfSFyr0bo06cH5t4d1t43+oqr
         vrabIzItdtYNAz/G53WScomnTNsRLkiQoczI76eMTQnsHb+2I2f32qj5+DIHf5peN1Ub
         xa8k0N+EjKkvWkLYSr9uFLFVC2oizu+anUlUYP6SkdFWQSXt/Znzlf88JmJMWNQJFYI9
         HVljNtk/20IV4ZF3ppGLjpQzG1q8F+sCfw04UYUVJ8VfNOjuF/StuQr3jRAsIEYj1PEH
         pY04cRzsxSesOT9juSMWz5D99ikx8zcUY5Y0cZwY0mR+NwkPjX711ZG+SnzqeN/iDxqC
         f8VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Ax+5fcJF;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r20si378973pfc.3.2019.11.14.10.00.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:00:49 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f54.google.com (mail-wr1-f54.google.com [209.85.221.54])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6D8CC2077B
	for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 18:00:49 +0000 (UTC)
Received: by mail-wr1-f54.google.com with SMTP id a15so7507128wrf.9
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:00:49 -0800 (PST)
X-Received: by 2002:a5d:640b:: with SMTP id z11mr9138534wru.195.1573754446679;
 Thu, 14 Nov 2019 10:00:46 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-2-jannh@google.com>
 <20191114174630.GF24045@linux.intel.com>
In-Reply-To: <20191114174630.GF24045@linux.intel.com>
From: Andy Lutomirski <luto@kernel.org>
Date: Thu, 14 Nov 2019 10:00:35 -0800
X-Gmail-Original-Message-ID: <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
Message-ID: <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
Subject: Re: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
To: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Ax+5fcJF;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Nov 14, 2019 at 9:46 AM Sean Christopherson
<sean.j.christopherson@intel.com> wrote:
>
> On Tue, Nov 12, 2019 at 10:10:01PM +0100, Jann Horn wrote:
> > A frequent cause of #GP exceptions are memory accesses to non-canonical
> > addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> > the kernel doesn't currently print the fault address for #GP.
> > Luckily, we already have the necessary infrastructure for decoding X86
> > instructions and computing the memory address that is being accessed;
> > hook it up to the #GP handler so that we can figure out whether the #GP
> > looks like it was caused by a non-canonical address, and if so, print
> > that address.
> >
> > While it is already possible to compute the faulting address manually by
> > disassembling the opcode dump and evaluating the instruction against the
> > register dump, this should make it slightly easier to identify crashes
> > at a glance.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> >  arch/x86/kernel/traps.c | 45 +++++++++++++++++++++++++++++++++++++++--
> >  1 file changed, 43 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > index c90312146da0..479cfc6e9507 100644
> > --- a/arch/x86/kernel/traps.c
> > +++ b/arch/x86/kernel/traps.c
> > @@ -56,6 +56,8 @@
> >  #include <asm/mpx.h>
> >  #include <asm/vm86.h>
> >  #include <asm/umip.h>
> > +#include <asm/insn.h>
> > +#include <asm/insn-eval.h>
> >
> >  #ifdef CONFIG_X86_64
> >  #include <asm/x86_init.h>
> > @@ -509,6 +511,42 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
> >       do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
> >  }
> >
> > +/*
> > + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> > + * address, print that address.
> > + */
> > +static void print_kernel_gp_address(struct pt_regs *regs)
> > +{
> > +#ifdef CONFIG_X86_64
> > +     u8 insn_bytes[MAX_INSN_SIZE];
> > +     struct insn insn;
> > +     unsigned long addr_ref;
> > +
> > +     if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> > +             return;
> > +
> > +     kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> > +     insn_get_modrm(&insn);
> > +     insn_get_sib(&insn);
> > +     addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
> > +
> > +     /*
> > +      * If insn_get_addr_ref() failed or we got a canonical address in the
> > +      * kernel half, bail out.
> > +      */
> > +     if ((addr_ref | __VIRTUAL_MASK) == ~0UL)
> > +             return;
> > +     /*
> > +      * For the user half, check against TASK_SIZE_MAX; this way, if the
> > +      * access crosses the canonical address boundary, we don't miss it.
> > +      */
> > +     if (addr_ref <= TASK_SIZE_MAX)
>
> Any objection to open coding the upper bound instead of using
> TASK_SIZE_MASK to make the threshold more obvious?
>
> > +             return;
> > +
> > +     pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
>
> Printing the raw address will confuse users in the case where the access
> straddles the lower canonical boundary.  Maybe combine this with open
> coding the straddle case?  With a rough heuristic to hedge a bit for
> instructions whose operand size isn't accurately reflected in opnd_bytes.
>
>         if (addr_ref > __VIRTUAL_MASK)
>                 pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
>         else if ((addr_ref + insn->opnd_bytes - 1) > __VIRTUAL_MASK)
>                 pr_alert("straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
>                          addr_ref, addr_ref + insn->opnd_bytes - 1);
>         else if ((addr_ref + PAGE_SIZE - 1) > __VIRTUAL_MASK)
>                 pr_alert("potentially straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
>                          addr_ref, addr_ref + PAGE_SIZE - 1);

This is unnecessarily complicated, and I suspect that Jann had the
right idea but just didn't quite explain it enough.  The secret here
is that TASK_SIZE_MAX is a full page below the canonical boundary
(thanks, Intel, for screwing up SYSRET), so, if we get #GP for an
address above TASK_SIZE_MAX, then it's either a #GP for a different
reason or it's a genuine non-canonical access.

So I think that just a comment about this would be enough.

*However*, the printout should at least hedge a bit and say something
like "probably dereferencing non-canonical address", since there are
plenty of ways to get #GP with an operand that is nominally
non-canonical but where the actual cause of #GP is different.  And I
think this code should be skipped entirely if error_code != 0.

--Andy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs%2BW7aS2cxxDYkqn_Q%40mail.gmail.com.
