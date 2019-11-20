Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBU642TXAKGQEV4IBVDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 695E21039CF
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:15:16 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id o17sf5011609uar.8
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 04:15:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574252115; cv=pass;
        d=google.com; s=arc-20160816;
        b=wqRVBlioq7tKdoNeUQwiWPT9+j5PO8OYhITrn6/V/pIp/8pO0QAI/WqOvFqbd6Lypf
         /5CzIv+J/HPZnxulUAYvS+2SjnA8FlgCeNRasHXKdSHS+A4QjK5BbMn/JMl8XKIYJ5f3
         mpyAZ06svR2RPuTLI8Wte6H2dv1SvzH3+Yb6nFXhrxNFRFnw0OrtNSn87K5IEd5NCoQl
         pzK87wmASaW7NemVHf6H1sfaZ2zi/34/Po8fm3CcuTdgN5AFFyaNBzIELmntFLgQGxzR
         jPDIjbYWn4BZTiRg7qNlo8IIw5Gs5FDAFITo7fTu1D94awgBDmLhmF2pxcD2o8qSVa3l
         z3fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G+AxIc3SuEj7tMAoJWRHjogW/rPLs08fryT+iOyYrak=;
        b=vfgr4E9wypdU2UmTnXVkAci3hCObzcDVsmL9FKq8SZuK0XAb9J3d122Ao1l6J0fn7K
         WJBqYCxRkcFQmACN/Rva0sPHrAMH9UU/bknaN7uoL6Lx8y+PpF8JtJMWemq/NO792XlY
         TdlliRhJPJ+KmTPEiF3FR3kK6YnYkFDsTkO4bzlWR1rXeADVkM6/z0UvJMyc+i2VWpip
         4LXAkkjhX1mMRWjUiWBunkXb6GGek9Spfvm4aUIGoc5yVgeKkjX3Dj6Jacu5is5AwwYS
         bMOnD6jhDRkwTapE2IxnA1AaXGszN+m/2+epy0zgAyVV6KPxYi/cbNyVFidGcd/T9gi1
         GNmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BCWKJcxl;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+AxIc3SuEj7tMAoJWRHjogW/rPLs08fryT+iOyYrak=;
        b=Q3wvmrb9kZsV5RbDz3/KlWepeuN+s0eVvuNogf9lvnjr8oyR8mtDpmLVT4y+TQ2BbO
         hTvyoNBpTFX1336HsxFPf+A5ZYt3RmLClJEd6NZhms6Qf0fVD4FvXI4LoJ5XzYFKxStb
         gTlATrAtR/TQufAHgvQr4zHBSsOf/+gCDDZgmV9ICbec3HAepi9/06QgMWOHbXCIBeiM
         aqC9Hlpkk2eXHQcnmIM36SiUVpUvQ5D076gZfjEPgFXqG/fNiQnFI3lR8w+IhYX2lvmC
         D66nx0R/C4G0AQhGOuQMLeSS6HypLbiAe8zxBGDXdzS21QWhlcIsoOgIH7Ftf/p9Pwm9
         r6ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+AxIc3SuEj7tMAoJWRHjogW/rPLs08fryT+iOyYrak=;
        b=AGFOysBBHpAqAErRD32jkebgGJnrgm+J8478lPsgw8TrLmCB1HBMYs1+DBsp2sUkp/
         SwKf5gQ86o5V9ujf7K1FQc1osMiIxZiJzbf0aNGywq9rDZlpya+HC6hYxVCN4L7cNaZF
         aWkvrxhaITIY7qd+DgzpSvDsdz0RqNxiCT+QS09NFwt79VHcxMcmWhwtBlae8Jdp0ltG
         MohQbbv6l1kPr9t+OTcKm+AIKuY0TsN74UBR7VD1ShieiOuAvw/545UD+qwpdkeuSVs7
         ayNN8LHdHFkUttdTYSD4CDZ4z+jIPnbkNk/pc9paBJiUSM8+MKAhGRdRU8RL2nks4cAj
         zVjw==
X-Gm-Message-State: APjAAAUbpKwTIxOwK1jcTCkrN1/0VFdJgpQRF8q/4epvEvyQsN6CZuvO
	Im9+tferOmA1ZkpRF0ejG6g=
X-Google-Smtp-Source: APXvYqyDnuoa+vUxMRgLEgKw6l1o2xmvFVaZJe/uhr1Z7yO+iAAcEUcXJ0BZbhUHd0V6oM7JwGOM8w==
X-Received: by 2002:ab0:6c5:: with SMTP id g63mr1460807uag.46.1574252115303;
        Wed, 20 Nov 2019 04:15:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3239:: with SMTP id x25ls226062vsf.4.gmail; Wed, 20
 Nov 2019 04:15:15 -0800 (PST)
X-Received: by 2002:a05:6102:677:: with SMTP id z23mr1361749vsf.130.1574252115034;
        Wed, 20 Nov 2019 04:15:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574252115; cv=none;
        d=google.com; s=arc-20160816;
        b=CauahckTNyaqN5s3K3fGc003ezoPRHvSNPB+5nGnSczA0cG8fcz44SDKkFRyTnS5FT
         AXTVhKAK971J8OQjrZg4baV813I2a/QhcggSbGuIxHn+/aYgkuUx8NmxKzyJj0UECsqx
         2OUZ+WdqdubXT39HWgN2CAVLKQlAdX3Q2k3Z6NUQwFMPyIp5RByCXjvQNDW9WmRFn3kJ
         Y10b0NpvDxBF3JuKh2UTtigcIpGxbGcd4hFqcmPbuXiguodcF73Nj5FqenGLPZp5oP5q
         QbAJokCME+dg591wjtPIGOc0F/REhCdgKO9czQ5n0MeYNebDrRkjGWcaREJDtinUalvc
         eVRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hrG1MrWdrTxQ+fEkYluZ+Amp57CnVbQolCFc6b0yOMw=;
        b=r9qKFGQALMUuNNaivOis8bLuvr3h9w/4I3QJUFEsVWN+faxx1G1orFZ4rrpOwsdahX
         Jo1zfFasamlU1BHaciA7GK2vt4JmlJW0gSfmvtU07WJM0iSJAY/1KeHLGTg+tMxggzvI
         NH2lDyDpWcilti6L5W+fZ41nO0ksYq6oGcYHSXTKLaAJov/6/WtnFxMN0Y5ss/rsoQR2
         9WhyIbnxlK3aL1PEi1uyv3ZIKD+mZhYj3gZ1Arb+v15c7uDBtCDPtu/r8wmZ5VzP4sIT
         EhXllCqaJ6agEcNRwQ00SWmnKGniXrBMJXlEhn2J4DCL26iTLTp3mdnyQzu3ruMYYckc
         elUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BCWKJcxl;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id e11si1412899uaf.0.2019.11.20.04.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 04:15:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id n16so22301316oig.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 04:15:15 -0800 (PST)
X-Received: by 2002:aca:4d47:: with SMTP id a68mr2558098oib.68.1574252113967;
 Wed, 20 Nov 2019 04:15:13 -0800 (PST)
MIME-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com> <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
In-Reply-To: <20191120111859.GA115930@gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 13:14:47 +0100
Message-ID: <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
To: Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BCWKJcxl;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Nov 20, 2019 at 12:19 PM Ingo Molnar <mingo@kernel.org> wrote:
> * Jann Horn <jannh@google.com> wrote:
>
> > A frequent cause of #GP exceptions are memory accesses to non-canonical
> > addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> > the kernel doesn't currently print the fault address for #GP.
> > Luckily, we already have the necessary infrastructure for decoding X86
> > instructions and computing the memory address that is being accessed;
> > hook it up to the #GP handler so that we can figure out whether the #GP
> > looks like it was caused by a non-canonical address, and if so, print
> > that address.
[...]
> > +/*
> > + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> > + * address, return that address.
> > + */
> > +static unsigned long get_kernel_gp_address(struct pt_regs *regs)
> > +{
> > +#ifdef CONFIG_X86_64
> > +     u8 insn_bytes[MAX_INSN_SIZE];
> > +     struct insn insn;
> > +     unsigned long addr_ref;
> > +
> > +     if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> > +             return 0;
> > +
> > +     kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> > +     insn_get_modrm(&insn);
> > +     insn_get_sib(&insn);
> > +     addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
>
> I had to look twice to realize that the 'insn_bytes' isn't an integer
> that shows the number of bytes in the instruction, but the instruction
> buffer itself.
>
> Could we please do s/insn_bytes/insn_buf or such?

Will change it.

> > +
> > +     /* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
> > +     if (addr_ref >= ~__VIRTUAL_MASK)
> > +             return 0;
> > +
> > +     /* Bail out if the entire operand is in the canonical user half. */
> > +     if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
> > +             return 0;
>
> BTW., it would be nice to split this logic in two: return the faulting
> address to do_general_protection(), and print it out both for
> non-canonical and canonical addresses as well -and use the canonical
> check to *additionally* print out a short note when the operand is
> non-canonical?

You mean something like this?

========================
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 9b23c4bda243..16a6bdaccb51 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -516,32 +516,36 @@ dotraplinkage void do_bounds(struct pt_regs
*regs, long error_code)
  * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
  * address, return that address.
  */
-static unsigned long get_kernel_gp_address(struct pt_regs *regs)
+static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
+                                          bool *non_canonical)
 {
 #ifdef CONFIG_X86_64
        u8 insn_buf[MAX_INSN_SIZE];
        struct insn insn;
-       unsigned long addr_ref;

        if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
-               return 0;
+               return false;

        kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
        insn_get_modrm(&insn);
        insn_get_sib(&insn);
-       addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
+       *addr = (unsigned long)insn_get_addr_ref(&insn, regs);

-       /* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
-       if (addr_ref >= ~__VIRTUAL_MASK)
-               return 0;
+       if (*addr == (unsigned long)-1L)
+               return false;

-       /* Bail out if the entire operand is in the canonical user half. */
-       if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
-               return 0;
+       /*
+        * Check that:
+        *  - the address is not in the kernel half or -1 (which means the
+        *    decoder failed to decode it)
+        *  - the last byte of the address is not in the user canonical half
+        */
+       *non_canonical = *addr < ~__VIRTUAL_MASK &&
+                        *addr + insn.opnd_bytes - 1 > __VIRTUAL_MASK;

-       return addr_ref;
+       return true;
 #else
-       return 0;
+       return false;
 #endif
 }

@@ -569,8 +573,10 @@ do_general_protection(struct pt_regs *regs, long
error_code)

        tsk = current;
        if (!user_mode(regs)) {
-               unsigned long non_canonical_addr = 0;
+               bool addr_resolved = false;
+               unsigned long gp_addr;
                unsigned long flags;
+               bool non_canonical;
                int sig;

                if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
@@ -595,18 +601,19 @@ do_general_protection(struct pt_regs *regs, long
error_code)
                if (error_code)
                        snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
                else
-                       non_canonical_addr = get_kernel_gp_address(regs);
+                       addr_resolved = get_kernel_gp_address(regs, &gp_addr,
+                                                             &non_canonical);

-               if (non_canonical_addr)
+               if (addr_resolved)
                        snprintf(desc, sizeof(desc),
-                           GPFSTR " probably for non-canonical address 0x%lx",
-                           non_canonical_addr);
+                           GPFSTR " probably for %saddress 0x%lx",
+                           non_canonical ? "non-canonical " : "", gp_addr);

                flags = oops_begin();
                sig = SIGSEGV;
                __die_header(desc, regs, error_code);
-               if (non_canonical_addr)
-                       kasan_non_canonical_hook(non_canonical_addr);
+               if (addr_resolved && non_canonical)
+                       kasan_non_canonical_hook(gp_addr);
                if (__die_body(desc, regs, error_code))
                        sig = 0;
                oops_end(flags, regs, sig);
========================

I guess that could potentially be useful if a #GP is triggered by
something like an SSE alignment error? I'll add it in unless someone
else complains.

> > +#define GPFSTR "general protection fault"
> >  dotraplinkage void
>
> Please separate macro and function definitions by an additional newline.

Will change it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0Frp4-%2BxHZ%3DUhbHh0hC_h-1VtJfwHw%3DkDo6NahyMv1ig%40mail.gmail.com.
