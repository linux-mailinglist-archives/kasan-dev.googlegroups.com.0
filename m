Return-Path: <kasan-dev+bncBCMIZB7QWENRBP4BZPXAKGQEJGTR5ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CEB01008D9
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 17:03:13 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id b12sf16593244iln.11
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 08:03:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574092992; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGqP4zhiHTEsch0H89VqzZZWhRzbbk2j5Ji5ElE4N5/4FB8jjbW+3dcfx9GVZwed7/
         V9hVNg2DqeXlNCQRp1RUmorokpqmrm+X3lAFoewxIlmgWpo8/nfhgwRxoVucNa5fT6Tq
         B/lvDKmeyUcOlf6Z51hxhe4hcJvsPqWt9NkRv9iXNxKyQTptc0y64TFstEYUDa1ZRKa+
         KM4+DTHKVU/EGne+eOhC7Ec2cfi13IBEZ1d3UnLt7pkn7rqDPYn8yVC6kDX09D8vTYW5
         Kb7HAHUxC95IipoyWuozsn+GFY3miqIsvqmTiLzbV1ZXzMXFuEqjzhSc4SzPZikhFikf
         rNhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Lc9iXaxJc/p9mNtzi892q+2Xj6zIE/16eYinSdT4a0Q=;
        b=RU3O9jXA3FVMMpmUe4/1RYLsPgtED77QqYMl5CpX0oajYqzprkEuQWJtW8h10EP+63
         FOB5Ahb3jt+bcMbQpHRfK1MTYSuiAWwz/V4EfgohEbY8OwEjLrLldDwYWiI1v7Ubs/4w
         TqtOFqwAgI8gAJV5JyUqiUAB1KN4l85pEJAwgWTepLYy1N9WGbAiAtoom+8cVHV2dgab
         rBOQCrRUrPrbpZWZ8nLv+WvFu5H/4PV8mSKAiEE1m5ysWsfgxwBxlIXQAPOHVWoBjjsX
         EVdk/UlP7nFL9vZGhLwiSwkSWbocsFTelrgZA97cXvaYPI8YVnyVApEu90F4Q7U4tuOj
         7GRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BBUuJAHx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lc9iXaxJc/p9mNtzi892q+2Xj6zIE/16eYinSdT4a0Q=;
        b=KwdyO3QLcPKstes2MkgdzqA92iSb+jxZbl1KvtxuID4muI0w4hMe1GYcG9Mb3143SQ
         NoyLsWJM+bJPkHEARzdXDb86fL2mpdUD6/2syIXPG8mh6+2KIaxJi+DQn/wExh8ieOfX
         j8osADEQKFkcusH6O+IB7CELr2T9294kB9uc2Tx1XZwHI40kHG1rRH9XScjiuO8qVouZ
         rim0MJ3Atc98N8r96Loog+0+8ZSAeo/S6DpMApYfK+Rwj54Tv+h7cC2RfRBctlOXdeUK
         VpSfrq6T7JLQ8p0SuZf5kAsFQW5zqktyUAWrCC313yH5HACVctNxcynQbR5+V+G8wjGB
         lq2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lc9iXaxJc/p9mNtzi892q+2Xj6zIE/16eYinSdT4a0Q=;
        b=QmxZy/xwt9Dy4IRujBsNw3ZRph3j62CDMteMfxADmytmzUyfDsCdkM6TipwBOQSOKZ
         TrkZx8RRjEdNM3twVdZ8pSoQkXwkZkwtjNQDw0ogpLnaniaT6PYDaryZ+BXGNWCTeMx6
         TuhhPjmSfVA/NAF8EkbsmvyZKz4ONNNAV8tw4BxT85zKM9PLjWjiSuW5pHdhgs3B/25E
         T1KKrDScFqpsY65efGpqR/TByMfqJkGrxtTos/bxmaH5p35wbIaM1nbR79rx/guO8rfZ
         XXPrPfUkF5y0jFu8qz/l+ulirALG+4xe2eNBbNOqkjKWovwSWOAG/FZyQ5h8lKK2Te7I
         pMtQ==
X-Gm-Message-State: APjAAAVR0M+WSybrs+XCwm162b7sieVYfBmDE7btPeuaBKR2fmy0Mfl6
	G2E0r6u9e7TpvVgR+xH2i68=
X-Google-Smtp-Source: APXvYqz/0cmHXWMzkPn7Rnhbx99FHBA2pHKJkqoVdsRhEgpJWFUUHq+3QyiaraRPleZWhInoXEYCjw==
X-Received: by 2002:a6b:b58b:: with SMTP id e133mr6603226iof.86.1574092991749;
        Mon, 18 Nov 2019 08:03:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:8e8b:: with SMTP id q133ls2692842iod.4.gmail; Mon, 18
 Nov 2019 08:03:11 -0800 (PST)
X-Received: by 2002:a5e:a501:: with SMTP id 1mr13759899iog.211.1574092991350;
        Mon, 18 Nov 2019 08:03:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574092991; cv=none;
        d=google.com; s=arc-20160816;
        b=qIKSCiWyJ0Um9Nb9b6noZ/4ZeuT+4/+ew/EKQND05K8WSs2rwhSRrsDkA4u3upbPKC
         lgx4U9CzOJjdVPrutUbNt8s6s0gKFzu2zokXX4NWqHWRF7hDV9x/qZNKH44Ygfd1BlIF
         wvLH2SKt/2hXT6w3izJtGCygfjc9I2HKyhCyiIAOlv5bqIMhpGIuLC7L1bCDJETw9s+f
         RrDkPJOIBkAiuUpVxw3uJ190qQLJ0ODV+Zw4X/l3S05ccykUmNBFSXiXfpLkcAyWk9/H
         wba87p7KCadz7go4q7ZXkwLNPeTFR7YGuHSdXDpGhnPHxUCvU/YL9W7VjoegDurYnblX
         bTiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aWBQvoRHIiT9gfZg6X80o74ola6obCU5UQn5MoahYmQ=;
        b=QNx2DhmLX502ueF1CSkzfPWO8F5MVgQe6NDQtZXHltdfgFOaE9VAej6hxyzfVi1LYu
         KhzjR6/R57Qro0aXP301dJLikCHfqDdf3urWJevChoWcEfb/NZc+TY9FcjB9+tbxR0vv
         K4Kb4Qa4Emi8LNeReFKIiu+Yf1XhOI0T2sFPIvqAo5c2tSYSxmGLaXc0OrToO3nkokEG
         uPoJ/QQ8YvMyZDZuMLQCSYZTGjmwmKAPj+7UpxImWkTIZ4jpAZcVanlmudGtKCJ0Gwti
         8/uw5+VohFwb/LQSOiVO9wjr7V3FlzuOdgmXA2LCwReoQNW4P6oCey2c6Oq12g8HU626
         sftA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BBUuJAHx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id y205si1011504iof.2.2019.11.18.08.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 08:03:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id h15so14828953qka.13
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 08:03:11 -0800 (PST)
X-Received: by 2002:a05:620a:1127:: with SMTP id p7mr25770552qkk.250.1574092990186;
 Mon, 18 Nov 2019 08:03:10 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic>
In-Reply-To: <20191118142144.GC6363@zn.tnic>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Nov 2019 17:02:58 +0100
Message-ID: <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Borislav Petkov <bp@alien8.de>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BBUuJAHx;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Mon, Nov 18, 2019 at 3:21 PM Borislav Petkov <bp@alien8.de> wrote:
>
> On Fri, Nov 15, 2019 at 08:17:27PM +0100, Jann Horn wrote:
> >  dotraplinkage void
> >  do_general_protection(struct pt_regs *regs, long error_code)
> >  {
> > @@ -547,8 +581,15 @@ do_general_protection(struct pt_regs *regs, long error_code)
> >                       return;
> >
> >               if (notify_die(DIE_GPF, desc, regs, error_code,
> > -                            X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> > -                     die(desc, regs, error_code);
> > +                            X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> > +                     return;
> > +
> > +             if (error_code)
> > +                     pr_alert("GPF is segment-related (see error code)\n");
> > +             else
> > +                     print_kernel_gp_address(regs);
> > +
> > +             die(desc, regs, error_code);
>
> Right, this way, those messages appear before the main "general
> protection ..." message:
>
> [    2.434372] traps: probably dereferencing non-canonical address 0xdfff000000000001
> [    2.442492] general protection fault: 0000 [#1] PREEMPT SMP
>
> Can we glue/merge them together? Or is this going to confuse tools too much:
>
> [    2.542218] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
>
> (and that sentence could be shorter too:
>
>         "general protection fault for non-canonical address 0xdfff000000000001"
>
> looks ok to me too.)

This exact form will confuse syzkaller crash parsing for Linux kernel:
https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L1347
It expects a "general protection fault:" line for these crashes.

A graceful way to update kernel crash messages would be to add more
tests with the new format here:
https://github.com/google/syzkaller/tree/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/testdata/linux/report
Update parsing code. Roll out new version. Update all other testing
systems that detect and parse kernel crashes. Then commit kernel
changes.

An unfortunate consequence of offloading testing to third-party systems...



> Here's a dirty diff together with a reproducer ontop of yours:
>
> ---
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index bf796f8c9998..dab702ba28a6 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -515,7 +515,7 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
>   * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
>   * address, print that address.
>   */
> -static void print_kernel_gp_address(struct pt_regs *regs)
> +static unsigned long get_kernel_gp_address(struct pt_regs *regs)
>  {
>  #ifdef CONFIG_X86_64
>         u8 insn_bytes[MAX_INSN_SIZE];
> @@ -523,7 +523,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
>         unsigned long addr_ref;
>
>         if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> -               return;
> +               return 0;
>
>         kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
>         insn_get_modrm(&insn);
> @@ -532,22 +532,22 @@ static void print_kernel_gp_address(struct pt_regs *regs)
>
>         /* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
>         if (addr_ref >= ~__VIRTUAL_MASK)
> -               return;
> +               return 0;
>
>         /* Bail out if the entire operand is in the canonical user half. */
>         if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
> -               return;
> +               return 0;
>
> -       pr_alert("probably dereferencing non-canonical address 0x%016lx\n",
> -                addr_ref);
> +       return addr_ref;
>  #endif
>  }
>
> +#define GPFSTR "general protection fault"
>  dotraplinkage void
>  do_general_protection(struct pt_regs *regs, long error_code)
>  {
> -       const char *desc = "general protection fault";
>         struct task_struct *tsk;
> +       char desc[90];
>
>         RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
>         cond_local_irq_enable(regs);
> @@ -584,12 +584,18 @@ do_general_protection(struct pt_regs *regs, long error_code)
>                                X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
>                         return;
>
> -               if (error_code)
> -                       pr_alert("GPF is segment-related (see error code)\n");
> -               else
> -                       print_kernel_gp_address(regs);
> +               if (error_code) {
> +                       snprintf(desc, 90, "segment-related " GPFSTR);
> +               } else {
> +                       unsigned long addr_ref = get_kernel_gp_address(regs);
> +
> +                       if (addr_ref)
> +                               snprintf(desc, 90, GPFSTR " while derefing a non-canonical address 0x%lx", addr_ref);
> +                       else
> +                               snprintf(desc, 90, GPFSTR);
> +               }
>
> -               die(desc, regs, error_code);
> +               die((const char *)desc, regs, error_code);
>                 return;
>         }
>
> diff --git a/init/main.c b/init/main.c
> index 91f6ebb30ef0..7acc7e660be9 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -1124,6 +1124,9 @@ static int __ref kernel_init(void *unused)
>
>         rcu_end_inkernel_boot();
>
> +       asm volatile("mov $0xdfff000000000001, %rax\n\t"
> +                    "jmpq *%rax\n\t");
> +
>         if (ramdisk_execute_command) {
>                 ret = run_init_process(ramdisk_execute_command);
>                 if (!ret)
>
> --
> Regards/Gruss,
>     Boris.
>
> https://people.kernel.org/tglx/notes-about-netiquette
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191118142144.GC6363%40zn.tnic.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbCOr%3Ddu1QEg8TtiZ-X6U%2B8ZPR4N07rJOeSCsd5h%2BzO3w%40mail.gmail.com.
