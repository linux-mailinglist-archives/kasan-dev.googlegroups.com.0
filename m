Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPXEYWDQMGQE2BWEV6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 394633CB6F3
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 13:49:20 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id 15-20020aa7924f0000b029033034a332ecsf6809270pfp.16
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 04:49:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626436159; cv=pass;
        d=google.com; s=arc-20160816;
        b=AjQOq0cT5ojbie/BS19NsIfEfjvpqRl6EPkcsVo7S8up4ERplUckWolOrWGXH/uD5+
         YnUZtCo/tN9IWVq2as7UAsbezh0lVMhVYx4OuOAD1VX+XxhkAV79o1pkNwj3aklKsgNf
         4mTgdTgpMb37UL/ofebHVW2UwoXSey8KCXOIhyfeX29f7+KsEQeZMi/7KAPIi8swKS53
         wr4Kk+Sg5IhneNuGhr5DejsdAD/hBQjlElnfNgBeJYETJLDjf36rCkjSYTB1JAmnL7Ra
         tGECtQoXpbJAJIuz1hzglZpc0YcDyF1NwDV7RODGjP1O2JOIidJcg3lo/QmYkCdfxZEI
         N4dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=b5RAFmrPbDVFlhAFfk/nZIx3oEtLGrCmyPkR70dmgZk=;
        b=NdB7+XQmUVD0cthqKFXR9iF6t49xb72FXEcWmRxFkrrTniUBKJk+IUyARqNaSpAkAl
         AaOr61rvYCPug6Ng3l8eyac0uVfQKXHhzPKA1kahewHoMDiEUR7+cmR8TmgMq0W+YuHM
         YQToMIdttSeovVoV4o3PMdvr8MOcDc2TfNqen9upoXXiDz+ixYHH8dNQ9sgTv8BrH/a2
         OQhFie0XrkhFlon8yNuzyldLzMU4ZPIZ4nX3XrINjmcMO0SwAejqdmXFpGAlQkiHBZyQ
         IrlgIaqJRbipog7fJ6xlEztIVXfQznlrezwv5MSpodNli4Jkt21zAgJR/OHuWWV09JuU
         6hMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kfmI7F/G";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b5RAFmrPbDVFlhAFfk/nZIx3oEtLGrCmyPkR70dmgZk=;
        b=WvdBV/sNLDHF32SxhGSnLKI6WFvB/hSVXb1HJFRvjvlq78A3bP/MgBtTWuwilRUDTF
         5HrFGDorosle4cjsgs+GBH/lFLX1BJtHrh4nxEWBCAW4xOtUdBmTjx8WOAHKciRdt93/
         hN84y7gfBy4hdKFxoEHIDKlcn8S5Vd2LuJw2t7vRzfSfjpJZzBvF1xxlAjU75+8XYQqO
         UdOR+u72aMVoSUcwIN4j6FLNEjfUTcpWzGWb6Hh/UvCYdSFg0qH9wG4y+73OMhTv0ygY
         jg2IZ/Vmkm7DNEAw6eZxIoo2lHM5MvOfvt+HjN6Vw4J9AdG1dy4MtBEDO5eSAN0z0dcx
         aFdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b5RAFmrPbDVFlhAFfk/nZIx3oEtLGrCmyPkR70dmgZk=;
        b=nejORIs1k3NWnUId02TltVDx9+9wyH1xyQJG/WnlUO8MEkGWJXSWJRwvRzEos9vL8I
         a23XWlPFxtg2XYGgHESUDNAadkia4a45pgG3eUCrCngwkWwt2vOKK2R1RXT6X5Ontab+
         D8Ml/FHDpsF55J695q5v34hdSDmWhaGZsa530BcZJMKc3AxaF/NgiONHxCzLgJYmf/mq
         U0FINzd56UCupRidrsKygBIeScYOLsn1qTMNWw6b1hj3b5x0o4i7Gp1n0pyb/rTgek2e
         Ln/nyB96miIFNuseKQIThVRg/+2XcKJC5lFMoyf9Fo0tdKa/ja/kCEHa7LeXYn+XjAAG
         xehg==
X-Gm-Message-State: AOAM5338cgt+t3D6im+9eNEhK6HUsZJH4UqYLnbxScJdCD/JRL+O/kTj
	kOjQBxG9QEyGUpkT239OnC4=
X-Google-Smtp-Source: ABdhPJyi+OMz3iVx6MD17GyTXY7rrvxmkZ2vbiLfovAYZLWlphNVa9wDAlmmXFqU6yxpDdVAaQPaGg==
X-Received: by 2002:a63:d213:: with SMTP id a19mr9637584pgg.28.1626436158866;
        Fri, 16 Jul 2021 04:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c241:: with SMTP id d1ls5668214pjx.1.canary-gmail;
 Fri, 16 Jul 2021 04:49:18 -0700 (PDT)
X-Received: by 2002:a17:90a:728d:: with SMTP id e13mr9681663pjg.181.1626436158115;
        Fri, 16 Jul 2021 04:49:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626436158; cv=none;
        d=google.com; s=arc-20160816;
        b=LoAy5uh1XmdUYAxKwxuXM+jVfCWwg1FKQhkF8hZoGJ9W9uLSzmhS2zt3fgHkiDTBVU
         Ylnd4K7W7pTj9BcN/4498aWbBswAJ/b4XA9XJUHiU7MtlhX+4T6jjww4k2MbJCaTHOmK
         jsMyIPAGETzF2yDnY2e0uwIp2hh4/FBFO/naiSVCcNFiMEXbqxoBPduXV760oLhFZSRH
         VRsgqBrLa64u4rZvs6a4Y6nL9UaH2bKGna6rOyNst/GVln6/zUQjbCf1tVY/rujbAzRa
         /6s1A88enxw47yiw2MSu43aAQ7HOU8eep/WpM0x7jegbV0uKBYt4zvNKL7eGq8ZjNBcS
         Uqhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Lb1Rl6A0HGKcykI+mvGe2MaXa5u6d/fROY/IK5zaRTs=;
        b=YQPhs3GeSo/ZQ+uodbK96w9mFvTfv3rb4U/tlzK4P3NZMLxkHVz1kHYrSPc0lyUVd7
         Q3IjWjAO//t5AraRX9rSW4/U25HcNXn7EKpR5AggfjladCWqI2OMw4kWrftYj10K55r8
         HA2nE8lEQKEtezyG4U3skO/pmzsSoO727DgK1nVWLLgREyAFUuElZODEwI6uJRYq2U4A
         R6jV6NJTdinB+vSMpKCm3kIOtiEKrU3JGXdLp+ippLBAifRueAmQiIL5cDUwhTx3sZvn
         9cCWOfOzbNacLmpsrXhoZZnJiYKEn1bAw21ZAI1wAB5P51jrpmtlL2VFhnZH/5cmXJ2A
         bxWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kfmI7F/G";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc33.google.com (mail-oo1-xc33.google.com. [2607:f8b0:4864:20::c33])
        by gmr-mx.google.com with ESMTPS id t202si311595pfc.2.2021.07.16.04.49.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jul 2021 04:49:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) client-ip=2607:f8b0:4864:20::c33;
Received: by mail-oo1-xc33.google.com with SMTP id o2-20020a0568200402b0290258a7ff4058so226460oou.10
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 04:49:18 -0700 (PDT)
X-Received: by 2002:a4a:df02:: with SMTP id i2mr156404oou.14.1626436157547;
 Fri, 16 Jul 2021 04:49:17 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133> <87mtqnxx89.fsf_-_@disp2133>
In-Reply-To: <87mtqnxx89.fsf_-_@disp2133>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jul 2021 13:49:06 +0200
Message-ID: <CANpmjNMW0QAbv6D5a+xFhTetD=8y9Pf6pX+y3hW0XxTQiAfXUQ@mail.gmail.com>
Subject: Re: [PATCH 4/6] signal/sparc: si_trapno is only used with SIGILL ILL_ILLTRP
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="kfmI7F/G";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as
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

On Thu, 15 Jul 2021 at 20:12, Eric W. Biederman <ebiederm@xmission.com> wrote:
> While reviewing the signal handlers on sparc it became clear that
> si_trapno is only set to a non-zero value when sending SIGILL with
> si_code ILL_ILLTRP.
>
> Add force_sig_fault_trapno and send SIGILL ILL_ILLTRP with it.
>
> Remove the define of __ARCH_SI_TRAPNO and remove the always zero
> si_trapno parameter from send_sig_fault and force_sig_fault.
>
> v1: https://lkml.kernel.org/r/m1eeers7q7.fsf_-_@fess.ebiederm.org
> v2: https://lkml.kernel.org/r/20210505141101.11519-7-ebiederm@xmission.com
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  arch/sparc/include/uapi/asm/siginfo.h |  3 --
>  arch/sparc/kernel/process_64.c        |  2 +-
>  arch/sparc/kernel/sys_sparc_32.c      |  2 +-
>  arch/sparc/kernel/sys_sparc_64.c      |  2 +-
>  arch/sparc/kernel/traps_32.c          | 22 +++++++-------
>  arch/sparc/kernel/traps_64.c          | 44 ++++++++++++---------------
>  arch/sparc/kernel/unaligned_32.c      |  2 +-
>  arch/sparc/mm/fault_32.c              |  2 +-
>  arch/sparc/mm/fault_64.c              |  2 +-
>  include/linux/sched/signal.h          |  1 +
>  kernel/signal.c                       | 19 ++++++++++++
>  11 files changed, 56 insertions(+), 45 deletions(-)
>
> diff --git a/arch/sparc/include/uapi/asm/siginfo.h b/arch/sparc/include/uapi/asm/siginfo.h
> index 68bdde4c2a2e..0e7c27522aed 100644
> --- a/arch/sparc/include/uapi/asm/siginfo.h
> +++ b/arch/sparc/include/uapi/asm/siginfo.h
> @@ -8,9 +8,6 @@
>
>  #endif /* defined(__sparc__) && defined(__arch64__) */
>
> -
> -#define __ARCH_SI_TRAPNO
> -
>  #include <asm-generic/siginfo.h>
>
>
> diff --git a/arch/sparc/kernel/process_64.c b/arch/sparc/kernel/process_64.c
> index d33c58a58d4f..547b06b49ce3 100644
> --- a/arch/sparc/kernel/process_64.c
> +++ b/arch/sparc/kernel/process_64.c
> @@ -518,7 +518,7 @@ void synchronize_user_stack(void)
>
>  static void stack_unaligned(unsigned long sp)
>  {
> -       force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) sp, 0);
> +       force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) sp);
>  }
>
>  static const char uwfault32[] = KERN_INFO \
> diff --git a/arch/sparc/kernel/sys_sparc_32.c b/arch/sparc/kernel/sys_sparc_32.c
> index be77538bc038..082a551897ed 100644
> --- a/arch/sparc/kernel/sys_sparc_32.c
> +++ b/arch/sparc/kernel/sys_sparc_32.c
> @@ -151,7 +151,7 @@ sparc_breakpoint (struct pt_regs *regs)
>  #ifdef DEBUG_SPARC_BREAKPOINT
>          printk ("TRAP: Entering kernel PC=%x, nPC=%x\n", regs->pc, regs->npc);
>  #endif
> -       force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc, 0);
> +       force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc);
>
>  #ifdef DEBUG_SPARC_BREAKPOINT
>         printk ("TRAP: Returning to space: PC=%x nPC=%x\n", regs->pc, regs->npc);
> diff --git a/arch/sparc/kernel/sys_sparc_64.c b/arch/sparc/kernel/sys_sparc_64.c
> index 6b92fadb6ec7..1e9a9e016237 100644
> --- a/arch/sparc/kernel/sys_sparc_64.c
> +++ b/arch/sparc/kernel/sys_sparc_64.c
> @@ -514,7 +514,7 @@ asmlinkage void sparc_breakpoint(struct pt_regs *regs)
>  #ifdef DEBUG_SPARC_BREAKPOINT
>          printk ("TRAP: Entering kernel PC=%lx, nPC=%lx\n", regs->tpc, regs->tnpc);
>  #endif
> -       force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->tpc, 0);
> +       force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->tpc);
>  #ifdef DEBUG_SPARC_BREAKPOINT
>         printk ("TRAP: Returning to space: PC=%lx nPC=%lx\n", regs->tpc, regs->tnpc);
>  #endif
> diff --git a/arch/sparc/kernel/traps_32.c b/arch/sparc/kernel/traps_32.c
> index 247a0d9683b2..5630e5a395e0 100644
> --- a/arch/sparc/kernel/traps_32.c
> +++ b/arch/sparc/kernel/traps_32.c
> @@ -102,8 +102,8 @@ void do_hw_interrupt(struct pt_regs *regs, unsigned long type)
>         if(regs->psr & PSR_PS)
>                 die_if_kernel("Kernel bad trap", regs);
>
> -       force_sig_fault(SIGILL, ILL_ILLTRP,
> -                       (void __user *)regs->pc, type - 0x80);
> +       force_sig_fault_trapno(SIGILL, ILL_ILLTRP,
> +                              (void __user *)regs->pc, type - 0x80);
>  }
>
>  void do_illegal_instruction(struct pt_regs *regs, unsigned long pc, unsigned long npc,
> @@ -116,7 +116,7 @@ void do_illegal_instruction(struct pt_regs *regs, unsigned long pc, unsigned lon
>                regs->pc, *(unsigned long *)regs->pc);
>  #endif
>
> -       send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc, 0, current);
> +       send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc, current);
>  }
>
>  void do_priv_instruction(struct pt_regs *regs, unsigned long pc, unsigned long npc,
> @@ -124,7 +124,7 @@ void do_priv_instruction(struct pt_regs *regs, unsigned long pc, unsigned long n
>  {
>         if(psr & PSR_PS)
>                 die_if_kernel("Penguin instruction from Penguin mode??!?!", regs);
> -       send_sig_fault(SIGILL, ILL_PRVOPC, (void __user *)pc, 0, current);
> +       send_sig_fault(SIGILL, ILL_PRVOPC, (void __user *)pc, current);
>  }
>
>  /* XXX User may want to be allowed to do this. XXX */
> @@ -145,7 +145,7 @@ void do_memaccess_unaligned(struct pt_regs *regs, unsigned long pc, unsigned lon
>  #endif
>         send_sig_fault(SIGBUS, BUS_ADRALN,
>                        /* FIXME: Should dig out mna address */ (void *)0,
> -                      0, current);
> +                      current);
>  }
>
>  static unsigned long init_fsr = 0x0UL;
> @@ -291,7 +291,7 @@ void do_fpe_trap(struct pt_regs *regs, unsigned long pc, unsigned long npc,
>                 else if (fsr & 0x01)
>                         code = FPE_FLTRES;
>         }
> -       send_sig_fault(SIGFPE, code, (void __user *)pc, 0, fpt);
> +       send_sig_fault(SIGFPE, code, (void __user *)pc, fpt);
>  #ifndef CONFIG_SMP
>         last_task_used_math = NULL;
>  #endif
> @@ -305,7 +305,7 @@ void handle_tag_overflow(struct pt_regs *regs, unsigned long pc, unsigned long n
>  {
>         if(psr & PSR_PS)
>                 die_if_kernel("Penguin overflow trap from kernel mode", regs);
> -       send_sig_fault(SIGEMT, EMT_TAGOVF, (void __user *)pc, 0, current);
> +       send_sig_fault(SIGEMT, EMT_TAGOVF, (void __user *)pc, current);
>  }
>
>  void handle_watchpoint(struct pt_regs *regs, unsigned long pc, unsigned long npc,
> @@ -327,13 +327,13 @@ void handle_reg_access(struct pt_regs *regs, unsigned long pc, unsigned long npc
>         printk("Register Access Exception at PC %08lx NPC %08lx PSR %08lx\n",
>                pc, npc, psr);
>  #endif
> -       force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)pc, 0);
> +       force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)pc);
>  }
>
>  void handle_cp_disabled(struct pt_regs *regs, unsigned long pc, unsigned long npc,
>                         unsigned long psr)
>  {
> -       send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, 0, current);
> +       send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, current);
>  }
>
>  void handle_cp_exception(struct pt_regs *regs, unsigned long pc, unsigned long npc,
> @@ -343,13 +343,13 @@ void handle_cp_exception(struct pt_regs *regs, unsigned long pc, unsigned long n
>         printk("Co-Processor Exception at PC %08lx NPC %08lx PSR %08lx\n",
>                pc, npc, psr);
>  #endif
> -       send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, 0, current);
> +       send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, current);
>  }
>
>  void handle_hw_divzero(struct pt_regs *regs, unsigned long pc, unsigned long npc,
>                        unsigned long psr)
>  {
> -       send_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)pc, 0, current);
> +       send_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)pc, current);
>  }
>
>  #ifdef CONFIG_DEBUG_BUGVERBOSE
> diff --git a/arch/sparc/kernel/traps_64.c b/arch/sparc/kernel/traps_64.c
> index a850dccd78ea..6863025ed56d 100644
> --- a/arch/sparc/kernel/traps_64.c
> +++ b/arch/sparc/kernel/traps_64.c
> @@ -107,8 +107,8 @@ void bad_trap(struct pt_regs *regs, long lvl)
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGILL, ILL_ILLTRP,
> -                       (void __user *)regs->tpc, lvl);
> +       force_sig_fault_trapno(SIGILL, ILL_ILLTRP,
> +                              (void __user *)regs->tpc, lvl);
>  }
>
>  void bad_trap_tl1(struct pt_regs *regs, long lvl)
> @@ -201,8 +201,7 @@ void spitfire_insn_access_exception(struct pt_regs *regs, unsigned long sfsr, un
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGSEGV, SEGV_MAPERR,
> -                       (void __user *)regs->tpc, 0);
> +       force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)regs->tpc);
>  out:
>         exception_exit(prev_state);
>  }
> @@ -237,7 +236,7 @@ void sun4v_insn_access_exception(struct pt_regs *regs, unsigned long addr, unsig
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *) addr, 0);
> +       force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *) addr);
>  }
>
>  void sun4v_insn_access_exception_tl1(struct pt_regs *regs, unsigned long addr, unsigned long type_ctx)
> @@ -321,7 +320,7 @@ void spitfire_data_access_exception(struct pt_regs *regs, unsigned long sfsr, un
>         if (is_no_fault_exception(regs))
>                 return;
>
> -       force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)sfar, 0);
> +       force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)sfar);
>  out:
>         exception_exit(prev_state);
>  }
> @@ -385,13 +384,13 @@ void sun4v_data_access_exception(struct pt_regs *regs, unsigned long addr, unsig
>          */
>         switch (type) {
>         case HV_FAULT_TYPE_INV_ASI:
> -               force_sig_fault(SIGILL, ILL_ILLADR, (void __user *)addr, 0);
> +               force_sig_fault(SIGILL, ILL_ILLADR, (void __user *)addr);
>                 break;
>         case HV_FAULT_TYPE_MCD_DIS:
> -               force_sig_fault(SIGSEGV, SEGV_ACCADI, (void __user *)addr, 0);
> +               force_sig_fault(SIGSEGV, SEGV_ACCADI, (void __user *)addr);
>                 break;
>         default:
> -               force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)addr, 0);
> +               force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)addr);
>                 break;
>         }
>  }
> @@ -568,7 +567,7 @@ static void spitfire_ue_log(unsigned long afsr, unsigned long afar, unsigned lon
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGBUS, BUS_OBJERR, (void *)0, 0);
> +       force_sig_fault(SIGBUS, BUS_OBJERR, (void *)0);
>  }
>
>  void spitfire_access_error(struct pt_regs *regs, unsigned long status_encoded, unsigned long afar)
> @@ -2069,8 +2068,7 @@ void do_mcd_err(struct pt_regs *regs, struct sun4v_error_entry ent)
>         /* Send SIGSEGV to the userspace process with the right signal
>          * code
>          */
> -       force_sig_fault(SIGSEGV, SEGV_ADIDERR, (void __user *)ent.err_raddr,
> -                       0);
> +       force_sig_fault(SIGSEGV, SEGV_ADIDERR, (void __user *)ent.err_raddr);
>  }
>
>  /* We run with %pil set to PIL_NORMAL_MAX and PSTATE_IE enabled in %pstate.
> @@ -2184,7 +2182,7 @@ bool sun4v_nonresum_error_user_handled(struct pt_regs *regs,
>         }
>         if (attrs & SUN4V_ERR_ATTRS_PIO) {
>                 force_sig_fault(SIGBUS, BUS_ADRERR,
> -                               (void __user *)sun4v_get_vaddr(regs), 0);
> +                               (void __user *)sun4v_get_vaddr(regs));
>                 return true;
>         }
>
> @@ -2340,8 +2338,7 @@ static void do_fpe_common(struct pt_regs *regs)
>                         else if (fsr & 0x01)
>                                 code = FPE_FLTRES;
>                 }
> -               force_sig_fault(SIGFPE, code,
> -                               (void __user *)regs->tpc, 0);
> +               force_sig_fault(SIGFPE, code, (void __user *)regs->tpc);
>         }
>  }
>
> @@ -2395,8 +2392,7 @@ void do_tof(struct pt_regs *regs)
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGEMT, EMT_TAGOVF,
> -                       (void __user *)regs->tpc, 0);
> +       force_sig_fault(SIGEMT, EMT_TAGOVF, (void __user *)regs->tpc);
>  out:
>         exception_exit(prev_state);
>  }
> @@ -2415,8 +2411,7 @@ void do_div0(struct pt_regs *regs)
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGFPE, FPE_INTDIV,
> -                       (void __user *)regs->tpc, 0);
> +       force_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)regs->tpc);
>  out:
>         exception_exit(prev_state);
>  }
> @@ -2612,7 +2607,7 @@ void do_illegal_instruction(struct pt_regs *regs)
>                         }
>                 }
>         }
> -       force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc, 0);
> +       force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc);
>  out:
>         exception_exit(prev_state);
>  }
> @@ -2632,7 +2627,7 @@ void mem_address_unaligned(struct pt_regs *regs, unsigned long sfar, unsigned lo
>         if (is_no_fault_exception(regs))
>                 return;
>
> -       force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *)sfar, 0);
> +       force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *)sfar);
>  out:
>         exception_exit(prev_state);
>  }
> @@ -2650,7 +2645,7 @@ void sun4v_do_mna(struct pt_regs *regs, unsigned long addr, unsigned long type_c
>         if (is_no_fault_exception(regs))
>                 return;
>
> -       force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) addr, 0);
> +       force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) addr);
>  }
>
>  /* sun4v_mem_corrupt_detect_precise() - Handle precise exception on an ADI
> @@ -2697,7 +2692,7 @@ void sun4v_mem_corrupt_detect_precise(struct pt_regs *regs, unsigned long addr,
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGSEGV, SEGV_ADIPERR, (void __user *)addr, 0);
> +       force_sig_fault(SIGSEGV, SEGV_ADIPERR, (void __user *)addr);
>  }
>
>  void do_privop(struct pt_regs *regs)
> @@ -2712,8 +2707,7 @@ void do_privop(struct pt_regs *regs)
>                 regs->tpc &= 0xffffffff;
>                 regs->tnpc &= 0xffffffff;
>         }
> -       force_sig_fault(SIGILL, ILL_PRVOPC,
> -                       (void __user *)regs->tpc, 0);
> +       force_sig_fault(SIGILL, ILL_PRVOPC, (void __user *)regs->tpc);
>  out:
>         exception_exit(prev_state);
>  }
> diff --git a/arch/sparc/kernel/unaligned_32.c b/arch/sparc/kernel/unaligned_32.c
> index ef5c5207c9ff..455f0258c745 100644
> --- a/arch/sparc/kernel/unaligned_32.c
> +++ b/arch/sparc/kernel/unaligned_32.c
> @@ -278,5 +278,5 @@ asmlinkage void user_unaligned_trap(struct pt_regs *regs, unsigned int insn)
>  {
>         send_sig_fault(SIGBUS, BUS_ADRALN,
>                        (void __user *)safe_compute_effective_address(regs, insn),
> -                      0, current);
> +                      current);
>  }
> diff --git a/arch/sparc/mm/fault_32.c b/arch/sparc/mm/fault_32.c
> index de2031c2b2d7..fa858626b85b 100644
> --- a/arch/sparc/mm/fault_32.c
> +++ b/arch/sparc/mm/fault_32.c
> @@ -83,7 +83,7 @@ static void __do_fault_siginfo(int code, int sig, struct pt_regs *regs,
>                 show_signal_msg(regs, sig, code,
>                                 addr, current);
>
> -       force_sig_fault(sig, code, (void __user *) addr, 0);
> +       force_sig_fault(sig, code, (void __user *) addr);
>  }
>
>  static unsigned long compute_si_addr(struct pt_regs *regs, int text_fault)
> diff --git a/arch/sparc/mm/fault_64.c b/arch/sparc/mm/fault_64.c
> index 0a6bcc85fba7..9a9652a15fed 100644
> --- a/arch/sparc/mm/fault_64.c
> +++ b/arch/sparc/mm/fault_64.c
> @@ -176,7 +176,7 @@ static void do_fault_siginfo(int code, int sig, struct pt_regs *regs,
>         if (unlikely(show_unhandled_signals))
>                 show_signal_msg(regs, sig, code, addr, current);
>
> -       force_sig_fault(sig, code, (void __user *) addr, 0);
> +       force_sig_fault(sig, code, (void __user *) addr);
>  }
>
>  static unsigned int get_fault_insn(struct pt_regs *regs, unsigned int insn)
> diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
> index b9126fe06c3f..99a9ab2b169a 100644
> --- a/include/linux/sched/signal.h
> +++ b/include/linux/sched/signal.h
> @@ -329,6 +329,7 @@ int force_sig_pkuerr(void __user *addr, u32 pkey);
>  int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
>
>  int force_sig_ptrace_errno_trap(int errno, void __user *addr);
> +int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
>
>  extern int send_sig_info(int, struct kernel_siginfo *, struct task_struct *);
>  extern void force_sigsegv(int sig);
> diff --git a/kernel/signal.c b/kernel/signal.c
> index a3229add4455..87a374225277 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1808,6 +1808,22 @@ int force_sig_ptrace_errno_trap(int errno, void __user *addr)
>         return force_sig_info(&info);
>  }
>
> +/* For the rare architectures that include trap information using
> + * si_trapno.
> + */
> +int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = sig;
> +       info.si_errno = 0;
> +       info.si_code  = code;
> +       info.si_addr  = addr;
> +       info.si_trapno = trapno;
> +       return force_sig_info(&info);
> +}
> +
>  int kill_pgrp(struct pid *pid, int sig, int priv)
>  {
>         int ret;
> @@ -3243,6 +3259,9 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>  #endif
>                         else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
>                                 layout = SIL_PERF_EVENT;
> +                       else if (IS_ENABLED(CONFIG_SPARC) &&
> +                                (sig == SIGILL) && (si_code == ILL_ILLTRP))
> +                               layout = SIL_FAULT_TRAPNO;
>  #ifdef __ARCH_SI_TRAPNO
>                         else if (layout == SIL_FAULT)
>                                 layout = SIL_FAULT_TRAPNO;
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87mtqnxx89.fsf_-_%40disp2133.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMW0QAbv6D5a%2BxFhTetD%3D8y9Pf6pX%2By3hW0XxTQiAfXUQ%40mail.gmail.com.
