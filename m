Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIPEYWDQMGQE7OBNHXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC113CB6EE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 13:48:50 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id r4-20020a4ab5040000b02902446eb55473sf6403017ooo.20
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 04:48:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626436129; cv=pass;
        d=google.com; s=arc-20160816;
        b=JEgIfqBoh6sOQnV6aGa32u+RZDS4sSBOYpJ9RWvb+Hm+hRM5ffLmCV2M4AlxChkQPS
         qMt6ElCzLlD094yJNt+NV3e9waKg9CEpQMBoFictExkhVcex+T8ORy8joZPcf1sOiGLE
         KDMAFMM9yphGrP6h6Q3rD4v3lOyQqymYmMDM1lm6XodkiMwbpmkP0htflTG3950MlsC/
         Kb/QjEb/C9MwqDltilmJoXVvfnzfR6c89iscZDqNDnJL3AKIcHjF1Tm1o6dLRik7Sazv
         A3ieKrqmnp4+0DOcMEoJFs2PqeEy63NaWGkWjUL6MtQI19q3LIzQJkxIRmKlhd2NiHTl
         +mCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FewLU/o9mwo048Ai6x6wsQ5RSN55q9XheB4ON/z+Pa0=;
        b=V9zA/CnWge1KQV2CFc0vhmMvCwGShYmGREtbzaeiZ/lbD+PvZTduqS95xg5hXemqwe
         O8Q8IGyXJ2kfmktG27pcWJedi6pJ7khyVwPK0R27QsLzEQRsXuAjWZvC7wTEWu1MmjWf
         Xb3MN7cVLmGpMOnl2JOG2UzLYlpufH/Bad18DFwMXF+A+NR3fULHxEfSTlKlIrzYKF3G
         c0SDnAwKLBwdq+QNn4Gv59uUngQ4P0pCOConXghCdciOIP2rpyrR92FX4DO7KHvuO/G1
         d5N4tSHelU3LAk4tzAKbd4uRrvdXzJrWF36j2g1gFwp6hFcfuDoC7Et7MEz/alU2ZsLD
         bYug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gSPmr7lU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FewLU/o9mwo048Ai6x6wsQ5RSN55q9XheB4ON/z+Pa0=;
        b=cl+DmeowPXLDW4Nwz1mLXI+Z3kN0Mqgq8R40MPII4FEcXnLWWfdDdyp2yfYbZuOet/
         u2xs+HugU4XB1vA7szsp3OwSdGgOkJP28bE8T7C/KR8WjANIA1Yp7rsj6EAlNYc0R/R2
         7bs5foqjnUmxqNQbyvbFhCE7BBzCXb9dqfXxQcFIghHViESLXNOwGNs51urVKjD+MA7v
         7FSNQGc3MIB17Y9WXkIBwQNTGZCq1HNmj/H3haohrAGu3fgGap7YHxrrbJ8831nk3ubR
         vstNLOiFICJ+zYXRQjs7Jn15s/GBZF1GSZOZXlxG6mQ79TmCgROQ7spUhV+a5/ueCzI4
         688g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FewLU/o9mwo048Ai6x6wsQ5RSN55q9XheB4ON/z+Pa0=;
        b=hEfxYRzZzKeK+lKpLL69IZYfpQK9QkCBA4uOkFIwmb6Fw8MeFhg54GSp1pSq1QthnH
         YNTgSmFcaFlrUv/EXAb88I483ZuPbB504Hd13Oqok6LUG+6gjiT4nn1ItGTXZnrUXn7v
         Xdcu3SHNlpkzhf/FWhNi3kPfTVIN2Fg1VbQLgC1yi8SAl/czVaAWBj951aptzxfEzTqt
         asPbejmuWE97PK6zRyWoW/0GY9HEla1YolnjGA/oXSOpa4I3bAkaSsoQck8V+aVf+YSS
         MBrjbnxVq8WxWBCdCyfhL0EbxxbOzeGfKJDb5sC5oAq/LwmuleT+836x9AuemqqdEGXn
         sQew==
X-Gm-Message-State: AOAM533jfe8ZtWpxaBmoqP+FkStFZhIi7bfOW5Oo4NX1BqyfKNqYV/uL
	B394nHLMOZe6517O4ZabPxw=
X-Google-Smtp-Source: ABdhPJztFBx9X5Lg8URZhR8ar+ktrOkSMzexK1MH/GjJV1grsqhq7xKbOueZMHja0B3ATIiQz4DTYw==
X-Received: by 2002:a05:6830:1c65:: with SMTP id s5mr2260125otg.256.1626436129518;
        Fri, 16 Jul 2021 04:48:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:eb97:: with SMTP id d23ls993615ooj.2.gmail; Fri, 16 Jul
 2021 04:48:49 -0700 (PDT)
X-Received: by 2002:a4a:4fca:: with SMTP id c193mr7244488oob.33.1626436129161;
        Fri, 16 Jul 2021 04:48:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626436129; cv=none;
        d=google.com; s=arc-20160816;
        b=Ir9+WiEFCK7S8rvJZdsbMMQAIvg24ouQkHrmNTRgpl5rA/4xDDcxhCZ18P83wXG0sR
         s7N8l8SF7ZrfwPa9WGHV3yGmpR3coQZRxJYplvddw9TzH55RQ2AzNCJOGNAfX4Ydw5SY
         Kvb1/g+SOlYs0zJdG9N8bCRG8bKCnt8lAhe5T5RGL3ijxQp+NwssB8GM1ReTdcptFxHQ
         RgkGq+Ij+9kxVAnFcHLVPv77SQsKYL8cjw7TbnAko+Gycpu80mm8UduaaPy/3E5hhjIp
         J9DnLXq1XkLFcrUqWXUwXYEs4G7oVf0plsq4YAG4v4nApyUdr45NnZyAbgAo/9ERO3Fn
         Sddw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JBDiVd1cIkOM0UYh+A3OX5H90z0c0oFIied3Z31qv0U=;
        b=U0mPHXoDnIWOMbKrweZS9lcU+itPZmfjAY3p64+9O1AiE4RnyB5VaYQ5ZLYQf4fxVq
         /aWOOj7uFc49uoTUyfBq4+A5OIMIpUiJoJxmy6OTvVMN5tHiQC9NFZhlCh1icUgapQ3d
         m59qUpst8udp1nEJ/VfktzvO/CEItNsGH0isTbd+Q1l49jpZ7maWW9QkiiLSj7zwmmbw
         ZJ39DyxkHMUp/M+WJP+BfNALGOGgxkyZGkVWgbuPVo258cgYxIumzhniHxHPJ7LfbPK7
         Dkj1MpmJz9Z5N0R0kEkBMi0k3eF3HM5OFLgdRyv4K2C6Efv6KvqrXbK2tt1Cbjn3p4IQ
         qfRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gSPmr7lU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id j26si1447487ooj.0.2021.07.16.04.48.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jul 2021 04:48:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id y66so1146684oie.7
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 04:48:49 -0700 (PDT)
X-Received: by 2002:aca:4705:: with SMTP id u5mr7755996oia.70.1626436128741;
 Fri, 16 Jul 2021 04:48:48 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133> <87h7gvxx7l.fsf_-_@disp2133>
In-Reply-To: <87h7gvxx7l.fsf_-_@disp2133>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jul 2021 13:48:37 +0200
Message-ID: <CANpmjNNUX0cz39a2TYU+MVwd2MzACkBs9E+rECFGgE-1p8nPFA@mail.gmail.com>
Subject: Re: [PATCH 5/6] signal/alpha: si_trapno is only used with SIGFPE and
 SIGTRAP TRAP_UNK
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
 header.i=@google.com header.s=20161025 header.b=gSPmr7lU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Thu, 15 Jul 2021 at 20:13, Eric W. Biederman <ebiederm@xmission.com> wrote:
> While reviewing the signal handlers on alpha it became clear that
> si_trapno is only set to a non-zero value when sending SIGFPE and when
> sending SITGRAP with si_code TRAP_UNK.
>
> Add send_sig_fault_trapno and send SIGTRAP TRAP_UNK, and SIGFPE with it.
>
> Remove the define of __ARCH_SI_TRAPNO and remove the always zero
> si_trapno parameter from send_sig_fault and force_sig_fault.
>
> v1: https://lkml.kernel.org/r/m1eeers7q7.fsf_-_@fess.ebiederm.org
> v2: https://lkml.kernel.org/r/20210505141101.11519-7-ebiederm@xmission.com
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  arch/alpha/include/uapi/asm/siginfo.h |  2 --
>  arch/alpha/kernel/osf_sys.c           |  2 +-
>  arch/alpha/kernel/signal.c            |  4 ++--
>  arch/alpha/kernel/traps.c             | 26 +++++++++++++-------------
>  arch/alpha/mm/fault.c                 |  4 ++--
>  include/linux/sched/signal.h          |  2 ++
>  kernel/signal.c                       | 21 +++++++++++++++++++++
>  7 files changed, 41 insertions(+), 20 deletions(-)
>
> diff --git a/arch/alpha/include/uapi/asm/siginfo.h b/arch/alpha/include/uapi/asm/siginfo.h
> index 6e1a2af2f962..e08eae88182b 100644
> --- a/arch/alpha/include/uapi/asm/siginfo.h
> +++ b/arch/alpha/include/uapi/asm/siginfo.h
> @@ -2,8 +2,6 @@
>  #ifndef _ALPHA_SIGINFO_H
>  #define _ALPHA_SIGINFO_H
>
> -#define __ARCH_SI_TRAPNO
> -
>  #include <asm-generic/siginfo.h>
>
>  #endif
> diff --git a/arch/alpha/kernel/osf_sys.c b/arch/alpha/kernel/osf_sys.c
> index d5367a1c6300..bbdb1a9a5fd8 100644
> --- a/arch/alpha/kernel/osf_sys.c
> +++ b/arch/alpha/kernel/osf_sys.c
> @@ -876,7 +876,7 @@ SYSCALL_DEFINE5(osf_setsysinfo, unsigned long, op, void __user *, buffer,
>                         if (fex & IEEE_TRAP_ENABLE_DZE) si_code = FPE_FLTDIV;
>                         if (fex & IEEE_TRAP_ENABLE_INV) si_code = FPE_FLTINV;
>
> -                       send_sig_fault(SIGFPE, si_code,
> +                       send_sig_fault_trapno(SIGFPE, si_code,
>                                        (void __user *)NULL,  /* FIXME */
>                                        0, current);
>                 }
> diff --git a/arch/alpha/kernel/signal.c b/arch/alpha/kernel/signal.c
> index 948b89789da8..bc077babafab 100644
> --- a/arch/alpha/kernel/signal.c
> +++ b/arch/alpha/kernel/signal.c
> @@ -219,7 +219,7 @@ do_sigreturn(struct sigcontext __user *sc)
>
>         /* Send SIGTRAP if we're single-stepping: */
>         if (ptrace_cancel_bpt (current)) {
> -               send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc, 0,
> +               send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc,
>                                current);
>         }
>         return;
> @@ -247,7 +247,7 @@ do_rt_sigreturn(struct rt_sigframe __user *frame)
>
>         /* Send SIGTRAP if we're single-stepping: */
>         if (ptrace_cancel_bpt (current)) {
> -               send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc, 0,
> +               send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc,
>                                current);
>         }
>         return;
> diff --git a/arch/alpha/kernel/traps.c b/arch/alpha/kernel/traps.c
> index 921d4b6e4d95..e9e3de18793b 100644
> --- a/arch/alpha/kernel/traps.c
> +++ b/arch/alpha/kernel/traps.c
> @@ -227,7 +227,7 @@ do_entArith(unsigned long summary, unsigned long write_mask,
>         }
>         die_if_kernel("Arithmetic fault", regs, 0, NULL);
>
> -       send_sig_fault(SIGFPE, si_code, (void __user *) regs->pc, 0, current);
> +       send_sig_fault_trapno(SIGFPE, si_code, (void __user *) regs->pc, 0, current);
>  }
>
>  asmlinkage void
> @@ -268,13 +268,13 @@ do_entIF(unsigned long type, struct pt_regs *regs)
>                         regs->pc -= 4;  /* make pc point to former bpt */
>                 }
>
> -               send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc, 0,
> +               send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc,
>                                current);
>                 return;
>
>               case 1: /* bugcheck */
> -               send_sig_fault(SIGTRAP, TRAP_UNK, (void __user *) regs->pc, 0,
> -                              current);
> +               send_sig_fault_trapno(SIGTRAP, TRAP_UNK,
> +                                     (void __user *) regs->pc, 0, current);
>                 return;
>
>               case 2: /* gentrap */
> @@ -335,8 +335,8 @@ do_entIF(unsigned long type, struct pt_regs *regs)
>                         break;
>                 }
>
> -               send_sig_fault(signo, code, (void __user *) regs->pc, regs->r16,
> -                              current);
> +               send_sig_fault_trapno(signo, code, (void __user *) regs->pc,
> +                                     regs->r16, current);
>                 return;
>
>               case 4: /* opDEC */
> @@ -360,9 +360,9 @@ do_entIF(unsigned long type, struct pt_regs *regs)
>                         if (si_code == 0)
>                                 return;
>                         if (si_code > 0) {
> -                               send_sig_fault(SIGFPE, si_code,
> -                                              (void __user *) regs->pc, 0,
> -                                              current);
> +                               send_sig_fault_trapno(SIGFPE, si_code,
> +                                                     (void __user *) regs->pc,
> +                                                     0, current);
>                                 return;
>                         }
>                 }
> @@ -387,7 +387,7 @@ do_entIF(unsigned long type, struct pt_regs *regs)
>                       ;
>         }
>
> -       send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc, 0, current);
> +       send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc, current);
>  }
>
>  /* There is an ifdef in the PALcode in MILO that enables a
> @@ -402,7 +402,7 @@ do_entDbg(struct pt_regs *regs)
>  {
>         die_if_kernel("Instruction fault", regs, 0, NULL);
>
> -       force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc, 0);
> +       force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc);
>  }
>
>
> @@ -964,12 +964,12 @@ do_entUnaUser(void __user * va, unsigned long opcode,
>                         si_code = SEGV_MAPERR;
>                 mmap_read_unlock(mm);
>         }
> -       send_sig_fault(SIGSEGV, si_code, va, 0, current);
> +       send_sig_fault(SIGSEGV, si_code, va, current);
>         return;
>
>  give_sigbus:
>         regs->pc -= 4;
> -       send_sig_fault(SIGBUS, BUS_ADRALN, va, 0, current);
> +       send_sig_fault(SIGBUS, BUS_ADRALN, va, current);
>         return;
>  }
>
> diff --git a/arch/alpha/mm/fault.c b/arch/alpha/mm/fault.c
> index 09172f017efc..eee5102c3d88 100644
> --- a/arch/alpha/mm/fault.c
> +++ b/arch/alpha/mm/fault.c
> @@ -219,13 +219,13 @@ do_page_fault(unsigned long address, unsigned long mmcsr,
>         mmap_read_unlock(mm);
>         /* Send a sigbus, regardless of whether we were in kernel
>            or user mode.  */
> -       force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address, 0);
> +       force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address);
>         if (!user_mode(regs))
>                 goto no_context;
>         return;
>
>   do_sigsegv:
> -       force_sig_fault(SIGSEGV, si_code, (void __user *) address, 0);
> +       force_sig_fault(SIGSEGV, si_code, (void __user *) address);
>         return;
>
>  #ifdef CONFIG_ALPHA_LARGE_VMALLOC
> diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
> index 99a9ab2b169a..6657184cef07 100644
> --- a/include/linux/sched/signal.h
> +++ b/include/linux/sched/signal.h
> @@ -330,6 +330,8 @@ int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
>
>  int force_sig_ptrace_errno_trap(int errno, void __user *addr);
>  int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
> +int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
> +                       struct task_struct *t);
>
>  extern int send_sig_info(int, struct kernel_siginfo *, struct task_struct *);
>  extern void force_sigsegv(int sig);
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 87a374225277..ae06a424aa72 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1824,6 +1824,23 @@ int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
>         return force_sig_info(&info);
>  }
>
> +/* For the rare architectures that include trap information using
> + * si_trapno.
> + */
> +int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
> +                         struct task_struct *t)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = sig;
> +       info.si_errno = 0;
> +       info.si_code  = code;
> +       info.si_addr  = addr;
> +       info.si_trapno = trapno;
> +       return send_sig_info(info.si_signo, &info, t);
> +}
> +
>  int kill_pgrp(struct pid *pid, int sig, int priv)
>  {
>         int ret;
> @@ -3262,6 +3279,10 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>                         else if (IS_ENABLED(CONFIG_SPARC) &&
>                                  (sig == SIGILL) && (si_code == ILL_ILLTRP))
>                                 layout = SIL_FAULT_TRAPNO;
> +                       else if (IS_ENABLED(CONFIG_ALPHA) &&
> +                                ((sig == SIGFPE) ||
> +                                 ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
> +                               layout = SIL_FAULT_TRAPNO;
>  #ifdef __ARCH_SI_TRAPNO
>                         else if (layout == SIL_FAULT)
>                                 layout = SIL_FAULT_TRAPNO;
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNUX0cz39a2TYU%2BMVwd2MzACkBs9E%2BrECFGgE-1p8nPFA%40mail.gmail.com.
