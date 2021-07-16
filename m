Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD7EYWDQMGQERNBW3KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 206633CB6E9
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 13:48:33 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id k32-20020a25b2a00000b0290557cf3415f8sf12306867ybj.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 04:48:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626436112; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xlvc6HVNY8BfcTuyXnu8WE8gexwlOMYKpbrhiUSLfXFoQfKBP+aj7w2CFSbvFPIr6k
         fg3i8yyTsjkqq8lHtLFbdOJwiciEByVGkQSZcz1fWoB3YPFIzMUjCR2dZYzo1u3Goa03
         oFQ8OftHNpwxSs3gIVVP78WIFLxBUDheLVLbMt5oWo0LcsiJkJwRyEgUhzw9N3U8XEHC
         9TezDi0R9gfvAP92GLdR2lBa+GQuUfviwD8CRkZ+yAR6E92edLFd/dWZwKY2CXD+njKU
         Y6G02qIDtTGNXHj/qfSABU7Mm3Mpc+7UcdyRUOZWWF0qpYQHrRWnrD+eftzNHaVn0i0G
         VVdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EOq4OdUtLmrxXQRsMQC1GUhXdKZUv07ZtMUiMQz/tFY=;
        b=Rtr32Rq4e2wOHmeVTLzCvHiZsz52WUPanm4mS+T7KTzrh2EU72NfWhtJkslHSnXsng
         R8RxH6m/00fpy/Rn1iWax2/BVFGALZbgdnRQQD8Tg/H1cRzRyBN3ul/PGayhWRlc+B/s
         NAShPE/fNsMweT/QsVat9qSxHdqND+4jGPXjc5eRl5q9S8f9lrPQnjKwgdNEO9Pwf3Qo
         THHblgmjXwAczPOq7uYzpyvFKXyo/Od1r4Fzb+17bVJqYpzquQhW//YHZukB7uMQyO0/
         VFyHIgeiEjcop5Qdn1492oMvLK6shpT/060W8JFPk23niv8JYfxBGp8U+g+LUqlgCrxJ
         Tb2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="D8DMuB/N";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EOq4OdUtLmrxXQRsMQC1GUhXdKZUv07ZtMUiMQz/tFY=;
        b=QRIdnuiSCgavg08eGC6Tnbbc0xI/sAfokBZmc9k3JbLfFM36PvHWLQYTmuAq5eEXDp
         yOFuW3VqJOAoSMTCQKz4mL/m94nf/xA0h+aMr0F/ohz37khWN8fdlfmj8Z1tgILMqopa
         aRnCLyADnuNBc9bZgFeh102gnLnXJP9z22F7W9aloTUBX+HWcz5OILrJomrPMfhI3BgD
         pifta4t8yPEblVcMf/DJQ5NoBHh+bi4xdfzZquFOxs3hU/wX0QnPRe/EpD7RucFlTjb0
         83agmdVTK4ts9fZcVJZvrlIEEp7ZQo8zwPCMl2NJMOl3LqiuirrhOpGrjsHcQ3J12dnx
         Zz0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EOq4OdUtLmrxXQRsMQC1GUhXdKZUv07ZtMUiMQz/tFY=;
        b=OlTheS3Eln+ye+2aWmbNImaOOgh/2e+E4gHuyPEH+Nnf2QBKSu+EvKq0D5d7o63Y0S
         zUu5sxJMQb1VvyeuiHpbJBBvIS9CxDVnDfk3RdpHe8iAl6YJyWVRYY/XIBOWnp7ygIg6
         hfOPPNGQB/luNhc9WufzIq9hi6uDw2kimToQRkM0sMl0+3JjeIMNK9TEheN9BGgM0vAb
         guXHERRYgi8MyDlzfCHgKHjmjqLAICnpVshR13zCXnbEUYtJDgIOSfIo7dP8xf4Po65D
         UPNI9yQGN3uzaENonaMoepvYmRWyJJl6xL4ag35C9S0YbLrDvaXquNfuyZIYbi/FXJdh
         MRYw==
X-Gm-Message-State: AOAM530F6wku+KPbvTCK6uuUI9pWgG3n5z9IhreJ1fkbA17ssoVm/FIm
	ffmvn/jtPcfLu8d47Tsa0ao=
X-Google-Smtp-Source: ABdhPJz8KCUmgaM21o8g5XK0VwhPeLesK9cjkyhpatBY4hqYgE0ZyLZLl+4WMeACt+Jjw4ot8rBULg==
X-Received: by 2002:a25:4206:: with SMTP id p6mr11888847yba.465.1626436112013;
        Fri, 16 Jul 2021 04:48:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4053:: with SMTP id n80ls5941768yba.11.gmail; Fri, 16
 Jul 2021 04:48:31 -0700 (PDT)
X-Received: by 2002:a25:ef0c:: with SMTP id g12mr12304312ybd.116.1626436111542;
        Fri, 16 Jul 2021 04:48:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626436111; cv=none;
        d=google.com; s=arc-20160816;
        b=FNhkZPBUKm0/D9SGTgWCk/rgcut5cHfmYVhgimYQxPUd3HaAQWI3UScIk7V1IHWjVe
         hCNwJrkcLB7b6LAEQAJe7dzVvbThkfgXe6lszhs/wvgFfULuhxlwJXr39Pf/YCn8BTaK
         wPAcMHUiWe4MPq3rRcWt4b4J0gi4sb5KKokMNyqkhPj38t9ufVb8ZJkSeSq6SWihg2C6
         48BhvSa2+rsYQL/9wyykZNsPGwjBYou1Dt5nFCNAHzfsrnq/EuM1CiAecRLsn6rhgdMC
         UzA44t8uMHnprx0KiCROvGYSpm8qgBYWyW7lQlxswc5g0HNL+6ncjnA4EreV0FbMtvjc
         ht7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SCAMfplbo3e2iODI9poYTm8lXc8h2ulhVqpOO6GIdUY=;
        b=HJun8fq+oT/lBJzJhisRIzInRqlbNtJ1+53iW8YoFxJ+fwzB13sUNK7NVPJyEf3/OL
         Mj0YxlEOg2dRWViYxWFGIJqZhOAi6J4/4rOUETBKVaTAB6NOlCs/Lxn8Iir0EUHL7dO6
         jtCBzevqEYrAaHCMbGq/U7zs/DyN+Ssgi7kqy1gSbldfswEHlHpw0IIOCTcWuSGAskZZ
         m/VHQW+kiWLAuyin8LkAImzjWkCgQsQHQ4CsZEOdzObEMJ8sBgFkET5TISJF94Z79nJD
         O+QRDU+aATTfr1ClncZu5+QgqwLkZh9dHtCnwKNHICIeLkmrwh2R+JtyqosB8FN1T5d5
         UmuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="D8DMuB/N";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id q62si1216384ybc.4.2021.07.16.04.48.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jul 2021 04:48:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id f12-20020a056830204cb029048bcf4c6bd9so9533606otp.8
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 04:48:31 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr8241154oti.251.1626436110870;
 Fri, 16 Jul 2021 04:48:30 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133> <87bl73xx6x.fsf_-_@disp2133>
In-Reply-To: <87bl73xx6x.fsf_-_@disp2133>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jul 2021 13:48:18 +0200
Message-ID: <CANpmjNOv4mf3PiEVvAUFAXkRaA3V37UBYoB2j2P7_qF868B6mA@mail.gmail.com>
Subject: Re: [PATCH 6/6] signal: Remove the generic __ARCH_SI_TRAPNO support
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
 header.i=@google.com header.s=20161025 header.b="D8DMuB/N";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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
> Now that __ARCH_SI_TRAPNO is no longer set by any architecture remove
> all of the code it enabled from the kernel.
>
> On alpha and sparc a more explict approach of using
> send_sig_fault_trapno or force_sig_fault_trapno in the very limited
> circumstances where si_trapno was set to a non-zero value.
>
> The generic support that is being removed always set si_trapno on all
> fault signals.  With only SIGILL ILL_ILLTRAP on sparc and SIGFPE and
> SIGTRAP TRAP_UNK on alpla providing si_trapno values asking all senders
> of fault signals to provide an si_trapno value does not make sense.
>
> Making si_trapno an ordinary extension of the fault siginfo layout has
> enabled the architecture generic implementation of SIGTRAP TRAP_PERF,
> and enables other faulting signals to grow architecture generic
> senders as well.
>
> v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
> v2: https://lkml.kernel.org/r/20210505141101.11519-8-ebiederm@xmission.com
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  arch/mips/include/uapi/asm/siginfo.h |  2 --
>  include/linux/sched/signal.h         |  8 --------
>  kernel/signal.c                      | 14 --------------
>  3 files changed, 24 deletions(-)
>
> diff --git a/arch/mips/include/uapi/asm/siginfo.h b/arch/mips/include/uapi/asm/siginfo.h
> index c34c7eef0a1c..8cb8bd061a68 100644
> --- a/arch/mips/include/uapi/asm/siginfo.h
> +++ b/arch/mips/include/uapi/asm/siginfo.h
> @@ -10,9 +10,7 @@
>  #ifndef _UAPI_ASM_SIGINFO_H
>  #define _UAPI_ASM_SIGINFO_H
>
> -
>  #define __ARCH_SIGEV_PREAMBLE_SIZE (sizeof(long) + 2*sizeof(int))
> -#undef __ARCH_SI_TRAPNO /* exception code needs to fill this ...  */
>
>  #define __ARCH_HAS_SWAPPED_SIGINFO
>
> diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
> index 6657184cef07..928e0025d358 100644
> --- a/include/linux/sched/signal.h
> +++ b/include/linux/sched/signal.h
> @@ -298,11 +298,6 @@ static inline void kernel_signal_stop(void)
>
>         schedule();
>  }
> -#ifdef __ARCH_SI_TRAPNO
> -# define ___ARCH_SI_TRAPNO(_a1) , _a1
> -#else
> -# define ___ARCH_SI_TRAPNO(_a1)
> -#endif
>  #ifdef __ia64__
>  # define ___ARCH_SI_IA64(_a1, _a2, _a3) , _a1, _a2, _a3
>  #else
> @@ -310,14 +305,11 @@ static inline void kernel_signal_stop(void)
>  #endif
>
>  int force_sig_fault_to_task(int sig, int code, void __user *addr
> -       ___ARCH_SI_TRAPNO(int trapno)
>         ___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
>         , struct task_struct *t);
>  int force_sig_fault(int sig, int code, void __user *addr
> -       ___ARCH_SI_TRAPNO(int trapno)
>         ___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr));
>  int send_sig_fault(int sig, int code, void __user *addr
> -       ___ARCH_SI_TRAPNO(int trapno)
>         ___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
>         , struct task_struct *t);
>
> diff --git a/kernel/signal.c b/kernel/signal.c
> index ae06a424aa72..2181423e562a 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1666,7 +1666,6 @@ void force_sigsegv(int sig)
>  }
>
>  int force_sig_fault_to_task(int sig, int code, void __user *addr
> -       ___ARCH_SI_TRAPNO(int trapno)
>         ___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
>         , struct task_struct *t)
>  {
> @@ -1677,9 +1676,6 @@ int force_sig_fault_to_task(int sig, int code, void __user *addr
>         info.si_errno = 0;
>         info.si_code  = code;
>         info.si_addr  = addr;
> -#ifdef __ARCH_SI_TRAPNO
> -       info.si_trapno = trapno;
> -#endif
>  #ifdef __ia64__
>         info.si_imm = imm;
>         info.si_flags = flags;
> @@ -1689,16 +1685,13 @@ int force_sig_fault_to_task(int sig, int code, void __user *addr
>  }
>
>  int force_sig_fault(int sig, int code, void __user *addr
> -       ___ARCH_SI_TRAPNO(int trapno)
>         ___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr))
>  {
>         return force_sig_fault_to_task(sig, code, addr
> -                                      ___ARCH_SI_TRAPNO(trapno)
>                                        ___ARCH_SI_IA64(imm, flags, isr), current);
>  }
>
>  int send_sig_fault(int sig, int code, void __user *addr
> -       ___ARCH_SI_TRAPNO(int trapno)
>         ___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
>         , struct task_struct *t)
>  {
> @@ -1709,9 +1702,6 @@ int send_sig_fault(int sig, int code, void __user *addr
>         info.si_errno = 0;
>         info.si_code  = code;
>         info.si_addr  = addr;
> -#ifdef __ARCH_SI_TRAPNO
> -       info.si_trapno = trapno;
> -#endif
>  #ifdef __ia64__
>         info.si_imm = imm;
>         info.si_flags = flags;
> @@ -3283,10 +3273,6 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>                                  ((sig == SIGFPE) ||
>                                   ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
>                                 layout = SIL_FAULT_TRAPNO;
> -#ifdef __ARCH_SI_TRAPNO
> -                       else if (layout == SIL_FAULT)
> -                               layout = SIL_FAULT_TRAPNO;
> -#endif
>                 }
>                 else if (si_code <= NSIGPOLL)
>                         layout = SIL_POLL;
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOv4mf3PiEVvAUFAXkRaA3V37UBYoB2j2P7_qF868B6mA%40mail.gmail.com.
