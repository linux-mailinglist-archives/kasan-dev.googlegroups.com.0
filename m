Return-Path: <kasan-dev+bncBDFJHU6GRMBBBN5E4KJQMGQEMVFUBKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CFE7A51F322
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 06:02:00 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id u26-20020adfb21a000000b0020ac48a9aa4sf5296557wra.5
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 21:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652068920; cv=pass;
        d=google.com; s=arc-20160816;
        b=BpnO+51p1nmwhWJrrGYuFaaDg3tG9FezEQXYbr1ItcZhtEyigs/kDtVz3W5Wq4mjA6
         p27GyFc6I0rJpkIEckOTOs37DJ48+AX+tVh8hdGZmZK+bEqgws0isA9RzeWF3LnoM+eF
         Dj2731KUpsmrYJntGMIZeyfp0Ipz1gSyTcbKP0DHyyUgRciKRx0aMJc7KRup5mEOo6C2
         Sx0S1j8cj4qQWhHcC3cLal8LNOIagzsBgcY1IUoXzsln6GHHs1083vnrIQA0xl6P4IBy
         KoyoKM2uEic9qTovjW7G6pWk7b4EzuJWfvZW+nqyAWlgXI8IvikIlkn2xzuhzZmpyvsT
         jo0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1qEaaMn16OooUPu12khw9f9LGAFzPdB4oUFvMPo5McE=;
        b=LjhffxyMOuv5VnAwQqbvSz2HjvJ1UbHenEd/gJnTErZBVSq1jp8VkClPPzS6gEvCSA
         hiQTTGi68UB36GqoPkg4qDFtKFh/LeoO/3w4iOhKeMb8h0Xx6bHHZT3zwMEx+7TT7pkx
         +Zo0jojlh3wnuQ+rc06M6QJB6nPRRNVdotZpUphmgMclVNlACbKUgNUj1FErE6IP0f63
         00hyPv8xFSzDBrfhBart8fdiqye5DENuFeZcHabmyYhEE5Y416QqZKh80jhGNS0Yytjc
         TNsm3hVtws8S62XHlCJGNtdR2/cge8MDhNM/1A1iqsErvKLEmY5dMbpHy5ynhw0k5T8m
         Mwzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b="IX/c5ofu";
       spf=neutral (google.com: 2a00:1450:4864:20::429 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1qEaaMn16OooUPu12khw9f9LGAFzPdB4oUFvMPo5McE=;
        b=HwBZvlW7xP1KP41GCrDmfP3gN21XPW6qbNWOELru4julbB87z7/DnkYvy3xWlbzm/z
         gWXEB5BKCum77Wy9nYRKbh6Rdp6Y/+lbppu6x/PGC42Qbxaww0oJt3g9iMF1cF4GyRz4
         Ojx4iKwuvzimf7W7wQgfPr1tcu08BY+P9aJFq04gkrnVeOkVCcdxCQiNDdeHlsp4RGNJ
         IVrIJcXZJ/gLgcy1b7ZropSkVgcm6QJAEbjDAmFLrDBuGxAUq0WUcL5iF+EnEe/pLMEG
         9L+stiqWMNEEzb+IorLn8vT/MEpZbp0H/8iR9Fzb/dQEE1IxU3q1sCUFeoOgwqXVUR/8
         j1jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1qEaaMn16OooUPu12khw9f9LGAFzPdB4oUFvMPo5McE=;
        b=MBv6vpGRV+M0hjruH70ebJrCVar9A9M6sZ3LnS+XsxD1SWm5neKbMg0TBA++vjkMXe
         TO15k6fTwI9JgHtnXilFENgJ7nTp9PA0QN02p5yluixvQzcRyCLlY4cvjP6pVZ6br3kz
         4iUz8PPkrq5suxeR04c6rHZpswLjqAPbnWxkGMjMQ0dPpXNqyrYkYTYc8FlumTmTtEba
         gUcdTs/71413TuVi8hEGB1wEG8pIpxVvtzkLj646opJuQLVGlQrcEyONanYckCzj/xqH
         252x0ZqfTe3TD9vxZG9IM1vwFYUKFiWEGe8E68hu3ghYdlw44PDd+kID5uufKGdn/fk2
         MfBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Nd2vThY9RlKzNDBDXBgD4XYrirAT523esD7y/R3XTNjjHd3H9
	BkvNmnw8Xtu3p2MmXhK38zQ=
X-Google-Smtp-Source: ABdhPJwvIR7dj8DFBkAIcGCQqyZ9f27nVkq6UI/oiPiA38nt/TSJ3W5ZZHKWC915pbgkiujcHJkqgg==
X-Received: by 2002:a5d:4b0d:0:b0:20a:f3d9:336e with SMTP id v13-20020a5d4b0d000000b0020af3d9336emr12733552wrq.467.1652068920131;
        Sun, 08 May 2022 21:02:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64ca:0:b0:20c:bb44:bd7 with SMTP id f10-20020a5d64ca000000b0020cbb440bd7ls143990wri.0.gmail;
 Sun, 08 May 2022 21:01:59 -0700 (PDT)
X-Received: by 2002:adf:ec03:0:b0:20a:d0b5:a06f with SMTP id x3-20020adfec03000000b0020ad0b5a06fmr11785924wrn.669.1652068919220;
        Sun, 08 May 2022 21:01:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652068919; cv=none;
        d=google.com; s=arc-20160816;
        b=XD9cdbe07ErPEBMScWgQsJa3zEoXqQ+Ok8O7wBevlB8SwDda/QzHFgnvw+aRy97VNt
         e47AFyMaGmQ3uDV/SGpqTPysEB03sIptLVBoyWiurqOlk6qCXSEcuiGcGsKWjWyBBXFi
         gS/raZ4XZYl8PgJVPrkAwk2Pd/4/+CvMKrLdHQ9DcpqGW4qyaYo9l5AClSXwDVeEEBm5
         47tB1ex+nOpotG/+jGUVZQ4lmSTXMeeVseXwlc+SGrSxQHPeuyewIbycRSIXMs3l+RzL
         jpULT019Sm97yQK8INeWQ9e4C3BZ8knfJ+3QNTm++zl5wcszS5tZAKtsGlGoc5kxCCCz
         nRGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SJ8dF+QuMh/vx+O3NBUHJR6SAWNkIGtKyfjSID7EqTw=;
        b=pQpcWJF6Wj0pCIwdA6hSVXoPnL7StQr53NNSKbXdM7u9X2XJjsXz6Y70POHkB2vfaS
         TuH+K/u7pR9OcgW3C2NzPziCdeFrZvJyZ2O72AOnYf28BkPKRLBFRbB0+1O1ZoAxCTHq
         P1yVlTnSjsPWUPe1Nu0+d5mRC4svxZf4Ov7cjTTKW9pjsz4GOtZE/fw+ZgN/boYs4C/4
         I9mJ8avHWyiBKoYM/OftxplqRQmVJ35+/3/xSrFxS4FQeMf/24jIeuKyGrIFjdVI5A/h
         w6nio5d05QiE6EJT9A91pnmr/QMI34QszUvO7oFsmHnuvlACunLE7ZKa+p3YV42lzBWC
         HWtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b="IX/c5ofu";
       spf=neutral (google.com: 2a00:1450:4864:20::429 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id bg21-20020a05600c3c9500b00394803e5756si279879wmb.0.2022.05.08.21.01.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 May 2022 21:01:59 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::429 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id x18so17669107wrc.0
        for <kasan-dev@googlegroups.com>; Sun, 08 May 2022 21:01:59 -0700 (PDT)
X-Received: by 2002:a5d:6d0d:0:b0:20c:530c:1681 with SMTP id
 e13-20020a5d6d0d000000b0020c530c1681mr11940881wrq.214.1652068918822; Sun, 08
 May 2022 21:01:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-4-jszhang@kernel.org>
In-Reply-To: <20220508160749.984-4-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Mon, 9 May 2022 09:31:47 +0530
Message-ID: <CAAhSdy32C59ULdP7KNNgy08jF5vUbvYoF6_n+kAopJfiLsJQFw@mail.gmail.com>
Subject: Re: [PATCH v2 3/4] riscv: replace has_fpu() with system_supports_fpu()
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b="IX/c5ofu";       spf=neutral (google.com: 2a00:1450:4864:20::429 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sun, May 8, 2022 at 9:46 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> This is to use the unified cpus_have_{final|const}_cap() instead of
> putting static key related here and there.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>  arch/riscv/include/asm/cpufeature.h | 5 +++++
>  arch/riscv/include/asm/switch_to.h  | 9 ++-------
>  arch/riscv/kernel/cpufeature.c      | 8 ++------
>  arch/riscv/kernel/process.c         | 2 +-
>  arch/riscv/kernel/signal.c          | 4 ++--
>  5 files changed, 12 insertions(+), 16 deletions(-)
>
> diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
> index d80ddd2f3b49..634a653c7fa2 100644
> --- a/arch/riscv/include/asm/cpufeature.h
> +++ b/arch/riscv/include/asm/cpufeature.h
> @@ -91,4 +91,9 @@ static inline void cpus_set_cap(unsigned int num)
>         }
>  }
>
> +static inline bool system_supports_fpu(void)
> +{
> +       return IS_ENABLED(CONFIG_FPU) && !cpus_have_final_cap(RISCV_HAS_NO_FPU);

This should be checking for "f" and "d" ISA extensions since "FPU" is
not an ISA extension name.

> +}
> +
>  #endif
> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/switch_to.h
> index 0a3f4f95c555..362cb18d12d5 100644
> --- a/arch/riscv/include/asm/switch_to.h
> +++ b/arch/riscv/include/asm/switch_to.h
> @@ -8,6 +8,7 @@
>
>  #include <linux/jump_label.h>
>  #include <linux/sched/task_stack.h>
> +#include <asm/cpufeature.h>
>  #include <asm/processor.h>
>  #include <asm/ptrace.h>
>  #include <asm/csr.h>
> @@ -56,13 +57,7 @@ static inline void __switch_to_aux(struct task_struct *prev,
>         fstate_restore(next, task_pt_regs(next));
>  }
>
> -extern struct static_key_false cpu_hwcap_fpu;
> -static __always_inline bool has_fpu(void)
> -{
> -       return static_branch_likely(&cpu_hwcap_fpu);
> -}
>  #else
> -static __always_inline bool has_fpu(void) { return false; }
>  #define fstate_save(task, regs) do { } while (0)
>  #define fstate_restore(task, regs) do { } while (0)
>  #define __switch_to_aux(__prev, __next) do { } while (0)
> @@ -75,7 +70,7 @@ extern struct task_struct *__switch_to(struct task_struct *,
>  do {                                                   \
>         struct task_struct *__prev = (prev);            \
>         struct task_struct *__next = (next);            \
> -       if (has_fpu())                                  \
> +       if (system_supports_fpu())                                      \
>                 __switch_to_aux(__prev, __next);        \
>         ((last) = __switch_to(__prev, __next));         \
>  } while (0)
> diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
> index e6c72cad0c1c..1edf3c3f8f62 100644
> --- a/arch/riscv/kernel/cpufeature.c
> +++ b/arch/riscv/kernel/cpufeature.c
> @@ -22,10 +22,6 @@ unsigned long elf_hwcap __read_mostly;
>  /* Host ISA bitmap */
>  static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
>
> -#ifdef CONFIG_FPU
> -__ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
> -#endif
> -
>  DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
>  EXPORT_SYMBOL(cpu_hwcaps);
>
> @@ -254,8 +250,8 @@ void __init riscv_fill_hwcap(void)
>         pr_info("riscv: ELF capabilities %s\n", print_str);
>
>  #ifdef CONFIG_FPU
> -       if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
> -               static_branch_enable(&cpu_hwcap_fpu);
> +       if (!(elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D)))
> +               cpus_set_cap(RISCV_HAS_NO_FPU);
>  #endif
>         enable_cpu_capabilities();
>         static_branch_enable(&riscv_const_caps_ready);
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index 504b496787aa..c9cd0b42299e 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -88,7 +88,7 @@ void start_thread(struct pt_regs *regs, unsigned long pc,
>         unsigned long sp)
>  {
>         regs->status = SR_PIE;
> -       if (has_fpu()) {
> +       if (system_supports_fpu()) {
>                 regs->status |= SR_FS_INITIAL;
>                 /*
>                  * Restore the initial value to the FP register
> diff --git a/arch/riscv/kernel/signal.c b/arch/riscv/kernel/signal.c
> index 9f4e59f80551..96aa593a989e 100644
> --- a/arch/riscv/kernel/signal.c
> +++ b/arch/riscv/kernel/signal.c
> @@ -90,7 +90,7 @@ static long restore_sigcontext(struct pt_regs *regs,
>         /* sc_regs is structured the same as the start of pt_regs */
>         err = __copy_from_user(regs, &sc->sc_regs, sizeof(sc->sc_regs));
>         /* Restore the floating-point state. */
> -       if (has_fpu())
> +       if (system_supports_fpu())
>                 err |= restore_fp_state(regs, &sc->sc_fpregs);
>         return err;
>  }
> @@ -143,7 +143,7 @@ static long setup_sigcontext(struct rt_sigframe __user *frame,
>         /* sc_regs is structured the same as the start of pt_regs */
>         err = __copy_to_user(&sc->sc_regs, regs, sizeof(sc->sc_regs));
>         /* Save the floating-point state. */
> -       if (has_fpu())
> +       if (system_supports_fpu())
>                 err |= save_fp_state(regs, &sc->sc_fpregs);
>         return err;
>  }
> --
> 2.34.1
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

Regards,
Anup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy32C59ULdP7KNNgy08jF5vUbvYoF6_n%2BkAopJfiLsJQFw%40mail.gmail.com.
