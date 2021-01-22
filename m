Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB6JVOAAMGQEFZ6MTUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D6BCC3005B4
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:43:21 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id v125sf2217655oig.7
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:43:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326601; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0m1kIKELlHPB7kG/PBI6eA/xViVV36UF3mup6YpUFJu0AC+kmNu40ySrnpsqWsDBz
         bMEjCXVxTCqirCwL/i3M345zQNYEBz0RhHR67oSZXkJIquKbvqM48XM599Y6wI2gGf9w
         7l6H3g7KXJTyblsIq5JRaIsNRESwjLKOQpcs9BYOSCJppoOXnsY5+M+1uG8XQk0RyJWQ
         HVQJCu7TTCGSBNbxnN9St4yIDSxd4AXlxTv/UyG1cPQVGMR1ciz19H8/Fe3STYWT4B53
         i8pHtWteApen7OxiQ99xSqDjwe2uRXs+WNvAuiQKgL+yTYT2CgMeOyaDBIHmVqI2WhwB
         DCvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9aPIjOmnLHy2JOe07Sn4EfepYn0Ea80eLnSrj/SzUBo=;
        b=vC7bVNQyhKO5mEY4lwfF63Wo+5AjdM20TNxuiRxZi+eSV54ziabmJyM1k+Ej8RRdqc
         5K2OonmDRoKiupcQfgBS70rlFUVSjNn7z5cdNDgswYSIsV5l4s9AYOt+CWrhMZOPu0kt
         Y7DFFCPkmeXuJqCxnXXoEFCzWCss20xCNd+3n5X62jwSA/xvh4ikaRlKiHR1Qb8qyFTT
         Di9LCwjQML2UZpyRKQYSxiH6Kc1Y18fPVHYCbscxkipIzn0BQBgSgcE/y0sxxzbyOmWV
         DSGq0eDXpn7g8/5mnKUflWuFZNsckHDIzwZdrGT7UrdxHoE1svu6lIryD/vMk++VfCFe
         sryQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NeoXBeCQ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9aPIjOmnLHy2JOe07Sn4EfepYn0Ea80eLnSrj/SzUBo=;
        b=anEh1E0mSoFu/9oGSUTgCVawHRw8TgoNNRnfNQWav3n8auh+gkMze9xI5Lu0Yg53sG
         hRsdKp3X2WqPWHstdbUerfgNMh5beOAx8ZUz/XZg93Mj4awHdVGBxqtLkD9orYoIaHPH
         Im8MdEtSeZq+ARVoqU0N43zxfGQhLajrjmatDV9yQFMmgQBfog1IR+34qAuKrI4L9t+m
         SjOeQQJ2o/AvQfIZ+JXtLZVEdPZ1OYXtt8vkizcNMK4tXKZXmN7g1GHMrEVdPPEED/LW
         jS4tYXM5Gnts94wVlJBzCwKQApG8jriHpHIlm7D3wYZOoZ01nuOGihV5zQ5pP64ljnsM
         koWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9aPIjOmnLHy2JOe07Sn4EfepYn0Ea80eLnSrj/SzUBo=;
        b=V9epcY/Sd+WN9HgWG8YP/DGBi70wQmv/WbjWoPD2lNmcHj/2PbxywiwfkaTFTHPFcZ
         1uIVAOnMYZ9QTrXd6xIbp1o05m+4M8mE9UdqonJgOytuCxLeQAQZHwcQPrF3lrwZ1LBb
         pK4q5wuJqIrNBWwJzZZl3DliE6wO+ztNCRJoyaBVYmY/2AjuJPKjbumW5EKYtXDsC8oy
         yrFDRBZYvuaVVVyi2fL0MN0kSNIuEnHlXQ92zuLDm0DzWp4B6r1hkw4oI5Tiv+lMW2BE
         j4Xp9KUFCIO2JX9lhTRjmlHiSjZYgjdXth0J1nhFl7Sft+bc4YTdolbnpfwqrERJmsRl
         GvDw==
X-Gm-Message-State: AOAM532SXpPxQTCn7Xuz/czN/lB+NtxzzU7eFrG0iUHZtY7DkDWV1VO8
	xBQ1siGsYocALsWuPPLaOHk=
X-Google-Smtp-Source: ABdhPJwrHbCG6tmEV5Lv1JLMPtklDIHlSgShTxOKN4IifwG63nBzrRLafq+x/WuSszfldTxuH+ZcnQ==
X-Received: by 2002:a9d:4c83:: with SMTP id m3mr3584757otf.353.1611326599330;
        Fri, 22 Jan 2021 06:43:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:3c3:: with SMTP id o3ls999951oie.1.gmail; Fri, 22
 Jan 2021 06:43:19 -0800 (PST)
X-Received: by 2002:aca:c448:: with SMTP id u69mr3361235oif.129.1611326599027;
        Fri, 22 Jan 2021 06:43:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326599; cv=none;
        d=google.com; s=arc-20160816;
        b=Cu+4HJ8OpR8A5VJDLnWq/ZsGRFws9CkrtyVisR56HYtSDJTee1ZVoBzNRN359c3MtL
         0UShQf5AM0LT38+06dxStfsGvSQjTJRZOb028mIGu8ctZZ70M1HRnjHl+PREyHsW7XaJ
         5D5H+/5wK+33flQXtj03PBbOaifUvq27K0gNzuQf5jwbKVH1aMw1mBrDZNyUaO9AE/rH
         02lCYOVhuevhOlmK5Ol90nq9asF6P6hds0WPmkobe80pTWU8WiGZUyr9vg6moPiZYb1o
         /SJNqLHuF2eMfk0WzVdaSCDI3akhAkrvEWARHCbeykgvtMfntkq6yKlL3z006sy1OWIr
         MuLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y8bgmkMu+cEZTApSrRWB5HvcRNQrWEtcL1QXInWauDE=;
        b=ZbkoT64VEfMK+LxrUv30goDFikwR0RN0kj4pRFoQ3f1LHDeVQfl4yLWSC7hqlh9Oj9
         Bb4CBi1ISzpI/SC9DmPZNDvWidOhdj3Oxp2wqKZK4plZ75Y2n+8KG37UaC61TZ073WHu
         CRZ1lHcNjaYwEFO5jgi/cEaprxgXD5FkwFFynWQqtZqeGfBECPpZcLX0ff0GmR7oVRZ/
         HwPi5xrPzpmOCllQhdJ+7b9dnvqYuu82hAoCMFGNvstOX0+VIXfaS7AKP3mN4zG1ZYmU
         MyYNdk0CyZHR57glxcmlPQVYQAnyIeluxuQLxafuZrWPW5OCwd/f6x4gdxBRiKO0lMNJ
         bzzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NeoXBeCQ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id k4si577764oib.1.2021.01.22.06.43.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 06:43:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id c132so3829966pga.3
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 06:43:18 -0800 (PST)
X-Received: by 2002:a65:430b:: with SMTP id j11mr4790496pgq.130.1611326598171;
 Fri, 22 Jan 2021 06:43:18 -0800 (PST)
MIME-Version: 1.0
References: <20210122141125.36166-1-vincenzo.frascino@arm.com> <20210122141125.36166-5-vincenzo.frascino@arm.com>
In-Reply-To: <20210122141125.36166-5-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jan 2021 15:43:07 +0100
Message-ID: <CAAeHK+zdcVJDYzXupc7Uq43toRZT3CKoJJNwJkdipoDNMMqbng@mail.gmail.com>
Subject: Re: [PATCH v7 4/4] arm64: mte: Enable async tag check fault
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NeoXBeCQ;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536
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

On Fri, Jan 22, 2021 at 3:11 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> MTE provides a mode that asynchronously updates the TFSR_EL1 register
> when a tag check exception is detected.
>
> To take advantage of this mode the kernel has to verify the status of
> the register at:
>   1. Context switching
>   2. Return to user/EL0 (Not required in entry from EL0 since the kernel
>   did not run)
>   3. Kernel entry from EL1
>   4. Kernel exit to EL1
>
> If the register is non-zero a trace is reported.
>
> Add the required features for EL1 detection and reporting.
>
> Note: ITFSB bit is set in the SCTLR_EL1 register hence it guaranties that
> the indirect writes to TFSR_EL1 are synchronized at exception entry to
> EL1. On the context switch path the synchronization is guarantied by the
> dsb() in __switch_to().
> The dsb(nsh) in mte_check_tfsr_exit() is provisional pending
> confirmation by the architects.
>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h     | 32 +++++++++++++++++++++++
>  arch/arm64/kernel/entry-common.c |  6 +++++
>  arch/arm64/kernel/mte.c          | 44 ++++++++++++++++++++++++++++++++
>  3 files changed, 82 insertions(+)
>
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index d02aff9f493d..237bb2f7309d 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -92,5 +92,37 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>
>  #endif /* CONFIG_ARM64_MTE */
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1(void);
> +
> +static inline void mte_check_tfsr_entry(void)
> +{
> +       mte_check_tfsr_el1();
> +}
> +
> +static inline void mte_check_tfsr_exit(void)
> +{
> +       /*
> +        * The asynchronous faults are sync'ed automatically with
> +        * TFSR_EL1 on kernel entry but for exit an explicit dsb()
> +        * is required.
> +        */
> +       dsb(nsh);
> +       isb();
> +
> +       mte_check_tfsr_el1();
> +}
> +#else
> +static inline void mte_check_tfsr_el1(void)
> +{
> +}
> +static inline void mte_check_tfsr_entry(void)
> +{
> +}
> +static inline void mte_check_tfsr_exit(void)
> +{
> +}
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
>  #endif /* __ASSEMBLY__ */
>  #endif /* __ASM_MTE_H  */
> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> index 5346953e4382..31666511ba67 100644
> --- a/arch/arm64/kernel/entry-common.c
> +++ b/arch/arm64/kernel/entry-common.c
> @@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
>         lockdep_hardirqs_off(CALLER_ADDR0);
>         rcu_irq_enter_check_tick();
>         trace_hardirqs_off_finish();
> +
> +       mte_check_tfsr_entry();
>  }
>
>  /*
> @@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
>  {
>         lockdep_assert_irqs_disabled();
>
> +       mte_check_tfsr_exit();
> +
>         if (interrupts_enabled(regs)) {
>                 if (regs->exit_rcu) {
>                         trace_hardirqs_on_prepare();
> @@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
>
>  asmlinkage void noinstr exit_to_user_mode(void)
>  {
> +       mte_check_tfsr_exit();
> +
>         trace_hardirqs_on_prepare();
>         lockdep_hardirqs_on_prepare(CALLER_ADDR0);
>         user_enter_irqoff();
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 92078e1eb627..7763ac1f2917 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -182,6 +182,37 @@ bool mte_report_once(void)
>         return READ_ONCE(report_fault_once);
>  }
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1(void)
> +{
> +       u64 tfsr_el1;
> +
> +       if (!system_supports_mte())
> +               return;
> +
> +       tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
> +
> +       /*
> +        * The kernel should never trigger an asynchronous fault on a
> +        * TTBR0 address, so we should never see TF0 set.
> +        * For futexes we disable checks via PSTATE.TCO.
> +        */
> +       WARN_ONCE(tfsr_el1 & SYS_TFSR_EL1_TF0,
> +                 "Kernel async tag fault on TTBR0 address");
> +
> +       if (unlikely(tfsr_el1 & SYS_TFSR_EL1_TF1)) {
> +               /*
> +                * Note: isb() is not required after this direct write
> +                * because there is no indirect read subsequent to it
> +                * (per ARM DDI 0487F.c table D13-1).
> +                */
> +               write_sysreg_s(0, SYS_TFSR_EL1);
> +
> +               kasan_report_async();
> +       }
> +}
> +#endif
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>         /* ISB required for the kernel uaccess routines */
> @@ -247,6 +278,19 @@ void mte_thread_switch(struct task_struct *next)
>         /* avoid expensive SCTLR_EL1 accesses if no change */
>         if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>                 update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
> +       else
> +               isb();
> +
> +       /*
> +        * Check if an async tag exception occurred at EL1.
> +        *
> +        * Note: On the context switch path we rely on the dsb() present
> +        * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
> +        * are synchronized before this point.
> +        * isb() above is required for the same reason.
> +        *
> +        */
> +       mte_check_tfsr_el1();
>  }
>
>  void mte_suspend_exit(void)
> --
> 2.30.0
>

Acked-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzdcVJDYzXupc7Uq43toRZT3CKoJJNwJkdipoDNMMqbng%40mail.gmail.com.
