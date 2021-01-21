Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCPYU2AAMGQE6SOTQOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 627912FF217
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:38:18 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id j14sf1049060eja.15
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:38:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611250698; cv=pass;
        d=google.com; s=arc-20160816;
        b=wDmABo4RlupkE423CKZ082fAZL1/pK7/NJhxG/2yXNnAYriO3vyyFMCECwI2gmT2FT
         cIcMkTLvQHuh+NPZQJe2dj44psBrjOdHKawi+DHXJnh6GGAN4QJbLMsX1zJy1L8jNLm8
         +tdwamB1RtemcWhmLRuLN5UVqR8J6ZGmyfignXbqgFc2iycYacJT88gV6fwqlgcnUVxR
         p25zQssU9qUE8eQ1BDsgEiSyl21ZNRpR/sZp3rOw7a8IV3OzdrqM38LzphPnAYKks3NS
         kickQYbhmhEHAZRDr5nIS0p321UX1wD8F4QrhJPvCSU545bpNm9SsEYOXK3Rk/DuX+Z3
         T2Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wNzttjxezWBXUH8JwA4eNXtDrv7UZRoUXdDpD0ktH7A=;
        b=CQnwKgXWjeI22vSlN6RZNqmxBFDpdYiOH1cpisRWMpKehm+n19bxfXAPw+QvdpatTK
         RP/c7xbUyfwhzgRlPPf5U+tfvV+Hk86NUs58v0z3roI4a3ltx287uZylEf9cArOwOQZF
         sWgZu2bf2M/c5DdLsMER75CAkfNr2Lo0gPY1mj/UvnsAuSW7YLqLTc91CVu/uFcNEOtl
         0k3Kh70wMC4ddKcPzifbgBGaDuEja3RIJwaXBX9IJ8AlyLnKJevNHDLBxgNxMTOdsVTm
         egXY7BfTcs+vF1bCU+3s4vhhIhVnOb7TlbNX4cH3+h+oQOgtR3AbT/tY3UYBw5SKac5n
         ytHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QASvLy/u";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wNzttjxezWBXUH8JwA4eNXtDrv7UZRoUXdDpD0ktH7A=;
        b=S0MCg+bNTWReXc47W0t8Xb1XIo1u+UxGchG7l4TDMzL9dRlTVU1+/pUP8n4rDuB1mV
         y3LS+sNQb2MHF3oUgH9WRXFANLjEI2fxhuNTtqcW+u8vA7JfDsnpYULsWA0Yi0sWQXAJ
         gvv2ajSF+YBCxvtXV+W7YlzDG+taKqJjb/fnaMhTE4cmTcOUoHS7SosV5KseOZrg+7h/
         CSSB/7BlYbm/Kpoh+JSFYaneQqHpjpseYEPn1BmGHiK5tkya042ONLnrCd+OS5pLq0FE
         Qt/tnma/v30Jrd1W8iqYLmMVUbjE+n1ee9TqgPSgMoeruZbjyCagTYWlseraI0v8tAQ+
         2psw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wNzttjxezWBXUH8JwA4eNXtDrv7UZRoUXdDpD0ktH7A=;
        b=UdvHFfpvUTYpR6FNcQbO1MoHFD1RDkR3i2ubuH/YpJLV2/JobcHDwKbmwt+Lyw2Q2A
         r3EFdw/6DD/WZZn0Ymow52Ruu4yXjTquaaH3QG15xT3gTAZdAJQTtS8Q4VtcMAmb6XXN
         5zQkU+6nf5hUFnY9BFlvnt60NI4XsDBWNU/vlAgE9ewBK0bxr0tDVTuGqZwp22XIgdGZ
         BgkzZsrXSfP2ttP9CeRRAwlAKgg8OF43qktaL2yI9WiwRMbsWlDJ7u/GLgQEAnNrwtdl
         6Ykzdr3xWyzYLiU5jAyrRnwkpjNIEnmj+oCTSzyKUgPyK8twOlR8r7ZsIcd3kf1bOY/x
         tPSw==
X-Gm-Message-State: AOAM530GUkoHmYNq8b1+ZfuN75ordjQXH4m1pD2PCp+Dnm0OHDvRM1MV
	IcWdMw/z1nyw8KGvGQtDVPQ=
X-Google-Smtp-Source: ABdhPJwr2jLPq/+zR65FXRPoumkvvm3OUcfkMd+VwtINB9R1qScCmfFYYn+BZqBf1ThRLVahxvt+AA==
X-Received: by 2002:a05:6402:513:: with SMTP id m19mr181130edv.229.1611250698177;
        Thu, 21 Jan 2021 09:38:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4715:: with SMTP id y21ls1560479ejq.2.gmail; Thu, 21
 Jan 2021 09:38:17 -0800 (PST)
X-Received: by 2002:a17:906:3a0d:: with SMTP id z13mr414957eje.2.1611250697323;
        Thu, 21 Jan 2021 09:38:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611250697; cv=none;
        d=google.com; s=arc-20160816;
        b=ixtzwXHAC6jrpNtcGe+vunQcCFn9Mi7QyIQLmvTb/JOxkcbq//am7RZZiuZMD2n9Th
         6HqdM0c5LrPwjfRg2mvSKapw18xUAia4/u3uQwucVyM+Rd1e/7fmx5stp5/cAyj3LBu2
         hQ8aG6IREVe7Lbevh5Km7igtRVC476JapGdSE7iP47pOHNGwDGxv1S/R/lnQXTG1fAkd
         v/wvryW2gfvm32/AKIWX9fgWqowwLi2w07c11bJrShPr2sSWP5lL4AHurlEe/Q/4DxMi
         qUZ3R2Crti5jb+IjvG2xcodUtwD7pTn0VCVvMaPB6WjhuWO4bsQZL8yo9TOzLdtgqaFG
         skbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wDrQK38YWH6ufWHF22W6c9HR6S6Bjf6Z7SDs/k7GPu0=;
        b=zJ1jQkzfkpmyWi+DMydFEWQZHNi7yemJMzOs/TM2Bj5RLUCb+BQk2XwuESS3ddYIQG
         cv7pP9xiOq6rjhc+NR1jbeJ1Hf4IN0QNG68z24DxzOCyEWIMSApGDLXWNmPobpoQ9D9F
         adamvJDfMNk9vJtG3WJrzU3B94nC15jJ/1ooyRM4BOW4Ugoq90eWnrI0Sf6ilbXaQAjr
         6yAQ5h7IIJIiseBM/qvPO/35SQQnJataPrvld7NmVDqf6Nl7zkUAjVcDQ3UQSzacATmj
         40hTjxG5r9sNrynYV3QvUntpEzBbGFTPARSliPcvcP4yrHQTNj9xg/yyM5W9nmBBcMEb
         4DUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QASvLy/u";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id j6si198560edh.0.2021.01.21.09.38.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:38:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id l12so912993ljc.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:38:17 -0800 (PST)
X-Received: by 2002:a2e:918d:: with SMTP id f13mr196763ljg.321.1611250696597;
 Thu, 21 Jan 2021 09:38:16 -0800 (PST)
MIME-Version: 1.0
References: <20210121163943.9889-1-vincenzo.frascino@arm.com> <20210121163943.9889-5-vincenzo.frascino@arm.com>
In-Reply-To: <20210121163943.9889-5-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:38:05 +0100
Message-ID: <CAAeHK+y9HbV6yVJ0f819Y=_6ijkKq06rqJSY+mh4NF4qd8t_oA@mail.gmail.com>
Subject: Re: [PATCH v5 4/6] arm64: mte: Enable async tag check fault
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
 header.i=@google.com header.s=20161025 header.b="QASvLy/u";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::232
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

On Thu, Jan 21, 2021 at 5:40 PM Vincenzo Frascino
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

Do we need a static bool reported like in do_tag_recovery() here?

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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By9HbV6yVJ0f819Y%3D_6ijkKq06rqJSY%2Bmh4NF4qd8t_oA%40mail.gmail.com.
