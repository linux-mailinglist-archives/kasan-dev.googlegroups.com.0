Return-Path: <kasan-dev+bncBDDL3KWR4EBRBT7P7T7QKGQENKCU3EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BDF9E2F51B8
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 19:11:28 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id v15sf856115otp.10
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 10:11:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610561487; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z7wZJPvsAq3mkNAM0ndUNJKpRaYUMxsV6aglZZ1kVdl8Z6iHgl5J31QKHm1rD26m5V
         VlGP43Ok91ncIL96Vzh/ZXjTBlPtpSK1m6FjmH3sBOmIXHY7xyswGGV8a2iP3E727b3k
         8yH9QHtbZenpwHxORlDoCMnFbXR4+lFU6bOpbvTw1gGkLZAqV2xMICjD5Y5kYkn3ugGk
         lzHren3hUlEOQSrELpAsgUq7GDr0duP/bHwD4TQh3w6OYhnTRfuf+RxOsVyhvJ3n7wov
         +E+FGUhKkYB7JdcJfWglgYTS9S9haxkyC/2Ki+pZ1ZCCZssZHSBw40t17tiuhAmsl/RJ
         5fPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=naeU/qGoXKfWFxQK20vPmDw6mXZWLJuyvHmGRPj6jak=;
        b=DUeWEkEYIC1+ideX6/438ZsZ8+r0CZW14oVPsxmJguAM6wKzYs4tqqPrS5gNvBBTYV
         LfJDcNm4HigSDr7iE0i3pMPC4Ra2gJWR1wXUdN7h7AWX5n9DFd8vYINkXu4s0kaLmzer
         zGzWvxLoe98jqkrK71L+RNIdjxeHPxwJwwEfzxMh6OJeXa3mbZPbFDNZA8wLV/PLnsaP
         L1ZhLziI3HdUjrvJ9jb+AzWGhH+k+6KfmEBUs7nRQHkLmoq2xG7RYrpItmFPqBeYH48e
         SUYlA4wOIteBzotjyvX2lXtRhjIxrufQDmVnOsJ132vnDBqL/PHG5PbVaFPPWhXzSfzg
         nDjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=naeU/qGoXKfWFxQK20vPmDw6mXZWLJuyvHmGRPj6jak=;
        b=OYOkeHRAx6DpQcWwEDr9eR4JmWblcT3J7g5LC2DSUXCaEfr8L9+QmLvFUyoi7apKAL
         8FMJDR7Hv8zVDYPBX/8Cr0UKjjFtp8VQhXqGWk+Bc+8wE9ZmZivJXAMAuhC4wylKWDPV
         RzdZh3XLUmdqqDOjSsNgliCrWAYjsKrqHqOXWwx6nj1nfIRX9mUDSA7BBWizdoUcTVL0
         /wjI2ZRIycyL6ow1l9HroWqiHI9PC1QXdHZ8BnWJ1JJuHj9PpWYncsubdHPwjS4Hl/Ht
         JNgwlKXAG5SWq6J/UACTpcfTHgMtwRIG2+j5TGvLBxKAUipVpmJYtDlTlyCbz5aPmTBC
         FC3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=naeU/qGoXKfWFxQK20vPmDw6mXZWLJuyvHmGRPj6jak=;
        b=EgoM50UMsFMpiaico6FapS5gC/Q6XO4oUmXgIzOLP1HJ8MMoIPbKV60jY5bVjTQs2Q
         6bVVvfeB8ZzNo8lWPtJL5hmzbhdjRGcnEff/mH1+NWM3AUmaGxOutLcittBBpMoc+rhO
         tFQpIRFkrfa5ywBRzv25zYHvYXJ6K3wepL25aOSIasOj5ZRr+lI1I2ylKduIiLA+xnI3
         S+J+p/wTPPCocpZKpzeqvwZ86wAY/sPVAp+xufxN1Wo2qlezaE9pK0PJDGDcs2oxKw7A
         c7+jPS3URo/0tNzM2VfLG5UiKFiKRAC8IBbtDvVEOHoj1N5k8Cqo8TNW1qSUSw7kQY1d
         9uJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Wj99hZ9naZJIgEIYqTmbSCSZpxFKKkDod28E/Kv8GMPvEHXNs
	dBEGrrgj/6EdPAqQqfH+ZZw=
X-Google-Smtp-Source: ABdhPJzrocXQpsjxcMRgywuMhRkR7oE5FZHTL/cIC0BtUf7ldu1Hb4oMVQhO7UfecZGxDBiAxTRwWw==
X-Received: by 2002:a05:6830:1c79:: with SMTP id s25mr2042238otg.172.1610561487773;
        Wed, 13 Jan 2021 10:11:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2413:: with SMTP id n19ls749215oic.7.gmail; Wed, 13 Jan
 2021 10:11:27 -0800 (PST)
X-Received: by 2002:aca:5e42:: with SMTP id s63mr338930oib.96.1610561487446;
        Wed, 13 Jan 2021 10:11:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610561487; cv=none;
        d=google.com; s=arc-20160816;
        b=T1Ey/JINsR2QbWCvs+Y33swdBjUQ+RhwisQ9o/b8+dfnpQyafQnzfx8AWfHz5+hikC
         uvtj35R54LThyZmSmjVJkcjpnVK9ifh5mXb7Xn1asI8+BnOQ5xLDiRdHIDpfIlkVZy++
         4fuLwp0KG26ak+v4QSb1wVpFJBghFzO+DQ+lV0d2kziSQ3fJ1Ku7GltgjPjQnEu657IB
         cmYxyVUHK+zl9gfxsD42haHzLIr0p63jXwr4ngDA3Tu2S7ra2clMMoHYTuSMM/Qq0qmm
         Fki2P3VmDFJhoGZKpmNhjzD5s11JkHpxqpIT0JKbIxsIX8kJMAyaPsFQGRVCHtqudxmr
         kXWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Wyz1Su/xaST1EOAoZqfpiIxYdBiyL0q1QoixULusD88=;
        b=JGdUNKA5QV+q8EL32fx4l3mlEo+Cd+X8BUXliPoEo2zE/KrcjulYrxdnxKgfbI1zNd
         9tO+CxoSb9NHayPLHD9XOf2JI4BYAsXyA4G6EIEfFttxDsLlF8rRcnlWICsWi0GHvfqr
         XJAHhS5cXdKUkHYqGXfDUq6VgDRjKWi4dyHZ9pqbMrqB503gJOkc6i8HLHrj9XQwmjl3
         s65Fzri49olaAGMr0yzbKieEiM4OGp9pepqyElEHydYoGEVpaUAWUnG/E0c/7SRjYFNj
         mVDY3JLumUC5zc2Yr/XQbJM95NEzNobyMqcAFS34Wb6XdOx6pByZbMET+e2KEWkCsooI
         cRzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f20si190843oig.2.2021.01.13.10.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Jan 2021 10:11:27 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7D14C233ED;
	Wed, 13 Jan 2021 18:11:24 +0000 (UTC)
Date: Wed, 13 Jan 2021 18:11:21 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 3/4] arm64: mte: Enable async tag check fault
Message-ID: <20210113181121.GF27045@gaia>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210107172908.42686-4-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jan 07, 2021 at 05:29:07PM +0000, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index d02aff9f493d..a60d3718baae 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -39,6 +39,7 @@ void mte_free_tag_storage(char *storage);
>  /* track which pages have valid allocation tags */
>  #define PG_mte_tagged	PG_arch_2
>  
> +void mte_check_tfsr_el1(void);
>  void mte_sync_tags(pte_t *ptep, pte_t pte);
>  void mte_copy_page_tags(void *kto, const void *kfrom);
>  void flush_mte_state(void);
> @@ -56,6 +57,9 @@ void mte_assign_mem_tag_range(void *addr, size_t size);
>  /* unused if !CONFIG_ARM64_MTE, silence the compiler */
>  #define PG_mte_tagged	0
>  
> +static inline void mte_check_tfsr_el1(void)
> +{
> +}

I think we should enable this dummy function when !CONFIG_KASAN_HW_TAGS.
It saves us an unnecessary function call in a few places.

>  static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
>  {
>  }
> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> index 5346953e4382..74b020ce72d7 100644
> --- a/arch/arm64/kernel/entry-common.c
> +++ b/arch/arm64/kernel/entry-common.c
> @@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
>  	lockdep_hardirqs_off(CALLER_ADDR0);
>  	rcu_irq_enter_check_tick();
>  	trace_hardirqs_off_finish();
> +
> +	mte_check_tfsr_el1();
>  }
>  
>  /*
> @@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
>  {
>  	lockdep_assert_irqs_disabled();
>  
> +	mte_check_tfsr_el1();
> +
>  	if (interrupts_enabled(regs)) {
>  		if (regs->exit_rcu) {
>  			trace_hardirqs_on_prepare();
> @@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
>  
>  asmlinkage void noinstr exit_to_user_mode(void)
>  {
> +	mte_check_tfsr_el1();

While for kernel entry the asynchronous faults are sync'ed automatically
with TFSR_EL1, we don't have this for exit, so we'd need an explicit
DSB. But rather than placing it here, it's better if we add a bool sync
argument to mte_check_tfsr_el1() which issues a dsb() before checking
the register. I think that's the only place where such argument would be
true (for now).

> +
>  	trace_hardirqs_on_prepare();
>  	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
>  	user_enter_irqoff();
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 5d992e16b420..26030f0b79fe 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -185,6 +185,34 @@ void mte_enable_kernel(enum kasan_arg_mode mode)
>  	isb();
>  }
>  
> +void mte_check_tfsr_el1(void)
> +{
> +	u64 tfsr_el1;
> +
> +	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +		return;

If we define the static inline when !CONFIG_KASAN_HW_TAGS, we could add
the #ifdef here around the whole function.

> +	if (!system_supports_mte())
> +		return;
> +
> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
> +
> +	/*
> +	 * The kernel should never hit the condition TF0 == 1
> +	 * at this point because for the futex code we set
> +	 * PSTATE.TCO.
> +	 */
> +	WARN_ON(tfsr_el1 & SYS_TFSR_EL1_TF0);
> +
> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
> +		write_sysreg_s(0, SYS_TFSR_EL1);
> +		isb();
> +
> +		pr_err("MTE: Asynchronous tag exception detected!");
> +	}
> +}
> +NOKPROBE_SYMBOL(mte_check_tfsr_el1);

Do we need this to be NOKPROBE_SYMBOL? It's not that low level.

> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> @@ -250,6 +278,15 @@ void mte_thread_switch(struct task_struct *next)
>  	/* avoid expensive SCTLR_EL1 accesses if no change */
>  	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>  		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
> +
> +	/*
> +	 * Check if an async tag exception occurred at EL1.
> +	 *
> +	 * Note: On the context switch patch we rely on the dsb() present

s/patch/path/

> +	 * in __switch_to() to guaranty that the indirect writes to TFSR_EL1

s/guaranty/guarantee/ (well, still valid though I think rarely used).

> +	 * are synchronized before this point.
> +	 */
> +	mte_check_tfsr_el1();
>  }
>  
>  void mte_suspend_exit(void)
> -- 
> 2.30.0

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113181121.GF27045%40gaia.
