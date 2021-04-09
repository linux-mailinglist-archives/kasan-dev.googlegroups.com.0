Return-Path: <kasan-dev+bncBDV37XP3XYDRBHGLYGBQMGQECNRFQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id EC39D35A11A
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 16:33:01 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id h75sf1329609vka.9
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Apr 2021 07:33:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617978780; cv=pass;
        d=google.com; s=arc-20160816;
        b=E4NIMJ96blbpE/9e8F0F2f3ssYeR4SXsOMAh7RzEVe50nvQXl7wGHjvrD6Wf6KJum0
         xug4ftFoVUNuIbVVYodu829ifWBItRTJ1VOWDMOieFp6h9d69jZF7U+haJFBVucicgFV
         YxDKo21H6GmOFuXNHtqM0vt3Lcg3ZvWXpqxO6sAKk6SCttguO3aI5CuQVSNbSGPqPQO0
         0vKOfav/PYLdoqAlLJhLuLTKD/6NMARzmit6biXB+uytCw9P/xqwuFGKRPkqL+RCrZ+t
         MW5jmfTfOMRXcFQsYnUPelygKR3cuRswhuskgZKOUoascwkZCqOYy2rk7RBdbmGz47s5
         4pQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oHYR/pXcp6ws3J+Jyml2ue4cugWSqrjjYGgK2ebdefo=;
        b=RWUtoLMkHm7iZu26OpZUjRp23WPhPLftkEdLEUnSj3RHIOyvUVBD8dcHWT3L+Fpo3m
         kKqCQDdpBnK0HR4UcU4bp56Nf2sBHVbC/0btpvIRX2AAUkMrtEvzAtrVnGoiKAOaticx
         uWVWFVuuZK7i9KSVRYnzBBSYin9+Yv72+B9fO1914lm2XGQ2A8c6ArYgM1PkCsNF+1+q
         fcCExLR5vTQEieIdA466LFnunn2LBbW1uDriMp+5i6U9I9zEo1NPDQNiBqlKKt8e2vLw
         tGL9QmI+io5dgDWBt8vVCvosaZcKepd8hyhQcf7PCPHeBMyK0cV14hNu+6TzXTysEF+9
         GhXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oHYR/pXcp6ws3J+Jyml2ue4cugWSqrjjYGgK2ebdefo=;
        b=Vdo6CMt+AeSx0JKZXHzlD7qBt2j1ArQ7mP38pIMPjdPs2BbSePbD7yZlwbvIyzhVLU
         0ixmbTbSDVhXTX3dqlZKodrnbxlxdss8kTmMFmaqVmeIrOlSpn3c+9w0QebgsEK7M9+8
         Ri3qbDZ3HFby3dju+ks0g/YUQqIrQIcBcHSWXoaGHAWBb55bavh+EihrbZrBA0dOLiU7
         DpDxZbTikxjUzA6t8ivbIBiSYHEcNBy1ces2FzojcpjRORKwAT+u4uG3ui5N2HzcyCdv
         Rpi2SlHuCyTEpxv5jCNG4p/jvfI516Hv+ELAFW+KgtGU0k/liGcSGLsuSCvTe3O8iZ3K
         DVxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oHYR/pXcp6ws3J+Jyml2ue4cugWSqrjjYGgK2ebdefo=;
        b=K2QGBEzU0mSWU7SS7ZQ6e1QbgIzPpYNEALvX97eKfCz9dBRkegk+R5QmmBIwUAW0TG
         U3KgYff/okaVTGBNR4oOlZXbZ5KvmB1JJgCrhNJTzdd2Sp2xVKo7GJ5JYtdqucKCq+oc
         Ok65rPq0wZ4lm6HKRdj6y0vwv7ptyPOcW561zTOgYoCMD4qn2GddHbvNAK2TW9lwS73Z
         tZOEYNxyG9MMYYGRbAaL6Pdivr8QPtQxDUKzBvSS4hXXENBSPn1qnpJVVD691uWMLhi/
         Kv5IRrCMtCO6M2fZnmHXSxbGGeNr7PWqXGXpIGchSa7lIlgF4P1UI5lMa8jqXmoGnaYJ
         S9lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xaEsqILmk6bxN6oUl+887n6AiO9ZHAZfwM/BWkUw4RcSHqM5i
	oCoWt1Stykmu4BvJ1RjkPXk=
X-Google-Smtp-Source: ABdhPJxaWvMXlgo73Jx86embk8SycIUlSRknN9ScSb/V5bQi8UWXZwU6QC5vdZdfIpBNfIjGFEL7IA==
X-Received: by 2002:ab0:254b:: with SMTP id l11mr10977097uan.131.1617978780518;
        Fri, 09 Apr 2021 07:33:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6709:: with SMTP id q9ls838850uam.2.gmail; Fri, 09 Apr
 2021 07:33:00 -0700 (PDT)
X-Received: by 2002:ab0:7c73:: with SMTP id h19mr8136311uax.62.1617978780013;
        Fri, 09 Apr 2021 07:33:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617978780; cv=none;
        d=google.com; s=arc-20160816;
        b=vly4wOwmzAQzb6Sz4VgUzd/jt7a9tE+/FJpon7Xs4k+98weFK47bNw/3N145VP5R8u
         GNStGdU2zqtgMGgOIZKSJ3F6GH01BJbzLf0VzPggpbDREViLmJoDtkb3bvNWgSMsxmOF
         OmlTtZCwzwLZAnbUUcuj06Ia0XH/Rurrt38HewbE0tixT2LKhgTbTgdBkCMuvv5PmB76
         SyrK6XZ52rM3kPd94dctSLg3yAi1drHuGqsLY+q96jVDYXbRFjmti6qdQTyX4b90illy
         vBjpZ323d6JMshWhxWAWgJSiIeMbBZBPWPYKoPwNbfgcoYqpLMvgDE0RDRc8ocLUHXB2
         yD7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=B8SCJi2FfP+gyTMmS2I7r/enSgl0qaBV2UMpTrJdhcI=;
        b=tn4jhIc0kYZYnNkxlA3JJS05REH6PVPSJirC8UMOH2hUEo1AyHgEoG6BCszbP07sGo
         qU7zvYZ7yZYjQl6LqqZbVjqKiKuYJiGTOHSTcqgiBiqujYUJwdKrZn2nZPGBxrB60w2U
         XWU9E1/rNdl2/OG2+TZ4KZUGqUl12drNmwoUg7+mcFYetkNnaQKi0aQrHHRyS3Uz5j/l
         Bi1JXMjZXz8HcMTVDGC36c8Cb5MXWXhXJS5ph/5OCMGjqOCKlhtybax6qU57K9qxtDdV
         E5Rqic2nynh08YiTCPG8F/9BC245z+5KCyRWIHr4XaZsgR0Z78hdh1G266U57UxOSpLg
         Iy3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p23si182857vkm.1.2021.04.09.07.32.59
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Apr 2021 07:33:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3C7351FB;
	Fri,  9 Apr 2021 07:32:59 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.28.223])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5EEE33F694;
	Fri,  9 Apr 2021 07:32:57 -0700 (PDT)
Date: Fri, 9 Apr 2021 15:32:47 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, stable@vger.kernel.org
Subject: Re: [PATCH v3] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210409143247.GA58461@C02TD0UTHF1T.local>
References: <20210409132419.29965-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210409132419.29965-1-vincenzo.frascino@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Vincenzo,

On Fri, Apr 09, 2021 at 02:24:19PM +0100, Vincenzo Frascino wrote:
> The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
> race with another CPU doing a set_tsk_thread_flag() and all the other flags
> can be lost in the process.
> 
> Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
> exit_to_user_mode() to address the problem.
> 
> Note: Moving the check in entry-common allows to use set_thread_flag()
> which is safe.
> 
> Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous tag check faults")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: stable@vger.kernel.org
> Reported-by: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h     |  9 +++++++++
>  arch/arm64/kernel/entry-common.c |  6 ++++++
>  arch/arm64/kernel/entry.S        | 34 --------------------------------
>  arch/arm64/kernel/mte.c          | 33 +++++++++++++++++++++++++++++--
>  4 files changed, 46 insertions(+), 36 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 9b557a457f24..c7ab681a95c3 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -49,6 +49,9 @@ int mte_ptrace_copy_tags(struct task_struct *child, long request,
>  
>  void mte_assign_mem_tag_range(void *addr, size_t size);
>  
> +void noinstr check_mte_async_tcf0(void);
> +void noinstr clear_mte_async_tcf0(void);

Can we please put the implementations in the header so that they can be
inlined? Otherwise when the HW doesn't support MTE we'll always do a pointless
branch to the out-of-line implementation.

With that, we can mark them __always_inline to avoid weirdness with an inline
noinstr function.

Otherwise, this looks good to me.

Thanks,
Mark.

> +
>  #else /* CONFIG_ARM64_MTE */
>  
>  /* unused if !CONFIG_ARM64_MTE, silence the compiler */
> @@ -83,6 +86,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
>  {
>  	return -EIO;
>  }
> +static inline void check_mte_async_tcf0(void)
> +{
> +}
> +static inline void clear_mte_async_tcf0(void)
> +{
> +}
>  
>  static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>  {
> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> index 9d3588450473..837d3624a1d5 100644
> --- a/arch/arm64/kernel/entry-common.c
> +++ b/arch/arm64/kernel/entry-common.c
> @@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
>  	CT_WARN_ON(ct_state() != CONTEXT_USER);
>  	user_exit_irqoff();
>  	trace_hardirqs_off_finish();
> +
> +	/* Check for asynchronous tag check faults in user space */
> +	check_mte_async_tcf0();



>  }
>  
>  asmlinkage void noinstr exit_to_user_mode(void)
>  {
> +	/* Ignore asynchronous tag check faults in the uaccess routines */
> +	clear_mte_async_tcf0();
> +
>  	trace_hardirqs_on_prepare();
>  	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
>  	user_enter_irqoff();
> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> index a31a0a713c85..fb57df0d453f 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -34,15 +34,11 @@
>   * user and kernel mode.
>   */
>  	.macro user_exit_irqoff
> -#if defined(CONFIG_CONTEXT_TRACKING) || defined(CONFIG_TRACE_IRQFLAGS)
>  	bl	enter_from_user_mode
> -#endif
>  	.endm
>  
>  	.macro user_enter_irqoff
> -#if defined(CONFIG_CONTEXT_TRACKING) || defined(CONFIG_TRACE_IRQFLAGS)
>  	bl	exit_to_user_mode
> -#endif
>  	.endm
>  
>  	.macro	clear_gp_regs
> @@ -147,32 +143,6 @@ alternative_cb_end
>  .L__asm_ssbd_skip\@:
>  	.endm
>  
> -	/* Check for MTE asynchronous tag check faults */
> -	.macro check_mte_async_tcf, flgs, tmp
> -#ifdef CONFIG_ARM64_MTE
> -alternative_if_not ARM64_MTE
> -	b	1f
> -alternative_else_nop_endif
> -	mrs_s	\tmp, SYS_TFSRE0_EL1
> -	tbz	\tmp, #SYS_TFSR_EL1_TF0_SHIFT, 1f
> -	/* Asynchronous TCF occurred for TTBR0 access, set the TI flag */
> -	orr	\flgs, \flgs, #_TIF_MTE_ASYNC_FAULT
> -	str	\flgs, [tsk, #TSK_TI_FLAGS]
> -	msr_s	SYS_TFSRE0_EL1, xzr
> -1:
> -#endif
> -	.endm
> -
> -	/* Clear the MTE asynchronous tag check faults */
> -	.macro clear_mte_async_tcf
> -#ifdef CONFIG_ARM64_MTE
> -alternative_if ARM64_MTE
> -	dsb	ish
> -	msr_s	SYS_TFSRE0_EL1, xzr
> -alternative_else_nop_endif
> -#endif
> -	.endm
> -
>  	.macro mte_set_gcr, tmp, tmp2
>  #ifdef CONFIG_ARM64_MTE
>  	/*
> @@ -243,8 +213,6 @@ alternative_else_nop_endif
>  	ldr	x19, [tsk, #TSK_TI_FLAGS]
>  	disable_step_tsk x19, x20
>  
> -	/* Check for asynchronous tag check faults in user space */
> -	check_mte_async_tcf x19, x22
>  	apply_ssbd 1, x22, x23
>  
>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
> @@ -775,8 +743,6 @@ SYM_CODE_START_LOCAL(ret_to_user)
>  	cbnz	x2, work_pending
>  finish_ret_to_user:
>  	user_enter_irqoff
> -	/* Ignore asynchronous tag check faults in the uaccess routines */
> -	clear_mte_async_tcf
>  	enable_step_tsk x19, x2
>  #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
>  	bl	stackleak_erase
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index b3c70a612c7a..84a942c25870 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -166,14 +166,43 @@ static void set_gcr_el1_excl(u64 excl)
>  	 */
>  }
>  
> -void flush_mte_state(void)
> +void noinstr check_mte_async_tcf0(void)
> +{
> +	u64 tcf0;
> +
> +	if (!system_supports_mte())
> +		return;
> +
> +	/*
> +	 * dsb(ish) is not required before the register read
> +	 * because the TFSRE0_EL1 is automatically synchronized
> +	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
> +	 * is set.
> +	 */
> +	tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);
> +
> +	if (tcf0 & SYS_TFSR_EL1_TF0)
> +		set_thread_flag(TIF_MTE_ASYNC_FAULT);
> +
> +	write_sysreg_s(0, SYS_TFSRE0_EL1);
> +}
> +
> +void noinstr clear_mte_async_tcf0(void)
>  {
>  	if (!system_supports_mte())
>  		return;
>  
> -	/* clear any pending asynchronous tag fault */
>  	dsb(ish);
>  	write_sysreg_s(0, SYS_TFSRE0_EL1);
> +}
> +
> +void flush_mte_state(void)
> +{
> +	if (!system_supports_mte())
> +		return;
> +
> +	/* clear any pending asynchronous tag fault */
> +	clear_mte_async_tcf0();
>  	clear_thread_flag(TIF_MTE_ASYNC_FAULT);
>  	/* disable tag checking */
>  	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
> -- 
> 2.30.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409143247.GA58461%40C02TD0UTHF1T.local.
