Return-Path: <kasan-dev+bncBDV37XP3XYDRBUV5XSBQMGQERMKLB5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B98535880A
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 17:18:44 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id hi14sf1628359pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 08:18:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617895122; cv=pass;
        d=google.com; s=arc-20160816;
        b=eFKEbjafhQY79MXFNyN4nWQIGcIuT6GHxhy1UOQ9WMXPuuNdFZUFz9eUo0j/r2I48u
         iC23mOw/7Gd4c39J+13oUfIENe1rvUiwj5zERa444rPdYS3wbj+rd7WOmKjrpy3cEoCQ
         Eyu4Ec7Q8TqeLa9w8JivUqC4vXQJwPRN4jno4ilEMTHukBvA/zBpxmke+L8Pw68J5Yh/
         0yek+NFnmyGlQLYsYvKywahAwoxHejCmNCUd/M1h9lTN/d6QBdp6fvLXFwYTBa6Er5zl
         OOn4DQ+R/5/18jtqd4pxZMLuxZTtJpvokKZ5AOa0HlBhCkeu/UkXwAFI1GNuYEdSbp1X
         Q6XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1z7+EOxmde4qIP46fY/MpktB/tgW218TcpX1T9zoTPc=;
        b=bxB4QqiKfNO9GO0LwCcuavsjY7RfBaehRiftoktc528R529SQI6WoTnquTAq/+TAM8
         AkkvqQq2ru1lg1SAjz+tuxlOPXxEgqzGZyTL8NrZD6Ld6jGMU9dydqaXV12tsL+h6QIb
         9jyMJrcxlWMEROz3ysacoCJviOTaAhJtVYWCNSGkv4fM130AxafMB8mqIaUSr5/WI+Pn
         l5Mm4xCvDjjq41c8RbkQo4N87VmzTyG/i7qvYNcBiCAtLZ05ZG28XGKPDi7WPHzvHt75
         Flm6COMJZ3aW87c2J22E7AcdYsO8kkDDdl2G+Afgg1lDtku97vbPUJtkBNkAhK2ZG8ox
         dBWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1z7+EOxmde4qIP46fY/MpktB/tgW218TcpX1T9zoTPc=;
        b=XbJSKmkIBosuyxYFltri04JdoHHyGObNVWJdTYuldvKitxUhfHjT1OdS4gcjrBuUBe
         l6fkvbYQaL7qkm5mCrdvyOrLRM7e+IEfnciktrPzK8//G2ntbNoHgwHZmM/yJ1SbEBHu
         t1dbbOCIJgigZYnvcFl6BL6qn7VIxQZg5fbfhzTTmcVikSS32UlvpWGWXRmny42cOZE9
         BQN5WyjRyPA6cvLJz5sQjhm/eWDaWHtTNJSIvtNdjNFlyCSiPW4do2YW32NZS9HBsd27
         Dtqn5V4NwTofpCeCArtVIUjKDhtDS7yv076IvoBEZ7GQuQvHphwmLdH+a5KlvjhR8rem
         Q5jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1z7+EOxmde4qIP46fY/MpktB/tgW218TcpX1T9zoTPc=;
        b=B8hPeMo5CrZn3AWUwEo1NdUd8baGrxSElK7TVUfB3z+QGcOF2Kp5ObFqDa9C4v/djw
         HbP19vGqQPSW6Lsl8COnG8tz0I9GOYUmxuiR45n8rcQl34s1FJyaNhC72Xl48eI678Qy
         /0liueaa5TRa0Vl7xn3lbKjrkhLDNPEU0cNCvos1+Y9SKf1RFcPuGT6Crc2etjyfUqh6
         E2GpQB70SrSuiQTaPPbNN7EwWEtYDXc6kbbyP+hEl4oK+pF6jr0chFM9P4o9RielE2Um
         7oDEVHej960aXtBl1zWeNZEejy64ewGwas8fJyaWUNZfmnU5Vi5uUoQQiQGcI5kELRns
         qlxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532D1NiceIQR2eJKTwfy5094/aFcs3NwH2GUhfubNf/RtUJnxnaM
	gU+gSNGrIQXBhToOYwZdduw=
X-Google-Smtp-Source: ABdhPJw2x6F+VloKmdUQN1cXr55DKPwrCHn+od1PaNfwQ6GCUi+r7pp+dqE9e0/ra+p6fBKPibHjeg==
X-Received: by 2002:a17:90a:5106:: with SMTP id t6mr9205046pjh.177.1617895122617;
        Thu, 08 Apr 2021 08:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:348e:: with SMTP id p14ls3370425pjb.1.canary-gmail;
 Thu, 08 Apr 2021 08:18:42 -0700 (PDT)
X-Received: by 2002:a17:90a:a389:: with SMTP id x9mr8017902pjp.232.1617895122050;
        Thu, 08 Apr 2021 08:18:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617895122; cv=none;
        d=google.com; s=arc-20160816;
        b=mpVIooVJQlzdM7RZDQMm/Isz8lSr6XGpRAmSXSp3up7F3+YHvieRAXnivYKRkTPuWX
         o3e+e2Q8l8VTje7wEopgmtmbJkl6uCBLVOFrQED1AKUdStAmfEsOQILW3MHjEyX9wIGl
         yISs88o1U5JyKk/hBj/alLdnGN1fsnpPP1X6T/JGiZ7qMF27SO0bS2ymiZ6VnxdcKj1L
         3NRkWa8YhIseBlWlu8Zd3HFqQDG8ep9A/Hu85jZi6ih+aaZc0aog5EEciV5fv2WsRNUG
         oHR5aCOt79jMWUzk1bYaJrdWuiPxHC9E0ACpDN6ATl2U+h9ble1wZlLA3jF3xAjwOZHV
         xUuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=OEh2lUk+ZSAW4tbM1IN3OtCF9EZo57PKXPiDCSHzyt0=;
        b=Svoi+xKHF3DZfo+VLElCccQ9Tc9y0d+eqyFz3Ayc4+vQmpwOQxtvdPsgzNp6JPc56Z
         o8gVfpp6UxkpBDkQ34xszT+jidE6jSttEDYRQmm+flt7uPiLyPYoLlKmCg0pB2GOvPeo
         CTZLy9q5TnsUGGZbLz3TOo23W4HjAczIJtJlP6AQDsbmSLrvnk91hkWugkQDIm5CDkub
         xb6i/bCre8+kaSGm7wiok5GMgtUD7CCdy8ODhOApS0+UhlPhiIBt4xZsYDzGYLYEJ2JA
         3QhUS7nl1X23AgQMDnGg57HY1majlNiB0r8vbdVCPsc5FcoxU2ZHP4ZphnT68PcbwZ5R
         79WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id nv12si502243pjb.3.2021.04.08.08.18.41
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Apr 2021 08:18:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 57521D6E;
	Thu,  8 Apr 2021 08:18:41 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.24.62])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 33FC33F694;
	Thu,  8 Apr 2021 08:18:40 -0700 (PDT)
Date: Thu, 8 Apr 2021 16:18:37 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: Re: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210408151837.GB37165@C02TD0UTHF1T.local>
References: <20210408143723.13024-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210408143723.13024-1-vincenzo.frascino@arm.com>
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

On Thu, Apr 08, 2021 at 03:37:23PM +0100, Vincenzo Frascino wrote:
> The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
> race with another CPU doing a set_tsk_thread_flag() and the flag can be
> lost in the process.
> 
> Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
> exit_to_user_mode() to address the problem.

Beware that these are called at critical points of the entry sequence,
so we need to take care that nothing is instrumented (e.g. we can only
safely use noinstr functions here).

> Note: Moving the check in entry-common allows to use set_thread_flag()
> which is safe.
> 
> Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous
> tag check faults")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Reported-by: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h     |  8 ++++++++
>  arch/arm64/kernel/entry-common.c |  6 ++++++
>  arch/arm64/kernel/entry.S        | 30 ------------------------------
>  arch/arm64/kernel/mte.c          | 25 +++++++++++++++++++++++--
>  4 files changed, 37 insertions(+), 32 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 9b557a457f24..188f778c6f7b 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -31,6 +31,8 @@ void mte_invalidate_tags(int type, pgoff_t offset);
>  void mte_invalidate_tags_area(int type);
>  void *mte_allocate_tag_storage(void);
>  void mte_free_tag_storage(char *storage);
> +void check_mte_async_tcf0(void);
> +void clear_mte_async_tcf0(void);
>  
>  #ifdef CONFIG_ARM64_MTE
>  
> @@ -83,6 +85,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
>  {
>  	return -EIO;
>  }
> +void check_mte_async_tcf0(void)
> +{
> +}
> +void clear_mte_async_tcf0(void)
> +{
> +}

Were these meant to be static inline?

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
> index a31a0a713c85..fafd74ae5021 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -147,32 +147,6 @@ alternative_cb_end
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
> @@ -243,8 +217,6 @@ alternative_else_nop_endif
>  	ldr	x19, [tsk, #TSK_TI_FLAGS]
>  	disable_step_tsk x19, x20
>  
> -	/* Check for asynchronous tag check faults in user space */
> -	check_mte_async_tcf x19, x22
>  	apply_ssbd 1, x22, x23
>  
>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
> @@ -775,8 +747,6 @@ SYM_CODE_START_LOCAL(ret_to_user)
>  	cbnz	x2, work_pending
>  finish_ret_to_user:
>  	user_enter_irqoff
> -	/* Ignore asynchronous tag check faults in the uaccess routines */
> -	clear_mte_async_tcf
>  	enable_step_tsk x19, x2
>  #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
>  	bl	stackleak_erase
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index b3c70a612c7a..e759b0eca47e 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -166,14 +166,35 @@ static void set_gcr_el1_excl(u64 excl)
>  	 */
>  }
>  
> +void check_mte_async_tcf0(void)

As above, this'll need to be noinstr. I also reckon we should put this
in the header so that it can be inlined.

> +{
> +	/*
> +	 * dsb(ish) is not required before the register read
> +	 * because the TFSRE0_EL1 is automatically synchronized
> +	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
> +	 * is set.
> +	 */
> +	u64 tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);

Shouldn't we have an MTE feature check first?

> +
> +	if (tcf0 & SYS_TFSR_EL1_TF0)
> +		set_thread_flag(TIF_MTE_ASYNC_FAULT);
> +
> +	write_sysreg_s(0, SYS_TFSRE0_EL1);
> +}
> +
> +void clear_mte_async_tcf0(void)
> +{
> +	dsb(ish);
> +	write_sysreg_s(0, SYS_TFSRE0_EL1);
> +}

Likewise here on all counts.

Thanks,
Mark.

>  void flush_mte_state(void)
>  {
>  	if (!system_supports_mte())
>  		return;
>  
>  	/* clear any pending asynchronous tag fault */
> -	dsb(ish);
> -	write_sysreg_s(0, SYS_TFSRE0_EL1);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408151837.GB37165%40C02TD0UTHF1T.local.
