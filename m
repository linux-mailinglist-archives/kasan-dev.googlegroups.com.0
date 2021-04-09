Return-Path: <kasan-dev+bncBDV37XP3XYDRB3P4YGBQMGQEAAPRC3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4672A35A2D8
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 18:18:55 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id p8sf2869541oto.9
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Apr 2021 09:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617985134; cv=pass;
        d=google.com; s=arc-20160816;
        b=vctatAoLIxvhCTms1UuXEh+E2yg7jhwYjrpgQJSE1E8pdLh4WsDWGETiRbZNoMZCLx
         kGfj2GDh1R7wQUrSKcNScGRaB12+FrVxwceLQQMkadEXx/BrxZHLhiFOVy+zlwBOu5nm
         rTptnRxJm3hoQpG/qVA+LegJM9u3UGvMWQSUFxwbu6W7XgDh0kkHHUZi6IpPQuiLK0VU
         tzAFuOBZRuY7oRbEglQsBFtysVOHY4jnv+qJs92mN3YYk11sNk8wNHm4L0ixmlCgzrap
         ddVZzD27jZg8LvrRScHovmuoAWp9MAUAIAmCVCoZQkHTLqNQ1wMsswYbS5qz5iKPJecP
         kpsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bQ5zpQbYzukezBqaH4ABKzOb9dfHksqDTCytbjTEbrA=;
        b=iBRniJ6pz2R0PGPdk+VmQ4j7d72VqlYHKasKO+IpLmdiduRrOHDVTwkIG4pjM0KEiy
         orUKQgWKHH2zQlE6djg9A9bAiy29JXyJ0sQRw6mkY7V+3D48QTL/2P5HmXKDCOyu6fHj
         31V0f9gXjxyA6qNsLNAdiLBczjS4kQ17eVl3hmlE5pMVcEHo17SBQEFD/nIn+7Qh0bSm
         6lYPxXSKWstFkMHgZYfNm/iZqVB1SnxHXc4yoFOVOshIcbAKFgtapSnDuUvN5ovo4VCa
         NExbJN9G+s2xd+VX9EZIpeG17noUnKyVpXaGIiGeFSrf2ILlRib97RQ5nr3HFGQrT6JE
         gxvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bQ5zpQbYzukezBqaH4ABKzOb9dfHksqDTCytbjTEbrA=;
        b=YpAi1Kq4S7fQ+cQX7Nm5VIppBwk9Fodf9h6DXeHoL0Q9YD18lMZc9wjJn9pEEeUv8N
         Z2d5Z9f7Rv1fKagR0lDKUbt65t3cO975ilEDBB/UUDreokEdpvQk8TduU8KfmTPwA2Mk
         kUbYiWaNoZ7vpIEAlQpUJqqU7XiTd9SmgIlaCOAiClt9npIttUG9Up5JRwEnSSG1Mfx2
         7lq1Yxxu9DmS3XvQ3zAhtlo3WF3Pijjwu/IlGQ1HTbSRcLQf8pIZbQrXtugb6rcQNlQ8
         lZg8mZ14KwN+TjiLUcLI0Hmx6D1R38t12b6zU2Dcvlkt5uj0zeZkAOP9ocxxsr8UamPh
         lu/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bQ5zpQbYzukezBqaH4ABKzOb9dfHksqDTCytbjTEbrA=;
        b=GyKgv344RjO43e2+AIfuoQtjwwUxzAN/kE3LYWOf/8VjRi+hpTnxrxCTd549zFKPKG
         MMsecjy6GAFBBxzGajmfBFvhlDeRV8maHUewNk3uheUKPva4Zi3cepUZZW7Hk9v+IK8C
         Q00cKXZ/fkokDGqOxcFO8hQzafKZiWJfEa88WFI82yv9638S/jaFRkR5x9PHU7E7Dd5N
         r5vdj1b9V65K1OFKy2p9f8KAah8iKMJav8xF2+OsFJM8t702jTaeWf4Nc/bYxT4l+x9T
         WKnYHO83EFnMggxmIWCRjGjUS6FBfRb/SxR0ezG23d7JGC1U5kEaCTWmidKkCzwlWSly
         SJQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316AsDIMkBYooVqQtQilu+5hLGYdRTT6CzP0xloPLEW20h40xr7
	ACfHEdDOh7INYZeVKzl1lGE=
X-Google-Smtp-Source: ABdhPJxKOmLAnNjldv+byGk3zPcVlXpMh19Lekwp1Q48XJ3pJirYgHah+FA3sdIdWRvCStYvs6CqjA==
X-Received: by 2002:a05:6808:1448:: with SMTP id x8mr10583256oiv.99.1617985134015;
        Fri, 09 Apr 2021 09:18:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2421:: with SMTP id k1ls2308868ots.0.gmail; Fri, 09
 Apr 2021 09:18:53 -0700 (PDT)
X-Received: by 2002:a9d:1b70:: with SMTP id l103mr13149460otl.203.1617985133580;
        Fri, 09 Apr 2021 09:18:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617985133; cv=none;
        d=google.com; s=arc-20160816;
        b=KmmExfqECfIVdmmJuw/EVdImIaD9n5hhlbxCt05c4vTcrZQrJGCgNgk7BHDzJHXmQ6
         Wq684jPzoUd/U/iX4SNmJd+DN3fqrKhE4RZPF9/L/BGcVjil5aB1z+PL/b/rsRlDImYs
         XFD3IcW+ECWcBr6+sWvYjyq7/A5dCySRrQRNZUtmF3f/BZifre2gLvwO4KUTw8w9CBNw
         N0Zsm8ditdQIK03jWA+1NOPJ2R7UnYW7z4rbyq4cg1ti273WyZUVzKvU4d9TT3xGW0x3
         j8wEu5TWkIzhxPcL7LseAGgDP6hfLavR9sst5n3j2ajjyE6gdO6suWlhsS/85oFTRyK8
         fQzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=2Dakwvs7oaLgjhwvbtkHqY5nuuHVmWTJnPVmrClHE2g=;
        b=uzRxGRH7K+KaTXIeKnzRA4f5lLKX2uaY8FB2lZuJDt+RsOJfHG/HZwYqTpIAFoec//
         3Gu0EEzFyQ0/zW6/FswIWzHWqtdKvtxwFOVBxnaw8RemITXjWPUjGxMBl1I47fkjBnQ3
         ScgvH7XpMLf8RYtrNAlcLbwn5Hmoj1QPUb8r9HmTw7E/JQ0WLsuxoc8z14dJa+CmK2wj
         KE/GVWesSx+SYs7VJr6/DqPh/e5blfSGNUNA44vJ2Ggd63gnEE6EPz67bZZz0dRKrEy3
         fUevNvytw8ncnuqFWVgTIQ4ygdIciJn8zJvQPQOB7RG0vt7g5WaytuoBQXeEUQckeh6L
         J7Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v31si163867ott.5.2021.04.09.09.18.53
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Apr 2021 09:18:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1E12B1FB;
	Fri,  9 Apr 2021 09:18:53 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.28.223])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B8FD23F73D;
	Fri,  9 Apr 2021 09:18:51 -0700 (PDT)
Date: Fri, 9 Apr 2021 17:18:45 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, stable@vger.kernel.org
Subject: Re: [PATCH v3] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210409161030.GA60611@C02TD0UTHF1T.local>
References: <20210409132419.29965-1-vincenzo.frascino@arm.com>
 <20210409143247.GA58461@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210409143247.GA58461@C02TD0UTHF1T.local>
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

On Fri, Apr 09, 2021 at 03:32:47PM +0100, Mark Rutland wrote:
> Hi Vincenzo,
> 
> On Fri, Apr 09, 2021 at 02:24:19PM +0100, Vincenzo Frascino wrote:
> > The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
> > race with another CPU doing a set_tsk_thread_flag() and all the other flags
> > can be lost in the process.
> > 
> > Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
> > exit_to_user_mode() to address the problem.
> > 
> > Note: Moving the check in entry-common allows to use set_thread_flag()
> > which is safe.

I've dug into this a bit more, and as set_thread_flag() calls some
potentially-instrumented helpers I don't think this is safe after all
(as e.g. those might cause an EL1 exception and clobber the ESR/FAR/etc
before the EL0 exception handler reads it).

Making that watertight is pretty hairy, as we either need to open-code
set_thread_flag() or go rework a load of core code. If we can use STSET
in the entry asm that'd be simpler, otherwise we'll need something more
involved.

Thanks,
Mark.

> > 
> > Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous tag check faults")
> > Cc: Catalin Marinas <catalin.marinas@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > Cc: stable@vger.kernel.org
> > Reported-by: Will Deacon <will@kernel.org>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  arch/arm64/include/asm/mte.h     |  9 +++++++++
> >  arch/arm64/kernel/entry-common.c |  6 ++++++
> >  arch/arm64/kernel/entry.S        | 34 --------------------------------
> >  arch/arm64/kernel/mte.c          | 33 +++++++++++++++++++++++++++++--
> >  4 files changed, 46 insertions(+), 36 deletions(-)
> > 
> > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > index 9b557a457f24..c7ab681a95c3 100644
> > --- a/arch/arm64/include/asm/mte.h
> > +++ b/arch/arm64/include/asm/mte.h
> > @@ -49,6 +49,9 @@ int mte_ptrace_copy_tags(struct task_struct *child, long request,
> >  
> >  void mte_assign_mem_tag_range(void *addr, size_t size);
> >  
> > +void noinstr check_mte_async_tcf0(void);
> > +void noinstr clear_mte_async_tcf0(void);
> 
> Can we please put the implementations in the header so that they can be
> inlined? Otherwise when the HW doesn't support MTE we'll always do a pointless
> branch to the out-of-line implementation.
> 
> With that, we can mark them __always_inline to avoid weirdness with an inline
> noinstr function.
> 
> Otherwise, this looks good to me.
> 
> Thanks,
> Mark.
> 
> > +
> >  #else /* CONFIG_ARM64_MTE */
> >  
> >  /* unused if !CONFIG_ARM64_MTE, silence the compiler */
> > @@ -83,6 +86,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
> >  {
> >  	return -EIO;
> >  }
> > +static inline void check_mte_async_tcf0(void)
> > +{
> > +}
> > +static inline void clear_mte_async_tcf0(void)
> > +{
> > +}
> >  
> >  static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> >  {
> > diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> > index 9d3588450473..837d3624a1d5 100644
> > --- a/arch/arm64/kernel/entry-common.c
> > +++ b/arch/arm64/kernel/entry-common.c
> > @@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
> >  	CT_WARN_ON(ct_state() != CONTEXT_USER);
> >  	user_exit_irqoff();
> >  	trace_hardirqs_off_finish();
> > +
> > +	/* Check for asynchronous tag check faults in user space */
> > +	check_mte_async_tcf0();
> 
> 
> 
> >  }
> >  
> >  asmlinkage void noinstr exit_to_user_mode(void)
> >  {
> > +	/* Ignore asynchronous tag check faults in the uaccess routines */
> > +	clear_mte_async_tcf0();
> > +
> >  	trace_hardirqs_on_prepare();
> >  	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
> >  	user_enter_irqoff();
> > diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> > index a31a0a713c85..fb57df0d453f 100644
> > --- a/arch/arm64/kernel/entry.S
> > +++ b/arch/arm64/kernel/entry.S
> > @@ -34,15 +34,11 @@
> >   * user and kernel mode.
> >   */
> >  	.macro user_exit_irqoff
> > -#if defined(CONFIG_CONTEXT_TRACKING) || defined(CONFIG_TRACE_IRQFLAGS)
> >  	bl	enter_from_user_mode
> > -#endif
> >  	.endm
> >  
> >  	.macro user_enter_irqoff
> > -#if defined(CONFIG_CONTEXT_TRACKING) || defined(CONFIG_TRACE_IRQFLAGS)
> >  	bl	exit_to_user_mode
> > -#endif
> >  	.endm
> >  
> >  	.macro	clear_gp_regs
> > @@ -147,32 +143,6 @@ alternative_cb_end
> >  .L__asm_ssbd_skip\@:
> >  	.endm
> >  
> > -	/* Check for MTE asynchronous tag check faults */
> > -	.macro check_mte_async_tcf, flgs, tmp
> > -#ifdef CONFIG_ARM64_MTE
> > -alternative_if_not ARM64_MTE
> > -	b	1f
> > -alternative_else_nop_endif
> > -	mrs_s	\tmp, SYS_TFSRE0_EL1
> > -	tbz	\tmp, #SYS_TFSR_EL1_TF0_SHIFT, 1f
> > -	/* Asynchronous TCF occurred for TTBR0 access, set the TI flag */
> > -	orr	\flgs, \flgs, #_TIF_MTE_ASYNC_FAULT
> > -	str	\flgs, [tsk, #TSK_TI_FLAGS]
> > -	msr_s	SYS_TFSRE0_EL1, xzr
> > -1:
> > -#endif
> > -	.endm
> > -
> > -	/* Clear the MTE asynchronous tag check faults */
> > -	.macro clear_mte_async_tcf
> > -#ifdef CONFIG_ARM64_MTE
> > -alternative_if ARM64_MTE
> > -	dsb	ish
> > -	msr_s	SYS_TFSRE0_EL1, xzr
> > -alternative_else_nop_endif
> > -#endif
> > -	.endm
> > -
> >  	.macro mte_set_gcr, tmp, tmp2
> >  #ifdef CONFIG_ARM64_MTE
> >  	/*
> > @@ -243,8 +213,6 @@ alternative_else_nop_endif
> >  	ldr	x19, [tsk, #TSK_TI_FLAGS]
> >  	disable_step_tsk x19, x20
> >  
> > -	/* Check for asynchronous tag check faults in user space */
> > -	check_mte_async_tcf x19, x22
> >  	apply_ssbd 1, x22, x23
> >  
> >  	ptrauth_keys_install_kernel tsk, x20, x22, x23
> > @@ -775,8 +743,6 @@ SYM_CODE_START_LOCAL(ret_to_user)
> >  	cbnz	x2, work_pending
> >  finish_ret_to_user:
> >  	user_enter_irqoff
> > -	/* Ignore asynchronous tag check faults in the uaccess routines */
> > -	clear_mte_async_tcf
> >  	enable_step_tsk x19, x2
> >  #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
> >  	bl	stackleak_erase
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index b3c70a612c7a..84a942c25870 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -166,14 +166,43 @@ static void set_gcr_el1_excl(u64 excl)
> >  	 */
> >  }
> >  
> > -void flush_mte_state(void)
> > +void noinstr check_mte_async_tcf0(void)
> > +{
> > +	u64 tcf0;
> > +
> > +	if (!system_supports_mte())
> > +		return;
> > +
> > +	/*
> > +	 * dsb(ish) is not required before the register read
> > +	 * because the TFSRE0_EL1 is automatically synchronized
> > +	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
> > +	 * is set.
> > +	 */
> > +	tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);
> > +
> > +	if (tcf0 & SYS_TFSR_EL1_TF0)
> > +		set_thread_flag(TIF_MTE_ASYNC_FAULT);
> > +
> > +	write_sysreg_s(0, SYS_TFSRE0_EL1);
> > +}
> > +
> > +void noinstr clear_mte_async_tcf0(void)
> >  {
> >  	if (!system_supports_mte())
> >  		return;
> >  
> > -	/* clear any pending asynchronous tag fault */
> >  	dsb(ish);
> >  	write_sysreg_s(0, SYS_TFSRE0_EL1);
> > +}
> > +
> > +void flush_mte_state(void)
> > +{
> > +	if (!system_supports_mte())
> > +		return;
> > +
> > +	/* clear any pending asynchronous tag fault */
> > +	clear_mte_async_tcf0();
> >  	clear_thread_flag(TIF_MTE_ASYNC_FAULT);
> >  	/* disable tag checking */
> >  	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
> > -- 
> > 2.30.2
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409161030.GA60611%40C02TD0UTHF1T.local.
