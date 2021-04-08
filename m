Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJGBXSBQMGQEQWIRCFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 22821358853
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 17:26:30 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id c25sf1606080ioz.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 08:26:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617895589; cv=pass;
        d=google.com; s=arc-20160816;
        b=S3XH9bRuDGfoZiNeukG5Np08VELtVuH+HjtkpWr/TEyGTJEwE9Nis98Vc0xUfDkpOe
         Cg9x1B2IXLOvA3RX53FK/C2y1gdWStAvD1WDZEr3eTK1SXoYkkiYgnMrE3PWUNUADbAO
         V65DBza12hdi0zG9NrbcMMFVhVjtJY2PAmoW7iGlqhd+8zcZ14gJr/OMr0n5d3+wB87g
         iwt63oQ7hoViHYk2m7bA3Wd5iOsQpY9niC/TPdUFWr07Mpf1RUT0HSvKWVpulPtyuYRg
         RCYyg+UnPjkB6C0GQ18omQ6Xx/EifZnIHLguszD8tHCTYNplQcaLee1WzrxCYNcl7OfM
         v4uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=BqENGsbr9HMF7aKFpX8wV3plYcO40flcixCmvX4FMx4=;
        b=EaVGGobSmh5nJFtiyAyvnebH2cGXPp4HSQXHpF1K6ist8qO9vtYsoiFzOH3p3ltO89
         sOVIO7en32PWGdv2ZZYhrfwC6GSpJxN/zQBiWxbn70Kp6kS5QZKc6f8cp1VljlgL2vH/
         Q/E18zV0oC+uVUgbSJR1sHbtt0v6f1FtglpSXlDGsuob5vZCry9wy9B6KrAhGr7z0N3F
         /PyWQb9FTWVMYvFnswg9BAqtHrEgFoa2eCA4PN8FjcVXsiqmJDiCBZD4CrA0zJaDaK0J
         OBHXPS0Nhp0+6liZ50FACeM4rslfdrvRk9umV8dYRKdQ/HqBstqM0S1VyAnaGp5xiD+M
         Nhzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BqENGsbr9HMF7aKFpX8wV3plYcO40flcixCmvX4FMx4=;
        b=W9e4T/hRkaCnyC9EAtkPDccKnQU1AP5z+0tzwfuSyUyvvJLx3nI6QMWvahZ3veSsWI
         oT7niCzTXVDcPaNiTISP5rfOE3E1cxnnPHE0Hnzjk8UiE33Y+h7yf0nmxKshkugKsdWi
         MTxzvWFaCbEU8/kDxBx1RmVjThtQGxaQ6iA7nzPczZPlm/juNSRG9tmoAu6uVmyDE3eq
         wI8sgOYk8DaHiFWuhHDDyJYmfk7SSkX6X4mBhZF/gqulIVevWv0XLpKZY7dIgnJRhWdF
         7Y5WggYb9EVSSxqLoun48EBRzA9juQPLgebiHcF0vjydQAsOBjIjPswHtr/G7NpOMKDo
         dnsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BqENGsbr9HMF7aKFpX8wV3plYcO40flcixCmvX4FMx4=;
        b=YlIGhBWRd3p/73XAicMeIT02fvpDydcNyve3ENNejFES6/pkJB+6bONzH4pdk/Teo7
         J+KZM7fBx3khUnjCQssaQ3j0xLra4YagC/xVZDxDe5gKR4fqEVIBfBaggMOJv8JiW7BB
         WJpWrlgGHg0VM3u1DV5M0SW53cmTDe6/hxtRfIo53N+9Qdlj++1ahdonNUPywGxXa9F2
         fkRbSuYjCJqaZqrsRS31RtItBvs4C5+EV14IJ+K6pMwyOK/on56pSuaIqagPhMhEAod/
         AifUUNJ3znqrw9ei187DYlv7KdDrv9FrK0GEUt3hWQtkvP1CM3UGRUpUKwrRZ7ereHoc
         m67Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ceRcf1iXf8wdRzl5nQ9OSC+8jHW4Kxl7EBlFmZ7gpgITzSvbQ
	STC8jlBlLMKoZGiCOeW+wBs=
X-Google-Smtp-Source: ABdhPJwHsTHxe6WP/KYRLzZJ6JPf+BYcHYFo2VUg4IdpgWzM5zJXiqjmAMEyIFZozsa9wrVxSJmPfw==
X-Received: by 2002:a6b:ec08:: with SMTP id c8mr6904306ioh.55.1617895588806;
        Thu, 08 Apr 2021 08:26:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1bca:: with SMTP id x10ls143865ilv.7.gmail; Thu, 08
 Apr 2021 08:26:28 -0700 (PDT)
X-Received: by 2002:a05:6e02:14cc:: with SMTP id o12mr7224869ilk.104.1617895588396;
        Thu, 08 Apr 2021 08:26:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617895588; cv=none;
        d=google.com; s=arc-20160816;
        b=ZCZfGyGqYoHv6iqS9ZgNAWjruls0l5rMbstSJsLa51mGfCDPGZx3F21zwAdU/k6U4R
         3n8INQY9/nxkzn9A56pgRz66NBqEJzeT4kRxseANMCtAfvE6kD49ilRX6jUceTQKV/2e
         2yqgaHlEYz7o1iSI1K2QldbnnnVFf/rZ7RXqdoUvegpo23lMPS2K67Q6mfG8KuUOLkkT
         rJEC2a7W1dd94kakV/dgDpJjFeW4xipDzw86j/OqlG3qI0cF/WRAa6PdOqM4CXJtRSaA
         8+cqRrdfc0ho8xGPQjwPjeXhPKkZLHxYtC3VVbuzhn39olj0KfTT86RF2yctmsZh9l1l
         8u5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Jy/booI587MHLA2QmhCaTR5EunqoflbLfEJ11hVHtlU=;
        b=kgP5mU8bAXwuIdufcX8FYj19IXwUqeF0mzg6Zw5vzeGjIU64PBbyA2EAlb8W+AZQLK
         Ijkychy+6vnbizGOZb/9QLKrGIXhNfSgQgyKB1pxqLVsNENHIg7bv8Q5nJHsYnDhkMb3
         UmegIdAam6X0e5TezZOQRjnCmLxc+iMF6HhuPRlN/5+kuxPuHRkar8l4JTisbnVw3X4E
         gFk5D1KFcwH3WZ+LjrbEkOGkSS9zLE+iADZzu/fsk4ui4d2ezMpNOJkDtNMGrycPK2Xw
         of8ulLy45Z2QSL3SB11TKd6FiT5HQPVZhfc2ZsISxnhDhLLawKFqzgMIhxRq4ws90epv
         C97w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w1si1559207ilh.2.2021.04.08.08.26.28
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Apr 2021 08:26:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B1A68D6E;
	Thu,  8 Apr 2021 08:26:27 -0700 (PDT)
Received: from [10.37.8.4] (unknown [10.37.8.4])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BE7E93F694;
	Thu,  8 Apr 2021 08:26:26 -0700 (PDT)
Subject: Re: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will@kernel.org>
References: <20210408143723.13024-1-vincenzo.frascino@arm.com>
 <20210408151837.GB37165@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <cff8d16e-c1a9-3f10-7c7f-06fb569741ce@arm.com>
Date: Thu, 8 Apr 2021 16:26:25 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210408151837.GB37165@C02TD0UTHF1T.local>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 4/8/21 4:18 PM, Mark Rutland wrote:
> Hi Vincenzo,
> 
> On Thu, Apr 08, 2021 at 03:37:23PM +0100, Vincenzo Frascino wrote:
>> The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
>> race with another CPU doing a set_tsk_thread_flag() and the flag can be
>> lost in the process.
>>
>> Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
>> exit_to_user_mode() to address the problem.
> 
> Beware that these are called at critical points of the entry sequence,
> so we need to take care that nothing is instrumented (e.g. we can only
> safely use noinstr functions here).
> 

Sure, I will add noinstr in the next version of the patch.

>> Note: Moving the check in entry-common allows to use set_thread_flag()
>> which is safe.
>>
>> Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous
>> tag check faults")
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Reported-by: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/include/asm/mte.h     |  8 ++++++++
>>  arch/arm64/kernel/entry-common.c |  6 ++++++
>>  arch/arm64/kernel/entry.S        | 30 ------------------------------
>>  arch/arm64/kernel/mte.c          | 25 +++++++++++++++++++++++--
>>  4 files changed, 37 insertions(+), 32 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 9b557a457f24..188f778c6f7b 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -31,6 +31,8 @@ void mte_invalidate_tags(int type, pgoff_t offset);
>>  void mte_invalidate_tags_area(int type);
>>  void *mte_allocate_tag_storage(void);
>>  void mte_free_tag_storage(char *storage);
>> +void check_mte_async_tcf0(void);
>> +void clear_mte_async_tcf0(void);
>>  
>>  #ifdef CONFIG_ARM64_MTE
>>  
>> @@ -83,6 +85,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
>>  {
>>  	return -EIO;
>>  }
>> +void check_mte_async_tcf0(void)
>> +{
>> +}
>> +void clear_mte_async_tcf0(void)
>> +{
>> +}
> 
> Were these meant to be static inline?
> 

Agree, it definitely needs static inline here.

>>  static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>>  {
>> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
>> index 9d3588450473..837d3624a1d5 100644
>> --- a/arch/arm64/kernel/entry-common.c
>> +++ b/arch/arm64/kernel/entry-common.c
>> @@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
>>  	CT_WARN_ON(ct_state() != CONTEXT_USER);
>>  	user_exit_irqoff();
>>  	trace_hardirqs_off_finish();
>> +
>> +	/* Check for asynchronous tag check faults in user space */
>> +	check_mte_async_tcf0();
>>  }
>>  
>>  asmlinkage void noinstr exit_to_user_mode(void)
>>  {
>> +	/* Ignore asynchronous tag check faults in the uaccess routines */
>> +	clear_mte_async_tcf0();
>> +
>>  	trace_hardirqs_on_prepare();
>>  	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
>>  	user_enter_irqoff();
>> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
>> index a31a0a713c85..fafd74ae5021 100644
>> --- a/arch/arm64/kernel/entry.S
>> +++ b/arch/arm64/kernel/entry.S
>> @@ -147,32 +147,6 @@ alternative_cb_end
>>  .L__asm_ssbd_skip\@:
>>  	.endm
>>  
>> -	/* Check for MTE asynchronous tag check faults */
>> -	.macro check_mte_async_tcf, flgs, tmp
>> -#ifdef CONFIG_ARM64_MTE
>> -alternative_if_not ARM64_MTE
>> -	b	1f
>> -alternative_else_nop_endif
>> -	mrs_s	\tmp, SYS_TFSRE0_EL1
>> -	tbz	\tmp, #SYS_TFSR_EL1_TF0_SHIFT, 1f
>> -	/* Asynchronous TCF occurred for TTBR0 access, set the TI flag */
>> -	orr	\flgs, \flgs, #_TIF_MTE_ASYNC_FAULT
>> -	str	\flgs, [tsk, #TSK_TI_FLAGS]
>> -	msr_s	SYS_TFSRE0_EL1, xzr
>> -1:
>> -#endif
>> -	.endm
>> -
>> -	/* Clear the MTE asynchronous tag check faults */
>> -	.macro clear_mte_async_tcf
>> -#ifdef CONFIG_ARM64_MTE
>> -alternative_if ARM64_MTE
>> -	dsb	ish
>> -	msr_s	SYS_TFSRE0_EL1, xzr
>> -alternative_else_nop_endif
>> -#endif
>> -	.endm
>> -
>>  	.macro mte_set_gcr, tmp, tmp2
>>  #ifdef CONFIG_ARM64_MTE
>>  	/*
>> @@ -243,8 +217,6 @@ alternative_else_nop_endif
>>  	ldr	x19, [tsk, #TSK_TI_FLAGS]
>>  	disable_step_tsk x19, x20
>>  
>> -	/* Check for asynchronous tag check faults in user space */
>> -	check_mte_async_tcf x19, x22
>>  	apply_ssbd 1, x22, x23
>>  
>>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
>> @@ -775,8 +747,6 @@ SYM_CODE_START_LOCAL(ret_to_user)
>>  	cbnz	x2, work_pending
>>  finish_ret_to_user:
>>  	user_enter_irqoff
>> -	/* Ignore asynchronous tag check faults in the uaccess routines */
>> -	clear_mte_async_tcf
>>  	enable_step_tsk x19, x2
>>  #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
>>  	bl	stackleak_erase
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index b3c70a612c7a..e759b0eca47e 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -166,14 +166,35 @@ static void set_gcr_el1_excl(u64 excl)
>>  	 */
>>  }
>>  
>> +void check_mte_async_tcf0(void)
> 
> As above, this'll need to be noinstr. I also reckon we should put this
> in the header so that it can be inlined.
> 

Yes, I agree.

>> +{
>> +	/*
>> +	 * dsb(ish) is not required before the register read
>> +	 * because the TFSRE0_EL1 is automatically synchronized
>> +	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
>> +	 * is set.
>> +	 */
>> +	u64 tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);
> 
> Shouldn't we have an MTE feature check first?
> 

Indeed, I will add it in the next version.

>> +
>> +	if (tcf0 & SYS_TFSR_EL1_TF0)
>> +		set_thread_flag(TIF_MTE_ASYNC_FAULT);
>> +
>> +	write_sysreg_s(0, SYS_TFSRE0_EL1);
>> +}
>> +
>> +void clear_mte_async_tcf0(void)
>> +{
>> +	dsb(ish);
>> +	write_sysreg_s(0, SYS_TFSRE0_EL1);
>> +}
> 
> Likewise here on all counts.
> 

I will add noinstr and the check in the next version.

> Thanks,
> Mark.
> 
>>  void flush_mte_state(void)
>>  {
>>  	if (!system_supports_mte())
>>  		return;
>>  
>>  	/* clear any pending asynchronous tag fault */
>> -	dsb(ish);
>> -	write_sysreg_s(0, SYS_TFSRE0_EL1);
>> +	clear_mte_async_tcf0();
>>  	clear_thread_flag(TIF_MTE_ASYNC_FAULT);
>>  	/* disable tag checking */
>>  	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
>> -- 
>> 2.30.2
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cff8d16e-c1a9-3f10-7c7f-06fb569741ce%40arm.com.
