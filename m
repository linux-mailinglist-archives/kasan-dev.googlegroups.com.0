Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB2VRW75QKGQEDEN63XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 01E0427863F
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:47:56 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id s68sf611486vss.3
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:47:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601034475; cv=pass;
        d=google.com; s=arc-20160816;
        b=sc8JgWMZsa4lZBAIrF2+qRrDuhVFBAmZZWZSCY9maVzMe++44WG8w1zmD89AwE7b/O
         27Z+1l+0RB5gKwRltREnuB3FSjXSecv0DgasdiLar0nyEqnmPebCRsZRVlZI5K7w+rN6
         ah8FT3x/9dhxsLbJ6ucDei5YNFYAWaNd6N9wKBtkuI9wshtB9EWDQUy5Z7HIMuCgrl0g
         FZ4ipEK7JaMNBt9udUSPz476rqKgZTfSp8tD14uIkB0RSKl1X/xqFl4kUot4zkeCKjve
         11aeMngxFsdaRvcXHeeIA4vTavV29poMv2uc29m7INMsnpJymaH5DNiPyL3E6yyRlWvn
         9x4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Cg6U4WkMLmX/9+CCdaxjCFSdDYCZzt//bdODQMRcvP4=;
        b=jfrlYlJm4gT2bcLoqqGgehgtYHg/NoSk6uU1wW0+RJTo5ORuE7Uqi9voyZbWLxek54
         3XDp57JCMMMMGRVrqS7ZXNO5KmMqjT4Wuuiy5nwHotlKHdgI9OWqxousLftUo58dMlt5
         8VcuAxZlX8JDnzR9AUNBO8YKeOoOUhlkSlukGmufQZduSejeSYDUbKF+/LeusmhwTNdL
         eFSXU/p9Y7eMo5dHTv9fY/7nXFbC28ggH2vWx8UKtKT5NwjK/ovSNJ1a88nAKBtoK3cn
         C15pp3bPJTCheH37DY6k6QJMPXgA5dIpNig9ZuBCcWDXnWK4vuFdZkZlbT7X888vzq9P
         ZEdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Cg6U4WkMLmX/9+CCdaxjCFSdDYCZzt//bdODQMRcvP4=;
        b=HLzCNXrVa4IryVboeFjbZCixZlpDMDOUun/w7uyVcSHoMJ+uqrciwivurdfHgtXXK6
         dQPpBkUfNI1Il5ZobjSFTDa15lrO9KSbKtK44Zn9zNaEGpSg7MZovDzrScw3Qa3FvKOT
         ByqsksecYILs05KRACMniVx3c+ARVzWa8LDrJ4wjUBJ6f2UDjhZ8qL81qPsdwnBG+NAi
         QxI20EEBMLUNgcqI8CYwbiwtbM+X213NjkQy7kBdvAIiWW6DFMZqh1yaBInd3YXiqbTQ
         jxif16NCagNnZlHJ1QHKHQciGBC0fHcZIqZR86BrDMAAVgfPYKtYDTRRsAsFBqIZ60YX
         NZcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Cg6U4WkMLmX/9+CCdaxjCFSdDYCZzt//bdODQMRcvP4=;
        b=F6ReJ7Soi5Nr/TRktLI6gGSsYfLmWNocQhSSIJv5Hj2e+x8CEAazbn1ONezIkHMKFx
         3YZSlP1pCM8X9uIVZG0HiTj0HmD0J2ZisxeRiFbrPJ9K8v+8yCe7EV3ga9GzRonwJNhU
         gVf+wcEoIgkqWxUCN1XjJikSmqOIRLt3Y4TYsLdghtD0kxsjrM9qeoMBMPcC79LfYDCX
         fshQhd58SEOXhKaTEczm7KIJT76yiKYBi2+KZ0ua16akuoNkM7kQHCFT1l4Kq1gcFrPL
         tH6GEAoGmvImcGiQGuoa0oCq3uxs8iUKVqY1Iq0XEZ7qZWHWNU0r3Mhz6TSx9JOs8OIu
         M7cQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531orn8JWeLtspmj7b8gIJkLpHX8JOWVaIxL/1evcU3iU2CDWfy7
	B9A0FDV9lPyMFYNV3yrwKdE=
X-Google-Smtp-Source: ABdhPJzAJg6P89mchl0DfSKhPH4zsUjVqh8x33mN5slo9M6JiJcG/gydwo+9quNcVDp4veGgym7bRg==
X-Received: by 2002:a67:3009:: with SMTP id w9mr2488950vsw.19.1601034474976;
        Fri, 25 Sep 2020 04:47:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3d1:: with SMTP id n17ls339104vsq.2.gmail; Fri, 25
 Sep 2020 04:47:54 -0700 (PDT)
X-Received: by 2002:a67:d601:: with SMTP id n1mr2483803vsj.2.1601034474506;
        Fri, 25 Sep 2020 04:47:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601034474; cv=none;
        d=google.com; s=arc-20160816;
        b=Ays9Zxam6wmkqi7wa0aKDSbO8iCXZTmCcaxtQUC2L1gEGNa92IO9E3XKmfRv4za7ZQ
         SCRkA32Gw9yG15cmsdsFm2T6L1tiiN0MXheIwJq9BPS5/o4Mq46n6pRxPephg2ylwsMS
         c7LCEl0o+3fC6Koe0LQc22YEYdr/cy2dRyH0IzBzHSvsgPrd95hAaAcbfc4uMjyQBTPg
         J/i+4SYzAbr1ej6bLkhLvIqk0PvQN8BKEa7xqvTPyIUa7avOUyPv7P3b0hoISgkext9p
         dj+dUlENNoRgqF37Af6K+ldPkDSQe+yNDua15suHELS8RhKeAnjDVbS3KwXghWqrW9Ye
         zrPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=KcT21iROjtZOWeAnuTzW91g5olilWaNvgTdYroBiAmA=;
        b=mMDjIblALZLXYe2PXyrVshzzxAbpywUvo3Z3oR5O7H8uEDgWVIrMN/wkr0UP7eYXF5
         o75z20PJ0nJE6rLCMrYmZO88ygIA+Obe8dMCt9EIdvZDpr8JJcctWC+XPhHapfs/x8oH
         mM/MuUYuFbsZ9VljpsgZq/ABW00ROOZH3QAkLFk1LVEyS99TB+njvSJLRvGqf4cbdyBN
         v7HtvwOk9Q2tfznTWdrCg6WUmJk5iz4zrsDm6zGg6szZ8+KplvE6+aE9O5fbIS1kRDYX
         HpYzB8Wk0b+e+bu2Yzwt8ewjjdhJktYfI50q3Xt2AllBlcij3/WBX/jfffcy5jNADs0K
         6i2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u25si140578vkl.5.2020.09.25.04.47.54
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Sep 2020 04:47:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 95A77101E;
	Fri, 25 Sep 2020 04:47:53 -0700 (PDT)
Received: from [10.37.12.53] (unknown [10.37.12.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 872613F70D;
	Fri, 25 Sep 2020 04:47:50 -0700 (PDT)
Subject: Re: [PATCH v3 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1600987622.git.andreyknvl@google.com>
 <4e503a54297cf46ea1261f43aa325c598d9bd73e.1600987622.git.andreyknvl@google.com>
 <20200925113433.GF4846@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <e4624059-1598-17eb-2c64-3e7f26c2a1ba@arm.com>
Date: Fri, 25 Sep 2020 12:50:23 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200925113433.GF4846@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

On 9/25/20 12:34 PM, Catalin Marinas wrote:
> On Fri, Sep 25, 2020 at 12:50:36AM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
>> index ff34461524d4..c7cc1fdfbd1a 100644
>> --- a/arch/arm64/kernel/entry.S
>> +++ b/arch/arm64/kernel/entry.S
>> @@ -175,6 +175,49 @@ alternative_else_nop_endif
>>  #endif
>>  	.endm
>>  
>> +	.macro mte_set_gcr, tmp, tmp2
>> +#ifdef CONFIG_ARM64_MTE
>> +alternative_if_not ARM64_MTE
>> +	b	1f
>> +alternative_else_nop_endif
> 
> You don't need the alternative here. The macro is only invoked in an
> alternative path already (I'd be surprised if it even works, we don't
> handle nested alternatives well).
>

Yes, you are right. I forgot to remove it.

>> +	/*
>> +	 * Calculate and set the exclude mask preserving
>> +	 * the RRND (bit[16]) setting.
>> +	 */
>> +	mrs_s	\tmp2, SYS_GCR_EL1
>> +	bfi	\tmp2, \tmp, #0, #16
>> +	msr_s	SYS_GCR_EL1, \tmp2
>> +	isb
>> +1:
>> +#endif
>> +	.endm
>> +
>> +	.macro mte_set_kernel_gcr, tsk, tmp, tmp2
> 
> What's the point of a 'tsk' argument here?
> 

It is unused. I kept the interface same in between kernel and user.
I can either add a comment or remove it. Which one do you prefer?

>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +#ifdef CONFIG_ARM64_MTE
> 
> Does KASAN_HW_TAGS depend on ARM64_MTE already? Just to avoid too may
> ifdefs. Otherwise, you can always write it as:
> 
> #if defined(CONFIG_KASAN_HW_TAGS) && defined(CONFIG_ARM64_MTE)
> 
> to save two lines (and its easier to read).
> 

It is indeed. I forgot to remove CONFIG_ARM64_MTE.

>> +alternative_if_not ARM64_MTE
>> +	b	1f
>> +alternative_else_nop_endif
>> +	ldr_l	\tmp, gcr_kernel_excl
>> +
>> +	mte_set_gcr \tmp, \tmp2
>> +1:
>> +#endif
>> +#endif
>> +	.endm
>> +
>> +	.macro mte_set_user_gcr, tsk, tmp, tmp2
>> +#ifdef CONFIG_ARM64_MTE
>> +alternative_if_not ARM64_MTE
>> +	b	1f
>> +alternative_else_nop_endif
>> +	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
>> +
>> +	mte_set_gcr \tmp, \tmp2
>> +1:
>> +#endif
>> +	.endm
>> +
>>  	.macro	kernel_entry, el, regsize = 64
>>  	.if	\regsize == 32
>>  	mov	w0, w0				// zero upper 32 bits of x0
>> @@ -214,6 +257,8 @@ alternative_else_nop_endif
>>  
>>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
>>  
>> +	mte_set_kernel_gcr tsk, x22, x23
>> +
>>  	scs_load tsk, x20
>>  	.else
>>  	add	x21, sp, #S_FRAME_SIZE
>> @@ -332,6 +377,8 @@ alternative_else_nop_endif
>>  	/* No kernel C function calls after this as user keys are set. */
>>  	ptrauth_keys_install_user tsk, x0, x1, x2
>>  
>> +	mte_set_user_gcr tsk, x0, x1
>> +
>>  	apply_ssbd 0, x0, x1
>>  	.endif
>>  
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 393d0c794be4..c3b4f056fc54 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -22,6 +22,8 @@
>>  #include <asm/ptrace.h>
>>  #include <asm/sysreg.h>
>>  
>> +u64 gcr_kernel_excl __ro_after_init;
>> +
>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>  {
>>  	pte_t old_pte = READ_ONCE(*ptep);
>> @@ -116,6 +118,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>  	return ptr;
>>  }
>>  
>> +void mte_init_tags(u64 max_tag)
>> +{
>> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
>> +
>> +	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
>> +}
>> +
>>  static void update_sctlr_el1_tcf0(u64 tcf0)
>>  {
>>  	/* ISB required for the kernel uaccess routines */
>> @@ -151,7 +160,11 @@ static void update_gcr_el1_excl(u64 excl)
>>  static void set_gcr_el1_excl(u64 excl)
>>  {
>>  	current->thread.gcr_user_excl = excl;
>> -	update_gcr_el1_excl(excl);
>> +
>> +	/*
>> +	 * SYS_GCR_EL1 will be set to current->thread.gcr_user_incl value
>                                                       ^^^^^^^^^^^^^
> That's gcr_user_excl now.
> 
>> +	 * by mte_restore_gcr() in kernel_exit,
> 
> I don't think mte_restore_gcr is still around in this patch.
> 

This comment requires updating. I missed it.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e4624059-1598-17eb-2c64-3e7f26c2a1ba%40arm.com.
