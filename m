Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4FBT35AKGQEHW73A7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FA20254409
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:54:41 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id m17sf879334uao.17
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:54:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598525680; cv=pass;
        d=google.com; s=arc-20160816;
        b=pUApieMZeQ1gMFTKQh4Asbb5xXo4wtoXk6E+l8XD94jYsFa9gff0Ga+7PTQub0MpfM
         yUSNsCr2PNag4/EoGTMVg1ANbtGifEb339QerCuj8PPnHnQnVgWmpHXu6vxx22C72VZY
         FovF/Atx9AIPdWWkwuScwdAyP3H+uyXgv4gNGk/sfc6RMsu7ypbxaJKjyzGtGAz9NnmR
         ZkKI1ASmkBYSxCHD7T9TpfFMjRP8TaWsrz7Ypze4YCsy7MzvB0N71I29Hn2X+/rjx1aH
         uDYzi4M2En/ozrYlBEKCSr/V9MP+3foLRqLEryRatZfQiq8M6otc3ppeAhuNXaHX3gRe
         8XLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=0t70EEtYYWP9dMJRTQY4CbMmnP2Ghbl1cvpsgmWmqUg=;
        b=cXCCRGYeC1yQ7MNpRdBr2lb7kxLCDsu/Of/DLyteWkxl6rGyLOJKz9b/iUDUC80QEz
         Kv9AKZo3Prjsjz7z51FmywVUse5RBbiP8K3WkgMMV2EalqkmdOGZnl89wVuqPUG0CaxX
         LhsAgH35AnIgUswqr3Ra3yjTXUacvyz2TWtsnk7FRHrJaxbjuXDbjtk6nID2PyDdAj9Z
         EyI58/2s6nTniXU5sibTOp1HEZfP3zCoptrE0Z26co2TxHYkYqJ2mQeeHcabygtC/YHU
         S7NoIVfUDsqHPcpyZOr7vfTPMSdBjBxEsrXX5MTcFPozt7ka+sFkKxwde7XD/EU8UOTO
         Frug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0t70EEtYYWP9dMJRTQY4CbMmnP2Ghbl1cvpsgmWmqUg=;
        b=FLJkbrO745PRLwGgWZ9dBbOg1MasHZSwrnrId+QA6xv4bRlUGQfPDfjvTlY0n1Zqtr
         iBwC+dE5b69RlaK3FnXeyrDrPn5zUr3GvKwpnx/KQXwLdJdFamF1ORQWGgw4c3Js6a3V
         X3fwPzEq3gFWyKTHmYSzMm97INGZg292cXtqJdk5Jl5lqtLnZpIDOD4MwGVR9etwXzwO
         f/LNt/u2l+Cz7r0Ef6SkrlQDMdab1YH3B3jQSpf0GKtGV0wxQCqcxnMtfnyKZsooTcrH
         x6OVwyJM9EAWHW7qGO0Y/1Mk8eEW2k1cy2Pi/XiTBfpzC6jOkNKFevlm67itqiMSN8Ef
         VHdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0t70EEtYYWP9dMJRTQY4CbMmnP2Ghbl1cvpsgmWmqUg=;
        b=oEdWXkl/bEVvFNzmAHMSQcWIHenh9DHeJo3wrs8jBjhoz4a2yQtSWxTHyVp2DeDAHz
         Ibb8DTh5yCtTm2m4MqErsH4la8GccDdJ1SJs6oOBJtarntJKBMPhWFalMrfS4vYfvud9
         7anTdK+yfGWZcKYDS4dMp4U0HE0cyiVVrB6MhqSy7Tw3xU/qzjUk+WQrVMNjFCWFWGGj
         JZ5ElNzMe3Benwzw4HEJmUhX2uFoL6WK0tuyVB8rtOQs4/hucBS/HHoxKcDG1XPYeXza
         nLjVKsjVjiZBLhW+/MEj2XEDJ157oJ9ia3O5YhL8R1rs5jW8439y30gy82Au/847s5kz
         d2ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531owHTyhLwP+OxmFkKKPpUpbp/FGq4fD9yArM0qCnhbVasMj+sx
	kKsG2m38zzpUZQzQL0BeEzw=
X-Google-Smtp-Source: ABdhPJxI1xZDYzZYTVVSvMAHbXG3mVsdwC7EN4+BMkC7O3SGw75aygHlX41+e5oTY7hzgVyXdry5+A==
X-Received: by 2002:a05:6102:538:: with SMTP id m24mr12242540vsa.40.1598525680399;
        Thu, 27 Aug 2020 03:54:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:24c1:: with SMTP id k184ls211913vsk.3.gmail; Thu, 27 Aug
 2020 03:54:40 -0700 (PDT)
X-Received: by 2002:a67:fbd1:: with SMTP id o17mr11461021vsr.19.1598525679949;
        Thu, 27 Aug 2020 03:54:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598525679; cv=none;
        d=google.com; s=arc-20160816;
        b=xNd8XfABn14MxD3R+b9p3A8O0JPS9dWcxoEyGOtZD4ie+kNsOSUUElmV35wGxz3PpX
         UTR78OJa3d80Jp5tz+YtGJ9DSneR44zcrw9I4w54pXCDAegeXICzRzKvIje8NB7hWgD+
         928j1KQqO6pBPtMvKGh6TdVUS9my+7Xk+aOQrz1zfPr4uhr8o7+wWb2e87Vzb7V6Q+bq
         FZEgxkDEnjYk6CzcagcFE/THiDE1CS8Z0vW0wk3bviBO/rvSQrByXAU6Hj5hdaxPj+j+
         krGGZMND8Mit8xuCi6ggopjQFdbDJvF7BYdAzdqEbilXt3hkd8PBLYSVkaITO0q6rDbS
         nGHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=UUUMvx26aJDmmt98HITyttc3HDjkAz0ni7+ERlxg9WE=;
        b=MyML4qhKp0ZFx4tx3V/tGMDk7qPHMuCKLe1RsbKWXSq+dCIJ851oNoRfVqtZ3Xt9hD
         8sp8+P3miPSx9r3DwHMNZuJVuBFKtGclJ5h+BiD+FDpGC8Q50RI8qRkbSUYx9acRHq07
         I1D8z7a6ARulfMxSwK7ou5LW0VT2ScQCGyd5k7ej3VIF5h36HLKSrDJ4yh5yYAYTY5b0
         uShLo6CDYmiaDAZcRPbniCBnnEEbS3rn7lPRftz3yN9ogXf/auAH/iiF7jruBo16SRlg
         6MhqUObpDy5fLgItdF7V+6w2WOwEYq2V/MLwlnQSq+FSidBMvJB/U9ZRGNUsy7OcJ3OT
         Trag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r16si37610vsl.2.2020.08.27.03.54.39
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 03:54:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6114C31B;
	Thu, 27 Aug 2020 03:54:39 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 220DF3F68F;
	Thu, 27 Aug 2020 03:54:36 -0700 (PDT)
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
References: <cover.1597425745.git.andreyknvl@google.com>
 <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com>
Date: Thu, 27 Aug 2020 11:56:49 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827103819.GE29264@gaia>
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

On 8/27/20 11:38 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
>> index cde127508e38..a17fefb0571b 100644
>> --- a/arch/arm64/kernel/entry.S
>> +++ b/arch/arm64/kernel/entry.S
>> @@ -172,6 +172,29 @@ alternative_else_nop_endif
>>  #endif
>>  	.endm
>>  
>> +	/* Note: tmp should always be a callee-saved register */
> 
> Why callee-saved? Do you preserve it anywhere here?
>

Aargh, this is an old comment, I forgot to remove it after the last refactor.
Thank you for pointing this out.

>> +	.macro mte_restore_gcr, el, tsk, tmp, tmp2
>> +#ifdef CONFIG_ARM64_MTE
>> +alternative_if_not ARM64_MTE
>> +	b	1f
>> +alternative_else_nop_endif
>> +	.if	\el == 0
>> +	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
>> +	.else
>> +	ldr_l	\tmp, gcr_kernel_excl
>> +	.endif
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
>>  	.macro	kernel_entry, el, regsize = 64
>>  	.if	\regsize == 32
>>  	mov	w0, w0				// zero upper 32 bits of x0
>> @@ -209,6 +232,8 @@ alternative_else_nop_endif
>>  
>>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
>>  
>> +	mte_restore_gcr 1, tsk, x22, x23
>> +
>>  	scs_load tsk, x20
>>  	.else
>>  	add	x21, sp, #S_FRAME_SIZE
>> @@ -386,6 +411,8 @@ alternative_else_nop_endif
>>  	/* No kernel C function calls after this as user keys are set. */
>>  	ptrauth_keys_install_user tsk, x0, x1, x2
>>  
>> +	mte_restore_gcr 0, tsk, x0, x1
>> +
>>  	apply_ssbd 0, x0, x1
>>  	.endif
>>  
>> @@ -957,6 +984,7 @@ SYM_FUNC_START(cpu_switch_to)
>>  	mov	sp, x9
>>  	msr	sp_el0, x1
>>  	ptrauth_keys_install_kernel x1, x8, x9, x10
>> +	mte_restore_gcr 1, x1, x8, x9
>>  	scs_save x0, x8
>>  	scs_load x1, x8
>>  	ret
> 
> Since we set GCR_EL1 on exception entry and return, why is this needed?
> We don't have a per-kernel thread GCR_EL1, it's global to all threads,
> so I think cpu_switch_to() should not be touched.
> 

I agree, we can remove it. We only require the kernel entry and the kernel exit
ones.

>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 7717ea9bc2a7..cfac7d02f032 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -18,10 +18,14 @@
>>  
>>  #include <asm/barrier.h>
>>  #include <asm/cpufeature.h>
>> +#include <asm/kasan.h>
>> +#include <asm/kprobes.h>
>>  #include <asm/mte.h>
>>  #include <asm/ptrace.h>
>>  #include <asm/sysreg.h>
>>  
>> +u64 gcr_kernel_excl __read_mostly;
> 
> Could we make this __ro_after_init?
>

Yes, it makes sense, it should be updated only once through mte_init_tags().

Something to consider though here is that this might not be the right approach
if in future we want to add stack tagging. In such a case we need to know the
kernel exclude mask before any C code is executed. Initializing the mask via
mte_init_tags() it is too late.

I was thinking to add a compilation define instead of having gcr_kernel_excl in
place. This might not work if the kernel excl mask is meant to change during the
execution.

Thoughts?

>> +
>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>  {
>>  	pte_t old_pte = READ_ONCE(*ptep);
>> @@ -115,6 +119,13 @@ void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>  	return ptr;
>>  }
>>  
>> +void mte_init_tags(u64 max_tag)
>> +{
>> +	u64 incl = ((1ULL << ((max_tag & MTE_TAG_MAX) + 1)) - 1);
> 
> I'd rather use GENMASK here, it is more readable.
> 

Agree, we can change it.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8affcfbe-b8b4-0914-1651-368f669ddf85%40arm.com.
