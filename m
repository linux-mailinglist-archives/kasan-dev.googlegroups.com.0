Return-Path: <kasan-dev+bncBDGZVRMH6UCRBAHVVK7AMGQEUAM5MPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16BFCA56392
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 10:21:06 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5fea43da180sf1488904eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 01:21:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741339265; cv=pass;
        d=google.com; s=arc-20240605;
        b=YvDH0peSRBQ2LcI5B3K+J8+zZ7920jXpZquxRw3wtw0P+hlQv+inEv+GSOyS6CAx5S
         sMZbFM5axW1aU1OICEps4iMVGkppeCTC1SQiB7kFVVHFnbZCSxu8LzWqppgFN2mEU4FF
         DUeFKNncyEQnUnkYrs01bU3t9h02O2b00rAvIZ4TXTvDDsqUstN0RUvrHbhMznjDWHso
         LncTP7P00gzSBEZSgDgFN6FhB+09a5J+yvFPtbydna3bO+EWCxpt3/3rbD4WvVaV82vE
         ZMtFJs+A1SBaCGZ8Lw1hKxx/niZ65aEJ6Fyo7UNV2qoEbT8KWzrAjeyqYif6k8yYicYw
         F5OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=JI6NuSEmfS0eOV1ZjYXVtuttgR98JahWdUdmDt7R9bo=;
        fh=7yf77wP6VE8YK/ux0wjdb36ZHMh0RxUFzHRmliKoLMA=;
        b=hYIXpdPcjwvW36Zf2IoSg7rUv+9rhcclP341X3EAyIHXfuoUUIT5N6Trxow7ws8EsR
         0hUwrZNo5+sd07LEJk2BXmRkUUJ/dSOV/eo6ACB9MaLQosXZ70K1B0qBU8lA7JXFnFGU
         kyQI3YP/C0FXVclaDY8zdHQSErpVU21Xkqih83yCRBiOX+H+t7RzMar6p/hVHVNH65b9
         Ij2a2C3M8cPRFn1OgiTcja5uKDOmuxsA7Tag+3+tSIJpUHJ7gYzmnU3wa+SYvjItf802
         IXA7Zbju8mTrTTr/y6BRWh4zvq2vVudWkI/KIP5fxX41fOygyKNy2vbUdGeOt2uBmvTV
         ESnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741339265; x=1741944065; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JI6NuSEmfS0eOV1ZjYXVtuttgR98JahWdUdmDt7R9bo=;
        b=sd8RJ7C+dBiZIFt0NxtEddvyIAqekPOtwEDqHpWPVvelajBkhSAuUeMWnjl6sHxaI2
         /N6353qIfUCdoQygsxkyTv2tlwMiPZ0nMLa574zkUy2I/GxD4KMEiZOAcHuDCitIkPWd
         Vr3KV4d4nAIu+fU4KRJB/GkCKgdn9y8p0vae7iHlkmUXeJ1IXrwIxqHlix5JR6T6AcDX
         HROC9VAlo4Ug3sEY8z51Jnt2TEVrFp1mddJvL/dZZPWK6RmZDoD0B4/t71+/A9zqn8w5
         nk75MgpUUJGtAf1Mj9CyGNJ9oZ2HppUbcrOgzFmdWxSLMoyGNQhS4ggRxpppwNxPgiG7
         jFOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741339265; x=1741944065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JI6NuSEmfS0eOV1ZjYXVtuttgR98JahWdUdmDt7R9bo=;
        b=A8GkAGYOaSYijS14cbl1J2RvWu86C91sxag7vQ0Id6/FM54pMPUPsO9XoOOMgnD5Pf
         CBRddnNFnCkrbkfcddY0/UZuln3cV17ayX2Mq5PwSwDg6oexDDd5ZJtaQ8g4FSwxsrT3
         z9u6VTmG5jeCirsO3+gIvRhDiXsWjSIVVh3Zz2zvK4dGWOjlZrEbYgu+cDjRIGWIujl9
         Npl4pq0AacELn3EN3NG+6cONvifL8hl9JGfSVtUcFqntD+KCa9J5s7c8mVp7HRqW5/I4
         QdDqfFnPVgJpYpYUZAgGKTBR0JdvBQsJ6bZAtvPNyZZ1sz9tzOjcEWmIR86gCklbWFAf
         BwVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV76KtQvRv4Kc7KrXTKuD76VQmE8UuOa9Jn+KlAn5V5ji72q0plarwT0SGWwwusOaMbLXmlUg==@lfdr.de
X-Gm-Message-State: AOJu0Yzubx+2jesmxWC9yAGYgoHNxpGkBTUOD3rDLPTPBUY5fDJfb08B
	V1QhY8/cTCpPCPnQ2bDiQQInDint3Q6o16Ugh/sB7Wzl66RqUv8D
X-Google-Smtp-Source: AGHT+IFGZFthzDQGOxTyXCBq+2EfX+8bFiUXprXexuw8Lw2SxYm+FELkXqqCQT7EUxaS2ta/oMFSSQ==
X-Received: by 2002:a05:6820:2711:b0:5fc:e3b3:3c10 with SMTP id 006d021491bc7-6004a770dd1mr1167678eaf.2.1741339264788;
        Fri, 07 Mar 2025 01:21:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGqZ8mt+D+EnTaUTxZkyFAj1yXuJ2ER8pgcQ2l+8OmBKA==
Received: by 2002:a4a:e784:0:b0:600:4dc9:e08f with SMTP id 006d021491bc7-6004dc9e3b3ls162849eaf.0.-pod-prod-09-us;
 Fri, 07 Mar 2025 01:21:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXOkCnVn9FjRNV1dumyNx9IYcfPQsYIQ4J7t3H6T0TKOf04mFg6sbDF9EhaIMjpoPraVlXFBGSQxQM=@googlegroups.com
X-Received: by 2002:a05:6808:144c:b0:3f6:74be:fceb with SMTP id 5614622812f47-3f697bf3034mr1491040b6e.33.1741339263918;
        Fri, 07 Mar 2025 01:21:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741339263; cv=none;
        d=google.com; s=arc-20240605;
        b=aLYdKOMT0l41BG8iKUMojbfKvgGg2bsmYCaCGIQ0JCdWWl4RbBVHxL64HiDRUZI+x3
         h2dzobz/NqzqBYAF6McKeuU2BAYo8IWLEWHvSSyWVpMM737Wx7i8F+i7pvhWt5MpdFlI
         //BrlSagXvZUnX6K6yxnVgzhvBZfBpTtDuoJpcxLMYFXefr9jdYc4Ib2ZNWiU/hDBK9y
         6BVRpW9hzpuLNdfsKqCecPNJjsaJFPWC5GC5MqsVYCPPRQlDAtTngNvJbYlWDSLiyJvX
         hD91kclD130rcIAW1uM+QY5A1V4AVHcZ14A5Q67nbM3S0zFINXFB2h2GY5u+rc9nJyJ6
         IR/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=TUIpcEC4TM+kELVJUpyhpFBd8j2jrm6anGOOdFHUNyE=;
        fh=votHqClNabudU9MdrGbl4j91LSOLnUVul2CYZRJQ3FU=;
        b=P/ChPIZ8uY0Oz6i5oLIKaguqdY9DP7uuRE2iqEDIkFpbfS//G/r0fJv3ArY+nDJe+n
         xVVMhnYpiQV1ociDKJTaQ7Q2Ww+A2+c7M4mmCp2hSYUsRCWZZKsjz6U3GTJDIaeqwtS/
         9MSZGFAD7v3DVM7YrI1CQsNqcyWeC0ncWzgxuwb+mqh1Ha2SBBi32hj2WdU61vVx+HGu
         A/vBirm/nsowIsNC2oYNm9x7pzSaZiUwRVWWx53DGxoTkeORSumP/gUfxpgbgnFSXM1b
         HblTFH7e+x4CESh0xcEPurW5g80vVpECigHQ2l5ykqmehMD8Pw3/LdJjoyk5ziUIg4Z7
         ELZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 5614622812f47-3f68ee953bcsi125030b6e.1.2025.03.07.01.21.03
        for <kasan-dev@googlegroups.com>;
        Fri, 07 Mar 2025 01:21:03 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 451521477;
	Fri,  7 Mar 2025 01:21:16 -0800 (PST)
Received: from [10.162.42.6] (a077893.blr.arm.com [10.162.42.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 03DC93F66E;
	Fri,  7 Mar 2025 01:20:59 -0800 (PST)
Message-ID: <c3dddb6f-dce1-45a6-b5f1-1fd247c510ab@arm.com>
Date: Fri, 7 Mar 2025 14:50:56 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] arm64/mm: Define PTE_SHIFT
To: Ryan Roberts <ryan.roberts@arm.com>, linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20250307050851.4034393-1-anshuman.khandual@arm.com>
 <17931f83-7142-4ca6-8bfe-466ec53b6e2c@arm.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <17931f83-7142-4ca6-8bfe-466ec53b6e2c@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
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



On 3/7/25 14:37, Ryan Roberts wrote:
> On 07/03/2025 05:08, Anshuman Khandual wrote:
>> Address bytes shifted with a single 64 bit page table entry (any page table
>> level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
>> is not very readable or easy to reason about. Besides it is going to change
>> with D128, where each 128 bit page table entry will shift address bytes by
>> 4 (aka 2^4 = 16) instead.
>>
>> Let's just formalise this address bytes shift value into a new macro called
>> PTE_SHIFT establishing a logical abstraction, thus improving readability as
>> well. This does not cause any functional change.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Cc: Mark Rutland <mark.rutland@arm.com>
>> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Andrey Konovalov <andreyknvl@gmail.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Ard Biesheuvel <ardb@kernel.org>
>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>> Cc: linux-arm-kernel@lists.infradead.org
>> Cc: linux-kernel@vger.kernel.org
>> Cc: kasan-dev@googlegroups.com
>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> 
> 
> +1 for PTDESC_ORDER

Alright.

> 
> Implementation looks good to me so:
> 
> Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>

Thanks !

> 
> one nit below.
> 
>> ---
>> This patch applies on v6.14-rc5
>>
>>  arch/arm64/Kconfig                      |  2 +-
>>  arch/arm64/include/asm/kernel-pgtable.h |  3 ++-
>>  arch/arm64/include/asm/pgtable-hwdef.h  | 26 +++++++++++++------------
>>  arch/arm64/kernel/pi/map_range.c        |  2 +-
>>  arch/arm64/mm/kasan_init.c              |  6 +++---
>>  5 files changed, 21 insertions(+), 18 deletions(-)
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index 940343beb3d4..fd3303f2ccda 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
>>  	default 18
>>  
>>  # max bits determined by the following formula:
>> -#  VA_BITS - PAGE_SHIFT - 3
>> +#  VA_BITS - PAGE_SHIFT - PTE_SHIFT
>>  config ARCH_MMAP_RND_BITS_MAX
>>  	default 19 if ARM64_VA_BITS=36
>>  	default 24 if ARM64_VA_BITS=39
>> diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
>> index fd5a08450b12..7150a7a10f00 100644
>> --- a/arch/arm64/include/asm/kernel-pgtable.h
>> +++ b/arch/arm64/include/asm/kernel-pgtable.h
>> @@ -49,7 +49,8 @@
>>  	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
>>  
>>  #define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
>> -	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
>> +	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + \
>> +	lvl * (PAGE_SHIFT - PTE_SHIFT), add) : 0)
> 
> nit: not sure what style guide says, but I would indent this continuation an
> extra level.

IIUC - An indentation is not normally required with a line continuation although
the starting letter should match the starting letter in the line above but after
the '(' (if any).

> 
> Thanks,
> Ryan
> 
>>  
>>  #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
>>  	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
>> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
>> index a9136cc551cc..43f98eac7653 100644
>> --- a/arch/arm64/include/asm/pgtable-hwdef.h
>> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
>> @@ -7,40 +7,42 @@
>>  
>>  #include <asm/memory.h>
>>  
>> +#define PTE_SHIFT 3
>> +
>>  /*
>>   * Number of page-table levels required to address 'va_bits' wide
>>   * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
>> - * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
>> + * bits with (PAGE_SHIFT - PTE_SHIFT) bits at each page table level. Hence:
>>   *
>> - *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
>> + *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTE_SHIFT))
>>   *
>>   * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
>>   *
>>   * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
>>   * due to build issues. So we open code DIV_ROUND_UP here:
>>   *
>> - *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
>> + *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTE_SHIFT) - 1) / (PAGE_SHIFT - PTE_SHIFT))
>>   *
>>   * which gets simplified as :
>>   */
>> -#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
>> +#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - PTE_SHIFT - 1) / (PAGE_SHIFT - PTE_SHIFT))
>>  
>>  /*
>>   * Size mapped by an entry at level n ( -1 <= n <= 3)
>> - * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
>> + * We map (PAGE_SHIFT - PTE_SHIFT) at all translation levels and PAGE_SHIFT bits
>>   * in the final page. The maximum number of translation levels supported by
>>   * the architecture is 5. Hence, starting at level n, we have further
>>   * ((4 - n) - 1) levels of translation excluding the offset within the page.
>>   * So, the total number of bits mapped by an entry at level n is :
>>   *
>> - *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
>> + *  ((4 - n) - 1) * (PAGE_SHIFT - PTE_SHIFT) + PAGE_SHIFT
>>   *
>>   * Rearranging it a bit we get :
>> - *   (4 - n) * (PAGE_SHIFT - 3) + 3
>> + *   (4 - n) * (PAGE_SHIFT - PTE_SHIFT) + PTE_SHIFT
>>   */
>> -#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
>> +#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - PTE_SHIFT) * (4 - (n)) + PTE_SHIFT)
>>  
>> -#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - PTE_SHIFT))
>>  
>>  /*
>>   * PMD_SHIFT determines the size a level 2 page table entry can map.
>> @@ -49,7 +51,7 @@
>>  #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
>>  #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
>>  #define PMD_MASK		(~(PMD_SIZE-1))
>> -#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - PTE_SHIFT))
>>  #endif
>>  
>>  /*
>> @@ -59,14 +61,14 @@
>>  #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
>>  #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
>>  #define PUD_MASK		(~(PUD_SIZE-1))
>> -#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - PTE_SHIFT))
>>  #endif
>>  
>>  #if CONFIG_PGTABLE_LEVELS > 4
>>  #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
>>  #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
>>  #define P4D_MASK		(~(P4D_SIZE-1))
>> -#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - PTE_SHIFT))
>>  #endif
>>  
>>  /*
>> diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
>> index 2b69e3beeef8..3530a5427f57 100644
>> --- a/arch/arm64/kernel/pi/map_range.c
>> +++ b/arch/arm64/kernel/pi/map_range.c
>> @@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
>>  {
>>  	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
>>  	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
>> -	int lshift = (3 - level) * (PAGE_SHIFT - 3);
>> +	int lshift = (3 - level) * (PAGE_SHIFT - PTE_SHIFT);
>>  	u64 lmask = (PAGE_SIZE << lshift) - 1;
>>  
>>  	start	&= PAGE_MASK;
>> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
>> index b65a29440a0c..90548079b42e 100644
>> --- a/arch/arm64/mm/kasan_init.c
>> +++ b/arch/arm64/mm/kasan_init.c
>> @@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
>>   */
>>  static bool __init root_level_aligned(u64 addr)
>>  {
>> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
>> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>>  
>>  	return (addr % (PAGE_SIZE << shift)) == 0;
>>  }
>> @@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
>>  	 */
>>  	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
>>  							: vabits_actual;
>> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
>> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>>  
>>  	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
>>  }
>> @@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
>>   */
>>  static int __init next_level_idx(u64 addr)
>>  {
>> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
>> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTE_SHIFT);
>>  
>>  	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
>>  }
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c3dddb6f-dce1-45a6-b5f1-1fd247c510ab%40arm.com.
