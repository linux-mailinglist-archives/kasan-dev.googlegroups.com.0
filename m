Return-Path: <kasan-dev+bncBDGZVRMH6UCRB4H7XK7AMGQESAJATEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C3EBA59140
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Mar 2025 11:33:22 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2254e0b4b85sf29129615ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Mar 2025 03:33:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741602800; cv=pass;
        d=google.com; s=arc-20240605;
        b=bqILZBuTE3+wZ0UNP0z2mC9SWu0Jf7MgqLOOao/ATU3CZC0ZuFLFMGzOIMQXWRLS0K
         bDNM6u8R3q4N44DDy3MMgbI4tI2HVlPqECaxbw789V/k8do9PQ7C6Yy6kgPZRtM0wB+t
         B1UvCGBjZa+MdAwmZWcIiuzfHmmb2iwYtx8DcrRpcbJfEMGGnqqW/S7WliwvKqzSkxuc
         IsYOc32mD+FQEyzWZ4sGIIvEO3YDNjyXsRZ3jc4hkX9c99ETlc2pQFtI+kLbI8VDncUY
         zexAF+RbOQz7DWPMWDXNVKpi88ZpPTm95s3Xcbd+9WbUkKkond3W92ZR6DdKmdm92l9Q
         NOtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=z5w+cYPl2EMr+EXwYp5AQl1K0ON6ncmFgPdUsgWtPqw=;
        fh=J4gPIkb3NygiT+x02ko0jZFJvmENK9IwZ675w2jBPAU=;
        b=Z82xu4qfhw46uq0DKyeBxGOOkCFYO+QWbP166vwZ7hPw+4fyLpiabK+BGN6gzRbFXh
         yt6cnlPXaWF2UFc7rOr6Fc9unOjia7vjYSuExivnve+YYYgeOvhAXmvFny42GAAbwMjd
         ak4eccW7ZLZmMZ0ZHxMFiJX8CAu/8oTarLKd+TvUeRy4/yP0gOLcZgPdXwum4Y6wPHbD
         C5LCPjjFVBPHl2YLiMQ40qqSUEM+LMy/ReRCzI6yZU3OvqO10MPbbXzL2CU/08Ltb9st
         A2TthqhN0EFAxLpdFXe+bNZ/XqTbMt4K2VQ8XbYk0hTqXJxwYrtdAIogBFG2+bLM0wzk
         9v1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741602800; x=1742207600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=z5w+cYPl2EMr+EXwYp5AQl1K0ON6ncmFgPdUsgWtPqw=;
        b=ikoFXjwJjJnk/q1aKisOrSp7JJ9E4wo5LaeXXhnzPLG0Gp1whe4/7Nm5s6NoQ4rTrC
         KCrS/GxeYhIOQY3VBrvQs6yuHixsPJSLLaf8fCmA+eBBol6Ibhi3TkI00VV2bqGu6yPR
         oCfTs6Fpu6voqIR6lbKPNDRcXPghJVl3EoxJBSZExGVgvnjIX3RD9s77hJ12e0v+r9Hb
         qJQDVwnIgSaCH8gWdwYECZYWuc4nLiPf2e9tsS8hHGGLVK3JxWAAy6BcxEzW44hS4oAs
         vz1VCgFi4d+kzeR4yylLbzGhdFbVztGMXeeLfcRg+s4zxA2k2/rZFbJnOJwB10h5FdHX
         5LfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741602800; x=1742207600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z5w+cYPl2EMr+EXwYp5AQl1K0ON6ncmFgPdUsgWtPqw=;
        b=iQaE7q/dC39Afu4q6238hv2qcCcpgsrRRPjyVXrZr1H3sNHMvFSBQax9eqy+YWFhSe
         KqO7808nsL/h84Ctq8xiF6fdyhG3M96kFJvZ7+JFSS3iHVX4VxlNT02s76T+NRveU7Wx
         TAY5UrKZhkLpibsDYC/VSoCWg2s0025WM5BBwWF+C1keG3waCcfTA3BGK10X4oBVqwU3
         uMJdYDlIT7lhETUA1euQbOtmqNbdLgxTyHUt9XpD4Bf7ocj1W01m2GrIWTS7IV39jfrq
         9aCQXBDjnXs24eoTErLvJntRTOLHdc4fO7YtcLk0QJuB8LaboWcuqZY2y+c5vHYU2RI9
         74VA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUaKJ7iski1vOm0G+KJehjs2Y5Wa3fniPpHXBoZLK5ErzC7H+zzLIwy3rz7hI7rDd6yqzYvlg==@lfdr.de
X-Gm-Message-State: AOJu0YxNRwaDyiv4o+H6Sf55u0HWR8Jnm1GfxnTqBjWyz/dNVbcTqAhZ
	dmY1n5W8Um/FCwXGd2GL/V0o2INJmf9FYiv7+0DgujEfwDJv//Jg
X-Google-Smtp-Source: AGHT+IGJC2y1BYmEKzwjMdQuHwJnB6MB5Ewc6LRWc8Rs/kyJXIp84yobNuqv+c1Uz4CU4S6ZzxzMSA==
X-Received: by 2002:a17:903:2f82:b0:223:fbbe:599c with SMTP id d9443c01a7336-2246452f784mr161744105ad.19.1741602800483;
        Mon, 10 Mar 2025 03:33:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF/xNaUYKmsQxUR71ytwhn6e7r2pfYelteek9xAPB9R2g==
Received: by 2002:a17:902:f907:b0:220:c91d:4fa2 with SMTP id
 d9443c01a7336-224090544b7ls20827105ad.0.-pod-prod-00-us; Mon, 10 Mar 2025
 03:33:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUV970kB2tc7V01yTglPQT/aijd7uo1czjqoSDpDJQPKJn8Mp6c+Vq5NvcTGLau471lVRDt8l1d9jo=@googlegroups.com
X-Received: by 2002:a17:902:e74d:b0:223:517a:d5a9 with SMTP id d9443c01a7336-22464503452mr151330585ad.15.1741602799013;
        Mon, 10 Mar 2025 03:33:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741602799; cv=none;
        d=google.com; s=arc-20240605;
        b=kdW4MD4fLZw5B5lxIhHdWRP6FwEBEQ1gTpDE0GNaSKUcwAqob+9W9oMx36zy4hlNFR
         gG0WxvjKHLuMGFKJN+KMoijcayFj5iJ7bsnjKfcRS/oKJkACNlAyKHQkVx6hJGwQeQ8p
         uP3RxqiFii18QPmOytqer32zFoItDyJurrpx5m3mMMUuAcv1DXkqEMRJAgpyZSyIFe7a
         KTRxAKxqjTcfCOUQr/3mSx6XklYTyKh01MsksRQENU6V5B1BHFp8aDR3AJ1vL0fIe9Jp
         VqkEpQJVWtTorw+igsIp/bmyrKYmphAHodRsUITjQmrZDTmBnAi9ulXk3ZxUH5QPbd8M
         EbhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=sGIUDpOjLBglWb8WEnUCJJvOLNIyDF4znjZoN8YXDwM=;
        fh=HAlp5hDvgQK7HY16ZKWuvqiAMn2Q+nJctprc79tXGM4=;
        b=lb/L+zU8ajW2qY5BgixVctAB3t66YvA/retuBD3PuITzmK/XZ096QIVH2eGvUEBdFY
         cY00lZ3kjRbfnMe6oI2HS0SrudWGZjuU4N8DDtImbeS6UnvrIPymglxm98OqvZVc0NWC
         9IgRopnczCb3nDuQ6QE2gbfRPudeu2XRGG1jW/4X4qS+Ek0aavlhmUVaBqAr08GeOnD9
         vZ64LBiszGUP8BZb7KnLUQvl/nGUMDGW/D0/CwIrisPJ/C+MF5G8aW0QikDEIl6JdrET
         rsb/RIWui6aOxjpBjBNcaHFfI/WIqIp4OyFM7s+iPbXAgklSKrf6S0BmksE/+/uENqz6
         2Z4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-22410a8fc9bsi3470395ad.6.2025.03.10.03.33.18
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Mar 2025 03:33:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 88F4E153B;
	Mon, 10 Mar 2025 03:33:29 -0700 (PDT)
Received: from [10.163.42.69] (unknown [10.163.42.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0F0DB3F673;
	Mon, 10 Mar 2025 03:33:13 -0700 (PDT)
Message-ID: <68188aa1-8f80-4f91-beb5-9ddb0129a490@arm.com>
Date: Mon, 10 Mar 2025 16:03:12 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2] arm64/mm: Define PTDESC_ORDER
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, Ryan Roberts <ryan.roberts@arm.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20250310040115.91298-1-anshuman.khandual@arm.com>
 <Z86-34-fgk7iskX_@J2N7QTR9R3.cambridge.arm.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <Z86-34-fgk7iskX_@J2N7QTR9R3.cambridge.arm.com>
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



On 3/10/25 15:58, Mark Rutland wrote:
> On Mon, Mar 10, 2025 at 09:31:15AM +0530, Anshuman Khandual wrote:
>> diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
>> index fd5a08450b12..78c7e03a0e35 100644
>> --- a/arch/arm64/include/asm/kernel-pgtable.h
>> +++ b/arch/arm64/include/asm/kernel-pgtable.h
>> @@ -45,11 +45,14 @@
>>  #define SPAN_NR_ENTRIES(vstart, vend, shift) \
>>  	((((vend) - 1) >> (shift)) - ((vstart) >> (shift)) + 1)
>>  
>> -#define EARLY_ENTRIES(vstart, vend, shift, add) \
>> -	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
>> +/* Number of VA bits resolved by a single translation table level */
>> +#define PTDESC_TABLE_SHIFT	(PAGE_SHIFT - PTDESC_ORDER)
> 
> To be clear, when I suggested adding PTDESC_TABLE_SHIFT, I expected that
> it would be used consistently in place of (PAGE_SHIFT - PTDESC_ORDER),
> and not only replacing that within the EARLY_ENTRIES() macro
> specifically.

I had that dilemma as well but alright, will respin this once more.

> 
> Mark.
> 
>> -#define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
>> -	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
>> +#define EARLY_ENTRIES(lvl, vstart, vend) \
>> +	SPAN_NR_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * PTDESC_TABLE_SHIFT)
>> +
>> +#define EARLY_LEVEL(lvl, lvls, vstart, vend, add) \
>> +	((lvls) > (lvl) ? EARLY_ENTRIES(lvl, vstart, vend) + (add) : 0)
>>  
>>  #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
>>  	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
>> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
>> index a9136cc551cc..3c544edc3968 100644
>> --- a/arch/arm64/include/asm/pgtable-hwdef.h
>> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
>> @@ -7,40 +7,43 @@
>>  
>>  #include <asm/memory.h>
>>  
>> +#define PTDESC_ORDER 3
>> +
>>  /*
>>   * Number of page-table levels required to address 'va_bits' wide
>>   * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
>> - * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
>> + * bits with (PAGE_SHIFT - PTDESC_ORDER) bits at each page table level. Hence:
>>   *
>> - *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
>> + *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTDESC_ORDER))
>>   *
>>   * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
>>   *
>>   * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
>>   * due to build issues. So we open code DIV_ROUND_UP here:
>>   *
>> - *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
>> + *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTDESC_ORDER) - 1) / (PAGE_SHIFT - PTDESC_ORDER))
>>   *
>>   * which gets simplified as :
>>   */
>> -#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
>> +#define ARM64_HW_PGTABLE_LEVELS(va_bits) \
>> +	(((va_bits) - PTDESC_ORDER - 1) / (PAGE_SHIFT - PTDESC_ORDER))
>>  
>>  /*
>>   * Size mapped by an entry at level n ( -1 <= n <= 3)
>> - * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
>> + * We map (PAGE_SHIFT - PTDESC_ORDER) at all translation levels and PAGE_SHIFT bits
>>   * in the final page. The maximum number of translation levels supported by
>>   * the architecture is 5. Hence, starting at level n, we have further
>>   * ((4 - n) - 1) levels of translation excluding the offset within the page.
>>   * So, the total number of bits mapped by an entry at level n is :
>>   *
>> - *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
>> + *  ((4 - n) - 1) * (PAGE_SHIFT - PTDESC_ORDER) + PAGE_SHIFT
>>   *
>>   * Rearranging it a bit we get :
>> - *   (4 - n) * (PAGE_SHIFT - 3) + 3
>> + *   (4 - n) * (PAGE_SHIFT - PTDESC_ORDER) + PTDESC_ORDER
>>   */
>> -#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
>> +#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - PTDESC_ORDER) * (4 - (n)) + PTDESC_ORDER)
>>  
>> -#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>>  
>>  /*
>>   * PMD_SHIFT determines the size a level 2 page table entry can map.
>> @@ -49,7 +52,7 @@
>>  #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
>>  #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
>>  #define PMD_MASK		(~(PMD_SIZE-1))
>> -#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>>  #endif
>>  
>>  /*
>> @@ -59,14 +62,14 @@
>>  #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
>>  #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
>>  #define PUD_MASK		(~(PUD_SIZE-1))
>> -#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>>  #endif
>>  
>>  #if CONFIG_PGTABLE_LEVELS > 4
>>  #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
>>  #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
>>  #define P4D_MASK		(~(P4D_SIZE-1))
>> -#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>>  #endif
>>  
>>  /*
>> diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
>> index 2b69e3beeef8..f74335e13929 100644
>> --- a/arch/arm64/kernel/pi/map_range.c
>> +++ b/arch/arm64/kernel/pi/map_range.c
>> @@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
>>  {
>>  	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
>>  	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
>> -	int lshift = (3 - level) * (PAGE_SHIFT - 3);
>> +	int lshift = (3 - level) * (PAGE_SHIFT - PTDESC_ORDER);
>>  	u64 lmask = (PAGE_SIZE << lshift) - 1;
>>  
>>  	start	&= PAGE_MASK;
>> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
>> index b65a29440a0c..211821f80571 100644
>> --- a/arch/arm64/mm/kasan_init.c
>> +++ b/arch/arm64/mm/kasan_init.c
>> @@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
>>   */
>>  static bool __init root_level_aligned(u64 addr)
>>  {
>> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
>> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTDESC_ORDER);
>>  
>>  	return (addr % (PAGE_SIZE << shift)) == 0;
>>  }
>> @@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
>>  	 */
>>  	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
>>  							: vabits_actual;
>> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
>> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTDESC_ORDER);
>>  
>>  	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
>>  }
>> @@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
>>   */
>>  static int __init next_level_idx(u64 addr)
>>  {
>> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
>> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTDESC_ORDER);
>>  
>>  	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
>>  }
>> -- 
>> 2.25.1
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68188aa1-8f80-4f91-beb5-9ddb0129a490%40arm.com.
