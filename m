Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZPARX5QKGQEI3SYDIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C46B26DDE2
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 16:19:19 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id z4sf1452835pgv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 07:19:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600352358; cv=pass;
        d=google.com; s=arc-20160816;
        b=IxHSUJk849xRzFn2ZnaIkpUQOFXsrmEHwRKqhasTp/Dnnla2co2GvVaT15yGi9l1Au
         VrzhykcuVbm3+5gL8D/vS4tOJbcBKI1IXZctT98x87AmnMO6QNv8IMr4jcwMHnD9HccF
         lJkKFh4lR/PvKggErfXUviM3jx2M//omUTcWUwwl3754yc6G/o2BSP0zIH7s5OwvthG/
         i6nS63WR+GoZJJDDFnS/r+vMPzNT32zt46R4FpOeU9xyX6cDyagYKCtXGrSEw2d1eCP5
         mI3j5iKqyStmdQOFtZPh2ZqumIwqqpOcvYzTN9aOml+P4AS9N60rISRNDkPyRknx3iGE
         GAVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=XRM2lHmU8M/znflVRTvJqyWqUex2wL2+b5M6SUbRCh8=;
        b=fm8Zb5Uh3We0uf6RXFByORGXw02uL8YEe5ix8FovrvnlI1BHAnfaNXq+vgZsaHvyVI
         JHDJQkRg0K/PO9JrtRMwjkR7nbJy14YUplM02lWWbhSniMZaqUuN/EKWX6wulJIGdC0M
         P+r79jdtCNkvKpwr4B5jdwX4vO/R7RHXxxIREbc/9hr+25TGITAMgB5EZRo0J25fw88E
         0Ffifsx1EHkOoNBhVQaXPBgdN5PBAInN/qgzwPa2VeOhn2wUg7+O6fAKZgjwUv9Qm89O
         5NFoEcj9rR9KJsUABYrQ1beY37uegeLD7pBxN2/M4QJ7PqNwoYAfa6le/q0SZq73m0Hu
         8nYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XRM2lHmU8M/znflVRTvJqyWqUex2wL2+b5M6SUbRCh8=;
        b=LqiNKXsEuvIAL9l/45F7z2uO2uBiAykl2S4gsySonIIjtdfJUy3eUVzm/dPL1EVdPk
         vqZSp0K5FAE7ldkffl4ekQvc7QSVT2ghU7L0bItf76YRdMHcNeaqMzKNqqtoCyMSZnlk
         09GPiDKg9gfYqMMAs3fKJ1YO3tNJIOaiCs7YOJmNfNRyiR3DbtFu4JlYuULJGpYeNc+O
         LuXPKPe13hItWWH/kZwxRgaqC55Vwml6zMGUXre7TnpfiK1eu1oBHUi3ygTCrfNStkjT
         EtGcY84U4Km/BKm0l/GpTvjahnM7jCqh4aXbghEgld19Fma94AGEXBgmjc+FsmTxB0xY
         +Tdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XRM2lHmU8M/znflVRTvJqyWqUex2wL2+b5M6SUbRCh8=;
        b=Cpxahik5PAglhDRWCIX5PfULhSj1uPjhk9dwX3C5kj+N6e5+2R+8BlfulfqkTwDtk5
         ViyxwQtWdkiTjDeIZyiYzVRIugrg81nmwlC12JPE8FtMEhGIJzloZjO6N4sPJjGVW/da
         GZZvbz0AUl6Ex4tIfWJNLc/gCzdEThR+zmb5MT53lxn2wukfjHV4861x7tnEVRknJKnk
         /HEN3Fj1CWpRwxG/RZ0EwdXZ1M+8i6wXszLdk/TUNDwylXtgbLlji0tLiIY49OsLNOH7
         GCQAo0HBJLxEvbA2EuiusBUGrdnEf6EHDwpjd/Y8wp+kg0JNusxy319VdPD00GSRlwUF
         +B2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308xaSAgrXeU4iHzdIjOFJnuS32gQ516eEF/6CbGnQ1DsYqwL3k
	OV1y1gqzlmQrPVzSs6Arw0Q=
X-Google-Smtp-Source: ABdhPJxTCGc1tKVXNmBB+USP8RDeSRZRpBhcCQ5muH9P8sr40HQdLsaKgZ1VA1LJoL8qX5c7sTZVPQ==
X-Received: by 2002:a17:90a:a787:: with SMTP id f7mr8618570pjq.103.1600352357770;
        Thu, 17 Sep 2020 07:19:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b4c:: with SMTP id g12ls1161568plt.7.gmail; Thu, 17
 Sep 2020 07:19:17 -0700 (PDT)
X-Received: by 2002:a17:902:c212:b029:d1:e629:92f4 with SMTP id 18-20020a170902c212b02900d1e62992f4mr11026192pll.75.1600352357036;
        Thu, 17 Sep 2020 07:19:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600352357; cv=none;
        d=google.com; s=arc-20160816;
        b=cMHKsdhOXxPB+yIvHEKwqAD5r7X+N3mWQG0HLZYkGLBS5yw+D2UsZzGE92y70PlIBJ
         s/DQmlRyLCEQLNXKH0xh7fksE+jTyrKApe/ChmtCn6Oj4bY8XDIOAguCnT9vL3b444g/
         T0eaOAN9NRakpREeNCCU6kOoygy+4NRC03q7kr01f36IdcUlyW084aylQWOnfY/YEOtx
         mHlbQNbhi0mt/97sxdB8snUjzyTloigPuyK0fGegdXOANh6JgVWb8haLYUO4eis9Jvy1
         VssSDkgtRSiKl6vDNrVxrFJ48+EG19gITOe5gUSgP8cETd9gZbYGHIO8Hdy/qWYldom9
         N2+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=VCaSOXDpuJO5DrVThAjjNFWPWNOGDMy+tKv5geGiBEs=;
        b=sarSIU+WOD9VW0qTfnDDB8d4mE2qEpubB5rnUu/M9iSeceS9u4xt0elnHCPaZKGkP9
         IhK4yRLdnOfZNZ4hxl189oStqJEs1DKTj2PXpNxmnq8FyC49drSfLu7xAkIIwffDamXB
         tuUZBtJwy7MBfyOrPcjuEORpf2r5/Os2m14d633tj0SIVVqoU6AAVoqSyngawlLlKZm6
         UX0ds4uUZikYo1E61gey+aX4p/ojUJ9la1eQ3AxCBNHXdOeIqwmikogCFSDupVDvBhqm
         s5nNKoiFTGhMnIJYKybytx92d3UZyc/MfpPNPdQdnQzj65rbHxtUKTL4HBQJVxBHRt2X
         99Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h5si348pfc.0.2020.09.17.07.19.16
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Sep 2020 07:19:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EBC1730E;
	Thu, 17 Sep 2020 07:19:15 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 95B3B3F718;
	Thu, 17 Sep 2020 07:19:13 -0700 (PDT)
Subject: Re: [PATCH v2 22/37] arm64: mte: Add in-kernel MTE helpers
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
References: <cover.1600204505.git.andreyknvl@google.com>
 <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
 <20200917134653.GB10662@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <7904f7c2-cf3b-315f-8885-e8709c232718@arm.com>
Date: Thu, 17 Sep 2020 15:21:41 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200917134653.GB10662@gaia>
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



On 9/17/20 2:46 PM, Catalin Marinas wrote:
> On Tue, Sep 15, 2020 at 11:16:04PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/include/asm/mte-helpers.h b/arch/arm64/include/asm/mte-helpers.h
>> new file mode 100644
>> index 000000000000..5dc2d443851b
>> --- /dev/null
>> +++ b/arch/arm64/include/asm/mte-helpers.h
>> @@ -0,0 +1,48 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +/*
>> + * Copyright (C) 2020 ARM Ltd.
>> + */
>> +#ifndef __ASM_MTE_ASM_H
>> +#define __ASM_MTE_ASM_H
>> +
>> +#define __MTE_PREAMBLE		".arch armv8.5-a\n.arch_extension memtag\n"
> 
> Because of how the .arch overrides a previous .arch, we should follow
> the ARM64_ASM_PREAMBLE introduced in commit 1764c3edc668 ("arm64: use a
> common .arch preamble for inline assembly"). The above should be
> something like:
> 
> #define __MTE_PREAMBLE	ARM64_ASM_PREAMBLE ".arch_extension memtag"
> 
> with the ARM64_ASM_PREAMBLE adjusted to armv8.5-a if available.

Good idea, I was not aware of commit 1764c3edc668. I will fix it accordingly.

> 
>> +#define MTE_GRANULE_SIZE	UL(16)
>> +#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
>> +#define MTE_TAG_SHIFT		56
>> +#define MTE_TAG_SIZE		4
>> +#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
>> +#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
> 
> In v1 I suggested we keep those definitions in mte-def.h (or
> mte-hwdef.h) so that they can be included in cache.h. Anything else
> should go in mte.h, I don't see the point of two headers for various MTE
> function prototypes.
> 

This is what I did in my patches I shared with Andrey. I suppose that since in
this version he introduced some functions that are needed in this file, he
reverted to the old name (mte-helper.h).

>> +
>> +#ifndef __ASSEMBLY__
>> +
>> +#include <linux/types.h>
>> +
>> +#ifdef CONFIG_ARM64_MTE
>> +
>> +#define mte_get_ptr_tag(ptr)	((u8)(((u64)(ptr)) >> MTE_TAG_SHIFT))
> 
> I wonder whether this could also be an inline function that takes a void
> *ptr.
> 
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 52a0638ed967..e238ffde2679 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -72,6 +74,52 @@ int memcmp_pages(struct page *page1, struct page *page2)
>>  	return ret;
>>  }
>>  
>> +u8 mte_get_mem_tag(void *addr)
>> +{
>> +	if (system_supports_mte())
>> +		asm volatile(ALTERNATIVE("ldr %0, [%0]",
>> +					 __MTE_PREAMBLE "ldg %0, [%0]",
>> +					 ARM64_MTE)
>> +			     : "+r" (addr));
> 
> This doesn't do what you think it does. LDG indeed reads the tag from
> memory but LDR loads the actual data at that address. Instead of the
> first LDR, you may want something like "mov %0, #0xf << 56" (and use
> some macros to avoid the hard-coded 56).
> 

The result of the load should never be used since it is meaningful only if
system_supports_mte(). It should be only required for compilation purposes.

Said that, I think I like more your solution hence I am going to adopt it.

>> +
>> +	return 0xF0 | mte_get_ptr_tag(addr);
>> +}
>> +
>> +u8 mte_get_random_tag(void)
>> +{
>> +	u8 tag = 0xF;
>> +	u64 addr = 0;
>> +
>> +	if (system_supports_mte()) {
>> +		asm volatile(ALTERNATIVE("add %0, %0, %0",
>> +					 __MTE_PREAMBLE "irg %0, %0",
>> +					 ARM64_MTE)
>> +			     : "+r" (addr));
> 
> What was the intention here? The first ADD doubles the pointer value and
> gets a tag out of it (possibly doubled as well, depends on the carry
> from bit 55). Better use something like "orr %0, %0, #0xf << 56".
>

Same as above but I will use the orr in the next version.

>> +
>> +		tag = mte_get_ptr_tag(addr);
>> +	}
>> +
>> +	return 0xF0 | tag;
> 
> This function return seems inconsistent with the previous one. I'd
> prefer the return line to be the same in both.
> 

The reason why it is different is that in this function extracting the tag from
the address makes sense only if irg is executed.

I can initialize addr to 0xf << 56 and make them the same.

>> +}
>> +
>> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>> +{
>> +	void *ptr = addr;
>> +
>> +	if ((!system_supports_mte()) || (size == 0))
>> +		return addr;
>> +
>> +	/* Make sure that size is aligned. */
>> +	WARN_ON(size & (MTE_GRANULE_SIZE - 1));
>> +
>> +	tag = 0xF0 | (tag & 0xF);
> 
> No point in tag & 0xf, the top nibble doesn't matter as you or 0xf0 in.
> 

Agree, will remove in the next version.

>> +	ptr = (void *)__tag_set(ptr, tag);
>> +
>> +	mte_assign_mem_tag_range(ptr, size);
>> +
>> +	return ptr;
>> +}
>> +
>>  static void update_sctlr_el1_tcf0(u64 tcf0)
>>  {
>>  	/* ISB required for the kernel uaccess routines */
>> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
>> index 03ca6d8b8670..cc2c3a378c00 100644
>> --- a/arch/arm64/lib/mte.S
>> +++ b/arch/arm64/lib/mte.S
>> @@ -149,3 +149,20 @@ SYM_FUNC_START(mte_restore_page_tags)
>>  
>>  	ret
>>  SYM_FUNC_END(mte_restore_page_tags)
>> +
>> +/*
>> + * Assign allocation tags for a region of memory based on the pointer tag
>> + *   x0 - source pointer
>> + *   x1 - size
>> + *
>> + * Note: size must be non-zero and MTE_GRANULE_SIZE aligned
>> + */
>> +SYM_FUNC_START(mte_assign_mem_tag_range)
>> +	/* if (src == NULL) return; */
>> +	cbz	x0, 2f
>> +1:	stg	x0, [x0]
>> +	add	x0, x0, #MTE_GRANULE_SIZE
>> +	sub	x1, x1, #MTE_GRANULE_SIZE
>> +	cbnz	x1, 1b
>> +2:	ret
>> +SYM_FUNC_END(mte_assign_mem_tag_range)
> 
> I thought Vincenzo agreed to my comments on the previous version w.r.t.
> the fist cbz and the last cbnz:
> 
> https://lore.kernel.org/linux-arm-kernel/921c4ed0-b5b5-bc01-5418-c52d80f1af59@arm.com/
> 

Ups, this is my fault, I just realized I missed to unstash this change. Will be
present in the next version.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7904f7c2-cf3b-315f-8885-e8709c232718%40arm.com.
