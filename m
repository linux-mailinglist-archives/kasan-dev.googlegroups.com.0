Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQ5HW75QKGQEF6HRAFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 42EE62785B5
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:25:56 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id t3sf1126745ood.7
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:25:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601033155; cv=pass;
        d=google.com; s=arc-20160816;
        b=KJiPjw1uK3qtbM8eGbqdXBIE5Ooqwn8GUakCyhmG3UNALzmwtKnkJPW2dq3s0YKZML
         FyWcxywrqWKN7m18oP0iVPpXMOf0ir4IJXcDVT8hycqGo08Kd4lYckBIV8g7aa3KmMa/
         BqGHAGv5v0af410g99kLpuDHmR9X3w8KjaK3OyBTlU2YJB5scxJaX6yr6nnKA1eNhy3n
         hVViLTCIyc5iT/vR+cw16DmmZe9GGy2QpyMm7spAmodohus7MTNwV7Lk0vpN7cp8xJu+
         kOTaWNd/wDJ3djEUX7rcGNHOrORE1Sq1AwTn14edrutcqQ5covkyXAjhpbHWXC111e2/
         zWsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Qb1yNl6mau3TSHdlp/u2tsB2OpsD3KZ9V7AwpcFQfds=;
        b=g2Na6eQGa68d5fs3rG31lUc8Nn1GDW/qmoHgi4YqFHQumWtXNK0DsybxOYipmurMFf
         iuzQXgIacNHyPHpNmC3mL3Y2Y8ljnvbTLxw0sL+f8zz+BBt6XqBG/yV5aBvZIzHVoMAx
         GsKsUz9bV5UR5iE4ZmUDMO/L7tMTwxV83LBjEfE3I4GEygfpqxuwSp1tx259knCnO4U3
         rb0ZeiOtFQzSC80Fo/snHqlUT5kPZonDqGpMh7p16MvU1gqVMyha5D066cddiRGgb0Rs
         Q3rS3qcCirf8d0cAULHV5c5IH7uJKm/Hs4raNGAeTB1cXyLsBxJ0Yw+pUZb650V9+iNp
         jIig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qb1yNl6mau3TSHdlp/u2tsB2OpsD3KZ9V7AwpcFQfds=;
        b=ir4EVL84ArwrhkwFEEcxqC0ySf33fQ+8bcJ2VWIOAJCsiiW6ERCtL7CGUFD4hFdwKf
         QMk4e/eXgzWlEi351uHnh89yYiN9oxihl7cjSk1o5OUFnV/QDXtwTY0OJro9dt/VQt9d
         ZjmO4yjmOKW+dlSZGNK82x10oZNZAVF0/5VSMliiMUEsGJFm4IiADVpZ/rwUVG1SMVAz
         vywnWaS9CPI0L0ZZsjZkV7eFxb5IKTDlfCjLd7xbb19tM89wcjIW7YeFs/c8d1YzdkCP
         P9TCVJastvCs7mDmupQQLSgXDil5+9+Zk+PTPn1T0geEVW8Zol/pfflBRyZ4xbL8y4iW
         xZSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qb1yNl6mau3TSHdlp/u2tsB2OpsD3KZ9V7AwpcFQfds=;
        b=ffA1tMNq8Qhxao/mW3Yb1TrVAd7agk0cZ9XjJx9fArJupHn4E6nSmSfJ+TH+Px9OWq
         q41eemCeqR38sgrsH+Nc125i7MlqyNngxAY66osx+qN0a6tkkvaT2odtDkQTqVggk0TM
         5Lmi56q9tSKu06tfmX0IcZw5E/xvK+TqMJvK8T0hTvd+GKDUOuF88kCAvBQg5NCKxM7E
         B0WBEdBOT3ELK5+kSbSZEjF4WVdoYkQBS2J/LFBXq+tuhey3xhfwseKdjDAilnpA5erg
         iVBk4awl6GYeGZj2LaTlLFZpCtGNHWel9doHwtlcOVK6bvefK7eH4HK7HieANTF1VZB0
         xmdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530j47fWd8gh//5zdg6FQPQe47CU7hXq96HOea+opT60KOv5pwln
	1iXD3Jbu/4MZBHLlmBgGptU=
X-Google-Smtp-Source: ABdhPJycRPKptBKbwthdLiBj9jYBC3y9skRJvcEDJCKcQp42UY+NUhq355UHqz7yoUgxeDq1qO+DLQ==
X-Received: by 2002:a05:6830:22d7:: with SMTP id q23mr2556849otc.322.1601033155191;
        Fri, 25 Sep 2020 04:25:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:40e:: with SMTP id 14ls651232otc.4.gmail; Fri, 25 Sep
 2020 04:25:54 -0700 (PDT)
X-Received: by 2002:a05:6830:551:: with SMTP id l17mr2656614otb.61.1601033154835;
        Fri, 25 Sep 2020 04:25:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601033154; cv=none;
        d=google.com; s=arc-20160816;
        b=Mr0IEjCZMlEDpc0BM7ywCwAqz9O/O9zK5qbeAOzrVfOVaiEN60mgJTFbs7JEoCms2m
         cBtUwTFp6Pmr1/Ki4KxpIPwzCo0DhMbLzAU8EpgfAVsTkBu4WU8y2GqdKtjJdkC787tb
         z9EFRVEOnRzZIBdK2+NKpLtGAYodeHlB7padz0y0Vxf5O4HIDCt+5RG0DJo1k2Aulg0b
         jDTKB5KzmZY4HTbeQemeQHRsZGPTmcuszYqkO2aXEE2EZHTxKKDftyXOhNT+CuKHNR5b
         WunOz19+VUzlKH2pJYuih2yxYukmCFhewjHOFsCKjEA1TUo3qJqsLfT2ZacynmRZ/t4j
         Wprw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=1wrrWDeSY31bZNujIdL1xrlXj+hz6PG+j/HfBsPypbY=;
        b=qqLcrviWayOK4xVUCrwTt6At7M2eX/0zGBlzOW0c6BFbDX246cTGAbo2QMsHotacBY
         4TV3c/uA02TTAQVN4/PFa9T47Y/hrhrZspbhTqskOU2jfNvNQTP95L7JO7yMj3UKN9Xm
         cHa+eAtr109vQyJngThEYBIAvmk9TXbTVRb9s6TtI55dUa8P/IR6NgdDEGL65L8QAcUV
         /VlIF0HnRamIWSDHqZShckI3f7STYJntiGBkl1x7u/3VumhUkiFjjCkWUTaLH0YlnpPG
         /Nu9KEd6azbYlwWZQskC59i4261m9iUr/+mv0eFHeSDpMo5TjCU7E3CaDtWknLHzaOsy
         MApw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l19si114516oih.2.2020.09.25.04.25.54
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Sep 2020 04:25:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6DC1F101E;
	Fri, 25 Sep 2020 04:25:54 -0700 (PDT)
Received: from [10.37.12.53] (unknown [10.37.12.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0B7F63F70D;
	Fri, 25 Sep 2020 04:25:51 -0700 (PDT)
Subject: Re: [PATCH v3 24/39] arm64: mte: Add in-kernel MTE helpers
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
 <ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl@google.com>
 <20200925101558.GB4846@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <e41f2af1-f208-cc99-64f9-2311ad7d50bf@arm.com>
Date: Fri, 25 Sep 2020 12:28:24 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200925101558.GB4846@gaia>
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

On 9/25/20 11:15 AM, Catalin Marinas wrote:
> On Fri, Sep 25, 2020 at 12:50:31AM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
>> index 035003acfa87..bc0dc66a6a27 100644
>> --- a/arch/arm64/include/asm/esr.h
>> +++ b/arch/arm64/include/asm/esr.h
>> @@ -103,6 +103,7 @@
>>  #define ESR_ELx_FSC		(0x3F)
>>  #define ESR_ELx_FSC_TYPE	(0x3C)
>>  #define ESR_ELx_FSC_EXTABT	(0x10)
>> +#define ESR_ELx_FSC_MTE		(0x11)
>>  #define ESR_ELx_FSC_SERROR	(0x11)
>>  #define ESR_ELx_FSC_ACCESS	(0x08)
>>  #define ESR_ELx_FSC_FAULT	(0x04)
>> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
>> new file mode 100644
>> index 000000000000..b0f27de8de33
>> --- /dev/null
>> +++ b/arch/arm64/include/asm/mte-kasan.h
>> @@ -0,0 +1,60 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +/*
>> + * Copyright (C) 2020 ARM Ltd.
>> + */
>> +#ifndef __ASM_MTE_ASM_H
>> +#define __ASM_MTE_ASM_H
>> +
>> +#include <asm/compiler.h>
>> +
>> +#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
> 
> Can this not live in mte.h?
>

Yes, I can move it there in the next version.

>> +#define MTE_GRANULE_SIZE	UL(16)
>> +#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
>> +#define MTE_TAG_SHIFT		56
>> +#define MTE_TAG_SIZE		4
>> +#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
>> +#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
> 
> I'd still like these MTE_* macros in a separate mte-hwdef.h file. The
> only reason I see they were not in mte.h is because they need to be
> included in asm/cache.h. They are not KASAN specific.
> 

Ok, fine I will reintroduce it in the next version.

>> +
>> +#ifndef __ASSEMBLY__
>> +
>> +#include <linux/types.h>
>> +
>> +#ifdef CONFIG_ARM64_MTE
>> +
>> +static inline u8 mte_get_ptr_tag(void *ptr)
>> +{
>> +	u8 tag = (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
>> +
>> +	return tag;
>> +}
> 
> So this returns the top 8 bits of the address (i.e. no masking with
> MTE_TAG_MASK). Fine by me.
> 
>> +
>> +u8 mte_get_mem_tag(void *addr);
>> +u8 mte_get_random_tag(void);
>> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>> +
>> +#else /* CONFIG_ARM64_MTE */
>> +
>> +static inline u8 mte_get_ptr_tag(void *ptr)
>> +{
>> +	return 0xFF;
>> +}
>> +
>> +static inline u8 mte_get_mem_tag(void *addr)
>> +{
>> +	return 0xFF;
>> +}
>> +static inline u8 mte_get_random_tag(void)
>> +{
>> +	return 0xFF;
>> +}
>> +static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>> +{
>> +	return addr;
>> +}
> 
> Maybe these can stay in mte-kasan.h, although they are not a direct
> interface for KASAN AFAICT (the arch_* equivalent are defined in
> asm/memory.h. If there's no good reason, we could move them to mte.h.
>

This is here because it is not a direct interface as you noticed. I tried to
keep the separation (even if it I have something to fix based on your comment
below ;)).

The other kasan implementation define the arch_* indirection in asm/memory.h in
every architecture. I think maintaining the design is the best way to non create
confusion.

>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 1c99fcadb58c..3a2bf3ccb26c 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -5,14 +5,13 @@
>>  #ifndef __ASM_MTE_H
>>  #define __ASM_MTE_H
>>  
>> -#define MTE_GRANULE_SIZE	UL(16)
>> -#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
>> -#define MTE_TAG_SHIFT		56
>> -#define MTE_TAG_SIZE		4
>> +#include <asm/mte-kasan.h>
>>  
>>  #ifndef __ASSEMBLY__
>>  
>> +#include <linux/bitfield.h>
>>  #include <linux/page-flags.h>
>> +#include <linux/types.h>
>>  
>>  #include <asm/pgtable-types.h>
>>  
>> @@ -45,7 +44,9 @@ long get_mte_ctrl(struct task_struct *task);
>>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>>  			 unsigned long addr, unsigned long data);
>>  
>> -#else
>> +void mte_assign_mem_tag_range(void *addr, size_t size);
> 
> So mte_set_mem_tag_range() is KASAN specific but
> mte_assign_mem_tag_range() is not. Slightly confusing.
> 

mte_assign_mem_tag_range() is the internal function implemented in assembler
which is not used directly by KASAN. Is it the name that you find confusing? Do
you have a better proposal?

>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 52a0638ed967..833b63fdd5e2 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -13,8 +13,10 @@
>>  #include <linux/swap.h>
>>  #include <linux/swapops.h>
>>  #include <linux/thread_info.h>
>> +#include <linux/types.h>
>>  #include <linux/uio.h>
>>  
>> +#include <asm/barrier.h>
>>  #include <asm/cpufeature.h>
>>  #include <asm/mte.h>
>>  #include <asm/ptrace.h>
>> @@ -72,6 +74,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
>>  	return ret;
>>  }
>>  
>> +u8 mte_get_mem_tag(void *addr)
>> +{
>> +	if (!system_supports_mte())
>> +		return 0xFF;
>> +
>> +	asm volatile(__MTE_PREAMBLE "ldg %0, [%0]"
>> +		    : "+r" (addr));
> 
> Nitpick: do we need volatile or plain asm would do?
> 

No we clearly don't anymore :) I will remove it in the next iteration.

> I wonder whether we'd need the "memory" clobber. I don't see how this
> would fail though, maybe later on with stack tagging if the compiler
> writes tags behind our back.
> 

As you said, I do not see how this can fail either. We can be overcautious
though here and add a comment that the clobber has been added in prevision of
stack tagging.

>> +
>> +	return 0xF0 | mte_get_ptr_tag(addr);
> 
> Since mte_get_ptr_tag() returns the top byte of the address, we don't
> need the additional 0xF0 or'ing. LDG only sets bits 59:56.
> 

Yes, this can clearly go away.

>> +}
>> +
>> +u8 mte_get_random_tag(void)
>> +{
>> +	void *addr;
>> +
>> +	if (!system_supports_mte())
>> +		return 0xFF;
>> +
>> +	asm volatile(__MTE_PREAMBLE "irg %0, %0"
>> +		    : "+r" (addr));
>> +
>> +	return 0xF0 | mte_get_ptr_tag(addr);
> 
> Same here.
> 

Agreed.

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
> 
> Doesn't the address need to be aligned as well?
> 

Yes, we need an extra WARN_ON here. I will add it in the next version.

>> +
>> +	tag = 0xF0 | tag;
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
>> index 03ca6d8b8670..aa0ab01252fe 100644
>> --- a/arch/arm64/lib/mte.S
>> +++ b/arch/arm64/lib/mte.S
>> @@ -149,3 +149,22 @@ SYM_FUNC_START(mte_restore_page_tags)
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
> 
> Doesn't the address need to be aligned as well?
> 

The comment can be extended.

>> + */
>> +SYM_FUNC_START(mte_assign_mem_tag_range)
>> +	/* if (src == NULL) return; */
>> +	cbz	x0, 2f
>> +	/* if (size == 0) return; */
>> +	cbz	x1, 2f
> 
> I find these checks unnecessary, as I said a couple of times before,
> just document the function pre-conditions. They are also incomplete
> (i.e. you check for NULL but not alignment).
> 

I thought we agreed to harden the code further, based on [1]. Maybe I
misunderstood. I am going to remove them and extend the comment in the next version.

[1]
https://lore.kernel.org/linux-arm-kernel/921c4ed0-b5b5-bc01-5418-c52d80f1af59@arm.com/

>> +1:	stg	x0, [x0]
>> +	add	x0, x0, #MTE_GRANULE_SIZE
>> +	subs	x1, x1, #MTE_GRANULE_SIZE
>> +	b.gt	1b
>> +2:	ret
>> +SYM_FUNC_END(mte_assign_mem_tag_range)
>> -- 
>> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e41f2af1-f208-cc99-64f9-2311ad7d50bf%40arm.com.
