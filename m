Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHEWT35AKGQEITSF3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD55E2543BE
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:29:49 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id c6sf858706uac.12
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:29:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598524188; cv=pass;
        d=google.com; s=arc-20160816;
        b=s+WOOxxrOAde1vimVKwZcWT2/+PvRd+T7gwIvQjYcpmh/VcKFZjAF0KpDNeXg1Lxe5
         g0mmQ+N42xj8Iw0jqiXotT+Zs8pscHAQWzl5Tso4oHvPc74x93p+EvIaqEML6YodxtT/
         OWN7zhEJ2OSndEM5mck2wVZenqsEuigN3GBY6fzIL4/D9f7TmlZbnOYH4loVQk9pOnO7
         //4womp43AWACTThE177fGGBHowYzJ7sslrjKljjy03BZEIP0BMtnIAlziSa6xlGTLxi
         /dTm4cXlxV8mHB3RWGA0dB6em3Bv7rtf5LFHXJz8t1syCP5MUKv7WQzX9AZ/czsDjg1h
         U57g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NnqHkoJiKYImyF7aQb3WFt1mmAxyUrkeFK6KIHSM2G4=;
        b=juZUuA5yZnozHdmTKcdVtZvgb+LfsILjK+Jcck5dw+L2+wOZpUPxb15Nf5rPsT87x9
         UpkGyXrsVRKtRxymAyEIDX/sKOZuVuDySsinsMm2sLjL4bUz7gxLRp/4PR1rmirpaKKo
         imEmbBX5r+zndwS667x0eSaePo15Sw5uylgBW0tDPJNUwddMxg7S8r0N93b40+xopl5S
         3aXUwMLV8xA/8wv7v8x57T/oNv0K0jbh3DPTMuC3z/VaekUk6VNDG49Ci0P9QN7KHs2a
         s7YAa9A6orWiTd1TFJazJwTWD9+AxUWfXg48gemsI4yE5w+v7tNRKJ1C5G3mf1hyDutw
         euNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NnqHkoJiKYImyF7aQb3WFt1mmAxyUrkeFK6KIHSM2G4=;
        b=F6Tz91pb2pbnNgK6BNWs2/lvhL06GEkHZU4BTqtEn5xgdxPLJREhmDmmEQlWMN9Dst
         HnYqySLuLH3NdpEDE0NNT450kHsN25TPqwuNNtMSQ2fEmZ0kR4DWwROR8Uqkxk2jK0Af
         WALN9rMSIzUFN7PmqIhokdNqKjNF1THHSdSi2nIW/4mlESXcbPqRecilQ4eXR4nb6r7J
         D84l455mcOZpH/Kofl4tZUB0F5UmoPNV4cTje09Ex6EveBvJmZNdnfALMQIrCVowGtMu
         7B9LENFC+OJYWjjhIScqaHAZRGjVhH5QIZUcB+isriYYg1Kf7NKWKvpoIle2jdq/htMA
         P9tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NnqHkoJiKYImyF7aQb3WFt1mmAxyUrkeFK6KIHSM2G4=;
        b=ZE4lsY+8h5IQyBORuec9nMnir7eQBB/enMQymysfWnmxRldu0nkfjFefoulb63z/Yp
         RqYqqIyNT4P7cPUHpmWuajOdxqUCE12Dcb+xgmH5jXL1sRbFuM1wYpcXI9sGsHiJ6Oop
         Q2th7HBSYp6vKl6FbGz6n6VAmdGeMXDF8+aM6eTjOb+cwAX7B0YLUdpgk5ZEGbkXq1uN
         aHFiVteceCiHpiOGchT3bYcAcpRtdZODvKCYCRrS4UavYG8yNFdoXNdk8bpp4FNPpIVJ
         3sQW7LjoUjSY25pfecRvWVbMianp3zEZxqjyi0oZgfvmfNxW4yGWIUpVlVEoixT3UXUa
         /muA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532H50k9RJOAdWXk+UsPhD+rNP0jRxBPTpGKKa84FaHs8JV8j/34
	DZVgtOVMqrXJG6D94RXODqw=
X-Google-Smtp-Source: ABdhPJzNLPCwfQUsp5p/76nvlmAKvzgpAX08X9YTt978hL4BlqHrqBrZJoy4ux+GTnN8430Xhaurpw==
X-Received: by 2002:a1f:9e8d:: with SMTP id h135mr11641704vke.4.1598524188269;
        Thu, 27 Aug 2020 03:29:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f28f:: with SMTP id m15ls208093vsk.0.gmail; Thu, 27 Aug
 2020 03:29:47 -0700 (PDT)
X-Received: by 2002:a67:f502:: with SMTP id u2mr12648654vsn.111.1598524187850;
        Thu, 27 Aug 2020 03:29:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598524187; cv=none;
        d=google.com; s=arc-20160816;
        b=cZvOmDSwTCP+A9Vt2natpaCsvDgRfR1A1N2qASSJtBgp7yP4T77Ucbqelf1QZ4p6+k
         +spWlj27bsrh96lCpLS7DR+lgHkEu+3dnIlkIpL7eyqqwTbcxmSc1WT7CjkSqcwWdU7Q
         uJQTLdiGJAXxk1ixqJZcpyduQVgRbJaynnLapQHhJm5MCclRRHcWWL21lQJzCgDciLV7
         IWF/AqQc0Yw/85xZ9gpasNiGVJzaAWXuZhg7pq/STlARG+zERGKBTwD2jyh5NCuEzBpX
         LaB4DldQzbstZCK1lC9G1p29BtMyFEWWhd167ylsuOi97EEHsRdhkn5Obp9AcAURXuzM
         hIyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=8cQmyjOvGU5u6BVbet96EOYh3oZUq6V6zZxzgUQWprI=;
        b=jAZ/YEGGXXoV9bX+pYqulGzXu66+Pf8NchFDDkbXtTTco6AYSzOu2a57/DqQvjEt1d
         CACzYwtLVghYAeUOP0XfA6cmrLtb3dmjXAsBAGx9ykRLWjH051Ikc2zODGcB6IOE6n91
         5LQO3MxIQ6u1xkItFgUTw4m2jbC6RAmPW0sFCeKUk6FqWjK2u9I2MCvMv5XX7HGjfQPc
         uAhynRSf3n4NiuEPvOtnShF7k9SXXt3fQcfZHNYqcafZwhDakjqjejfxPfcAlTC9TKZI
         d6AWqWwChjvcC6y42y9osCyueax9YquL3OBAmTQG3DWBM0mgw6iEoHQyE+yq0s+MKj6h
         Crmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i3si84958vsm.1.2020.08.27.03.29.47
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 03:29:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 198D7101E;
	Thu, 27 Aug 2020 03:29:47 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C33C03F66B;
	Thu, 27 Aug 2020 03:29:43 -0700 (PDT)
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
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
 <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
 <20200827093808.GB29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <588f3812-c9d0-8dbe-fce2-1ea89f558bd2@arm.com>
Date: Thu, 27 Aug 2020 11:31:56 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827093808.GB29264@gaia>
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

Hi Catalin,

On 8/27/20 10:38 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 1c99fcadb58c..733be1cb5c95 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -5,14 +5,19 @@
>>  #ifndef __ASM_MTE_H
>>  #define __ASM_MTE_H
>>  
>> -#define MTE_GRANULE_SIZE	UL(16)
>> +#include <asm/mte_asm.h>
> 
> So the reason for this move is to include it in asm/cache.h. Fine by
> me but...
> 
>>  #define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
>>  #define MTE_TAG_SHIFT		56
>>  #define MTE_TAG_SIZE		4
>> +#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
>> +#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
> 
> ... I'd rather move all these definitions in a file with a more
> meaningful name like mte-def.h. The _asm implies being meant for .S
> files inclusion which isn't the case.
> 

mte-asm.h was originally called mte_helper.h hence it made sense to have these
defines here. But I agree with your proposal it makes things more readable and
it is in line with the rest of the arm64 code (e.g. page-def.h).

We should as well update the commit message accordingly.

>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index eb39504e390a..e2d708b4583d 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -72,6 +74,47 @@ int memcmp_pages(struct page *page1, struct page *page2)
>>  	return ret;
>>  }
>>  
>> +u8 mte_get_mem_tag(void *addr)
>> +{
>> +	if (system_supports_mte())
>> +		addr = mte_assign_valid_ptr_tag(addr);
> 
> The mte_assign_valid_ptr_tag() is slightly misleading. All it does is
> read the allocation tag from memory.
> 
> I also think this should be inline asm, possibly using alternatives.
> It's just an LDG instruction (and it saves us from having to invent a
> better function name).
> 

Yes, I agree, I implemented this code in the early days and never got around to
refactor it.

>> +
>> +	return 0xF0 | mte_get_ptr_tag(addr);
>> +}
>> +
>> +u8 mte_get_random_tag(void)
>> +{
>> +	u8 tag = 0xF;
>> +
>> +	if (system_supports_mte())
>> +		tag = mte_get_ptr_tag(mte_assign_random_ptr_tag(NULL));
> 
> Another alternative inline asm with an IRG instruction.
> 

As per above.

>> +
>> +	return 0xF0 | tag;
>> +}
>> +
>> +void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>> +{
>> +	void *ptr = addr;
>> +
>> +	if ((!system_supports_mte()) || (size == 0))
>> +		return addr;
>> +
>> +	tag = 0xF0 | (tag & 0xF);
>> +	ptr = (void *)__tag_set(ptr, tag);
>> +	size = ALIGN(size, MTE_GRANULE_SIZE);
> 
> I think aligning the size is dangerous. Can we instead turn it into a
> WARN_ON if not already aligned? At a quick look, the callers of
> kasan_{un,}poison_memory() already align the size.
> 

The size here is used only for tagging purposes and if we want to tag a
subgranule amount of memory we end up tagging the granule anyway. Why do you
think it can be dangerous?

Anyway I agree on the fact that is seems redundant, a WARN_ON here should be
sufficient.

>> +
>> +	mte_assign_mem_tag_range(ptr, size);
>> +
>> +	/*
>> +	 * mte_assign_mem_tag_range() can be invoked in a multi-threaded
>> +	 * context, ensure that tags are written in memory before the
>> +	 * reference is used.
>> +	 */
>> +	smp_wmb();
>> +
>> +	return ptr;
> 
> I'm not sure I understand the barrier here. It ensures the relative
> ordering of memory (or tag) accesses on a CPU as observed by other CPUs.
> While the first access here is setting the tag, I can't see what other
> access on _this_ CPU it is ordered with.
> 

You are right it can be removed. I was just overthinking here.

>> +}
>> +
>>  static void update_sctlr_el1_tcf0(u64 tcf0)
>>  {
>>  	/* ISB required for the kernel uaccess routines */
>> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
>> index 03ca6d8b8670..8c743540e32c 100644
>> --- a/arch/arm64/lib/mte.S
>> +++ b/arch/arm64/lib/mte.S
>> @@ -149,3 +149,44 @@ SYM_FUNC_START(mte_restore_page_tags)
>>  
>>  	ret
>>  SYM_FUNC_END(mte_restore_page_tags)
>> +
>> +/*
>> + * Assign pointer tag based on the allocation tag
>> + *   x0 - source pointer
>> + * Returns:
>> + *   x0 - pointer with the correct tag to access memory
>> + */
>> +SYM_FUNC_START(mte_assign_valid_ptr_tag)
>> +	ldg	x0, [x0]
>> +	ret
>> +SYM_FUNC_END(mte_assign_valid_ptr_tag)
>> +
>> +/*
>> + * Assign random pointer tag
>> + *   x0 - source pointer
>> + * Returns:
>> + *   x0 - pointer with a random tag
>> + */
>> +SYM_FUNC_START(mte_assign_random_ptr_tag)
>> +	irg	x0, x0
>> +	ret
>> +SYM_FUNC_END(mte_assign_random_ptr_tag)
> 
> As I said above, these two can be inline asm.
> 

Agreed.

>> +
>> +/*
>> + * Assign allocation tags for a region of memory based on the pointer tag
>> + *   x0 - source pointer
>> + *   x1 - size
>> + *
>> + * Note: size is expected to be MTE_GRANULE_SIZE aligned
>> + */
>> +SYM_FUNC_START(mte_assign_mem_tag_range)
>> +	/* if (src == NULL) return; */
>> +	cbz	x0, 2f
>> +	/* if (size == 0) return; */
> 
> You could skip the cbz here and just document that the size should be
> non-zero and aligned. The caller already takes care of this check.
>

I would prefer to keep the check here, unless there is a valid reason, since
allocate(0) is a viable option hence tag(x, 0) should be as well. The caller
takes care of it in one place, today, but I do not know where the API will be
used in future.

>> +	cbz	x1, 2f
>> +1:	stg	x0, [x0]
>> +	add	x0, x0, #MTE_GRANULE_SIZE
>> +	sub	x1, x1, #MTE_GRANULE_SIZE
>> +	cbnz	x1, 1b
>> +2:	ret
>> +SYM_FUNC_END(mte_assign_mem_tag_range)
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/588f3812-c9d0-8dbe-fce2-1ea89f558bd2%40arm.com.
