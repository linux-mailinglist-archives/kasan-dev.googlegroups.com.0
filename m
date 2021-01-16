Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMHLROAAMGQEXEFXNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B39A2F8D89
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 15:18:25 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id u6sf3467486uaq.3
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:18:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610806704; cv=pass;
        d=google.com; s=arc-20160816;
        b=ebTBqXdyhLjsuRhE1zgZyaGaWIi0ErYSLKiMEu+R05nUPCb4P9HLBfThG+qYNKd5a9
         F5VsN2GTzSH6uSkzzY8QdddJm2PNQzrUXJ94WXFlT52Eil/KXKlpfE4OIOrvHjAhxRja
         v3ldN3VK/MymUvYE06AuW+RAnUSxmOugh7Dl3lRalkFJw34GimBRca3tm9qToeyPNS6m
         W0tQ7qUMY08Ba8EdKbK5ZjFkeuafNCRZxxgQW1o6KF6R7cdic7K9nJJ88KPtpyRgmyaG
         +uL42nvRJWMPHZghTf4RdOcE4Qeq9wC1elM1hGHi4CTHHi4Di+Z7DIw8oXhHecBrqfLY
         NKbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=BrDdLYdvf+QjWy2JLYf5DWZFRx58dz7ciI14ERXVW+k=;
        b=VVQ0TqXBF5eldkhMFHdMPRY8oGzW/LagwBrakxARgwFLXtt7ii63pqfD2x58N6KtWD
         hIoUiQmyvuiTpDrzZi61gV95Xu7D5mtrpY92FVJxSZpKgsFrhWHKw2PtgB6JI1xt6rM/
         DdkEspGeqqwhKyQ9tPiXzGdQtnn11LMQbfEi39Q2HOScCe6NDXGqFYRaum4NmOlicEII
         yYbeuiuBBbYax7YVAJEmxU63cKiaacv9TYjU7SHTVqXmjM0TrRI4XzwNGOqziHmjU9m3
         yalf6ZrQ9Qo5KPzLN+M0oFA8ti81YMd6w11PTfVcFmnu/UC7dZ14wIS5uF8rIBL4B1ry
         aMow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BrDdLYdvf+QjWy2JLYf5DWZFRx58dz7ciI14ERXVW+k=;
        b=plVw/Wsws/D0MIJmwiINxYoZ6lB6xwQjNChOstfw8C7GIjCc7eXbVfM1m7lj07+OJY
         WiOy5s71wcPaDHk8XY2rm3LDVOu2aouhHry4sWnW5+atLVjSxo/GvHxvaxogRyxrYX2r
         zzz7ORiDsz2N7rkINGJ+cu7RgWnrXb+CIdQgb0t9YbBnV1C0pf+iadarGpuT6Rnxnf4r
         d+jyf0AMVmAW8I/NGUC68VoZW5Pc1r/r0EHZEwtBiKy/h3sOAiIsN2OuAKIfB69j19df
         Mz1bmzb4iQ5v/wd5h9lQ8Kjrpf7jOYd240K8BCYwc4ye20PA5AwAyimaSnYJJM6R7ely
         yWww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BrDdLYdvf+QjWy2JLYf5DWZFRx58dz7ciI14ERXVW+k=;
        b=DGf5CxwP4eLwYHKCzkNlwA8CZ9rJUMUrhrp+Dor6dJYl1/mHqMpG7+eyCvEnYlqS4X
         d4Yx4lPjwfc1KFWRErMc+W1InLAZyEdvCJb64m3TBZcXncjODths8xO0THm/4mQrQyoy
         QBFHOtnfITFG55KuSVrA14GTfDM3ZEFEcaptctJwI72wP5NCIyTHRMQm3+9ctnZeC6Kj
         rC+FjDnUAMvSnfuLDEmbRbNwY6SZKzbreyPbuKQyiwFtvWBYKzozxS0f1m+iSLoFQDmg
         SQU/uh7P/XuYmOb0jqFBXQKlERNAMa7g3fzBu5frcuvujPSbsLfUfUsNWXjFNGlc8b8t
         8l5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eyf2T+lhQz7LGpiiSZZ10HkFlesvmQYmdKuKiRs6/j8yMIa6u
	rIaE4uWU3E6CPkNra9eO2v0=
X-Google-Smtp-Source: ABdhPJxSFSK5sqQBU9E2bZgldNtArJA7qi9/8gD9WzCvYKC/MP9mI8DVxDHBKOth1sYQoKEsA8LJzQ==
X-Received: by 2002:ab0:242:: with SMTP id 60mr12782774uas.134.1610806704576;
        Sat, 16 Jan 2021 06:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:83c:: with SMTP id k28ls16035vsb.4.gmail; Sat, 16
 Jan 2021 06:18:24 -0800 (PST)
X-Received: by 2002:a67:ff12:: with SMTP id v18mr97077vsp.20.1610806704149;
        Sat, 16 Jan 2021 06:18:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610806704; cv=none;
        d=google.com; s=arc-20160816;
        b=nItLIoM9JQnSHa4GPVCqGzQyrlvqexuey3VUN8XOnw1eUtjhGpkUfAiHmB9tjx25bK
         sUwBro9ApsCSFRHt3RMkmJ1P/mkL+D6M/SPHSNMCFb5vFbzE9YtWSoQW681ZjttnFlrz
         VUAkwOuwHVKXCj8pGWDvFeYqM4w+C9sd+n9dmfLUVOztF2eLlva8sC9JHpwwVt0NjXJc
         CdD+fSxtwJdvOX5h1iV1TnYfV3PVahVOitN07pF213y6H65ASHjKpDtnE3ks35NIUMtI
         O+tdziGRQG+VSvxAv9FVqG4W8Pi6x/ARbrUhylJD5AAnyPOHRkRT6md/OlRvP9zPR35c
         igEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=qLUqcF8suA3M2PgMJQiYux2QNW8Y11Zf68wR2kKBo2o=;
        b=Ba9nwfw1Gtdd+2jpoYlhMVbdVkoHycg/I7/BFnVA2Z5hfV/v6bX39nCPWQsdYnfZis
         X1RHs4hmof9+F2n0pWdCnB7yLWIA0+lfXbJU5COxXk3Tqf+i5/LFRZNTrIpj3mTQv46J
         ixSCCn5aDgLPBV42NlDtKtEQOYQ/acCdFGCANO7BAonuK/tqHtKlfFm3B2+iaxQYfspt
         en2QLpEygU6Gr3+ZqsKy8KMj8iCBKlkb790qy8JgMwl0jZ362ZigIE6bdvQyHBVW21CO
         BmecxGmZu3MVcIIGX65Qf7nwuyLyUTFRdfzoXVcmrWADBkcI1q/eUlCYoYcnIGc2YeNh
         /3cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g3si935527vkl.1.2021.01.16.06.18.23
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Jan 2021 06:18:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 57E6712FC;
	Sat, 16 Jan 2021 06:18:23 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A19953F719;
	Sat, 16 Jan 2021 06:18:20 -0800 (PST)
Subject: Re: [PATCH v3 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-5-vincenzo.frascino@arm.com>
 <20210115154520.GD44111@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <4b1a5cdf-e1bf-3a7e-593f-0089cedbbc03@arm.com>
Date: Sat, 16 Jan 2021 14:22:08 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210115154520.GD44111@C02TD0UTHF1T.local>
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

Hi Mark,

On 1/15/21 3:45 PM, Mark Rutland wrote:
> On Fri, Jan 15, 2021 at 12:00:43PM +0000, Vincenzo Frascino wrote:
>> mte_assign_mem_tag_range() is called on production KASAN HW hot
>> paths. It makes sense to optimize it in an attempt to reduce the
>> overhead.
>>
>> Optimize mte_assign_mem_tag_range() based on the indications provided at
>> [1].
> 
> ... what exactly is the optimization?
> 
> I /think/ you're just trying to have it inlined, but you should mention
> that explicitly.
> 

Good point, I will change it in the next version. I used "Optimize" as a
continuation of the topic in the previous thread but you are right it is not
immediately obvious.

>>
>> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
>>  arch/arm64/lib/mte.S         | 15 ---------------
>>  2 files changed, 25 insertions(+), 16 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 1a715963d909..9730f2b07b79 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
>>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>>  			 unsigned long addr, unsigned long data);
>>  
>> -void mte_assign_mem_tag_range(void *addr, size_t size);
>> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>> +{
>> +	u64 _addr = (u64)addr;
>> +	u64 _end = _addr + size;
>> +
>> +	/*
>> +	 * This function must be invoked from an MTE enabled context.
>> +	 *
>> +	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
>> +	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
>> +	 */
>> +	do {
>> +		/*
>> +		 * 'asm volatile' is required to prevent the compiler to move
>> +		 * the statement outside of the loop.
>> +		 */
>> +		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
>> +			     :
>> +			     : "r" (_addr)
>> +			     : "memory");
>> +
>> +		_addr += MTE_GRANULE_SIZE;
>> +	} while (_addr < _end);
> 
> Is there any chance that this can be used for the last bytes of the
> virtual address space? This might need to change to `_addr == _end` if
> that is possible, otherwise it'll terminate early in that case.
> 

Theoretically it is a possibility. I will change the condition and add a note
for that.

>> +}
> 
> What does the code generation look like for this, relative to the
> assembly version?
> 

The assembly looks like this:

 390:   8b000022        add     x2, x1, x0
 394:   aa0003e1        mov     x1, x0
 398:   d9200821        stg     x1, [x1]
 39c:   91004021        add     x1, x1, #0x10
 3a0:   eb01005f        cmp     x2, x1
 3a4:   54ffffa8        b.hi    398 <mte_set_mem_tag_range+0x48>

You can see the handcrafted one below.

> Thanks,
> Mark.
> 
>> +
>>  
>>  #else /* CONFIG_ARM64_MTE */
>>  
>> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
>> index 9e1a12e10053..a0a650451510 100644
>> --- a/arch/arm64/lib/mte.S
>> +++ b/arch/arm64/lib/mte.S
>> @@ -150,18 +150,3 @@ SYM_FUNC_START(mte_restore_page_tags)
>>  	ret
>>  SYM_FUNC_END(mte_restore_page_tags)
>>  
>> -/*
>> - * Assign allocation tags for a region of memory based on the pointer tag
>> - *   x0 - source pointer
>> - *   x1 - size
>> - *
>> - * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
>> - * size must be non-zero and MTE_GRANULE_SIZE aligned.
>> - */
>> -SYM_FUNC_START(mte_assign_mem_tag_range)
>> -1:	stg	x0, [x0]
>> -	add	x0, x0, #MTE_GRANULE_SIZE
>> -	subs	x1, x1, #MTE_GRANULE_SIZE
>> -	b.gt	1b
>> -	ret
>> -SYM_FUNC_END(mte_assign_mem_tag_range)
>> -- 
>> 2.30.0
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4b1a5cdf-e1bf-3a7e-593f-0089cedbbc03%40arm.com.
