Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHXSQD6AKGQEXN7S2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D94E2886BB
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 12:19:12 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id t15sf2771444otm.9
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 03:19:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602238751; cv=pass;
        d=google.com; s=arc-20160816;
        b=zesIjjO5dmz1U/C0itMKNwU5i7uHsLLCu3t23KW4Ix3H39LjQgmWYhaEuMd99aIWj6
         wtWEcem+dZsjGyEeyt4sWazOHztcJQAaY4qWNpjRUZDu58SZH7Pl1LgDnHCB+6eDexMY
         KVxnzZW5gCQ9Np+A962uazEF0eXOM/+16XvfYyKyEURB5DykMGm7HivjscwgAj1ZrM4H
         mB21q54ha3HiNUG6WTssyTNnqkk6TkfFJsW1EAX3+bdJnlbaW2vEGF8FNfOlyCMfFM8i
         TJfUOMLJrynuGNqUzPxeZVOfD2QhWmTi7uuM1xV3puXIBdRWvIBabClg0n2rb/VKOecU
         FfDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ndnwVEm11dP/v34UBuacnAvKRpGVRYKOIvWgzoRXrWM=;
        b=cO8nmdGkYXo4680Z6Wbi8Ml0COY/hsv71KSZzviBlWoQLb9Cq8I4s5aFuON0/DSdK2
         VmfvsYsFTp1lFkUCPj4SDrh/b4JRhdKtoGqOtLdDjP1YxjCv3gTIcPUqnIn+wTfqa5m4
         GKln8RrZU+/lsx9kn54vau/GFlfmtSRtfnhsF1Un3g78Yk2OiyeZVw117iEMaIO+tkye
         iSLxIw+bCXNwGmwiBpeLJMyHmNKJXNBoRi7XLIMPEqaSqTipWwJiIV58qv7/Hn8DHJx0
         JgoW+m4VMCFT1aHbCBrPEpqoF8Kl5OAVzoRLwSCzlYMxAyZJa6dJVDSMcJAHRyr2mL6h
         Ih8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ndnwVEm11dP/v34UBuacnAvKRpGVRYKOIvWgzoRXrWM=;
        b=YyuZiUI1ubEkiZOM7WtDAxI89zR893yyUZ+ZYxo2ppaqWOcy54whT3/JOLxMP2HLD5
         7jAlmvxKEMjjXbWwnzqnnvzYtm+g2UsNbhEi5qC+DfBnEUe2+6snZZsT9gnSlCnSRhHI
         2SpkMTpAOzMts9llry/ePag7JYtKLwa8E7GsI+F425+rRtvbKKygsrhJDs9zJRVcWmif
         QEau7N8a9twe9ire3tUTCbPIt6tdLRN/xrPk2F4ZXp/9YTsl9R13vb/g79fGqQhv658l
         jGn86hBCjGFJrV1N7KZewrrAPo1+Ct5NFdndvqUgcnEl1riqglRmT5GQmQiKAJE+hMoJ
         o6mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ndnwVEm11dP/v34UBuacnAvKRpGVRYKOIvWgzoRXrWM=;
        b=jH8TE0n0xa/FaspJamz0/FyOGzs4/ErR4ENldOOvOR+pQJiwpWs0a6+HWhuYjcv7xp
         ygoQF/uDNx6I/cg6tEBdI2mgwsi1JjkdadnDh46ZPQn6h/dwITpQt6O6vWi/Sq04Cv5j
         J1N4JIzoWfEb4mQSoxXDVhYp9O4f3bSfhlY4GLO2Ar9TYDW/+GpBxqFOFYY0eTude4kh
         W7ITsNVt4S4HZXjd2ZgXlpnXKO3p82fRnEJSCqKUYTXQQoRg+6w4oMfV/e2CYt7A/Tky
         JKZHAotI3tVpw0Agw34Dpgf2oL+qgnbcqgQmBA8zSJBf3y/OCqxc//aEtjmEH13pecfZ
         T5bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531g7BvHvVO8kdcL2Jh32XWmvmXaRZb8Wxh+YLO6QFPf/+gPWXjZ
	V4MD3AJj0GG5WEVo9zVSbOY=
X-Google-Smtp-Source: ABdhPJx1NIfbpAXRwx2NejipIbMD/JIK4y4FaQh5RF8ggp8eSB3n95b05g1nP4UfxGfkI+KiX0cVOQ==
X-Received: by 2002:a9d:3426:: with SMTP id v35mr8562614otb.364.1602238751026;
        Fri, 09 Oct 2020 03:19:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f0b:: with SMTP id u11ls2002469otg.3.gmail; Fri,
 09 Oct 2020 03:19:10 -0700 (PDT)
X-Received: by 2002:a9d:65d1:: with SMTP id z17mr8292913oth.79.1602238750737;
        Fri, 09 Oct 2020 03:19:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602238750; cv=none;
        d=google.com; s=arc-20160816;
        b=slrC9tfPwCnMyj68DMC0mwkQ1sU3EspdnfEyYbLZMdpLI+E6z41kQl6Mjn8JuWksX4
         OEXOuUkOlg2jqxH8zWkEEpDCeVmlrMqPBEeJMT0fJGUqTFP4PHTx2PM5PfFaK74lnckn
         Aw/W21IYEEo7SUv5SC6A/upP7xFIBMjzS/Tny9Jq6ZSkiakpE/7DigFzmjif7Ssn6TDB
         p1oJd6kOjLvMvoUVM5ZekqPAaspudOOwJ31d56Q4QKLT/Z71ztu3wZWVeMkG1Ycd3uDR
         ZY0WTBE9hNUkjB7n+hpJSBp00ooQ1+wH3khJz8HccaLmtYr+a9mHtaV7vXM1XVvXGqPi
         DSKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Trmgiyu5A1QKZbl6hfLFny6M2gop+zPmFdxUi+LzqgM=;
        b=Z7JVPWBXYSkyxFs/N4ztDcsut1BDfhD6fw0QQFcb5lAzegUcUFWAKkaEvGsAdkflVF
         J9YBNZWQkBLQINGu/1gjPQ0mCl7T7lVnCgDpQS52BP24/UqpCXkNrWqTA0lkfqHdStYz
         +tLwXPs/c6hCkxc4QpJxFuBYIBo1Oq2vM3H1GOG7fX6odNi8sdAU+0t559KHSfHEeQgA
         AU+0WaGtFZllQ6H7bvFOsdpMqLJLP0BYt/GSfC0q64Mo7Sxq/d14uRJzqdV4TIx6CEbp
         HqALauwY+IU/9i7SRL3GcKe5li/GRQehRWHixYyqmT2dyF6iY9u4HVbhzrdBX5s/tHym
         qkhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r6si1395394oth.4.2020.10.09.03.19.10
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Oct 2020 03:19:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 812C7D6E;
	Fri,  9 Oct 2020 03:19:10 -0700 (PDT)
Received: from [10.37.12.22] (unknown [10.37.12.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E973A3F66B;
	Fri,  9 Oct 2020 03:19:07 -0700 (PDT)
Subject: Re: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1601593784.git.andreyknvl@google.com>
 <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
 <20201002140652.GG7034@gaia> <1b2327ee-5f30-e412-7359-32a7a38b4c8d@arm.com>
 <20201009081111.GA23638@gaia> <106f8670-3dd0-70ad-91ac-4f419585df50@arm.com>
 <20201009101643.GG23638@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c1b9abaf-bd3b-c51a-6d5d-600f3b2c2386@arm.com>
Date: Fri, 9 Oct 2020 11:21:49 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201009101643.GG23638@gaia>
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



On 10/9/20 11:16 AM, Catalin Marinas wrote:
> On Fri, Oct 09, 2020 at 10:56:02AM +0100, Vincenzo Frascino wrote:
>> On 10/9/20 9:11 AM, Catalin Marinas wrote:
>>> On Thu, Oct 08, 2020 at 07:24:12PM +0100, Vincenzo Frascino wrote:
>>>> On 10/2/20 3:06 PM, Catalin Marinas wrote:
>>>>> On Fri, Oct 02, 2020 at 01:10:30AM +0200, Andrey Konovalov wrote:
>>>>>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>>>>>> index 7c67ac6f08df..d1847f29f59b 100644
>>>>>> --- a/arch/arm64/kernel/mte.c
>>>>>> +++ b/arch/arm64/kernel/mte.c
>>>>>> @@ -23,6 +23,8 @@
>>>>>>  #include <asm/ptrace.h>
>>>>>>  #include <asm/sysreg.h>
>>>>>>  
>>>>>> +u64 gcr_kernel_excl __ro_after_init;
>>>>>> +
>>>>>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>>>>>  {
>>>>>>  	pte_t old_pte = READ_ONCE(*ptep);
>>>>>> @@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>>>>>  	return ptr;
>>>>>>  }
>>>>>>  
>>>>>> +void mte_init_tags(u64 max_tag)
>>>>>> +{
>>>>>> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
>>>>>
>>>>> Nitpick: it's not obvious that MTE_TAG_MAX is a mask, so better write
>>>>> this as GENMASK(min(max_tag, MTE_TAG_MAX), 0).
>>>>
>>>> The two things do not seem equivalent because the format of the tags in KASAN is
>>>> 0xFF and in MTE is 0xF, hence if extract the minimum whatever is the tag passed
>>>> by KASAN it will always be MTE_TAG_MAX.
>>>>
>>>> To make it cleaner I propose: GENMASK(FIELD_GET(MTE_TAG_MAX, max_tag), 0);
>>>
>>> I don't think that's any clearer since FIELD_GET still assumes that
>>> MTE_TAG_MAX is a mask. I think it's better to add a comment on why this
>>> is needed, as you explained above that the KASAN tags go to 0xff.
>>>
>>> If you want to get rid of MTE_TAG_MAX altogether, just do a
>>>
>>> 	max_tag &= (1 << MAX_TAG_SIZE) - 1;
>>>
>>> before setting incl (a comment is still useful).
>>>
>>
>> Agree, but still think we should use FIELD_GET here since it is common language
>> in the kernel.
>>
>> How about we get rid of MTE_TAG_MAX and we do something like:
>>
>> GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT, max_tag), 0);
> 
> It works for me and you can drop the MTE_TAG_MAX definition (I think
> it's only used here).
> 

Yes indeed, I will drop it.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c1b9abaf-bd3b-c51a-6d5d-600f3b2c2386%40arm.com.
