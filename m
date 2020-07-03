Return-Path: <kasan-dev+bncBC32535MUICBB7FZ7P3QKGQEHN4MYFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E954F2134DC
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 09:23:41 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id d79sf5451255vkf.11
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jul 2020 00:23:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593761021; cv=pass;
        d=google.com; s=arc-20160816;
        b=JG8I4XJtv3IdZvHR/f+RRAc/L1NK6PANRGs8Efb7H9xWYUizrAdJ8rsV180oFONxmr
         tgJ9P/Qxg2x1L6eI1D8LsD4RX3mVdz6mJo6766riH6XJiPrdfBx4egyBrBnPx2tc2whn
         clkG9voNVuUwygspeSWqjP5qEhAZf3uoWmkCVWcs3TmIQZY3Oarvzp8ByMA0yce2j4/g
         ocsK6eFqwVLzTO5Z32u5DwexCaLt6L6d8OJ2Z+qh9AJ+VjifMvus2MrHd4dKJltQmvSn
         XdFwoDHC6A2pwZ2CxF3swSiwWHGl3Z/c761B0NEOVXg8Y+DMtTBQXhqxWn1BK/KnjG10
         mHDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:autocrypt:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=XNxBwHYRZkKotF1UcDBFRVH4MbDdPZnUjM6w95DKXH4=;
        b=UcLKUowZJ86By3cOCZBwZTDcLa1p8ZCsPLH1fteKqjO5bA4YFlX3bJFrPbprq2MDrw
         1d1nGKtUjA2YjGEYo4+fmOaXiU1q7mhed1mHSQVaN4Qqeo1xz3TM0euTJUyin0wmgV6c
         Os75S940QEPrZBn49/DTQ/TjWf4CPV11OpIGGyoYcT1Njo8qUudPL+4HKI791GtZG15A
         yEDvEKgtCcU2vrZi+8iVhVPn8erVzw98tSG1rbQm4/xTUvmJIogTndytci1LIWHKnr5H
         0F8Z039psZC2vYUeQnXXtRm6sdtVxysXl9/OeRyzy6LPUlmauGk5V2vHgBBYRd5GWCXZ
         HLwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a5WFzLt7;
       spf=pass (google.com: domain of david@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XNxBwHYRZkKotF1UcDBFRVH4MbDdPZnUjM6w95DKXH4=;
        b=JAEJfKHX+jQikP7i3srChROEGvSfss4DDPGYzUo0n4SjLlqwWkqYNjPilixpv/sk24
         bYcLABtFGZoMumWKLZ2HUD66qthVCL58EeHLZpgCtn6Pt4H6j4qqlbWNro9HulnZwlMf
         WzIKXg+CRN0a+JGfeqjNHZuDerqa4e1NOGfUFvI04Go7wXbN+/BjmvbXI5CMRJlX/LGq
         Za1yZBVKwFuXKgjTutr8e9T1dIMOia9+t+HWhTGokFZawaanQ/8UMd0+Nnv6qOa75cJP
         U8t6HpwpYcNep9rETK1iwRXkrILvAPF2FLTwtprAJu3LOjUbex+suN2GxSq4Yfr6rPMG
         oJ2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XNxBwHYRZkKotF1UcDBFRVH4MbDdPZnUjM6w95DKXH4=;
        b=IlWfdxkafjQ4J7H8hPmjZcGOXCIDRGoDIKH3h5k2huqQ2UAFIMqpFvi4a/kxGYwkAT
         ej4kerT3hlwxzu3V5Dku6gH0LvqhglTXnit4XRp2AHygcN3IRH5s34fmYbCQXWwwsUly
         PHu7zDg1lCss41wvTOPWJ6p8K3DcnkF+TszrlXiBFdkL1TNvYIm0wlXPIQ03W5ylcvVI
         SiDsUy59rmHk6C6WJqO7aRcAS2CP9VjOOhT56oesjj2wjRVn4LBpk9hHnIym7dSFEJzZ
         SMpSA0Bx5EfzveTK3nB1zU2C5fMsCKmXW0+fACwM3ROsOEWUKs2lRjcXKhhB72o0h4Tx
         f3wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Hc146GbWH4VwzJSj0eiBnV+x3FUBDfgItOZfn2FXRsNIfHNbq
	/N0e2+dKsLFOfMAaKgjVS7Y=
X-Google-Smtp-Source: ABdhPJwr79gQ11EcP6k0YF5zzw8JDpeG5nFPjwZ7Ocjj4JV88wOUWtetm4mVylrRtS3fk0fpCnmpZA==
X-Received: by 2002:a05:6102:22e9:: with SMTP id b9mr26174262vsh.100.1593761020946;
        Fri, 03 Jul 2020 00:23:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d605:: with SMTP id n5ls1026228vsj.11.gmail; Fri, 03 Jul
 2020 00:23:40 -0700 (PDT)
X-Received: by 2002:a67:1086:: with SMTP id 128mr19807673vsq.0.1593761020445;
        Fri, 03 Jul 2020 00:23:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593761020; cv=none;
        d=google.com; s=arc-20160816;
        b=sOMF3s9jKzXMgU0+XmboaxnKH7Z9bPiPmfcISRLk01vg/1Nlr9E1kOpw+aKEr7oYkO
         stLJZ33FdL5XL90Y9IPon5iSbqkg7Ovz9AcSo2iSk1kzu9j3yDTI/Qhako3Raxt1wm9u
         /dw8ZBmx7PYrx72jGpEQWYpp2suKJgj5SZZOKpRepAcF7LpHASAd1uh4QN4WlMP9jsQO
         wTNipbpdrzPuLMQUXlTbN/iaQ8wsxFho13Zp669BxdHRm3wfTjiJ2ox0C0AczTaEFvQ8
         DiybHcmNaFpbr30EQKvdduOPJIoxiZzbAeiZ9KRkn3V4rwjQJ9nT4APQlm2TNMe8Eo0F
         H3vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:autocrypt:from:references
         :cc:to:subject:dkim-signature;
        bh=9IrB0nwoPQg3scxw1qShp/wCtwnU4uLcL7itN2Vnaqw=;
        b=gVIYqa6D0D7BND061gyJv0jwUpHPs2YFDcgLnD2e76SJH8cvfmI+RP1kL/JiWtdj2d
         6b0XwcFUybi0C5Sl5NoUPoTzr/B2cpiAUVuhP2aLjGrZauc3JiQouyqMRBhCMUcbVVMJ
         UC3ZCJByGT4DaGyqY3CCnb7xs57k14xwa+XfjbKMwRN8AQr7Pd6asawx2pMWjRxl7JmK
         UVHDQJh2QcG1XI6iYyqa6CE4LaerJHiFbr5+N/FqlhKzt9/X0KOy5dKi3AwILLZLRuRp
         XQYhMAseMjGSnSXfRfkqPMBWkHH2oTEAW+4q5BMI9IjiCkQa6CLEr1PiwlQymgij5hR8
         7R7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a5WFzLt7;
       spf=pass (google.com: domain of david@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id s7si211947vsm.0.2020.07.03.00.23.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Jul 2020 00:23:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-433-EbZGAn7VMRCA21lz1n8nmw-1; Fri, 03 Jul 2020 03:23:36 -0400
X-MC-Unique: EbZGAn7VMRCA21lz1n8nmw-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id EB035107ACF6;
	Fri,  3 Jul 2020 07:23:33 +0000 (UTC)
Received: from [10.36.114.0] (ovpn-114-0.ams2.redhat.com [10.36.114.0])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 1515010013D9;
	Fri,  3 Jul 2020 07:23:30 +0000 (UTC)
Subject: Re: [PATCH] mm: define pte_add_end for consistency
To: Wei Yang <richard.weiyang@linux.alibaba.com>
Cc: dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 akpm@linux-foundation.org, x86@kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
 <20200701021113.GA51306@L-31X9LVDL-1304.local>
 <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
 <20200701115441.GA4979@L-31X9LVDL-1304.local>
 <7562991b-c1e7-4037-a3f0-124acd0669b7@redhat.com>
 <20200703013435.GA11340@L-31X9LVDL-1304.local>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; prefer-encrypt=mutual; keydata=
 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
Organization: Red Hat GmbH
Message-ID: <14e6a073-0a8c-3827-4d6f-072d08fbd6cc@redhat.com>
Date: Fri, 3 Jul 2020 09:23:30 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <20200703013435.GA11340@L-31X9LVDL-1304.local>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=a5WFzLt7;
       spf=pass (google.com: domain of david@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 03.07.20 03:34, Wei Yang wrote:
> On Thu, Jul 02, 2020 at 06:28:19PM +0200, David Hildenbrand wrote:
>> On 01.07.20 13:54, Wei Yang wrote:
>>> On Wed, Jul 01, 2020 at 10:29:08AM +0200, David Hildenbrand wrote:
>>>> On 01.07.20 04:11, Wei Yang wrote:
>>>>> On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>>>>>> On 30.06.20 05:18, Wei Yang wrote:
>>>>>>> When walking page tables, we define several helpers to get the address of
>>>>>>> the next boundary. But we don't have one for pte level.
>>>>>>>
>>>>>>> Let's define it and consolidate the code in several places.
>>>>>>>
>>>>>>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>>>>>>> ---
>>>>>>>  arch/x86/mm/init_64.c   | 6 ++----
>>>>>>>  include/linux/pgtable.h | 7 +++++++
>>>>>>>  mm/kasan/init.c         | 4 +---
>>>>>>>  3 files changed, 10 insertions(+), 7 deletions(-)
>>>>>>>
>>>>>>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>>>>>>> index dbae185511cd..f902fbd17f27 100644
>>>>>>> --- a/arch/x86/mm/init_64.c
>>>>>>> +++ b/arch/x86/mm/init_64.c
>>>>>>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>>>>>>  
>>>>>>>  	pte = pte_start + pte_index(addr);
>>>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>>> -		if (next > end)
>>>>>>> -			next = end;
>>>>>>> +		next = pte_addr_end(addr, end);
>>>>>>>  
>>>>>>>  		if (!pte_present(*pte))
>>>>>>>  			continue;
>>>>>>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>>>>>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>>>>>>  
>>>>>>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>>>>>>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>>> +			next = pte_addr_end(addr, end);
>>>>>>>  			pmd = pmd_offset(pud, addr);
>>>>>>>  			if (pmd_none(*pmd))
>>>>>>>  				continue;
>>>>>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>>>>>> index 32b6c52d41b9..0de09c6c89d2 100644
>>>>>>> --- a/include/linux/pgtable.h
>>>>>>> +++ b/include/linux/pgtable.h
>>>>>>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>>>>>>  })
>>>>>>>  #endif
>>>>>>>  
>>>>>>> +#ifndef pte_addr_end
>>>>>>> +#define pte_addr_end(addr, end)						\
>>>>>>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>>>>>>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>>>>>>> +})
>>>>>>> +#endif
>>>>>>> +
>>>>>>>  /*
>>>>>>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>>>>>>   * and any p?d_bad entries - reporting the error before resetting to none.
>>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>>>> index fe6be0be1f76..89f748601f74 100644
>>>>>>> --- a/mm/kasan/init.c
>>>>>>> +++ b/mm/kasan/init.c
>>>>>>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>>>>>>  	unsigned long next;
>>>>>>>  
>>>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>>> -		if (next > end)
>>>>>>> -			next = end;
>>>>>>> +		next = pte_addr_end(addr, end);
>>>>>>>  
>>>>>>>  		if (!pte_present(*pte))
>>>>>>>  			continue;
>>>>>>>
>>>>>>
>>>>>> I'm not really a friend of this I have to say. We're simply iterating
>>>>>> over single pages, not much magic ....
>>>>>
>>>>> Hmm... yes, we are iterating on Page boundary, while we many have the case
>>>>> when addr or end is not PAGE_ALIGN.
>>>>
>>>> I really do wonder if not having page aligned addresses actually happens
>>>> in real life. Page tables operate on page granularity, and
>>>> adding/removing unaligned parts feels wrong ... and that's also why I
>>>> dislike such a helper.
>>>>
>>>> 1. kasan_add_zero_shadow()/kasan_remove_zero_shadow(). If I understand
>>>> the logic (WARN_ON()) correctly, we bail out in case we would ever end
>>>> up in such a scenario, where we would want to add/remove things not
>>>> aligned to PAGE_SIZE.
>>>>
>>>> 2. remove_pagetable()...->remove_pte_table()
>>>>
>>>> vmemmap_free() should never try to de-populate sub-pages. Even with
>>>> sub-section hot-add/remove (2MB / 512 pages), with valid struct page
>>>> sizes (56, 64, 72, 80), we always end up with full pages.
>>>>
>>>> kernel_physical_mapping_remove() is only called via
>>>> arch_remove_memory(). That will never remove unaligned parts.
>>>>
>>>
>>> I don't have a very clear mind now, while when you look into
>>> remove_pte_table(), it has two cases based on alignment of addr and next.
>>>
>>> If we always remove a page, the second case won't happen?
>>
>> So, the code talks about that the second case can only happen for
>> vmemmap, never for direct mappings.
>>
>> I don't see a way how this could ever happen with current page sizes,
>> even with sub-section hotadd (2MB). Maybe that is a legacy leftover or
>> was never relevant? Or I am missing something important, where we could
>> have sub-4k-page vmemmap data.
>>
> 
> I took a calculation on the sub-section page struct size, it is page size (4K)
> aligned. This means you are right, which we won't depopulate a sub-page.
> 
> And yes, I am not sure all those variants would fit this case. So I would like
> to leave as it now. How about your opinion?

I'd say we clean this up and protect it by WARN_ON_ONCE(). Then, it
won't need another round of investigation to find out that handling
sub-pages is irrelevant.

If you don't want to tackle this, I can have a look. Just let me know.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/14e6a073-0a8c-3827-4d6f-072d08fbd6cc%40redhat.com.
