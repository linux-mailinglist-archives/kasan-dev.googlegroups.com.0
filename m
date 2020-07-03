Return-Path: <kasan-dev+bncBAABB3O27P3QKGQED5F62AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DA18213671
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 10:33:50 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id k13sf21339707ilh.23
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jul 2020 01:33:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593765229; cv=pass;
        d=google.com; s=arc-20160816;
        b=ukzer41rZohI9zSpL80duLmVFlTk/s7vPZJxj81oTQ67gLdJ6w/7gjozmj1FRmk3ka
         d8USANHnAAlYSxzCRxHhzHbIlTNx35mQZa3waUzMtMgHSvs+oV3zEegNzJxIXMbZkS6B
         Fb+BgPE+0fCauZqQQlqDJhnkOUEoX3rZ+lNXs8WgaokGeOIy0+Mmj6Q7nwmQ9s8ej7D5
         ZKbuMImR5fC7duHzZghEjiianGmjqGMyN08jkCex5tVeP/fI0R3QCovUgnfx3tn7p338
         Ogh79v1SBlNtwOtZ0xAV7b08eeS2y88CF0iRs0qshgv+leJ818eOw9WhP53oF04r9kSh
         X9Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=H1cy3PZAjl4lbZE9dV7hFfA6eFpck5j234TR1XiQXOg=;
        b=Dd3KLeZgc3Ti800Ef8Ng9hnUsLireqh+2fxp9/VGHmnqYLOFqKRWFXQUKeMBWf991Z
         lcTpP9FqlxEByBzvLr+HfzizGjK/dUjfkMFob1ahBRXkO48gqvNMhW6rYVvWLPIhb9wZ
         V5a0Z4a9dRzBQl1Os7FWjopgf58PEjdVHtnXr8nj6aXu/PK56p7Y64XUzvNV7U5/d0I+
         jS36SNJVl5znPAuueEyhx/bFZGZPzKRJ7VgE0AbgvxwW0ftZcQRHS1mJZ3p3fmKsuqNV
         JOfo6WxlZBkzsiILZVQzbqjNeUFPiBVIblCpaPxkjX3/nSPPo2dxF3hholSNA72FdHXp
         chkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H1cy3PZAjl4lbZE9dV7hFfA6eFpck5j234TR1XiQXOg=;
        b=qqYEU3eaId5vz7ziht1om3ilpWAEG7fREam4PvFwTFZRlKVtUKJRFKKR65+PDEPVES
         s8S4JdCmvrZOalBxfwtI7EbCWv13XoF+6aAngqgSWVrKnUyez9W8Mp1y4nYCkckKhdPP
         CczYbESBFs8cIBMVlksndUgz4sdoKXA/4YWoc6G/MycUAueevnHctU7XYG3rVbXgyII8
         ok+fb143RCqPZH8Da1Ek5/kc0HEGEKtoiotg/QhrhlNX8C50Mx1FjZr5uT+OeTkPQ3x+
         5HO921dPmlk3sgh43y8VJeVBPk+yQ2e9fc1oldd4c3lRtHyMBaSJtUuOubfRJzL/jjV0
         y+8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H1cy3PZAjl4lbZE9dV7hFfA6eFpck5j234TR1XiQXOg=;
        b=gkw89c90LUo5waEcyHe79ZheRwGCS8QPgDx/86BRe+dWd93ouZy7yX6oLUrryNK5FV
         PMTpm5S9L3cawikxB71Q3Ujc5sWUQwNHgDo8o7rNPNfDnFDUjkHm8YeEMKsPzEEDZMtC
         ZnTGnwUVDxgBN+dT2hniaaO9UD7JL2pSA5W3kfnDHFcjXJ4FZ2fGoqEBsf1pF8/5zpuO
         0M+32yy010IKOURBBOcgFCIz4K+Vg04SREtnbx6TTGs1XO114bKtN1oY7InRIPEzpBN4
         EFuA38dTHKg+aQuS3MnodZceRRZ7LuaTl4nxYe07FAGizM71Sz8s43+7K+mMNzeo/UM3
         7anQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ectFaIreYs/+hFjm4SB+tZYGg3deMo3MnbxhKHMktCL6Kd7aZ
	XwvWYRKe3Uaxojb9W5QZKPU=
X-Google-Smtp-Source: ABdhPJzvi2nmg3YBY++eRIyi+jEgaEtS/q9BOdD/e4+izsEI3Z7Fd0adg5SUfl7g1k5pRZen8eBKOg==
X-Received: by 2002:a92:5a52:: with SMTP id o79mr13852497ilb.89.1593765229488;
        Fri, 03 Jul 2020 01:33:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:5b18:: with SMTP id v24ls1674825ioh.10.gmail; Fri, 03
 Jul 2020 01:33:49 -0700 (PDT)
X-Received: by 2002:a05:6602:148d:: with SMTP id a13mr11536588iow.44.1593765229261;
        Fri, 03 Jul 2020 01:33:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593765229; cv=none;
        d=google.com; s=arc-20160816;
        b=Mvn/Rxg3DFoB38l8J+gTAqX0HBQo2pDHsvieKuCBVy/Itkt2/JA8yOKUPDtGvkQoRl
         sBBDHa8AgXBDeyQslW4kA1Hvu+GEhJau1YrKWfIg8zBD0WWRsZymdejOEHnj/dWw2vQ+
         dxqghGhEqaMQfcbax7934WaQUBejWfz6G+W/nl73W3VKa/Sx6bHE2HDQQyD31+rjeCC4
         +/YP4YYn22DAaMzTGKF4bapbO4Pl2E8C/eLJjOo32bGJxk+M+fqP07LUOu7i7AoHsoKJ
         dw8aj0QRGuz76/UKLhlPGCbUUGe0ZNkDjpkSmCCQLysNY+/F+j3GBjUYBlp3DpHXpYn3
         NoQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date;
        bh=Gs3xUcfd6MO5qKFgS9vsGwOb/CrAJRHpbXGBkONixaQ=;
        b=DvdAblmCx/LIlL69QAqzKOcrF0BnZ9R1ydYSV/zNGq9am7WyMsiJTyXNDBk0qy6a3m
         sPszF2K3VPrHqlVMT/2MNWtahkIxl1vmB4KnmxbVIBxmBINmxmWcDyNrfvDDQq/WGedH
         dnN3edMBEWhSusahq7eFA41Ckxnhiq1VrU+ZI8hMujRlIV1LWSotPA8JtBj0V9syT0Yt
         eR7WOtmN3Lj6u4f7GGavrYoEj1xidkGvSheARML8XtKQBjjBZJVYnB2A1hLN0OxRq1Qv
         twtOH0Fxma4WlrQQtF+xnFpQFQz9IPMimHn7TwXB8FgG/UgkkE0tJC/N6a+CUP7+XIDV
         ltqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out4436.biz.mail.alibaba.com (out4436.biz.mail.alibaba.com. [47.88.44.36])
        by gmr-mx.google.com with ESMTPS id d3si115879iow.4.2020.07.03.01.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Jul 2020 01:33:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 47.88.44.36 as permitted sender) client-ip=47.88.44.36;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R101e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e07425;MF=richard.weiyang@linux.alibaba.com;NM=1;PH=DS;RN=13;SR=0;TI=SMTPD_---0U1YpQ-n_1593765212;
Received: from localhost(mailfrom:richard.weiyang@linux.alibaba.com fp:SMTPD_---0U1YpQ-n_1593765212)
          by smtp.aliyun-inc.com(127.0.0.1);
          Fri, 03 Jul 2020 16:33:32 +0800
Date: Fri, 3 Jul 2020 16:33:32 +0800
From: Wei Yang <richard.weiyang@linux.alibaba.com>
To: David Hildenbrand <david@redhat.com>
Cc: Wei Yang <richard.weiyang@linux.alibaba.com>,
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm: define pte_add_end for consistency
Message-ID: <20200703083332.GA17076@L-31X9LVDL-1304.local>
Reply-To: Wei Yang <richard.weiyang@linux.alibaba.com>
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
 <20200701021113.GA51306@L-31X9LVDL-1304.local>
 <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
 <20200701115441.GA4979@L-31X9LVDL-1304.local>
 <7562991b-c1e7-4037-a3f0-124acd0669b7@redhat.com>
 <20200703013435.GA11340@L-31X9LVDL-1304.local>
 <14e6a073-0a8c-3827-4d6f-072d08fbd6cc@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <14e6a073-0a8c-3827-4d6f-072d08fbd6cc@redhat.com>
X-Original-Sender: richard.weiyang@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard.weiyang@linux.alibaba.com designates
 47.88.44.36 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

On Fri, Jul 03, 2020 at 09:23:30AM +0200, David Hildenbrand wrote:
>On 03.07.20 03:34, Wei Yang wrote:
>> On Thu, Jul 02, 2020 at 06:28:19PM +0200, David Hildenbrand wrote:
>>> On 01.07.20 13:54, Wei Yang wrote:
>>>> On Wed, Jul 01, 2020 at 10:29:08AM +0200, David Hildenbrand wrote:
>>>>> On 01.07.20 04:11, Wei Yang wrote:
>>>>>> On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>>>>>>> On 30.06.20 05:18, Wei Yang wrote:
>>>>>>>> When walking page tables, we define several helpers to get the address of
>>>>>>>> the next boundary. But we don't have one for pte level.
>>>>>>>>
>>>>>>>> Let's define it and consolidate the code in several places.
>>>>>>>>
>>>>>>>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>>>>>>>> ---
>>>>>>>>  arch/x86/mm/init_64.c   | 6 ++----
>>>>>>>>  include/linux/pgtable.h | 7 +++++++
>>>>>>>>  mm/kasan/init.c         | 4 +---
>>>>>>>>  3 files changed, 10 insertions(+), 7 deletions(-)
>>>>>>>>
>>>>>>>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>>>>>>>> index dbae185511cd..f902fbd17f27 100644
>>>>>>>> --- a/arch/x86/mm/init_64.c
>>>>>>>> +++ b/arch/x86/mm/init_64.c
>>>>>>>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>>>>>>>  
>>>>>>>>  	pte = pte_start + pte_index(addr);
>>>>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>>>> -		if (next > end)
>>>>>>>> -			next = end;
>>>>>>>> +		next = pte_addr_end(addr, end);
>>>>>>>>  
>>>>>>>>  		if (!pte_present(*pte))
>>>>>>>>  			continue;
>>>>>>>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>>>>>>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>>>>>>>  
>>>>>>>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>>>>>>>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>>>> +			next = pte_addr_end(addr, end);
>>>>>>>>  			pmd = pmd_offset(pud, addr);
>>>>>>>>  			if (pmd_none(*pmd))
>>>>>>>>  				continue;
>>>>>>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>>>>>>> index 32b6c52d41b9..0de09c6c89d2 100644
>>>>>>>> --- a/include/linux/pgtable.h
>>>>>>>> +++ b/include/linux/pgtable.h
>>>>>>>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>>>>>>>  })
>>>>>>>>  #endif
>>>>>>>>  
>>>>>>>> +#ifndef pte_addr_end
>>>>>>>> +#define pte_addr_end(addr, end)						\
>>>>>>>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>>>>>>>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>>>>>>>> +})
>>>>>>>> +#endif
>>>>>>>> +
>>>>>>>>  /*
>>>>>>>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>>>>>>>   * and any p?d_bad entries - reporting the error before resetting to none.
>>>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>>>>> index fe6be0be1f76..89f748601f74 100644
>>>>>>>> --- a/mm/kasan/init.c
>>>>>>>> +++ b/mm/kasan/init.c
>>>>>>>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>>>>>>>  	unsigned long next;
>>>>>>>>  
>>>>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>>>> -		if (next > end)
>>>>>>>> -			next = end;
>>>>>>>> +		next = pte_addr_end(addr, end);
>>>>>>>>  
>>>>>>>>  		if (!pte_present(*pte))
>>>>>>>>  			continue;
>>>>>>>>
>>>>>>>
>>>>>>> I'm not really a friend of this I have to say. We're simply iterating
>>>>>>> over single pages, not much magic ....
>>>>>>
>>>>>> Hmm... yes, we are iterating on Page boundary, while we many have the case
>>>>>> when addr or end is not PAGE_ALIGN.
>>>>>
>>>>> I really do wonder if not having page aligned addresses actually happens
>>>>> in real life. Page tables operate on page granularity, and
>>>>> adding/removing unaligned parts feels wrong ... and that's also why I
>>>>> dislike such a helper.
>>>>>
>>>>> 1. kasan_add_zero_shadow()/kasan_remove_zero_shadow(). If I understand
>>>>> the logic (WARN_ON()) correctly, we bail out in case we would ever end
>>>>> up in such a scenario, where we would want to add/remove things not
>>>>> aligned to PAGE_SIZE.
>>>>>
>>>>> 2. remove_pagetable()...->remove_pte_table()
>>>>>
>>>>> vmemmap_free() should never try to de-populate sub-pages. Even with
>>>>> sub-section hot-add/remove (2MB / 512 pages), with valid struct page
>>>>> sizes (56, 64, 72, 80), we always end up with full pages.
>>>>>
>>>>> kernel_physical_mapping_remove() is only called via
>>>>> arch_remove_memory(). That will never remove unaligned parts.
>>>>>
>>>>
>>>> I don't have a very clear mind now, while when you look into
>>>> remove_pte_table(), it has two cases based on alignment of addr and next.
>>>>
>>>> If we always remove a page, the second case won't happen?
>>>
>>> So, the code talks about that the second case can only happen for
>>> vmemmap, never for direct mappings.
>>>
>>> I don't see a way how this could ever happen with current page sizes,
>>> even with sub-section hotadd (2MB). Maybe that is a legacy leftover or
>>> was never relevant? Or I am missing something important, where we could
>>> have sub-4k-page vmemmap data.
>>>
>> 
>> I took a calculation on the sub-section page struct size, it is page size (4K)
>> aligned. This means you are right, which we won't depopulate a sub-page.
>> 
>> And yes, I am not sure all those variants would fit this case. So I would like
>> to leave as it now. How about your opinion?
>
>I'd say we clean this up and protect it by WARN_ON_ONCE(). Then, it
>won't need another round of investigation to find out that handling
>sub-pages is irrelevant.
>
>If you don't want to tackle this, I can have a look. Just let me know.
>

Actually, I don't get what you are trying to do. So go ahead, maybe I can
review your change.

>-- 
>Thanks,
>
>David / dhildenb

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200703083332.GA17076%40L-31X9LVDL-1304.local.
