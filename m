Return-Path: <kasan-dev+bncBAABBTMW7L3QKGQEXAU2GRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 90D30213106
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 03:35:10 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id c17sf31708247ybf.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jul 2020 18:35:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593740109; cv=pass;
        d=google.com; s=arc-20160816;
        b=wFCHUEyFApgevdbqLKQPkkDkdi2ofSgKCo7Sdk+29haztHAXnyfbRJTFYunwsPj4Sa
         q5UDFROZuLJar8rd1eV2OfuGV863m6YK5wBUKi6RMWT+MTp6Q5rWEEWQ4WTk5nuhvlFR
         RwMriWSDFrnXfilnRk2diftJ3S4rbaVKr7zQELCIq+uhtV9gThnns7siuH5iRN3g0g7Y
         j0dYv/fS2l36AUGAcXcnwRs+9reUN9SvY3FNt0Fsd7p6/qSEccCbL1oRwg3LOrBsPlXe
         84z4a8DKlDdmlPVZ51Sfkxk/t0UObyEBBaL+IUh0eN2YJPcNPIKJfgZIsqWo/qMip7D9
         sJzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=5JiV0dykAmUpTLuSp3coWAOlTihMbYqhDefRCc2GG4w=;
        b=rbjeTM4zsNLUvkIfguusJoW+YO9K5drhiYaJViLq/jWyQcMZmvnwKb+8duARZs0GU5
         i/OOb1DH0oFJ7SU+jG64y0hipynygd/SKRfjrnA4V5RsY/hO1AIhV/uCtCrzD1DnNDzB
         5HEKcyDsaYjS/O/pbWQFGf3IWuBHA1NRQvJpYwZlejN3Da6qcR0k6aASnvODxsN6Bfy/
         O7v6S+EzKIIvUBiWe6bAPolm7EKFTGtdq/BXO1TRD8/jF2xsEU8w/oGU+/Qy8aRbcgem
         rUFud68BxmpIUd5cS/hq/Cnjjv1w8xQbeFTHFPZr3C+rdDtWh1QhMQRkJbwjadWOyuWv
         sAow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5JiV0dykAmUpTLuSp3coWAOlTihMbYqhDefRCc2GG4w=;
        b=GR1iNOhkvlkJ4gsysYBjgU0eaOjoer4V8KPbSdcn8V00arHr2yw2wb8RvT72X/T2e1
         hhS8VoBLglbEQAy+9SFqU8PNsoyKInqqsSTZaH8J1lQsxLozgV2kszcTGLj/7EjTwwKN
         7anLYsdcpdcuqV1DR8aJWuMZfRhyHJwMCM4Kwfxk3MBN8sF8b7xo6nebr8C1JeuVol9K
         J7aUWIMGrHFFgqGcnWRS9bAgLkrKsvIf0kc7P0JFmqB/Fi25Edm6/fZ9ZgqsnIjAh75C
         rMOlzBt7FTKkm7JMOnFS9OfeONfjz4TzCA/OmBrepWYzftDPkCmcm0RJjxGaX/jivoIo
         tW3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5JiV0dykAmUpTLuSp3coWAOlTihMbYqhDefRCc2GG4w=;
        b=prZORbzwaM98xVzi5/lcXIcWTmTAzzigQfKHh6UKJkg1fxI+GwCzEUi/Suf4zL0FhC
         jCrwqceZU0p7QwRJbN7fjuciHPxFM8EXG/gvSwxFkHBWSJtwsxOIOFJU8pdxYcNoq+Kv
         9DEGHb1g10xDugt30DOy09iCqY4xs2OtT3qZflYCRqkpwc+ylTSRUOoOfEE08QAjlzEO
         mqmILekFhA015VNFbpBaRumMWqUgeJOYmbTtVPr6BZsf/wH5chIzyaEc6t/Pux2wluvs
         dSgZj5JyHxYr3QfnoSbONGx0DSCrPUBRs0sS+Eb56D9yiM35uD0hU6fziJtFP0sVd9J0
         3kHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dU7Z7e5EYG+TW9X5wCFuaMg8CYrQnlf5kN8a595EtVcrTIu6z
	pHIjrgT4WLoaD+qJVW9yjcs=
X-Google-Smtp-Source: ABdhPJxxUxueKsgEyIcbwqxL2FIc96nTKA/4jvknXELReZTjqyV27YUy+bUN4itpXr3EVr6Oj01SpA==
X-Received: by 2002:a25:e088:: with SMTP id x130mr30128332ybg.147.1593740109395;
        Thu, 02 Jul 2020 18:35:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:44:: with SMTP id e4ls2981836ybp.10.gmail; Thu, 02 Jul
 2020 18:35:09 -0700 (PDT)
X-Received: by 2002:a25:4289:: with SMTP id p131mr9160122yba.477.1593740109066;
        Thu, 02 Jul 2020 18:35:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593740109; cv=none;
        d=google.com; s=arc-20160816;
        b=fajToK8hkXXeqSlqWJ8P4Sl9C+YqwthnSzWwidE02KqLK+2aevylWid/esfNlDy7xg
         B4l8GocMBhtsvkU5cDrwt2epUtkxkPOuWJorP/aU4D5NwZaOlSXExx6H1u2uTWTvF7W3
         hg1ByXSuzraTRlgvGMTbcTq63zavtOFimv0TunzrVtuvsFAWnPFMbscxLO+rJ41pag3N
         Sy1aX/bT8eqtiyu8mODITiP6Xst8Tpf/hYBYtKEQnMyVT1XmyZwp+cNzicVHikh8y8uW
         xfM8zO0uncboBsiCTEfTqUZZ9fYYTNJgWxXTDKHgzsgxlsjVG8mEP6BCIQxsTGufHx6S
         wYHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date;
        bh=MxbKeqyw33+HJN25d5KMmT2sQlkCyH4DXreK9urYMpc=;
        b=1A8JnXdmhhwv5qZi30kgZ04M4oqEouvyZgn5ScQlhz+7BciO1UnAw2KOktyfr3Kgoc
         j5XtsvcYYC/rBxGs2rfH4HpsuwDz/eH+Ui5UOxOuY/BGH1hTnlHzIPHTA4YVp7FJbRkX
         818tF3FBk1cJrLDlV/Tj4ZC0kRaDFI7J2HkOKGDeJns7udX0dtkthrlBj28+9ZCzdOxa
         OWKZmUN6jnizJ9anS1pPMzBJ2Ase5Qa+3HjiJ8OfVNOoHShexJXkII4bHGbaegRVPchs
         RgcgRXq0/NJ4RJmQM5DosmL4wGHDNLG2uFTYxfy1CLLNFn+B9mqf63xQfhxeA8UJAgMp
         ivww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out4436.biz.mail.alibaba.com (out4436.biz.mail.alibaba.com. [47.88.44.36])
        by gmr-mx.google.com with ESMTPS id v16si742104ybe.2.2020.07.02.18.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Jul 2020 18:35:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 47.88.44.36 as permitted sender) client-ip=47.88.44.36;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R131e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04357;MF=richard.weiyang@linux.alibaba.com;NM=1;PH=DS;RN=13;SR=0;TI=SMTPD_---0U1XFdqr_1593740075;
Received: from localhost(mailfrom:richard.weiyang@linux.alibaba.com fp:SMTPD_---0U1XFdqr_1593740075)
          by smtp.aliyun-inc.com(127.0.0.1);
          Fri, 03 Jul 2020 09:34:36 +0800
Date: Fri, 3 Jul 2020 09:34:35 +0800
From: Wei Yang <richard.weiyang@linux.alibaba.com>
To: David Hildenbrand <david@redhat.com>
Cc: Wei Yang <richard.weiyang@linux.alibaba.com>,
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm: define pte_add_end for consistency
Message-ID: <20200703013435.GA11340@L-31X9LVDL-1304.local>
Reply-To: Wei Yang <richard.weiyang@linux.alibaba.com>
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
 <20200701021113.GA51306@L-31X9LVDL-1304.local>
 <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
 <20200701115441.GA4979@L-31X9LVDL-1304.local>
 <7562991b-c1e7-4037-a3f0-124acd0669b7@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7562991b-c1e7-4037-a3f0-124acd0669b7@redhat.com>
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

On Thu, Jul 02, 2020 at 06:28:19PM +0200, David Hildenbrand wrote:
>On 01.07.20 13:54, Wei Yang wrote:
>> On Wed, Jul 01, 2020 at 10:29:08AM +0200, David Hildenbrand wrote:
>>> On 01.07.20 04:11, Wei Yang wrote:
>>>> On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>>>>> On 30.06.20 05:18, Wei Yang wrote:
>>>>>> When walking page tables, we define several helpers to get the address of
>>>>>> the next boundary. But we don't have one for pte level.
>>>>>>
>>>>>> Let's define it and consolidate the code in several places.
>>>>>>
>>>>>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>>>>>> ---
>>>>>>  arch/x86/mm/init_64.c   | 6 ++----
>>>>>>  include/linux/pgtable.h | 7 +++++++
>>>>>>  mm/kasan/init.c         | 4 +---
>>>>>>  3 files changed, 10 insertions(+), 7 deletions(-)
>>>>>>
>>>>>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>>>>>> index dbae185511cd..f902fbd17f27 100644
>>>>>> --- a/arch/x86/mm/init_64.c
>>>>>> +++ b/arch/x86/mm/init_64.c
>>>>>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>>>>>  
>>>>>>  	pte = pte_start + pte_index(addr);
>>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>> -		if (next > end)
>>>>>> -			next = end;
>>>>>> +		next = pte_addr_end(addr, end);
>>>>>>  
>>>>>>  		if (!pte_present(*pte))
>>>>>>  			continue;
>>>>>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>>>>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>>>>>  
>>>>>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>>>>>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>> +			next = pte_addr_end(addr, end);
>>>>>>  			pmd = pmd_offset(pud, addr);
>>>>>>  			if (pmd_none(*pmd))
>>>>>>  				continue;
>>>>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>>>>> index 32b6c52d41b9..0de09c6c89d2 100644
>>>>>> --- a/include/linux/pgtable.h
>>>>>> +++ b/include/linux/pgtable.h
>>>>>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>>>>>  })
>>>>>>  #endif
>>>>>>  
>>>>>> +#ifndef pte_addr_end
>>>>>> +#define pte_addr_end(addr, end)						\
>>>>>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>>>>>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>>>>>> +})
>>>>>> +#endif
>>>>>> +
>>>>>>  /*
>>>>>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>>>>>   * and any p?d_bad entries - reporting the error before resetting to none.
>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>>> index fe6be0be1f76..89f748601f74 100644
>>>>>> --- a/mm/kasan/init.c
>>>>>> +++ b/mm/kasan/init.c
>>>>>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>>>>>  	unsigned long next;
>>>>>>  
>>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>>> -		if (next > end)
>>>>>> -			next = end;
>>>>>> +		next = pte_addr_end(addr, end);
>>>>>>  
>>>>>>  		if (!pte_present(*pte))
>>>>>>  			continue;
>>>>>>
>>>>>
>>>>> I'm not really a friend of this I have to say. We're simply iterating
>>>>> over single pages, not much magic ....
>>>>
>>>> Hmm... yes, we are iterating on Page boundary, while we many have the case
>>>> when addr or end is not PAGE_ALIGN.
>>>
>>> I really do wonder if not having page aligned addresses actually happens
>>> in real life. Page tables operate on page granularity, and
>>> adding/removing unaligned parts feels wrong ... and that's also why I
>>> dislike such a helper.
>>>
>>> 1. kasan_add_zero_shadow()/kasan_remove_zero_shadow(). If I understand
>>> the logic (WARN_ON()) correctly, we bail out in case we would ever end
>>> up in such a scenario, where we would want to add/remove things not
>>> aligned to PAGE_SIZE.
>>>
>>> 2. remove_pagetable()...->remove_pte_table()
>>>
>>> vmemmap_free() should never try to de-populate sub-pages. Even with
>>> sub-section hot-add/remove (2MB / 512 pages), with valid struct page
>>> sizes (56, 64, 72, 80), we always end up with full pages.
>>>
>>> kernel_physical_mapping_remove() is only called via
>>> arch_remove_memory(). That will never remove unaligned parts.
>>>
>> 
>> I don't have a very clear mind now, while when you look into
>> remove_pte_table(), it has two cases based on alignment of addr and next.
>> 
>> If we always remove a page, the second case won't happen?
>
>So, the code talks about that the second case can only happen for
>vmemmap, never for direct mappings.
>
>I don't see a way how this could ever happen with current page sizes,
>even with sub-section hotadd (2MB). Maybe that is a legacy leftover or
>was never relevant? Or I am missing something important, where we could
>have sub-4k-page vmemmap data.
>

I took a calculation on the sub-section page struct size, it is page size (4K)
aligned. This means you are right, which we won't depopulate a sub-page.

And yes, I am not sure all those variants would fit this case. So I would like
to leave as it now. How about your opinion?

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200703013435.GA11340%40L-31X9LVDL-1304.local.
