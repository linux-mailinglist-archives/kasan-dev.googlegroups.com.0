Return-Path: <kasan-dev+bncBC32535MUICBBYES6H3QKGQEXPXR3KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AADE210627
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jul 2020 10:29:21 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id h4sf15757686qkl.23
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jul 2020 01:29:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593592160; cv=pass;
        d=google.com; s=arc-20160816;
        b=crnTGeNmYJ3LUN3Ib0U7sPFJ8EYiqQh7QrVDfRAGBy/9NBaTUHHwUdVmVLMiZTISmv
         KpcBzvaspZzFrBLL29tHji3Z1bpNdC7srdy6/eM1z8QDfHs2F7Z/O7k9ccs5p+fJb3jG
         FYkDuf9lGZLA9g8p2xF5IeuGuSP3uf+eooB9rMTFEgNFnxcbPNziWQgfnTZW/JJ/FkSX
         MCzrPns0VBbenMCRpfiWX0m4UEQwX2Lw0/U9Nqdo0VdPf/1/FeYbMGbIAg4stQsLrgXn
         8kjrHrQcbPiRyKujo8yisiwyBzfNMwAA1JJFlCGMVSt/wTcOW7OVfqkO/lzk1tcOm0/Z
         5hlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:autocrypt:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=9WX7IR+VTaf5RxVUSaywj5gRdTAT2hM0Sp9wd15PtSg=;
        b=NKtwVSnp7IvjpRX5FLYKZmsBsHr6N+Ii2qlYifxyLsN0YzjTXDoKz0FRL++AwnK7Nt
         mLcVbXFLMt2ivbaBU82qwnHcJzNzASMDqBN6uU4ZJXbrghoROIYEdm8a/jSDhrf6L3Yl
         omHZVia6V8GIWwnJsrZdMLuzv+O+8C9SD8UOKV2S8RMbErOXAeejfryDQtImQagRRi66
         3EhobP+Q4oLueKMHPKM6hVSLVOjuy8qigjrIv+vKGPhSD5pye4wt3DnDgtz2nGRq0qAF
         WcCx7K4CU7YrxP1mMQcA8FarNH9ZmYHuyyy+QaLRUwf3Ot6OAlb++ZZHZ3labjeQD5i6
         x4wQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DcoMP3al;
       spf=pass (google.com: domain of david@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9WX7IR+VTaf5RxVUSaywj5gRdTAT2hM0Sp9wd15PtSg=;
        b=fsxYLCdFCF29yZw5hUzxs7s599/crWTuCp8fHwPEUzBpuS4fgtdxcMB9RcU6ZZoMwF
         swrh0NzSQJXF+bB4XJrHSwQ/rCTXREJChebVt5qUxxciCiapHhU5iInDfBCK9qbl1ope
         YkyoVyBDQVtzpMd/x4h5jIMFTAyUn4DBpDMLde7FTYfrzmt37pcFbfeaHGX3BBTUg7Mc
         H1Mmv6o12fyEYZpiuMVH1Lx6Npr4p8A4YhNAhCH3Hp69HQIjRzbDbUQ/gudvWJO5N/Y7
         kZzbV9PF7XaKHRbjJvWAazjRC5aeNCZ4BIUMvEpyf5KF03Rzr3edLrZAtu4rtnBIIgZd
         rcLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9WX7IR+VTaf5RxVUSaywj5gRdTAT2hM0Sp9wd15PtSg=;
        b=VAmptRF2TYt//NFSepOJOZR/6HZiy4iaNwhezQsQjX3z4FDGhHaG8pGijN3BfDWG8h
         dqwAR4KT0HUw6BwiDBkzpgmTNZRJQ/9CEXGZIADEWmuVoERoPRsu4Bi8ESvI+1bNN7uI
         zPJ9UVrksYg1W9COpTTsXSbFpuj1saS8Si4Wz7LS2bAUEyunfx+hYE4mWPsXWGCJxJ1p
         sC5MLGATBam0dCf4DlpN0GPtfzvk2ZGUQG41ASfVzQUdJ5/yQQ8Cb1LlYJnPS8fMZgWK
         ckvClSccI4ooRTLGYjf9LMf/KmmNOEcvp9QIJ+3m5nmYi4v2Qs5TwMjXWrkLqBVaq6Xn
         AAgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hQ1nxD8Y68p3fz4vc1hdHCS9//d1RqwvKkQQGB7gn/fNsgjkg
	1mA4V5Wf/EacnmsQWfIXhDk=
X-Google-Smtp-Source: ABdhPJwkyeGiaR4CsjToCC6lkzbsU6r6gEtSlkKvME5o4xvrRTjpDf2LwbhteRpubydha8abGvEtDg==
X-Received: by 2002:a37:5bc4:: with SMTP id p187mr24652822qkb.166.1593592160099;
        Wed, 01 Jul 2020 01:29:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3612:: with SMTP id m18ls633578qtb.9.gmail; Wed, 01 Jul
 2020 01:29:19 -0700 (PDT)
X-Received: by 2002:ac8:5303:: with SMTP id t3mr24452017qtn.108.1593592159743;
        Wed, 01 Jul 2020 01:29:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593592159; cv=none;
        d=google.com; s=arc-20160816;
        b=rzhqtCDI7l9l2L+wfeL+BCHCrkI6gxkPrY7V0nZGgM4PJmeZt05XOcyAkMyV+kujqA
         GsOl6TgjJ3butybqOschSDiJPdn1oOiTXEi/sscSPUN6Q/Xbozglgbxk500fTYHHYIlm
         r1ll/tgA5SXTUjk1oYXLE5bjMia6Qjgw1bwA4Egve+3Fr4tq64LpMJZkmr0us4hJTTaf
         hKrM5iQjaU1PJiQ6KEi1Qi0HzMZ+TJLCuR7kEASphvYmK5gFe4jKc/Js8oDelz4wd+4d
         D9B68t2NlodgtITye8ecrlX74UJ4nLF99eMushmdVpOg3BXCqLxY0P52/R5SihEkZZvO
         C7TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:autocrypt:from:references
         :cc:to:subject:dkim-signature;
        bh=rOccC/nMWU0M4+XO6d1YsLmlKl8IhBukUbLvPQ9C0os=;
        b=i1hXBM3cFo8fuE7gT63IMNKTk6CHchY7ni2bQwny9A1e3zLhzzJ1DthZ87ulyFGkFF
         lVqOOqgkH/OIi7FfyE3jx4JpwMi0sTaJlY30nr0XvjSvvuSuVyW8BUtHjZ04R/8WtJr0
         t2AvmzqmIvBYKBcxMLCkiqhPI1qVga7zslcCECCFK+JwbGmQCEcnEoFlw8bRvB7je1t4
         p4zoEIoQbA2COfM1JoCSRLAlAyrEfE/JV9R2q2dcIQBJuVK3Jkh/GLqHzR2bBVsYT3MD
         Oj7g1uR63NVE9xaFSJHWB774RjaIFic9o1XleE4PFM8qau9SScG30c27DgN7QnAhXjU7
         ueAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DcoMP3al;
       spf=pass (google.com: domain of david@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id y21si271441qka.2.2020.07.01.01.29.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Jul 2020 01:29:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-381-X6NjWalSOliMFEI7Q2laIg-1; Wed, 01 Jul 2020 04:29:17 -0400
X-MC-Unique: X6NjWalSOliMFEI7Q2laIg-1
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.phx2.redhat.com [10.5.11.23])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 6BA228015F4;
	Wed,  1 Jul 2020 08:29:15 +0000 (UTC)
Received: from [10.36.112.52] (ovpn-112-52.ams2.redhat.com [10.36.112.52])
	by smtp.corp.redhat.com (Postfix) with ESMTP id A2E2D2B5BF;
	Wed,  1 Jul 2020 08:29:09 +0000 (UTC)
Subject: Re: [PATCH] mm: define pte_add_end for consistency
To: Wei Yang <richard.weiyang@linux.alibaba.com>
Cc: dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 akpm@linux-foundation.org, x86@kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
 <20200701021113.GA51306@L-31X9LVDL-1304.local>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; prefer-encrypt=mutual; keydata=
 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
Organization: Red Hat GmbH
Message-ID: <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
Date: Wed, 1 Jul 2020 10:29:08 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <20200701021113.GA51306@L-31X9LVDL-1304.local>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.23
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DcoMP3al;
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

On 01.07.20 04:11, Wei Yang wrote:
> On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>> On 30.06.20 05:18, Wei Yang wrote:
>>> When walking page tables, we define several helpers to get the address of
>>> the next boundary. But we don't have one for pte level.
>>>
>>> Let's define it and consolidate the code in several places.
>>>
>>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>>> ---
>>>  arch/x86/mm/init_64.c   | 6 ++----
>>>  include/linux/pgtable.h | 7 +++++++
>>>  mm/kasan/init.c         | 4 +---
>>>  3 files changed, 10 insertions(+), 7 deletions(-)
>>>
>>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>>> index dbae185511cd..f902fbd17f27 100644
>>> --- a/arch/x86/mm/init_64.c
>>> +++ b/arch/x86/mm/init_64.c
>>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>>  
>>>  	pte = pte_start + pte_index(addr);
>>>  	for (; addr < end; addr = next, pte++) {
>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>> -		if (next > end)
>>> -			next = end;
>>> +		next = pte_addr_end(addr, end);
>>>  
>>>  		if (!pte_present(*pte))
>>>  			continue;
>>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>>  
>>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>>> +			next = pte_addr_end(addr, end);
>>>  			pmd = pmd_offset(pud, addr);
>>>  			if (pmd_none(*pmd))
>>>  				continue;
>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>> index 32b6c52d41b9..0de09c6c89d2 100644
>>> --- a/include/linux/pgtable.h
>>> +++ b/include/linux/pgtable.h
>>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>>  })
>>>  #endif
>>>  
>>> +#ifndef pte_addr_end
>>> +#define pte_addr_end(addr, end)						\
>>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>>> +})
>>> +#endif
>>> +
>>>  /*
>>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>>   * and any p?d_bad entries - reporting the error before resetting to none.
>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>> index fe6be0be1f76..89f748601f74 100644
>>> --- a/mm/kasan/init.c
>>> +++ b/mm/kasan/init.c
>>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>>  	unsigned long next;
>>>  
>>>  	for (; addr < end; addr = next, pte++) {
>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>> -		if (next > end)
>>> -			next = end;
>>> +		next = pte_addr_end(addr, end);
>>>  
>>>  		if (!pte_present(*pte))
>>>  			continue;
>>>
>>
>> I'm not really a friend of this I have to say. We're simply iterating
>> over single pages, not much magic ....
> 
> Hmm... yes, we are iterating on Page boundary, while we many have the case
> when addr or end is not PAGE_ALIGN.

I really do wonder if not having page aligned addresses actually happens
in real life. Page tables operate on page granularity, and
adding/removing unaligned parts feels wrong ... and that's also why I
dislike such a helper.

1. kasan_add_zero_shadow()/kasan_remove_zero_shadow(). If I understand
the logic (WARN_ON()) correctly, we bail out in case we would ever end
up in such a scenario, where we would want to add/remove things not
aligned to PAGE_SIZE.

2. remove_pagetable()...->remove_pte_table()

vmemmap_free() should never try to de-populate sub-pages. Even with
sub-section hot-add/remove (2MB / 512 pages), with valid struct page
sizes (56, 64, 72, 80), we always end up with full pages.

kernel_physical_mapping_remove() is only called via
arch_remove_memory(). That will never remove unaligned parts.

3. register_page_bootmem_memmap()

It operates on full pages only.


This needs in-depth analysis, but my gut feeling is that this alignment
is unnecessary.

> 
>>
>> What would definitely make sense is replacing (addr + PAGE_SIZE) &
>> PAGE_MASK; by PAGE_ALIGN() ...
>>
> 
> No, PAGE_ALIGN() is expanded to be 
> 
> 	(addr + PAGE_SIZE - 1) & PAGE_MASK;
> 
> If we change the code to PAGE_ALIGN(), we would end up with infinite loop.

Very right, it would have to be PAGE_ALIGN(addr + 1).

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da4a470e-f34c-fbf8-c95a-93a7d30a215b%40redhat.com.
