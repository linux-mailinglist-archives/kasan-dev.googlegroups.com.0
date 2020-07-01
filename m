Return-Path: <kasan-dev+bncBAABBBXT6H3QKGQEUX4L5DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id A878E210A92
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jul 2020 13:54:47 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id z7sf26126442ybz.1
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jul 2020 04:54:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593604486; cv=pass;
        d=google.com; s=arc-20160816;
        b=u84VAXHGNsHn/9PspOXL7E5z0s15+Cgj1jfbHESBmKdRglclouXS2gggAZcwfgU2ix
         8oG5DrJoev7PMLt9qpM4kfCbni5iTk60kJFV0YpLoWN09iG9HB40J5gXViHE+o9jaKZT
         YrABsgT3/2uaIYXGsR41U9enXclpUwRNCs4cDc3huurxquPToFbGcrbfB5Si5NG3yUuF
         X3tpwB4HG7yBjZmi+nHNVK7vJqQuspOPGHrUGf2L8wFpdK8Iyo7Nl4RxS3m+JyyryzJI
         zrjh+UBZ7NBkf76QJEJjS/bRALY4NSmAJxlVPtNFe3CtBB3/l7sAz4oVopvlQWK/SCPS
         90Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=hsEfkwFr+77pR/ZXxUBE0a41tLnzSdWcPzujsoP8D8M=;
        b=sh372NV+fzk2wkd05DVMcwmjo0MVP7TQGTuk9r4wBKquJcnYlW44OC+rEn50mpeeC+
         uOph7QfdnQyIlPJP2E6Xk7vBXUjUFTEKSnosTaGH4WMyYglSEhP/tZ/zJyYPAldRJhPn
         YPoBYhOgpnggQFRcVLN0ofeA3/a4QVr+uqGdY+WXHJ+71mQrIxuKw7oXFk0qI2U30+df
         KBnoH4+VLTm1B0PNb/abeoBVBHKaZ7hH/7bqkkphxJLWCuD7MJc1TvaMkiuTlR1VK+U9
         7FTyVUmhZ9h60LW2OcsKewySCj+MVqyUOTiv3gXeEWuQ0+bjeB2sTYYNuNsOPlWrv6Ln
         810A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.131 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hsEfkwFr+77pR/ZXxUBE0a41tLnzSdWcPzujsoP8D8M=;
        b=bUyOiOSDvZkxGxxlZbumPWR59Rxe7pfeR/QIseuv9lSwth4gTrfSvTGtptvxdAR9p3
         VJ+CSwRvzn4XzXhIwFw2qD8ygP+eIprCOdJt3STrOuk08UYh2KT4kFpiqaX5eUfN44Aj
         ss7f3l+VjOEJLdwVZlT/LY3doBDAiI65oYi537L9NIQEHbGgteWyqZwo4srXlZWSk5AZ
         YLVGMBfBrTAbyzbGa7iS9CqAsIMNTn7zcHYTGgmYJcEKN74C/Z38E6olBidQ6ZXbZHOa
         L2uTvXTsQ3XazZkIIWpHEJ093/mOmhGyLK6UoPwd+xYC48aDPIKIWhpNnU+R27vKsdDP
         devQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hsEfkwFr+77pR/ZXxUBE0a41tLnzSdWcPzujsoP8D8M=;
        b=raShClFk6gYfr1UhLfhveAkcsHEP6WCk66ZqLUD/a6OLWNsqblHmoke+GWG6n2yHAC
         ThvsW8og4c9kb7kqf3B1ZLmFEaqJfn2yhr66BkJJ6toxxc4qG3VGe16s/d8p5WDbgccv
         eQrTbQqtZzRGico8hEjzTvY4/gjtOnZJwE5appBj6qUjEZV8Z0QWtNyezOVziXrbwcNm
         s3SuYjvgcPpa5QHA/QQwri+oFOcvbwD8QJhGLSWVEhE1vIPHSWlkjVyvGtqVXl14qV25
         NGH59qhe1Y4GIIHYP2LvXbvVEgO+98A5MwUZ/p+oxAJ9O/0vRsIck7GJC1ilzSos/5uD
         tPQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WHmqmHtBDxD33JhU606h6/LCAXrec3lv+GJRl0jApvgNDAC3D
	wgxP5dVOFTj1ONPd1DybdrU=
X-Google-Smtp-Source: ABdhPJw3eS9BmqqsDKNp22Qt/A3x2DTmHKjo4lz3d7RbW1oqNh5R6j4YmIjtuzvBKa/Q8Z6FclqcxQ==
X-Received: by 2002:a5b:c02:: with SMTP id f2mr42544711ybq.151.1593604486536;
        Wed, 01 Jul 2020 04:54:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4707:: with SMTP id u7ls852643yba.5.gmail; Wed, 01 Jul
 2020 04:54:46 -0700 (PDT)
X-Received: by 2002:a25:d297:: with SMTP id j145mr43383635ybg.18.1593604486181;
        Wed, 01 Jul 2020 04:54:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593604486; cv=none;
        d=google.com; s=arc-20160816;
        b=UPk2Sk/VBSxfikNKcCmOi+DSzvt7wgGqL50FetYyGr4FFIGpmhq+TGf7fCtLKypoTV
         zWHS6ahTXz5iovBnGpTjKcwEluSNKtFt/AcqxPQQ5v7Ds2fIC2SDG+h1kD9ln3Ry7M13
         u8QaghkDw24hgwMp2Jv/78cFuOsIsGh3WEe54Xmg5h3YdgevZJI3YscIZnGvzYSz8uQA
         i9N2w+VCKmFdkOKKOP87RHDrQI+nPKrCi4oUNhI6TlWN70y2W7zix4Qynjv3TOilwCGu
         qqi98UATIb8bux3wnz1cHCBYgDJe3cMgM/XeAul0evmFplHs9yPaUlY6FfCMUiVON3Sn
         0yVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date;
        bh=4988yP6aCx4qqtbysXTHl0MTah/cJRcfjgODRFPz3Hs=;
        b=GQ2sAQCrHoIi/9aeB7Pwek8FoAZ4X3CQC4yOu2mHG2as4uZZ1MsAC5gUPw0rofRz+A
         JyisJidSvbMcWeWDLYf/YZah8C0Xku6dTtf14wUx9ZYGVi/OUSLBjkcJT93OCq6xmZSs
         jvCpLBXSrkCAWIE1BJV/TwVxphCD64Wa3n7rOupd4RHQJMzeba2WFUcS7CGgA3arfT4l
         Km4H3etUbeCZLqCpy0j+upJae9hfadYdq91xsu/69O2pd1sYjcntMWAh2LXR56TrH1yD
         X7czBUIiGfB8FnecOlsx0GcbcPxwwrpvU+XqlEVPjp0aD0cRJgTXFLIVJXjrFFByr3d8
         99ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.131 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-131.freemail.mail.aliyun.com (out30-131.freemail.mail.aliyun.com. [115.124.30.131])
        by gmr-mx.google.com with ESMTPS id v16si369664ybe.2.2020.07.01.04.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Jul 2020 04:54:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.131 as permitted sender) client-ip=115.124.30.131;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R191e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04407;MF=richard.weiyang@linux.alibaba.com;NM=1;PH=DS;RN=13;SR=0;TI=SMTPD_---0U1MIZDg_1593604481;
Received: from localhost(mailfrom:richard.weiyang@linux.alibaba.com fp:SMTPD_---0U1MIZDg_1593604481)
          by smtp.aliyun-inc.com(127.0.0.1);
          Wed, 01 Jul 2020 19:54:42 +0800
Date: Wed, 1 Jul 2020 19:54:41 +0800
From: Wei Yang <richard.weiyang@linux.alibaba.com>
To: David Hildenbrand <david@redhat.com>
Cc: Wei Yang <richard.weiyang@linux.alibaba.com>,
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm: define pte_add_end for consistency
Message-ID: <20200701115441.GA4979@L-31X9LVDL-1304.local>
Reply-To: Wei Yang <richard.weiyang@linux.alibaba.com>
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
 <20200701021113.GA51306@L-31X9LVDL-1304.local>
 <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
X-Original-Sender: richard.weiyang@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard.weiyang@linux.alibaba.com designates
 115.124.30.131 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
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

On Wed, Jul 01, 2020 at 10:29:08AM +0200, David Hildenbrand wrote:
>On 01.07.20 04:11, Wei Yang wrote:
>> On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>>> On 30.06.20 05:18, Wei Yang wrote:
>>>> When walking page tables, we define several helpers to get the address of
>>>> the next boundary. But we don't have one for pte level.
>>>>
>>>> Let's define it and consolidate the code in several places.
>>>>
>>>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>>>> ---
>>>>  arch/x86/mm/init_64.c   | 6 ++----
>>>>  include/linux/pgtable.h | 7 +++++++
>>>>  mm/kasan/init.c         | 4 +---
>>>>  3 files changed, 10 insertions(+), 7 deletions(-)
>>>>
>>>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>>>> index dbae185511cd..f902fbd17f27 100644
>>>> --- a/arch/x86/mm/init_64.c
>>>> +++ b/arch/x86/mm/init_64.c
>>>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>>>  
>>>>  	pte = pte_start + pte_index(addr);
>>>>  	for (; addr < end; addr = next, pte++) {
>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>> -		if (next > end)
>>>> -			next = end;
>>>> +		next = pte_addr_end(addr, end);
>>>>  
>>>>  		if (!pte_present(*pte))
>>>>  			continue;
>>>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>>>  
>>>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>>>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>> +			next = pte_addr_end(addr, end);
>>>>  			pmd = pmd_offset(pud, addr);
>>>>  			if (pmd_none(*pmd))
>>>>  				continue;
>>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>>> index 32b6c52d41b9..0de09c6c89d2 100644
>>>> --- a/include/linux/pgtable.h
>>>> +++ b/include/linux/pgtable.h
>>>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>>>  })
>>>>  #endif
>>>>  
>>>> +#ifndef pte_addr_end
>>>> +#define pte_addr_end(addr, end)						\
>>>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>>>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>>>> +})
>>>> +#endif
>>>> +
>>>>  /*
>>>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>>>   * and any p?d_bad entries - reporting the error before resetting to none.
>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>> index fe6be0be1f76..89f748601f74 100644
>>>> --- a/mm/kasan/init.c
>>>> +++ b/mm/kasan/init.c
>>>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>>>  	unsigned long next;
>>>>  
>>>>  	for (; addr < end; addr = next, pte++) {
>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>> -		if (next > end)
>>>> -			next = end;
>>>> +		next = pte_addr_end(addr, end);
>>>>  
>>>>  		if (!pte_present(*pte))
>>>>  			continue;
>>>>
>>>
>>> I'm not really a friend of this I have to say. We're simply iterating
>>> over single pages, not much magic ....
>> 
>> Hmm... yes, we are iterating on Page boundary, while we many have the case
>> when addr or end is not PAGE_ALIGN.
>
>I really do wonder if not having page aligned addresses actually happens
>in real life. Page tables operate on page granularity, and
>adding/removing unaligned parts feels wrong ... and that's also why I
>dislike such a helper.
>
>1. kasan_add_zero_shadow()/kasan_remove_zero_shadow(). If I understand
>the logic (WARN_ON()) correctly, we bail out in case we would ever end
>up in such a scenario, where we would want to add/remove things not
>aligned to PAGE_SIZE.
>
>2. remove_pagetable()...->remove_pte_table()
>
>vmemmap_free() should never try to de-populate sub-pages. Even with
>sub-section hot-add/remove (2MB / 512 pages), with valid struct page
>sizes (56, 64, 72, 80), we always end up with full pages.
>
>kernel_physical_mapping_remove() is only called via
>arch_remove_memory(). That will never remove unaligned parts.
>

I don't have a very clear mind now, while when you look into
remove_pte_table(), it has two cases based on alignment of addr and next.

If we always remove a page, the second case won't happen?

>3. register_page_bootmem_memmap()
>
>It operates on full pages only.
>
>
>This needs in-depth analysis, but my gut feeling is that this alignment
>is unnecessary.
>
>> 
>>>
>>> What would definitely make sense is replacing (addr + PAGE_SIZE) &
>>> PAGE_MASK; by PAGE_ALIGN() ...
>>>
>> 
>> No, PAGE_ALIGN() is expanded to be 
>> 
>> 	(addr + PAGE_SIZE - 1) & PAGE_MASK;
>> 
>> If we change the code to PAGE_ALIGN(), we would end up with infinite loop.
>
>Very right, it would have to be PAGE_ALIGN(addr + 1).
>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200701115441.GA4979%40L-31X9LVDL-1304.local.
