Return-Path: <kasan-dev+bncBAABBRPB573QKGQEXOVWJCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A5D92101BF
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jul 2020 04:11:18 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id w21sf14118563oti.16
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 19:11:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593569477; cv=pass;
        d=google.com; s=arc-20160816;
        b=GY0Edwss3hIir0QQ/QftlDpY1yXzbdGFnxwWCFU0Wven9+KSjrtUY14Y1xINMToOdg
         YlyWvPLjC0zDs5iRV1iWA1l9E2jEhnCgsaZ9u+DR/NPd9iVBBgm7sGortY2g+VGOJsdx
         4kYMwflEtVnLT+40oms+XaPhFS/G09jzL1pPyKxSfS/khsKjbwCBOIAv9Aj7seNtxwEV
         6emg5V1s0uf80fuBs2+vfNxfTrXLacZPUgbi+EsWLozDwVrvsMcjOXW5qPxSvljPjVLg
         tHz4mo674snksaYv36w7Bzf2Dfwz9Ew0eWPpvq7vsvF+5J4VFLmPlf0/JKdyLgg8ejkm
         pqpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=xP595efsrXPmIrjdzYkYvpsjNxoQ/FN8brwFNd8TVzc=;
        b=dFSZwa9CI0s5GhuyffMSOOw7wbzr3TSwwOrhvg6EjBQckXtM6uHDkvEuku8L5NUbly
         XCckG58LxIBg/lxgJpWYMty/0zxryzM2y8EDaCXd7un55fJEWVMTBkoQni1q5NVgYdSZ
         kRqM8KUXDeUlq3lKcpZVzy56S/bNQvYYbyZSzng6BlT+zMBxQR8mxo/soz1L2JCGJ18T
         ydJZKMBmwJhie6UkueeGZl7OO0vKOoXSWr/XV90v+tBw5aPQvk1O3qlwKGHq9AyoTN4f
         hRqaMTKtYuTggaIxINvxGRoWP1exJ087ndrTORDgxOOGRimTiyyPH/ZxmWDWssUx8fRn
         wwhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.132 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xP595efsrXPmIrjdzYkYvpsjNxoQ/FN8brwFNd8TVzc=;
        b=AzV+nf+iOq3Khofw1p1P1czGrJIbf1et0fUmRyWZ89uIyq8ocHy8ONpUs5AZwBX+tu
         wd3+ExVEVbuLROCGcl3LsY2+qec1EewFW+1wdsAkCBwZanyOXCQocmqxV3bNlU+muzeL
         d2zJdPxDOlGGKMrFTkmOlmczGIX4afisz6ra04Td+my4tP4c3rN4F/zH1iVRA9u/Ptov
         KVFxigxl6xDCQw7UCOCdC7g3KH+MLkgDYOae0C/Etmh+u+3CBdDKresUHnqK0C9NQrUP
         MiafG65YTUxZ2hW7Tgfufm6l5eg9HOUkc6zYC+IHLvq7u3DsBMDs+NGayXZfXEL8q5Ip
         f/6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xP595efsrXPmIrjdzYkYvpsjNxoQ/FN8brwFNd8TVzc=;
        b=IdPmCrUFwj+yT/VtY/ues4g6opmyFqp1QBjprzUln0YznSeBAL3Ym/f/uQT/ZU+KUd
         MBoCP5XVLixEX5MQ7NwIb35WSNZ8+C+GfXdiimhFieFs6i/4MBnvBjBCo6hrHG2ZNKQs
         tDr8To6qM7l0apLVpwmKmjjqOd83pz/sOoIz89kiXCloxDbc7BeL6j8ciUiwTQt9A3AN
         E/iEJ49Lz0o6YMlbBJciYaArvk/yaX9M9U2mP+1FwznfNT/vJ39sljYgoXvQ871NQlMR
         DUHuvNNQ0EEQ7kyXWAeoEuAXCD0nYJrAK3cmlRJavu65tN95r0vATXhTXiGYKO7rqzNW
         2Dhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mtty9HaYWuqtvSxASPHAYYCxjXtagZqmgTAxNHqBXWtpIrMFR
	GDw253DlBLybVNTMCZaU38A=
X-Google-Smtp-Source: ABdhPJyw2XoLhZAkK9zOcfOPP3kaqz/w7xxE/ei8CyM+b8oMNPKIFPI65jE8+Sc0Skzvu1l1zFpGNw==
X-Received: by 2002:a9d:77d0:: with SMTP id w16mr12796200otl.235.1593569477271;
        Tue, 30 Jun 2020 19:11:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cfc3:: with SMTP id f186ls182550oig.11.gmail; Tue, 30
 Jun 2020 19:11:17 -0700 (PDT)
X-Received: by 2002:aca:bb86:: with SMTP id l128mr17882657oif.85.1593569476981;
        Tue, 30 Jun 2020 19:11:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593569476; cv=none;
        d=google.com; s=arc-20160816;
        b=QjzByBquKj8KMZCe8MpbJmlgagQgxB+exN3ZHEQLXv1trmywTIDwvyke2xE51M/TAC
         FfsiVeMCU2xvcaKZoIexvshUyL9wd5oQFD44wWsF668XLdWQ414BF8iXU2e/DI7vjq3c
         X0KtIR4spGkTgqCCmlloql0Z+RFfEaEXOTjp/56NnaWY2sk/e3CJeliY00VEWq6eWaS3
         f+fWnVzIVz20xftYOgkg2ahftvBsgHDmSrdNdPkpchL8VSJ0JvHKtMdPYHXDslgxqVC7
         nsxloMGSk+SCHoUF0YGy7EzsM0fRKYW3e9+cI7IgmMrn1NkAPvMfKByQDgInWqyC7fpe
         fARg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date;
        bh=xLNUuGlJoIvS4DQUGhLqbVMzWyQpP11n3ZgWOfwY+PY=;
        b=zAjCAabA4/GGP1gL2JOyZWm8/gphsE3/4ttDZTy0MxtJa4iX6W9Fe9uZLdiYQ9jj8m
         sT1xj9uJmaL+9x4sV88h8YakONkMbVruXJUwjAjhwXyRQDQEVYvadi8W334+ddCjqhwX
         KUdJnCd3RDNy6gexugmqeIcp5NdfDxwE9iEJJq88rRPVuhcg5Bu9uQRe8VCasnLWTCQK
         Z75S4gt+PM3e+C5NvuXNQxyO5jKaUDo5U7gkDPSazB+iyZxUag5i3UCpSW5qCfn7NqcT
         XYOKaceMThxL6xU9LEyt8js/nET0hjWoweAQBf4rIzQbGo8qUrbRG8HcTTUBzopFW5El
         uFKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.132 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-132.freemail.mail.aliyun.com (out30-132.freemail.mail.aliyun.com. [115.124.30.132])
        by gmr-mx.google.com with ESMTPS id j2si222219otr.0.2020.06.30.19.11.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jun 2020 19:11:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.132 as permitted sender) client-ip=115.124.30.132;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R161e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e01355;MF=richard.weiyang@linux.alibaba.com;NM=1;PH=DS;RN=13;SR=0;TI=SMTPD_---0U1E10Wi_1593569473;
Received: from localhost(mailfrom:richard.weiyang@linux.alibaba.com fp:SMTPD_---0U1E10Wi_1593569473)
          by smtp.aliyun-inc.com(127.0.0.1);
          Wed, 01 Jul 2020 10:11:13 +0800
Date: Wed, 1 Jul 2020 10:11:13 +0800
From: Wei Yang <richard.weiyang@linux.alibaba.com>
To: David Hildenbrand <david@redhat.com>
Cc: Wei Yang <richard.weiyang@linux.alibaba.com>,
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm: define pte_add_end for consistency
Message-ID: <20200701021113.GA51306@L-31X9LVDL-1304.local>
Reply-To: Wei Yang <richard.weiyang@linux.alibaba.com>
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
X-Original-Sender: richard.weiyang@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard.weiyang@linux.alibaba.com designates
 115.124.30.132 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
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

On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>On 30.06.20 05:18, Wei Yang wrote:
>> When walking page tables, we define several helpers to get the address of
>> the next boundary. But we don't have one for pte level.
>> 
>> Let's define it and consolidate the code in several places.
>> 
>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>> ---
>>  arch/x86/mm/init_64.c   | 6 ++----
>>  include/linux/pgtable.h | 7 +++++++
>>  mm/kasan/init.c         | 4 +---
>>  3 files changed, 10 insertions(+), 7 deletions(-)
>> 
>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>> index dbae185511cd..f902fbd17f27 100644
>> --- a/arch/x86/mm/init_64.c
>> +++ b/arch/x86/mm/init_64.c
>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>  
>>  	pte = pte_start + pte_index(addr);
>>  	for (; addr < end; addr = next, pte++) {
>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>> -		if (next > end)
>> -			next = end;
>> +		next = pte_addr_end(addr, end);
>>  
>>  		if (!pte_present(*pte))
>>  			continue;
>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>  
>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>> +			next = pte_addr_end(addr, end);
>>  			pmd = pmd_offset(pud, addr);
>>  			if (pmd_none(*pmd))
>>  				continue;
>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>> index 32b6c52d41b9..0de09c6c89d2 100644
>> --- a/include/linux/pgtable.h
>> +++ b/include/linux/pgtable.h
>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>  })
>>  #endif
>>  
>> +#ifndef pte_addr_end
>> +#define pte_addr_end(addr, end)						\
>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>> +})
>> +#endif
>> +
>>  /*
>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>   * and any p?d_bad entries - reporting the error before resetting to none.
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index fe6be0be1f76..89f748601f74 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>  	unsigned long next;
>>  
>>  	for (; addr < end; addr = next, pte++) {
>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>> -		if (next > end)
>> -			next = end;
>> +		next = pte_addr_end(addr, end);
>>  
>>  		if (!pte_present(*pte))
>>  			continue;
>> 
>
>I'm not really a friend of this I have to say. We're simply iterating
>over single pages, not much magic ....

Hmm... yes, we are iterating on Page boundary, while we many have the case
when addr or end is not PAGE_ALIGN.

>
>What would definitely make sense is replacing (addr + PAGE_SIZE) &
>PAGE_MASK; by PAGE_ALIGN() ...
>

No, PAGE_ALIGN() is expanded to be 

	(addr + PAGE_SIZE - 1) & PAGE_MASK;

If we change the code to PAGE_ALIGN(), we would end up with infinite loop.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200701021113.GA51306%40L-31X9LVDL-1304.local.
