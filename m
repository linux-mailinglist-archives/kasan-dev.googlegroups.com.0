Return-Path: <kasan-dev+bncBDQ27FVWWUFRBSE6UTXQKGQETY5R7LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C61B11424D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 15:08:09 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id c8sf2494851qte.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 06:08:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575554888; cv=pass;
        d=google.com; s=arc-20160816;
        b=JVxD2sPYfZiHQAyyu67K93qPUDikJ01MSwmdbtu7JNGGvp7CnY0kM8Nmw85V30HXwi
         VRXEmlVVxrR1YqDIQsWehxBOeONQ1CHga5hgTtRDA7j3xp3sfqI4tqBiHPF8qm8wl4Bc
         Kt+y14KFAdwuiASuI15+P+TtOluNuDJUNd7sJfOh8G1T8UlWbIYVUZUDLn2f2Ebftujg
         9z+nvxokXrH8mU5oT25psWDlf6Hsxf+YNPIc48vT9X+hv1wJQw7GHugYdgP6a6kz6Lch
         O86V33VP5UHUD881dHEA+PeONZcQ02UgswEdno+kJkFIZ+xBTxz1+MxunxuOmSSQAVF+
         yuLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=ZXsABWw19tZnu68lVhyrKsYtjsW+Uic+hDq5WSyv4C4=;
        b=LuI00AVZXJ/hA/IU8JpnLY1hqGPmGTK1ffRbSqbb5CghZE7AiOPxithMjYz6xN05lw
         u17JJQpfU/xCLPv0DMwdR7FPAkHh9uOF43LQUwnYTjxfttIpvnHdiafg0YZA7psQ0z/q
         b3RKekUjO08Tgl1M9rqd8J6VHjyaMe6pMojVfCFaj0oQEsj4rZoUkp3Oldu8+ae1mYvm
         IcWWwPkYdYChxrCqXMmg/Yf6Mqe7D8nATa1C3MwgkMJfNVCr9P+VvxlpBS0TmNKv2g8Q
         fN5n2DxQJddRbVzcNxp38LhdDsc6ez0b6N5tDcvLltzicGa6uT6//Bul3AxPKNxWRWaf
         qhTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YSP7XlpR;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZXsABWw19tZnu68lVhyrKsYtjsW+Uic+hDq5WSyv4C4=;
        b=sTJc76S5RhFrIUc9Wd4yDDc+JLERg2Vol80jdkEIS01XgEBvbocFURnF8Mv05Af80Q
         eSOP29Xmkt9d0ckz2yGZoUT6ZqPS5JnI8Z2jCPhPY2Uuo1osczEtIjRETU2hn/jX5eNw
         HgZxgCKfPr7jGS9hFnsJqTRA+wMjcDYxgGpkEcFD/kBDruJFkdnrn7I6Iyj88sVna44p
         w1y2wQRQbzUH72nNY/qkOHETPwLGTHhSTiLxBkIRnqbh1IiS4SYv+z7VKtxgUmvOev3N
         PAcODz7AaJyMgCPRxLNcVe+ag4yCjzqHvimFspNQ7B4R5YgLm/3/Wg3dViavb02Qo/WR
         PllQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZXsABWw19tZnu68lVhyrKsYtjsW+Uic+hDq5WSyv4C4=;
        b=C98BM9YhhNZfL/A/sBFcvzgPNQdoA0kbVaFVLA0/tEk/7nQNreczns6Eea529GMnMq
         0U1K/q8Sr1ZZYPCdQuHAyo8Ge2YYTshV/1rIxBlB8s/Hj9lv7u1SHCi/laz0VhyrkZId
         3yiCfVp3C82Z3FlUN2q+AfWgKutiRA2M2c4152LBhvXQy0jVwYNH+n397HDMHO+aG2bu
         5VtfzAQInWlSzwapPs3uUEQ4BmOtQQuuE1FAtlK+nq3noKIHA5JhK9SHHP3qNrv9tqNI
         2obJWalbNDiz8YOgQ1O9RnyGr8AboQKTfGsw4LwP7iip2csdA/e/ioyn9WHoyRVm63Fn
         Y3lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXbb4GYpmzkXFh7G265rfog5auA2O5s+Fja4B9WQjhv3GCOAuOB
	uMgfmRpQAArKTOwiJPsRR3E=
X-Google-Smtp-Source: APXvYqyXTGbb3OESKYLDZbBLxt9dbxU4OkWB6JmLNYYg4cRtLc7CDwAkzeaOCM18BRXOX9XU/uc7XA==
X-Received: by 2002:a37:6c6:: with SMTP id 189mr7909371qkg.179.1575554888159;
        Thu, 05 Dec 2019 06:08:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:bfc3:: with SMTP id p186ls1123631qkf.13.gmail; Thu, 05
 Dec 2019 06:08:07 -0800 (PST)
X-Received: by 2002:a37:a1d2:: with SMTP id k201mr2299627qke.239.1575554887720;
        Thu, 05 Dec 2019 06:08:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575554887; cv=none;
        d=google.com; s=arc-20160816;
        b=o4JNkL5S0HKQRa/jhAUhm+YPLzCup//trwi6h98w0kQHa+GwgGkKoDGyyCJSZDYLHS
         o/0hG3/wibi5AveNZXw8+/4irE4JkdmEz+on2a+j8AwN7VNLLpoubLIg7psZ2FcGzKqa
         gmDxSx1bHv0B31HwRr9o3MzzEz9oVMKxAK+5NO/MoN9KhCwUhFxZNJ2COae/VzqUGI9+
         AW+8bNpGkARAKweZDfSCxM4ATWeq5CUWhrX83ajUYi5th6H/EZAaHGZWuo13IAHSy4ZV
         1fnpQbbDKCWpH0QzWuH6pgBdsHzUt4WjLFafKn/+jWAgz0A/VrHDqlwRZscvS3X8qe92
         pBng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=gDPaTgf8omrU7t5A7U4CSa0w+DMkgZN9EG6vHr/qYkw=;
        b=X5Gzhl4fYlALAKYjce/z60tnkIjAejlmd2QP3COigvjCGLbU2/B13wfJXYNQqU7EUU
         lKdai4mS9JwijQqEACzQcXKws0oT95xue7p/JJYGZ1hLDeg1XoEsBlA44Qd4x2zx7qcq
         ntfe5NyaugMrbls7icdV/DbgSLfUJjgkDBRlvEF7sXcCBbAHR6wtxRN5HSdQ9BtrnvQ2
         mcbmWcFOjnbqNgjqsjNVtMB558Bb4Y3IYvaPks3K6OAf9dCWuL6D+IL2IauOphrhBm0y
         NB0Sspu8TM6vrJDSzjoOw0sSuerXOZGdyy5EZ3fyF7+zrxpTCVFPv4ZG5ayiLkLACDf7
         uyiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YSP7XlpR;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id u8si484240qku.7.2019.12.05.06.08.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 06:08:07 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id s35so1343929pjb.7
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 06:08:07 -0800 (PST)
X-Received: by 2002:a17:90a:8989:: with SMTP id v9mr9477111pjn.119.1575554886778;
        Thu, 05 Dec 2019 06:08:06 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-61b9-031c-bed1-3502.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:61b9:31c:bed1:3502])
        by smtp.gmail.com with ESMTPSA id n26sm11980521pgd.46.2019.12.05.06.08.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2019 06:08:05 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, Qian Cai <cai@lca.pw>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH 2/2] kasan: Don't allocate page tables in kasan_release_vmalloc()
In-Reply-To: <87eexjekml.fsf@dja-thinkpad.axtens.net>
References: <20191204204534.32202-1-aryabinin@virtuozzo.com> <20191204204534.32202-2-aryabinin@virtuozzo.com> <87eexjekml.fsf@dja-thinkpad.axtens.net>
Date: Fri, 06 Dec 2019 01:08:02 +1100
Message-ID: <87y2vqdfwd.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=YSP7XlpR;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Daniel Axtens <dja@axtens.net> writes:

> Andrey Ryabinin <aryabinin@virtuozzo.com> writes:
>
> Ah you beat me by a few hours, I was going to send a similar but
> slightly simpler patch - we should be able to use apply_to_page_range
> for the 'inner' part of the range and just walk the page table for the
> possible pages on the edges of the range. That means we could avoid a
> full, loop-driven page table walker. But I'd also be very open to
> generalising apply_to_page_range(); I think I'd add
> apply_to_existing_pages() and add an argument to the static walker
> functions.
>
> Let me try that out and we'll see what it looks like.

I had a go, it's here:

https://lore.kernel.org/linux-mm/20191205140407.1874-1-dja@axtens.net/T/#t

I think it's ugly but not so ugly as to not be worth it. There's also
another patch for syzkaller bugs that Dmitry picked up as patch 3 of the
series, it works and is needed whether you want to go with my approach
or Andrey's.

Regards,
Daniel

>
> Regards,
> Daniel
>
>> The purpose of kasan_release_vmalloc() is to unmap and deallocate shadow
>> memory. The usage of apply_to_page_range() isn't suitable in that scenario
>> because it allocates pages to fill missing page tables entries.
>> This also cause sleep in atomic bug:
>>
>> 	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
>> 	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:
>>
>> 	Call Trace:
>> 	 __dump_stack lib/dump_stack.c:77 [inline]
>> 	 dump_stack+0x199/0x216 lib/dump_stack.c:118
>> 	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
>> 	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
>> 	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
>> 	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
>> 	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
>> 	 alloc_pages include/linux/gfp.h:532 [inline]
>> 	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
>> 	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
>> 	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
>> 	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
>> 	 apply_to_pte_range mm/memory.c:2031 [inline]
>> 	 apply_to_pmd_range mm/memory.c:2068 [inline]
>> 	 apply_to_pud_range mm/memory.c:2088 [inline]
>> 	 apply_to_p4d_range mm/memory.c:2108 [inline]
>> 	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
>> 	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
>> 	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
>> 	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
>> 	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
>> 	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
>> 	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
>> 	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
>> 	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
>> 	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
>> 	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
>> 	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
>> 	 __vmalloc_node mm/vmalloc.c:2607 [inline]
>> 	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
>> 	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
>> 	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
>> 	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
>> 	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
>> 	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
>> 	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
>> 	 __do_sys_setsockopt net/socket.c:2133 [inline]
>> 	 __se_sys_setsockopt net/socket.c:2130 [inline]
>> 	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
>> 	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
>> 	 entry_SYSCALL_64_after_hwframe+0x49/0xbe
>>
>> Add kasan_unmap_page_range() which skips empty page table entries instead
>> of allocating them.
>>
>> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
>> Reported-by: Dmitry Vyukov <dvyukov@google.com>
>> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> ---
>>  mm/kasan/common.c | 82 +++++++++++++++++++++++++++++++++++++++--------
>>  1 file changed, 68 insertions(+), 14 deletions(-)
>>
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index a1e6273be8c3..e9ba7d8ad324 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -857,22 +857,77 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
>>  	kasan_unpoison_shadow(start, size);
>>  }
>>  
>> -static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>> -					void *unused)
>> +static void kasan_unmap_pte_range(pmd_t *pmd, unsigned long addr,
>> +				unsigned long end)
>>  {
>> -	unsigned long page;
>> +	pte_t *pte;
>>  
>> -	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
>> +	pte = pte_offset_kernel(pmd, addr);
>> +	do {
>> +		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
>>  
>> -	spin_lock(&init_mm.page_table_lock);
>> +		if (!pte_none(ptent))
>> +			__free_page(pte_page(ptent));
>> +	} while (pte++, addr += PAGE_SIZE, addr != end);
>> +}
>>  
>> -	if (likely(!pte_none(*ptep))) {
>> -		pte_clear(&init_mm, addr, ptep);
>> -		free_page(page);
>> -	}
>> -	spin_unlock(&init_mm.page_table_lock);
>> +static void kasan_unmap_pmd_range(pud_t *pud, unsigned long addr,
>> +				unsigned long end)
>> +{
>> +	pmd_t *pmd;
>> +	unsigned long next;
>>  
>> -	return 0;
>> +	pmd = pmd_offset(pud, addr);
>> +	do {
>> +		next = pmd_addr_end(addr, end);
>> +		if (pmd_none_or_clear_bad(pmd))
>> +			continue;
>> +		kasan_unmap_pte_range(pmd, addr, next);
>> +	} while (pmd++, addr = next, addr != end);
>> +}
>> +
>> +static void kasan_unmap_pud_range(p4d_t *p4d, unsigned long addr,
>> +				unsigned long end)
>> +{
>> +	pud_t *pud;
>> +	unsigned long next;
>> +
>> +	pud = pud_offset(p4d, addr);
>> +	do {
>> +		next = pud_addr_end(addr, end);
>> +		if (pud_none_or_clear_bad(pud))
>> +			continue;
>> +		kasan_unmap_pmd_range(pud, addr, next);
>> +	} while (pud++, addr = next, addr != end);
>> +}
>> +
>> +static void kasan_unmap_p4d_range(pgd_t *pgd, unsigned long addr,
>> +				unsigned long end)
>> +{
>> +	p4d_t *p4d;
>> +	unsigned long next;
>> +
>> +	p4d = p4d_offset(pgd, addr);
>> +	do {
>> +		next = p4d_addr_end(addr, end);
>> +		if (p4d_none_or_clear_bad(p4d))
>> +			continue;
>> +		kasan_unmap_pud_range(p4d, addr, next);
>> +	} while (p4d++, addr = next, addr != end);
>> +}
>> +
>> +static void kasan_unmap_page_range(unsigned long addr, unsigned long end)
>> +{
>> +	pgd_t *pgd;
>> +	unsigned long next;
>> +
>> +	pgd = pgd_offset_k(addr);
>> +	do {
>> +		next = pgd_addr_end(addr, end);
>> +		if (pgd_none_or_clear_bad(pgd))
>> +			continue;
>> +		kasan_unmap_p4d_range(pgd, addr, next);
>> +	} while (pgd++, addr = next, addr != end);
>>  }
>>  
>>  /*
>> @@ -978,9 +1033,8 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>>  	shadow_end = kasan_mem_to_shadow((void *)region_end);
>>  
>>  	if (shadow_end > shadow_start) {
>> -		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
>> -				    (unsigned long)(shadow_end - shadow_start),
>> -				    kasan_depopulate_vmalloc_pte, NULL);
>> +		kasan_unmap_page_range((unsigned long)shadow_start,
>> +				    (unsigned long)shadow_end);
>>  		flush_tlb_kernel_range((unsigned long)shadow_start,
>>  				       (unsigned long)shadow_end);
>>  	}
>> -- 
>> 2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2vqdfwd.fsf%40dja-thinkpad.axtens.net.
