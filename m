Return-Path: <kasan-dev+bncBDQ27FVWWUFRBF4CUHXQKGQE5C7JTTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98A9811382A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 00:28:24 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id m26sf852432otk.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 15:28:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575502103; cv=pass;
        d=google.com; s=arc-20160816;
        b=vvT5SeYcJrxSsMbTmDgcsmhD5htz2B5/Z1UCycljFlMp+YkPAoP6GIf0bEZX1A+wbq
         qRffxMs7z+gV9RfpNtcgb2vPtFEmNR1Dzi83A45z7h+lxZzh2IBCeeWZH9Rk8MSeu+Lb
         CNSs1Na0g3RD0J7XnUAVYz+ldLK41mD3m17bz3E4lbi4N0dw3aWq9+okmyM9n3ToC+pw
         KMVsVF1NQNjQX4gWQ1Auy88phOoe1aCLkjfTW8E8VtttdKR+ld298vPefgLiCNVM/0KB
         XfX0G3F0ygGdDGLa8D3q6sIx+KlZKoa0RwopOdzFmdN7pVpbd8MffNSeYpa4nl2OFuWj
         ygEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=7gELG7yGeVI6F6R3MZUvcppY3kjXTDY60deCB6EFFlo=;
        b=BpOEhaQQtJNolwJ49xJqQhhJX+Hnrz6DQquPL81LdykjZooziTVtyePSFLUEyzgFeZ
         dJUj8axuXGsFDt+ez39+GNfJGo700uRje7IKhTofA8mYe2dFl8akg85nKDMvKxEIXTer
         TnY3kKZphdgE1kF4GnvMPdNATSjLzc88SaDKjF9/+lhMkkhyYRpq7IwhDJZcct0+vQAW
         FQgt9zlVI38d9IG5aT4r+KD5hKXgzX2U9tusIbG8mEn+JZ7GP/UZp4m+LcGH2TUiekYZ
         da0EYCz6S7eeD+oQkpFhIkvaQxEhu8ryCZ7cMyUOsJRhjubJDh5TIJE+4Vs9myPJJcag
         CFAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="cy/5prub";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gELG7yGeVI6F6R3MZUvcppY3kjXTDY60deCB6EFFlo=;
        b=ZkME5Q1qg9/eaRaIQvQmS6b0yl4i6y1OnpqCcV8wn0voBrympeOAf685/rfrN+Vp28
         yx3CLpa/pqXbmVjHNFVjXNEITFq6OnA6mwaj+0PWZB1eM/NI1s5N2uciF7zhMOwicqvf
         zQnipEl5nJzf7nVCkLEuQAt6RKm0C87uWE2Rls2bYrXJm6FsZ+Dvn+yrr2dzMbi2tGKR
         gRDATb+dMs76JeZY0Hfg018rYX/t8ImSU8JPRsnjyT8xep78fJZvOorN4HPVa7EfA4Gt
         XnJjTpeAr4Trpo4//FPeA9VjmQiygzP6+w0Rhw+zi9Wocvj68q6lvZAMplTFfxRC9ip5
         ZRSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gELG7yGeVI6F6R3MZUvcppY3kjXTDY60deCB6EFFlo=;
        b=Cwk/WsNTK9vs+eI56SZoVnedITEwkSLFaXyo0R7jxXU2mRoqHkR75qfjQVKfZ5HI2M
         rwLqxRzXEEheTRdXNfy/Oxuyl1fiH3x3XJ1mavrzs+Vi5R0QGZKbn69bUhY5/JG2MyHf
         mQQFv4GQ/4LiJ/E8+KInRi3r6+8nIFbCfZsXY8KdMYYMayjqnOPKGHUpt7FfeVmI+XPz
         P3qvD013lkg5DNl8pdh8NfLmOt9Cd8m46OI+qUZNuMzC4Su9eqQqwzE62KmIsn4QnE2Z
         nJTDF28/Q/r95z/nGBTr41SLTQTNYVf2s0KaQoejXsyZ7UHF41wAQ7fiwpwtH2vzIf5K
         B2BA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUWbzy0X2Th1Bz0rpIMTiRPvREIxmogRVXIWU+zGM2q/Z0dgcgE
	9ODhTRGM9X84aFDptQTNFUI=
X-Google-Smtp-Source: APXvYqz/22iPfRI2T7w9nJJOkeYprHB3b4LF1E5GvZtpRcoZUzp02Rg7qAr82TpBJQ/+Le0yKCUELA==
X-Received: by 2002:a05:6808:b1c:: with SMTP id s28mr5007229oij.2.1575502103311;
        Wed, 04 Dec 2019 15:28:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4597:: with SMTP id z23ls291297oib.15.gmail; Wed, 04 Dec
 2019 15:28:22 -0800 (PST)
X-Received: by 2002:aca:5dd7:: with SMTP id r206mr1135978oib.3.1575502102807;
        Wed, 04 Dec 2019 15:28:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575502102; cv=none;
        d=google.com; s=arc-20160816;
        b=e+019QurqlMFs8sEArGLaK0gntgslx8iUMQrWBNsoOmZWS9h8bax4POiaGYczQt27+
         RAMH1XKkMoBugP6RBvGFjL70JcgEswaoVZkKR5eccWfpMF4u6/ACb5EXS4hJsX1HgK24
         h4fXvWFo69cdUkTXTVs9MG/kDLkCqLtLvwmlZ5sK8XI+ej8EBFTj3LztmSUfsWQ82OCl
         E6dw8TqxsRWnuxssYs17p0Dy0X7APH8f7z2BZmARH4MP/awPIVBOavXpyaIWzBD+qwMT
         iaLzft/5ZZLaXA5i3ZR/Ayt75XHIDwg8+Ic32TbjNzHJf0awDtHDldrFqptmQ4/j/+/7
         +4Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=KnZoHBXFVRHNSaPqiDHNhvaOhX8uk2RjtLzlrEN0A1o=;
        b=bCGHDL+ucDW//HjBGiKAYIttRdUqPJBk4/+cbAtrOnMEtvygveli286o3/sgV6UsKm
         GNcmzjlEHADLIoyAA4ymtdvege8N8SAS9oLZ6rVd22z9ULcxds+Qs6zSHi1Vur8gsew9
         iVN0ju6BLKnveVEpoQLLCaRitLRrDNMZKKIaUv6ipkVaTbJWuVkXYrCvpBTSHOpeMPCO
         zfSpvmtZ9nbNMRLIpScI2Z5XtD3Ggfntp52ZXKQ1wEqY8fJpi4rMtGkmaOO2blf/ybwq
         GGICLRCcqA48xbrD0IN78aVK0YqHjD204KbEimOCsss2ZpnY2LToNvhwD90qYW7ssJpb
         IDDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="cy/5prub";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id v14si411146otn.0.2019.12.04.15.28.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 15:28:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id h13so397094plr.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 15:28:22 -0800 (PST)
X-Received: by 2002:a17:90a:8901:: with SMTP id u1mr5995266pjn.64.1575502102372;
        Wed, 04 Dec 2019 15:28:22 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-7daa-d2ea-7edb-cfe8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:7daa:d2ea:7edb:cfe8])
        by smtp.gmail.com with ESMTPSA id v29sm8375949pgl.88.2019.12.04.15.28.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Dec 2019 15:28:21 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, Qian Cai <cai@lca.pw>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH 2/2] kasan: Don't allocate page tables in kasan_release_vmalloc()
In-Reply-To: <20191204204534.32202-2-aryabinin@virtuozzo.com>
References: <20191204204534.32202-1-aryabinin@virtuozzo.com> <20191204204534.32202-2-aryabinin@virtuozzo.com>
Date: Thu, 05 Dec 2019 10:28:18 +1100
Message-ID: <87eexjekml.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="cy/5prub";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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

Andrey Ryabinin <aryabinin@virtuozzo.com> writes:

Ah you beat me by a few hours, I was going to send a similar but
slightly simpler patch - we should be able to use apply_to_page_range
for the 'inner' part of the range and just walk the page table for the
possible pages on the edges of the range. That means we could avoid a
full, loop-driven page table walker. But I'd also be very open to
generalising apply_to_page_range(); I think I'd add
apply_to_existing_pages() and add an argument to the static walker
functions.

Let me try that out and we'll see what it looks like.

Regards,
Daniel

> The purpose of kasan_release_vmalloc() is to unmap and deallocate shadow
> memory. The usage of apply_to_page_range() isn't suitable in that scenario
> because it allocates pages to fill missing page tables entries.
> This also cause sleep in atomic bug:
>
> 	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> 	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:
>
> 	Call Trace:
> 	 __dump_stack lib/dump_stack.c:77 [inline]
> 	 dump_stack+0x199/0x216 lib/dump_stack.c:118
> 	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
> 	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
> 	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
> 	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
> 	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
> 	 alloc_pages include/linux/gfp.h:532 [inline]
> 	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
> 	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
> 	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
> 	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
> 	 apply_to_pte_range mm/memory.c:2031 [inline]
> 	 apply_to_pmd_range mm/memory.c:2068 [inline]
> 	 apply_to_pud_range mm/memory.c:2088 [inline]
> 	 apply_to_p4d_range mm/memory.c:2108 [inline]
> 	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
> 	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
> 	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
> 	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
> 	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
> 	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
> 	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
> 	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
> 	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
> 	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
> 	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
> 	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
> 	 __vmalloc_node mm/vmalloc.c:2607 [inline]
> 	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
> 	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
> 	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
> 	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
> 	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
> 	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
> 	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
> 	 __do_sys_setsockopt net/socket.c:2133 [inline]
> 	 __se_sys_setsockopt net/socket.c:2130 [inline]
> 	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
> 	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
> 	 entry_SYSCALL_64_after_hwframe+0x49/0xbe
>
> Add kasan_unmap_page_range() which skips empty page table entries instead
> of allocating them.
>
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> ---
>  mm/kasan/common.c | 82 +++++++++++++++++++++++++++++++++++++++--------
>  1 file changed, 68 insertions(+), 14 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a1e6273be8c3..e9ba7d8ad324 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -857,22 +857,77 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
>  	kasan_unpoison_shadow(start, size);
>  }
>  
> -static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> -					void *unused)
> +static void kasan_unmap_pte_range(pmd_t *pmd, unsigned long addr,
> +				unsigned long end)
>  {
> -	unsigned long page;
> +	pte_t *pte;
>  
> -	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> +	pte = pte_offset_kernel(pmd, addr);
> +	do {
> +		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
>  
> -	spin_lock(&init_mm.page_table_lock);
> +		if (!pte_none(ptent))
> +			__free_page(pte_page(ptent));
> +	} while (pte++, addr += PAGE_SIZE, addr != end);
> +}
>  
> -	if (likely(!pte_none(*ptep))) {
> -		pte_clear(&init_mm, addr, ptep);
> -		free_page(page);
> -	}
> -	spin_unlock(&init_mm.page_table_lock);
> +static void kasan_unmap_pmd_range(pud_t *pud, unsigned long addr,
> +				unsigned long end)
> +{
> +	pmd_t *pmd;
> +	unsigned long next;
>  
> -	return 0;
> +	pmd = pmd_offset(pud, addr);
> +	do {
> +		next = pmd_addr_end(addr, end);
> +		if (pmd_none_or_clear_bad(pmd))
> +			continue;
> +		kasan_unmap_pte_range(pmd, addr, next);
> +	} while (pmd++, addr = next, addr != end);
> +}
> +
> +static void kasan_unmap_pud_range(p4d_t *p4d, unsigned long addr,
> +				unsigned long end)
> +{
> +	pud_t *pud;
> +	unsigned long next;
> +
> +	pud = pud_offset(p4d, addr);
> +	do {
> +		next = pud_addr_end(addr, end);
> +		if (pud_none_or_clear_bad(pud))
> +			continue;
> +		kasan_unmap_pmd_range(pud, addr, next);
> +	} while (pud++, addr = next, addr != end);
> +}
> +
> +static void kasan_unmap_p4d_range(pgd_t *pgd, unsigned long addr,
> +				unsigned long end)
> +{
> +	p4d_t *p4d;
> +	unsigned long next;
> +
> +	p4d = p4d_offset(pgd, addr);
> +	do {
> +		next = p4d_addr_end(addr, end);
> +		if (p4d_none_or_clear_bad(p4d))
> +			continue;
> +		kasan_unmap_pud_range(p4d, addr, next);
> +	} while (p4d++, addr = next, addr != end);
> +}
> +
> +static void kasan_unmap_page_range(unsigned long addr, unsigned long end)
> +{
> +	pgd_t *pgd;
> +	unsigned long next;
> +
> +	pgd = pgd_offset_k(addr);
> +	do {
> +		next = pgd_addr_end(addr, end);
> +		if (pgd_none_or_clear_bad(pgd))
> +			continue;
> +		kasan_unmap_p4d_range(pgd, addr, next);
> +	} while (pgd++, addr = next, addr != end);
>  }
>  
>  /*
> @@ -978,9 +1033,8 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  	shadow_end = kasan_mem_to_shadow((void *)region_end);
>  
>  	if (shadow_end > shadow_start) {
> -		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
> -				    (unsigned long)(shadow_end - shadow_start),
> -				    kasan_depopulate_vmalloc_pte, NULL);
> +		kasan_unmap_page_range((unsigned long)shadow_start,
> +				    (unsigned long)shadow_end);
>  		flush_tlb_kernel_range((unsigned long)shadow_start,
>  				       (unsigned long)shadow_end);
>  	}
> -- 
> 2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87eexjekml.fsf%40dja-thinkpad.axtens.net.
