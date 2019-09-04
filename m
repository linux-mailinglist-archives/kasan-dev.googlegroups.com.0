Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBRPFX3VQKGQEO6HWAYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A9230A82B8
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 14:49:09 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id n3sf738990wmf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 05:49:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567601349; cv=pass;
        d=google.com; s=arc-20160816;
        b=qnhE+EKG/Qvyv6qK1ST2Pf2sY1RKs8V1m7BKXjE526R/6zSAgWsOmN+9QdElUiW/Vv
         xShT9yGH2tqNDLC04f6WtNA65+zpP7/JoKhkaovhnMjk1vJX2IH7MrURBC6ZxL1NGkul
         F64Mdr0U+euYCDDUoHVQGg4uqjmQUOoOioHInBrKjW2NH5jdiwuH1btEHV0wMn9ThEww
         CwlbG8630D/Uu/S6PIUrrhuVIhObS8g3M0j/xr+xUSLzpLZsW881QU3e2LT8fzyh9m0Q
         JY29gLbq9MiRYun4T2sPBMhJ77l+uT+mIdxG7Wx/f1to0gitEhDIte/eSMx1v6QmK0m8
         MMzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=mGFTWDlemYM3d5cJJpgBVc8jTO2irPZNSyZw/9+cUYo=;
        b=bQOFGNZ9EjppXstjFPUXhvZ0bNd6brgyHsmQgu7BH6A06dEWNrkws0vA067qo15GGY
         pj2v7IN2CavPzMCWDVm/wMaRxKyifBmhr1fERDMSmaYoFtwbvhWq9qGchQiZ6qVkcgXy
         O5TIHkMiAD+9N8ph4sOk3ZImG5DHWTT2VE83tvWOQdB5AOakGAG04OWSfzeyubtcED7S
         cyrsfOIvL/gEOcW11rqkWveY6rD/rZZvZyX0A/ZD/oLEUP6kd/fGwidqQC3hZDRuFyqR
         raWpdrU2hgs2ciYXeTGssG5Y3j/Z5Gv+/sjLRTHkJyLLqZNnpbusYnIddm3nZWSzgt86
         mfXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mGFTWDlemYM3d5cJJpgBVc8jTO2irPZNSyZw/9+cUYo=;
        b=PeHeGiUqXMtXEMCC17PyXuvJ9v3EtOHvbkle93L7s4XFpAi6Rblng3aNBpjsRZaKJw
         JKYRNgj57JOeav5arLVFs+nHLaHSAo0YGOBjCvxSPACLL2IqbwNJxbA5u3QA8topKdvW
         CYzuiMQJv8exc2bxdkrep7ai2oJG+fww8N8J43Mq5lxEpF5MXzXFrmPckLEBICYP4qze
         BtHkKZLwr1DL8rtOrr1ejTNDKGo9iDu8Nyi9o9070dt3oYKE6uqlNNv7EXOI2O+omwUR
         sZYISrPcVksmdwMsub9d27OZRlw3xgazJH7aJgopbQt9KIJpEYYRlgtM0E85mSakQytA
         5ZmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mGFTWDlemYM3d5cJJpgBVc8jTO2irPZNSyZw/9+cUYo=;
        b=RMGivPMTDpAiDhzpv9mWGTRuOSEn9eBwGBh68xAplaLvSGH2U/drXuf4qiTTUb1xBW
         QiSKzjAE8ukEMR/47+NYPuW3fEDiJ4Cq1/jHta4PfprI6PHC/h6VJbwoYpn6KB62bq4a
         /Q9pbORYbxd30bVFDoSdz1TgiYJdTWEQzm5YMdBdJACEZvz/aoNLMslPMy3JcG6RhZlX
         cll0BRb88X9+Mh69jwlSevNq0XLNeEGC5PKxWOoD/TDAzIaW5ck4kMGb6wjEl9sA6hii
         KbqL2Rn6mJOkwUOPqI7e1HbonofFmRtRHwr7utKAoBkBL686lT4Q+4qLlD7AekpfUhhC
         9LAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXa4M/Adhuc3vPK2CJLcXppFdsrysrtbVUUcOi1Ic2FmSbhCYlI
	6r4clyCoMpTV7v4YbmgC9j8=
X-Google-Smtp-Source: APXvYqwjcqN5Pz6mx05RQd5CRkcNy83EHCGnrp+zoldYWiBrxEeeh7dvq/0ZwvgKfBkmngqoxznstA==
X-Received: by 2002:adf:fd03:: with SMTP id e3mr40183515wrr.291.1567601349373;
        Wed, 04 Sep 2019 05:49:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a78e:: with SMTP id q136ls1158545wme.1.gmail; Wed, 04
 Sep 2019 05:49:08 -0700 (PDT)
X-Received: by 2002:a1c:a54a:: with SMTP id o71mr4423847wme.51.1567601348851;
        Wed, 04 Sep 2019 05:49:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567601348; cv=none;
        d=google.com; s=arc-20160816;
        b=SFU3i9jhNqsqWZER8zL5VGJ7EwHFoMjGGv6v00WehEl06pf1yrrW9yMEpoTJVN0Zkg
         CLfrz24MYm2ScxrsrxJq0A+3VyJv7vlzjr1coeTn0OmWt7DqbKSqOwrRHavJ01FwOoeT
         uu4r3OKs48Z+WSJp+qI8USDfJgq9xtP5/ekyG0XIisukmS2uROZqUo1xDDybjcAE6/QH
         HzVOyAN9BYZX7ZxLvKBX0RM9bSazMm9yyTM2lKet16bzEaCdM1c1LvNp0FysDXa7UbFP
         HUqAruilb9L93JJO2F+NxKcbsxT8Pgjr7eJeVIVLZjIuRPmThQTLM2unh8RLX1SH2qVq
         gFFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PC5IFzzSR7B/D3u/zLTll22794H9JBcYpW4N8jNkrT8=;
        b=DdontK00p1wq2KKH1RMttEgj5eyWb8KvGFZT6E24jrgDY8/NSx0OTU0kUeaAa9Jbm1
         vaqb144MamrGvFVF6txmW3YsW0/frdvQel/A364h8xZ03b/b8Rljl1KfUmKMRO7mA75k
         oc8bDvIAx5pOl4GoFU4kt7iRgyUx5z0DElUxEFaFsOW+gS3zI/gu0Lu8TZe6zO4iaSoz
         oE8zpfBMw+80g1OnbUW/5lWzr1NHBWDU8C4IOOTUR2GMPRbR5DZ7VqsdMO7NbMg7wv15
         wP2+C0XcQGXqnnP5HfgKlncjDbK6MT8qHD1SEB3TtPTU0OsLcE5/KLwBfvRB96vhN8ar
         JYBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id l14si145031wmc.1.2019.09.04.05.49.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Sep 2019 05:49:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id F03BCAF47;
	Wed,  4 Sep 2019 12:49:07 +0000 (UTC)
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
Date: Wed, 4 Sep 2019 14:49:06 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/4/19 8:51 AM, Walter Wu wrote:
> This patch is KASAN report adds the alloc/free stacks for page allocator
> in order to help programmer to see memory corruption caused by page.
> 
> By default, KASAN doesn't record alloc/free stack for page allocator.
> It is difficult to fix up page use-after-free issue.
> 
> This feature depends on page owner to record the last stack of pages.
> It is very helpful for solving the page use-after-free or out-of-bound.
> 
> KASAN report will show the last stack of page, it may be:
> a) If page is in-use state, then it prints alloc stack.
>    It is useful to fix up page out-of-bound issue.

I expect this will conflict both in syntax and semantics with my series [1] that
adds the freeing stack to page_owner when used together with debug_pagealloc,
and it's now in mmotm. Glad others see the need as well :) Perhaps you could
review the series, see if it fulfils your usecase (AFAICS the series should be a
superset, by storing both stacks at once), and perhaps either make KASAN enable
debug_pagealloc, or turn KASAN into an alternative enabler of the functionality
there?

Thanks, Vlastimil

[1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/t/#u

> BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x90
> Write of size 1 at addr ffffffc0d64ea00a by task cat/115
> ...
> Allocation stack of page:
>  prep_new_page+0x1a0/0x1d8
>  get_page_from_freelist+0xd78/0x2748
>  __alloc_pages_nodemask+0x1d4/0x1978
>  kmalloc_order+0x28/0x58
>  kmalloc_order_trace+0x28/0xe0
>  kmalloc_pagealloc_oob_right+0x2c/0x90
> 
> b) If page is freed state, then it prints free stack.
>    It is useful to fix up page use-after-free issue.
> 
> BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
> Write of size 1 at addr ffffffc0d651c000 by task cat/115
> ...
> Free stack of page:
>  kasan_free_pages+0x68/0x70
>  __free_pages_ok+0x3c0/0x1328
>  __free_pages+0x50/0x78
>  kfree+0x1c4/0x250
>  kmalloc_pagealloc_uaf+0x38/0x80
> 
> 
> This has been discussed, please refer below link.
> https://bugzilla.kernel.org/show_bug.cgi?id=203967
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
>  lib/Kconfig.kasan | 9 +++++++++
>  mm/kasan/common.c | 6 ++++++
>  2 files changed, 15 insertions(+)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 4fafba1a923b..ba17f706b5f8 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -135,6 +135,15 @@ config KASAN_S390_4_LEVEL_PAGING
>  	  to 3TB of RAM with KASan enabled). This options allows to force
>  	  4-level paging instead.
>  
> +config KASAN_DUMP_PAGE
> +	bool "Dump the page last stack information"
> +	depends on KASAN && PAGE_OWNER
> +	help
> +	  By default, KASAN doesn't record alloc/free stack for page allocator.
> +	  It is difficult to fix up page use-after-free issue.
> +	  This feature depends on page owner to record the last stack of page.
> +	  It is very helpful for solving the page use-after-free or out-of-bound.
> +
>  config TEST_KASAN
>  	tristate "Module for testing KASAN for bug detection"
>  	depends on m && KASAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2277b82902d8..2a32474efa74 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -35,6 +35,7 @@
>  #include <linux/vmalloc.h>
>  #include <linux/bug.h>
>  #include <linux/uaccess.h>
> +#include <linux/page_owner.h>
>  
>  #include "kasan.h"
>  #include "../slab.h"
> @@ -227,6 +228,11 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
>  
>  void kasan_free_pages(struct page *page, unsigned int order)
>  {
> +#ifdef CONFIG_KASAN_DUMP_PAGE
> +	gfp_t gfp_flags = GFP_KERNEL;
> +
> +	set_page_owner(page, order, gfp_flags);
> +#endif
>  	if (likely(!PageHighMem(page)))
>  		kasan_poison_shadow(page_address(page),
>  				PAGE_SIZE << order,
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/401064ae-279d-bef3-a8d5-0fe155d0886d%40suse.cz.
