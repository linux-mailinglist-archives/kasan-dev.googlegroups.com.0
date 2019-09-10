Return-Path: <kasan-dev+bncBAABBGPF3XVQKGQEG7M6YPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F4A7AE758
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 11:53:30 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id d20sf10330552otp.17
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 02:53:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568109209; cv=pass;
        d=google.com; s=arc-20160816;
        b=pneBV/HJ0GMOPTmrSV7BvX1f3nr71bzSiQbznr/JkuaOG8/8hEvRS9aHBNVy+ADuu1
         Mxxo1R6ipPduewVSfgawyd320LLGArbyyU2SmBuXCOpUOhLfbn7sBK6pQ+3Wd6iPo5F5
         vpiIR6JEhC95wQaYwm2u1lgbdSYi1uD+Tt9PrfWw4Q7qFvPevxkBXdDRqIid8YbFN/xd
         ASs4q6QBB2n7oI7FtOWrNvghAX2FuQCGZS6sF+8qBhsYur5Tt+9pNnRxyu5NsidzZJa0
         hnmbXTGYnAF1sNs6EvsHEC04BQITl1sAgHsWfEQq6zyEc4FVnI0pQEYfjzqNp3gHxiea
         /33w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=K+cO/PQGkKraaRgniLV1B1J2T9hhv6tXXTpUjaEmIN8=;
        b=rhg8B3ID7oJhSrp1JsAr3sseBnPaRsxAT9VjCFhD2kcDCRRqC/LYE66oPgnttRyXbL
         Z9iiewty/pxZJqfF6lmtWtkfdff8tFb5ahzpI4DDDgSpxu6Vo1Uk73xvRK37XHSqhkaX
         uFV88TE6REslmOHuJfV4ZmP6sJ5pLh7G0f7IPSZa4WdpeLS5k5WDc+l7WM1ON+BEMt5B
         gARbCZIwLU90+ZZbWPH1lZrjvkwDG19upB/W8YqiGtQsXqvt1Yp7pl563ZHj4xHGdiTe
         vBeZJOtDWfHcCe1QAyPzIiONbwmFwZtz5oLj0RcTNXlffJEQRiIq+bPdG+18rZWybzpX
         8fdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K+cO/PQGkKraaRgniLV1B1J2T9hhv6tXXTpUjaEmIN8=;
        b=TUhM4NwheGpVjDI7Z3EAvpzZi/736E2inZ1qg3ZPzc5OkJydDjCNt/MeELEUwPvE67
         63FD8fcwA34G7LTHnOv5uAiU7HfQk4PcFxhmI1rNKKKNynqGokB8ad6H/5Vq29LFVu0V
         jBUDdHEcwzW69LgXgn8QDjxoEZ05N7G7b0Vxxm3xQR51sj/vHwVW5jaLUXLCGLRKVeix
         bksscJhhQ4HOFqkrXaHTEjNfRjic9+9stqRa/v/slvSsIZs4HT68Jsatbt4Zt8ZFOR35
         3DXg9Ah289LaESiu2TkYYqCnzAaU3teg66xc8HFeZ9HaVHlFWlkg9z+S7EC4kc8BkjJ7
         tsWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K+cO/PQGkKraaRgniLV1B1J2T9hhv6tXXTpUjaEmIN8=;
        b=f01DGvTlz4SznLY98DmaSsccIal6O8TSQr+l7zpxTKiHVhErZGXvNzV0kdKw5xJIvW
         p/l2s3yb6rh0doBfxpvzAIB5D1bba8+r5zMrrbXxS1JPVDoAHF0Wx6dC4V1P4/21ATUQ
         44+183fpWkYR6GtUoCzIbPPlxv9XhtckpkxCHJ5LjMwcwhEnO0rHSlAxIN6xaZ3YbXpX
         TAjGqfrY2LrVEuxQFQtF2PnhgkOQCOOsmDXF3LpjO4sr1pq+E4p+RPVxdPgHevxC2sQM
         tthaOYB08HCY2vUNEzRN32T9REZfKpQoffqvwErlPTAzVfFZ1UbYiTW+aeXoXxnup8tI
         ebmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUSQT+KAD4b9my75X9J3ecHsBMbptjI8sHYa/X+7KIK9iEoo2ET
	aNj6OWIOWfarwpaErRV6AUw=
X-Google-Smtp-Source: APXvYqxvDquLxkDKHhm9KND19SWTuLLzbmQ3rpPszv0NZJ3rSgYbu4OCBi/4a7Iaeolk1LdUcHE66Q==
X-Received: by 2002:a9d:6852:: with SMTP id c18mr26577143oto.310.1568109209189;
        Tue, 10 Sep 2019 02:53:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2095:: with SMTP id y21ls1992784otq.5.gmail; Tue,
 10 Sep 2019 02:53:29 -0700 (PDT)
X-Received: by 2002:a05:6830:1446:: with SMTP id w6mr6348010otp.183.1568109208989;
        Tue, 10 Sep 2019 02:53:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568109208; cv=none;
        d=google.com; s=arc-20160816;
        b=rFcdZArS7sQj/N8Nzmkm4Kgj+odlWIKOKr/RJYi+W4c3eBR3vsz4+EIe81gDwcM9L1
         19wxFoFsh/A7NrVmOANfLp2vEGvG/PWsldX0tz9CyU4EfY+zgw1Qm165FitFBn6to0WY
         JQ8FKtpF8Bd0NUNqVPzrTNElOqTAdCOvBu2/D7wIAr70p1y4KE6eAtSrpCg9L+4IHz1d
         44JAS68MWMRzGe+wOwEO4OPF6YCeEq93lN3oAmrkSqfGSd296+Z3dsfwghXkk8my0reG
         8UPbSTGT8UTtalQ1X9PuLt5bVaFjqSx+EGQWL21+5rylh6cp7GTxgQy85VPwMAZdzwCr
         ZYEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=uMUjVEOW6+klAW0D/p3IklnpSnYgShMcjEeYN7symRI=;
        b=GxAYeQaHLBQ/xH7rV3yj3LVQtjc//NztNbhHRBjONM3eNAUHgBK9Da83iw/V2ePguY
         3k/he0CunlGiPHpNeHTfi/3ez43Adi+ad44yPYK436CdpO432Lvj8tArEVh/B34PBL6l
         OD+Z+fshlhegFZaLR1pCraeOrzzic+DlE70z9TFMVvyapm8FLIx5l+G2a4dMYF/FM8sg
         ajg3nABF8pSfavxDyIe1zR1sCU9soZfWBklD3lOp2zIUj2EoRdxmLv1Geb8nZHxAsmgv
         ryJGIQEPPeIxktfrQKE/jH76fQOMDzVOrRjscl8AELxTMd3R8lE7rU1Ka2rCC7uQ6pBL
         ogYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id m2si951405otn.4.2019.09.10.02.53.28
        for <kasan-dev@googlegroups.com>;
        Tue, 10 Sep 2019 02:53:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 39136821071a4a61acaf347912375c23-20190910
X-UUID: 39136821071a4a61acaf347912375c23-20190910
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 761175253; Tue, 10 Sep 2019 17:53:25 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 10 Sep 2019 17:53:23 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 10 Sep 2019 17:53:23 +0800
Message-ID: <1568109204.24886.14.camel@mtksdccf07>
Subject: Re: [PATCH v2 0/2] mm/kasan: dump alloc/free stack for page
 allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, "Arnd
 Bergmann" <arnd@arndb.de>, Qian Cai <cai@lca.pw>
CC: Alexander Potapenko <glider@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>, "Thomas
 Gleixner" <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Tue, 10 Sep 2019 17:53:24 +0800
In-Reply-To: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
References: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2019-09-09 at 16:24 +0800, walter-zh.wu@mediatek.com wrote:
> From: Walter Wu <walter-zh.wu@mediatek.com>
> 
> This patch is KASAN report adds the alloc/free stacks for page allocator
> in order to help programmer to see memory corruption caused by page.
> 
> By default, KASAN doesn't record alloc and free stack for page allocator.
> It is difficult to fix up page use-after-free or dobule-free issue.
> 
> Our patchsets will record the last stack of pages.
> It is very helpful for solving the page use-after-free or double-free.
> 
> KASAN report will show the last stack of page, it may be:
> a) If page is in-use state, then it prints alloc stack.
>    It is useful to fix up page out-of-bound issue.
> 
> BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x90
> Write of size 1 at addr ffffffc0d64ea00a by task cat/115
> ...
> Allocation stack of page:
>  set_page_stack.constprop.1+0x30/0xc8
>  kasan_alloc_pages+0x18/0x38
>  prep_new_page+0x5c/0x150
>  get_page_from_freelist+0xb8c/0x17c8
>  __alloc_pages_nodemask+0x1a0/0x11b0
>  kmalloc_order+0x28/0x58
>  kmalloc_order_trace+0x28/0xe0
>  kmalloc_pagealloc_oob_right+0x2c/0x68
> 
> b) If page is freed state, then it prints free stack.
>    It is useful to fix up page use-after-free or double-free issue.
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
> This has been discussed, please refer below link.
> https://bugzilla.kernel.org/show_bug.cgi?id=203967
> 
> Changes since v1:
> - slim page_owner and move it into kasan
> - enable the feature by default
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
>  include/linux/kasan.h |  1 +
>  lib/Kconfig.kasan     |  2 ++
>  mm/kasan/common.c     | 32 ++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h      |  5 +++++
>  mm/kasan/report.c     | 27 +++++++++++++++++++++++++++
>  5 files changed, 67 insertions(+)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index cc8a03cc9674..97e1bcb20489 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -19,6 +19,7 @@ extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
>  extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
>  extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
> +extern struct page_ext_operations page_stack_ops;
>  
>  int kasan_populate_early_shadow(const void *shadow_start,
>  				const void *shadow_end);
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 4fafba1a923b..b5a9410ba4e8 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -41,6 +41,7 @@ config KASAN_GENERIC
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	select STACKDEPOT
> +	select PAGE_EXTENSION
>  	help
>  	  Enables generic KASAN mode.
>  	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
> @@ -63,6 +64,7 @@ config KASAN_SW_TAGS
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	select STACKDEPOT
> +	select PAGE_EXTENSION
>  	help
>  	  Enables software tag-based KASAN mode.
>  	  This mode requires Top Byte Ignore support by the CPU and therefore
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2277b82902d8..c349143d2587 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -211,10 +211,38 @@ void kasan_unpoison_stack_above_sp_to(const void *watermark)
>  	kasan_unpoison_shadow(sp, size);
>  }
>  
> +static bool need_page_stack(void)
> +{
> +	return true;
> +}
> +
> +struct page_ext_operations page_stack_ops = {
> +	.size = sizeof(depot_stack_handle_t),
> +	.need = need_page_stack,
> +};
> +
> +static void set_page_stack(struct page *page, gfp_t gfp_mask)
> +{
> +	struct page_ext *page_ext = lookup_page_ext(page);
> +	depot_stack_handle_t handle;
> +	depot_stack_handle_t *page_stack;
> +
> +	if (unlikely(!page_ext))
> +		return;
> +
> +	handle = save_stack(gfp_mask);
> +
> +	page_stack = get_page_stack(page_ext);
> +	*page_stack = handle;
> +}
> +
>  void kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>  	u8 tag;
>  	unsigned long i;
> +	gfp_t gfp_flags = GFP_KERNEL;
> +
> +	set_page_stack(page, gfp_flags);
>  
>  	if (unlikely(PageHighMem(page)))
>  		return;
> @@ -227,6 +255,10 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
>  
>  void kasan_free_pages(struct page *page, unsigned int order)
>  {
> +	gfp_t gfp_flags = GFP_KERNEL;
> +
> +	set_page_stack(page, gfp_flags);
> +
>  	if (likely(!PageHighMem(page)))
>  		kasan_poison_shadow(page_address(page),
>  				PAGE_SIZE << order,
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 014f19e76247..95b3b510d04f 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -126,6 +126,11 @@ static inline bool addr_has_shadow(const void *addr)
>  	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
>  }
>  
> +static inline depot_stack_handle_t *get_page_stack(struct page_ext *page_ext)
> +{
> +	return (void *)page_ext + page_stack_ops.offset;
> +}
> +
>  void kasan_poison_shadow(const void *address, size_t size, u8 value);
>  
>  /**
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0e5f965f1882..2e26bc192114 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -344,6 +344,32 @@ static void print_address_stack_frame(const void *addr)
>  	print_decoded_frame_descr(frame_descr);
>  }
>  
> +static void dump_page_stack(struct page *page)
> +{
> +	struct page_ext *page_ext = lookup_page_ext(page);
> +	depot_stack_handle_t handle;
> +	unsigned long *entries;
> +	unsigned int nr_entries;
> +	depot_stack_handle_t *page_stack;
> +
> +	if (unlikely(!page_ext))
> +		return;
> +
> +	page_stack = get_page_stack(page_ext);
> +
> +	handle = READ_ONCE(*page_stack);
> +	if (!handle)
> +		return;
> +
> +	if ((unsigned long)page->flags & PAGE_FLAGS_CHECK_AT_PREP)
> +		pr_info("Allocation stack of page:\n");
> +	else
> +		pr_info("Free stack of page:\n");
> +
> +	nr_entries = stack_depot_fetch(handle, &entries);
> +	stack_trace_print(entries, nr_entries, 0);
> +}
> +
>  static void print_address_description(void *addr)
>  {
>  	struct page *page = addr_to_page(addr);
> @@ -366,6 +392,7 @@ static void print_address_description(void *addr)
>  	if (page) {
>  		pr_err("The buggy address belongs to the page:\n");
>  		dump_page(page, "kasan: bad access detected");
> +		dump_page_stack(page);
>  	}
>  
>  	print_address_stack_frame(addr);

Hi All,

We implement another version, it is different with v1. We hope that you
can give an ideas and make the KASAN report better. If it is possible,
we can use the less memory to show the corruption information that is
enough to help programmer to fix up memory corruption.

Thanks.
Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568109204.24886.14.camel%40mtksdccf07.
