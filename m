Return-Path: <kasan-dev+bncBCX7JJ6OTQGBBQHHXSMAMGQEJO6DUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C89565A7B09
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 12:11:12 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id ay21-20020a05600c1e1500b003a6271a9718sf8104625wmb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 03:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661940672; cv=pass;
        d=google.com; s=arc-20160816;
        b=inT8UNQdWRr7R0rYtN8qQWRoRGirIcMgbVfkmCJ+dCMlgJYZp3KOKKJrDdhiLZM/6B
         UE75wtFV/CCIlljU1JUDoTnjBZAaXoNiHL5jr023IUiowt7VxiKPU970+ssjmQ6Uz6HH
         dKc9dHJFBN4oU44eAMCjPXh+pfxeCs/y4f+khmadzGJJynWR6P0meuTCxK6mfuYRpZcB
         bK8oyhWe4mxXdy7DmniEnQiUr+N8kS3sZSc1lvThKU7flYuc8GbgSNBC8trpE48MlLh8
         bfu6knHyMaoTDRcXCDn1FiqPW3IodjDKRGwaZ/Q1eSUjbUOpU9iJsa+l7eVvarFT2+B4
         d2dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=27fJW8v+e3J8TwC/e82ARhXELUuO/94wPDoZWLwq3PQ=;
        b=xuZbUtY9bxtMz+gG7x5Ff04SggXONyA96csknfJWQtY1FZ0ugQqrwBeqtu0Yc4qccX
         0xk/9w3GZltnnaECp/GiiKkItj1+izAGStxCEDivWjmLwAvJ+fCbWCy85gt35De0lmkz
         XHhqtv3mHrShPhpDI2bvgmksnB224m60vudiECNlOGk12+ilnhroklYHwWYeDzZMypqc
         0FXjNCokFf6j4sWYhYBo1YrQryD9D5YZ/UFGwZr6QGjUZRzXJ6t/Yy/MQa7b8Q1K8K4c
         U408X7ad1D7WiDVX6RdIS+BdWa7QRL3+qe9QKvQ+wV4SPafBbGymeYrZ4qVnosUnc8No
         z6Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=Yy6RUQdM;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=KUiIFlqb;
       spf=pass (google.com: domain of mgorman@suse.de designates 195.135.220.28 as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=27fJW8v+e3J8TwC/e82ARhXELUuO/94wPDoZWLwq3PQ=;
        b=PPExd+mSw5Y+hrF1A9A96Pml9HCunuqZZcGS3lfz9Tna9bMq90J8ZMv8ExYeF/zXhD
         /0qftLuYrTk0u75ILkCrW20qQZiba/R0qPSwCwHTOJdbpqMx6UH0QQ+KSKGIe33bUxva
         KM6KXzV3dMVxpTYK8qUUx0zwRLzLjeOCzOPXEydPUoe+JZTPUjXlJF3pB0lYK8dnVQF8
         elKD0mwpaQuku3Nk/r0gdBh+30Rp7SF3L9hggV1jNNfE9N0sml5rO1clqDPNPpW62sIz
         zEKnCapqPV0vOXLwaXY9fyx+EKz3/JxU5aQTnm5cknEWnoVnKF5Oi9EwbLufPorTX7Eq
         Mfdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=27fJW8v+e3J8TwC/e82ARhXELUuO/94wPDoZWLwq3PQ=;
        b=TbtxTGBFnMlUOLa8kXd+wb1e4IW13++fznNT8m9QWPFpABMFvuRe8xkk7BRtH76QeQ
         TueyQX6I/UKjloyhsksw78BbDpRcIjIPnRbnzRSVvrC+56EIFTlARq07KDgDy8yPtUns
         I1+b4WxoI44fbGmZH9bAWgA06sx35URBOz5DrQytkUmeqVtyvQIXiBO9xsFN2SwQNhRT
         FPvJPIkAzv05k8cSlCETv0xZA5UcY4I/VFir+gGDh2SYsHcJE0Jg/vW/Pkm5T7f6sV11
         BlbT9Od69eLsz157NcZDO4ew174uHuTFtg9Ny4Dypx7EMPhXYxDtb4imVxG6e8NrN7r5
         Z1bQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo10b641N5s8A4q1dFFrFH9xrEs/duuWyyydcG5TDKQecx15KWiW
	chruIGTFBVO8NfIW2Jg8Y8U=
X-Google-Smtp-Source: AA6agR7QWOb2OmI4JyNa6E8X52n/HGDe8Z+syc8eWGLawfgGeAiLEIcr5Gb+KDELi6FsVCcdnJgagA==
X-Received: by 2002:a05:6000:5c1:b0:225:58df:56ac with SMTP id bh1-20020a05600005c100b0022558df56acmr11735547wrb.397.1661940672357;
        Wed, 31 Aug 2022 03:11:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c04d:0:b0:3a5:1ad:8654 with SMTP id u13-20020a7bc04d000000b003a501ad8654ls517975wmc.2.-pod-control-gmail;
 Wed, 31 Aug 2022 03:11:10 -0700 (PDT)
X-Received: by 2002:a1c:6a0a:0:b0:3a5:bcad:f2cc with SMTP id f10-20020a1c6a0a000000b003a5bcadf2ccmr1512287wmc.74.1661940670498;
        Wed, 31 Aug 2022 03:11:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661940670; cv=none;
        d=google.com; s=arc-20160816;
        b=AEMkTXnI8466q6RKalm4UupoLP63UaGBEKoE/i/nhMZhDKLN8Nv2gnVe1KthRcGut0
         sL2xsW5aszAPrUmusIvytSt7rqfoTwjKE5moSIFTKIf9jX9Pd3ecqslgEJZyClpqv4GR
         cmMkoUwisvHHd8wnd9Sn3AEvyxHggMSVVHoZNalkP9ohzysalWmjFWH6DaaUCJ21CxvY
         tFfG/IQzsUZrK/RgVq+3kCTk3Fp1C9OsebYK4hilv68f/DeT0NFMBybebgnUjheRZ3rB
         Jxg0mqDceUhiVPnj2f9iYH5vQLP9EceO2Rh0ol5D5ciwpUl1lf3RQlDQrjlIDYvbLpmV
         xMhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=9ZcqM4yN/Uj2veB6/peO+/NOESYU9wobXvQy0yQjV4o=;
        b=eS4vwp4J7+dVkY6XGsEff+KTMrduoYcqT1rxGL3Uw46sID38kMcaK7IFL6FrBXFf2O
         tzR+z65XJ/JiavshpgsX5BhnhoV239/GkCk9gechGCHMuINr8+rKBl7E2r6PdiOd7IsQ
         EZa+9tTpnJQSIHlUKBiBv0BeFbfryXvcVJTG/NKC5v6IfmqgL0LScYZetie3lg5iYmep
         L/bxsJle68xCVuQq3JyH03C9aSpap133JJr5tJcM9DSjKF1+o0UA+C3NBvvYrHQMpoFQ
         FHQiU9VfE7hniXEUFrcpq/z4MWR53tqiYWNISJa7ko+9bvxgc00jfQiGodCqeQzKxZNQ
         gupA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=Yy6RUQdM;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=KUiIFlqb;
       spf=pass (google.com: domain of mgorman@suse.de designates 195.135.220.28 as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id ay1-20020a5d6f01000000b00226f006a4eesi1633wrb.7.2022.08.31.03.11.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 03:11:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of mgorman@suse.de designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 279092226F;
	Wed, 31 Aug 2022 10:11:10 +0000 (UTC)
Received: from suse.de (unknown [10.163.43.106])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id C2D002C142;
	Wed, 31 Aug 2022 10:11:04 +0000 (UTC)
Date: Wed, 31 Aug 2022 11:11:03 +0100
From: Mel Gorman <mgorman@suse.de>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 10/30] mm: enable page allocation tagging for
 __get_free_pages and alloc_pages
Message-ID: <20220831101103.fj5hjgy3dbb44fit@suse.de>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-11-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-11-surenb@google.com>
X-Original-Sender: mgorman@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=Yy6RUQdM;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=KUiIFlqb;
       spf=pass (google.com: domain of mgorman@suse.de designates
 195.135.220.28 as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Tue, Aug 30, 2022 at 02:48:59PM -0700, Suren Baghdasaryan wrote:
> Redefine alloc_pages, __get_free_pages to record allocations done by
> these functions. Instrument deallocation hooks to record object freeing.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> +#ifdef CONFIG_PAGE_ALLOC_TAGGING
> +
>  #include <linux/alloc_tag.h>
>  #include <linux/page_ext.h>
>  
> @@ -25,4 +27,37 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
>  		alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
>  }
>  
> +/*
> + * Redefinitions of the common page allocators/destructors
> + */
> +#define pgtag_alloc_pages(gfp, order)					\
> +({									\
> +	struct page *_page = _alloc_pages((gfp), (order));		\
> +									\
> +	if (_page)							\
> +		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> +	_page;								\
> +})
> +

Instead of renaming alloc_pages, why is the tagging not done in
__alloc_pages()? At least __alloc_pages_bulk() is also missed. The branch
can be guarded with IS_ENABLED.

> +#define pgtag_get_free_pages(gfp_mask, order)				\
> +({									\
> +	struct page *_page;						\
> +	unsigned long _res = _get_free_pages((gfp_mask), (order), &_page);\
> +									\
> +	if (_res)							\
> +		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> +	_res;								\
> +})
> +

Similar, the tagging could happen in a core function instead of a wrapper.

> +#else /* CONFIG_PAGE_ALLOC_TAGGING */
> +
> +#define pgtag_alloc_pages(gfp, order) _alloc_pages(gfp, order)
> +
> +#define pgtag_get_free_pages(gfp_mask, order) \
> +	_get_free_pages((gfp_mask), (order), NULL)
> +
> +#define pgalloc_tag_dec(__page, __size)		do {} while (0)
> +
> +#endif /* CONFIG_PAGE_ALLOC_TAGGING */
> +
>  #endif /* _LINUX_PGALLOC_TAG_H */
> diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> index b73d3248d976..f7e6d9564a49 100644
> --- a/mm/mempolicy.c
> +++ b/mm/mempolicy.c
> @@ -2249,7 +2249,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
>   * flags are used.
>   * Return: The page on success or NULL if allocation fails.
>   */
> -struct page *alloc_pages(gfp_t gfp, unsigned order)
> +struct page *_alloc_pages(gfp_t gfp, unsigned int order)
>  {
>  	struct mempolicy *pol = &default_policy;
>  	struct page *page;
> @@ -2273,7 +2273,7 @@ struct page *alloc_pages(gfp_t gfp, unsigned order)
>  
>  	return page;
>  }
> -EXPORT_SYMBOL(alloc_pages);
> +EXPORT_SYMBOL(_alloc_pages);
>  
>  struct folio *folio_alloc(gfp_t gfp, unsigned order)
>  {
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index e5486d47406e..165daba19e2a 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -763,6 +763,7 @@ static inline bool pcp_allowed_order(unsigned int order)
>  
>  static inline void free_the_page(struct page *page, unsigned int order)
>  {
> +
>  	if (pcp_allowed_order(order))		/* Via pcp? */
>  		free_unref_page(page, order);
>  	else

Spurious wide-space change.

-- 
Mel Gorman
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831101103.fj5hjgy3dbb44fit%40suse.de.
