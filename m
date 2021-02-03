Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD5H5KAAMGQE4KRUA3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9214B30D998
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:14:07 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id n18sf14486313wrm.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:14:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612354447; cv=pass;
        d=google.com; s=arc-20160816;
        b=LwUH6WrHljpJoZyCGVkO4AswdhCTkbbui4cWll/hxgWVJnOvEnicZFvrsM5/iTkwlz
         O3wfvfMS+FwqsU1SpvGl3J08whnBtGGXfE8jDubKeQo0zz0eRfjHr4JvNMvcKx8BDLhF
         uCCkUMFKS18VMOfswOOGHZlQ420GrCUeEvo1lAl+vf3lmrDw+Yk/pybO+Jkz+CddU37C
         9G1L/pMaMKSRQ9yTZuwgjUkQ8vtegWrZlvKbiE6fPr9RztpJl6PgDcMzhMJlrx2sBvT+
         /r9nuPrTYpkl6fULwKPkJQ5Qplbj91L04mOKuuVRrA4dt0bfQ97GpSpng4q0hJZPX+K7
         pf9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=FmgeGM9BTYVd/MrdM9OWvCEoSi+lBhxMBzAilFMVPd0=;
        b=Me2f1wkVPDQ1xp6nNdOW4zuKyqCxJdaiywl6MqP2t4oCNk3b1ZJx7PsCDoBCtcV24f
         dBRsC/GHyHCJ8itiO+XTrUm8CaIRmluE9dizhm/y2d4Ngxa5gL+2wIVI9oKwInu+gYeJ
         MfgnFGY9qCiG+vY40fybrOuDyDE/+P+TPNMiQ1BnUg8ZIIf8IdXGv/hKFTfTKMuWqhs6
         ra/NS7uV4Gee/mcWDljaz4LaP5SCSpI5vGg4OEQLbiTQxGys2fq5AbESfPYYO/8b9/1M
         +AklmqK8mwPh/U9Ydi+0srsmUWEpduxanfUA0p/uQFmj39kHpdea72N+YtmXe0CZ4LOx
         OQXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jxovcCp2;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FmgeGM9BTYVd/MrdM9OWvCEoSi+lBhxMBzAilFMVPd0=;
        b=Xp96SDq893LxUKD/RNazOQ4n+kC2zkNlfCcT18I3+6W6Mt3ip8+rCc2gxard4sZoQy
         VGqUUhNTXklKvpWgKj6O8MEmh6kyHCbXqGC7pfJNLLCuqmqaWzOCp9VM0cKGUUqAp/og
         JAoqo5Bg3t1XNProsmgyOPc73uMeSu210tHdSnVB55q3O+BuGd6yg/HqtMbF14V4osp0
         2i+PnZWvMecdDJ5vh/FTW74Y4ad28pdWsZUnWvc2/Rjl7NhufzFF3cugMtYRL8CZb4bA
         d4xpOglEj0LbRuZYA2cB1gWArfIdppMV0wteic2de+zLNR1v+OhqYNC4r/aSMX9ZbY7l
         XWFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FmgeGM9BTYVd/MrdM9OWvCEoSi+lBhxMBzAilFMVPd0=;
        b=CnDNrDkF7c21gf9qryWZDjKNHgmrmDUB66a6EI+S9lcgvDHD5yh0U/ITNgyG0IbEHa
         mrVDKzSYPOdT9UirV7wgryPu4D/beMRqtoH+VTTtP4gZ0f6AfNgUo5zqq9wtqFJ04dwd
         Cx+dFtPTbWDSMFw0WfOcONW0MTkoeh5GVwSeRE/2MyKCmAlVjvIjIpvJoO3oYKUm8B/c
         PXlsZlHFQf9WSG5eSPFau92gX0Ssc8dynOGHQ/1RkAAJp6WMnhQkDWfzXHW6iZdwbBgv
         6p99wR6xAExYi2tGJOln7jiQA3GUKYBaEXOTliEFBZcgFrRqSBDCKpuXTGlBIiMiBwI7
         m6rA==
X-Gm-Message-State: AOAM5336EfQt3pm6N8BtrNWQ2qCJMo8re36Fb2wTD525IPfAufp8zh2Q
	022vFISM2SBM9mD5riUkli0=
X-Google-Smtp-Source: ABdhPJxpdeJYpFFLIaNy7uFZh/9RjL7T5WOZ+BF44oddbwQ56luTr8wASfynkM3eZlCOHKzafCUFHA==
X-Received: by 2002:a5d:4988:: with SMTP id r8mr3259764wrq.26.1612354447401;
        Wed, 03 Feb 2021 04:14:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:385:: with SMTP id 127ls940429wmd.0.canary-gmail; Wed,
 03 Feb 2021 04:14:06 -0800 (PST)
X-Received: by 2002:a1c:b1c3:: with SMTP id a186mr2592183wmf.8.1612354446504;
        Wed, 03 Feb 2021 04:14:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612354446; cv=none;
        d=google.com; s=arc-20160816;
        b=R/txNAKJOAe/jfRkbDBNw2NL7MZHX2vNZJjnGrKKeA8USjl0gbvHZH+GZFLfrJhKMq
         U8j6XQVfTiDDOKYcyBSR4t9Qt5/fu9eZH0CmC9u/yYqx2jjjBtnmNvcV1TZd5/5cPl3t
         DSkEYFW654BQSJUNYqpIXKVlG4GNjngRQ2MOeiLGE98yDQM8ME3KJ6DmgfDwo19kyUtU
         HFm7zz0KUd3UWsI0c3I04Fj0AWW5Fi9Pn4ZQWNdsJEak2jzF/L6asuoHj+t+YxNoeoBR
         YGcjHEbiMCAz8hSWSQc3BYQtIMlPm/OitqbHaUIzQ1kzaA71ewy/sd6tMEqIR9zpp5ol
         6hiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zSxY3nTKxJ1IPmcAhiUV2gxjS9POrRlqCu2+Tg/s2dQ=;
        b=LxDACs2E31XyfDZT7VEpGA4/kx9TKv/7ldZd5mniM8uD0/rioQ99TskHveqgeor3n2
         sOhIb371oBiuMRzFXrzhVBZorTGIi5nHHCGT3XG2TemOxOizuOELn0RqTDMz/A91rnx8
         2hbQS/FzMhoFen5DOWQLvQiTVOLaYc9jwSy5tKybjtLvN5k2iLABKTWRqnRuamrXwDQd
         YpaJcemrq9qE6tq2zhC6s1BC3FJKV2yH3pz2IalbMNQ7QkqLtrvy8ZjdL0e9BKmA2Dpo
         hZkPPEmGOVUE8jNfMQpMcedj7ftt5Zn6auIYh8OF9QW49byQhiLv80RVrhAQiXEEy6NI
         0xQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jxovcCp2;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id s3si86161wrt.5.2021.02.03.04.14.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:14:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id y187so4991169wmd.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 04:14:06 -0800 (PST)
X-Received: by 2002:a7b:c5d6:: with SMTP id n22mr2512430wmk.70.1612354445997;
        Wed, 03 Feb 2021 04:14:05 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1de:c7d:30ce:1840])
        by smtp.gmail.com with ESMTPSA id t17sm2566202wmi.46.2021.02.03.04.14.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 04:14:05 -0800 (PST)
Date: Wed, 3 Feb 2021 13:13:59 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 05/12] kasan: unify large kfree checks
Message-ID: <YBqThxfjUL1U9FCZ@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <dbef8131b70766f8d798d24bb1ab9ae75dadea61.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dbef8131b70766f8d798d24bb1ab9ae75dadea61.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jxovcCp2;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> Unify checks in kasan_kfree_large() and in kasan_slab_free_mempool()
> for large allocations as it's done for small kfree() allocations.
> 
> With this change, kasan_slab_free_mempool() starts checking that the
> first byte of the memory that's being freed is accessible.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan.h | 16 ++++++++--------
>  mm/kasan/common.c     | 36 ++++++++++++++++++++++++++----------
>  2 files changed, 34 insertions(+), 18 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 2d5de4092185..d53ea3c047bc 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -200,6 +200,13 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
>  	return false;
>  }
>  
> +void __kasan_kfree_large(void *ptr, unsigned long ip);
> +static __always_inline void kasan_kfree_large(void *ptr)
> +{
> +	if (kasan_enabled())
> +		__kasan_kfree_large(ptr, _RET_IP_);
> +}
> +
>  void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
>  static __always_inline void kasan_slab_free_mempool(void *ptr)
>  {
> @@ -247,13 +254,6 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
>  	return (void *)object;
>  }
>  
> -void __kasan_kfree_large(void *ptr, unsigned long ip);
> -static __always_inline void kasan_kfree_large(void *ptr)
> -{
> -	if (kasan_enabled())
> -		__kasan_kfree_large(ptr, _RET_IP_);
> -}
> -
>  /*
>   * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
>   * the hardware tag-based mode that doesn't rely on compiler instrumentation.
> @@ -302,6 +302,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
>  {
>  	return false;
>  }
> +static inline void kasan_kfree_large(void *ptr) {}
>  static inline void kasan_slab_free_mempool(void *ptr) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>  				   gfp_t flags)
> @@ -322,7 +323,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
>  {
>  	return (void *)object;
>  }
> -static inline void kasan_kfree_large(void *ptr) {}
>  static inline bool kasan_check_byte(const void *address)
>  {
>  	return true;
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 086bb77292b6..9c64a00bbf9c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -364,6 +364,31 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  	return ____kasan_slab_free(cache, object, ip, true);
>  }
>  
> +static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
> +{
> +	if (ptr != page_address(virt_to_head_page(ptr))) {
> +		kasan_report_invalid_free(ptr, ip);
> +		return true;
> +	}
> +
> +	if (!kasan_byte_accessible(ptr)) {
> +		kasan_report_invalid_free(ptr, ip);
> +		return true;
> +	}
> +
> +	/*
> +	 * The object will be poisoned by kasan_free_pages() or
> +	 * kasan_slab_free_mempool().
> +	 */
> +
> +	return false;
> +}
> +
> +void __kasan_kfree_large(void *ptr, unsigned long ip)
> +{
> +	____kasan_kfree_large(ptr, ip);
> +}
> +
>  void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  {
>  	struct page *page;
> @@ -377,10 +402,8 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
>  	 */
>  	if (unlikely(!PageSlab(page))) {
> -		if (ptr != page_address(page)) {
> -			kasan_report_invalid_free(ptr, ip);
> +		if (____kasan_kfree_large(ptr, ip))
>  			return;
> -		}
>  		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE);
>  	} else {
>  		____kasan_slab_free(page->slab_cache, ptr, ip, false);
> @@ -539,13 +562,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
>  }
>  
> -void __kasan_kfree_large(void *ptr, unsigned long ip)
> -{
> -	if (ptr != page_address(virt_to_head_page(ptr)))
> -		kasan_report_invalid_free(ptr, ip);
> -	/* The object will be poisoned by kasan_free_pages(). */
> -}
> -
>  bool __kasan_check_byte(const void *address, unsigned long ip)
>  {
>  	if (!kasan_byte_accessible(address)) {
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBqThxfjUL1U9FCZ%40elver.google.com.
