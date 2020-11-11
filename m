Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXGWD6QKGQEW2HB5QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 416DE2AF895
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:53:35 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id j1sf781830lfg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:53:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120814; cv=pass;
        d=google.com; s=arc-20160816;
        b=pboK0OOBTNd3f5wCoOwZOrzlnxOKS87fZF6IXcKPXojxqi7DkIuYGegj8y0OSX+VZk
         Qk7XjyTgr+yEFhRpEWA55ooinq8mizn0405o1sAqn78ohib+ZkvTb5SOKU5TMajw1WKo
         QOAf1793Krlm08N1f6VwUnnYYUa6tvK7JGfRdmnuhArakR3J32odCI9lGt4CidSv2fqL
         eUWRUpXjscUTGG3YzsIW3rfRTJK6Q4+vg7egmcBiLmS88nxjK0V8JHMW8f1rUqz9ZS/I
         2ZyHUAKNIneRQWdBp/iLfA4317Ovpm3zXTDNXULwi0yYOEEz32iIMW3erzyXKQr17tZe
         ysNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6I/WUAbKX/2xIRovP1o6dIbTyg3XMSmOxB7qEipERZw=;
        b=Od8ax8meS1gluezYBg/3lVInH4/KgSqdBVRvRNNru32EUYL/1NHVCLgk/slgMGh4KL
         nCyL5AAoCDBpwECAhqrDVQMoa4AtZZkZGPnchTmNryRLawcRKDPzVAzSBgRqoEBx63s5
         HM3Iz6WZySDhoxq+4MCWSKzxPUUIyBkdgwFh2hLqe7ufmUX+wT2RurPqYBm1zjwGT0/N
         8XXmD207/2amAZ5IjBDinCkr24ZbX78lmzeOd2F6QP5t5WwDkPeayO96lOm4MQ8x2y3k
         rYQzLbbAPrvHs/GK5UZ322PhIarFM1wgrPzlq+fe70JOekVC5CIU7pxIHtNmBIrCXqqA
         izlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mJji5oqY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6I/WUAbKX/2xIRovP1o6dIbTyg3XMSmOxB7qEipERZw=;
        b=JOwwdWRLB/bNsi18aGqGtzN+Ky7f/puBhyi6g12aoX+w1xrN/Pth23w+9M/70ybLb3
         /Lpb8xpBS5KafSIe8CljHkNspCy2e+EqEAlV70qvCSY62aAyg8NgJ5ZqdUHt+oNnylCn
         QeWzJpOqOaxapaHVgv0OrYqBNt627FxxFCwPaRmE+q9y6xCaPXpcEbwFXdCH1/Jmzl3B
         Yth3JaI5a/ssjqcUhDgRoZWvqSUNydO1290J8HXaVKQ+k5gZdtroKSiP1krWVB8qcVVt
         pc4dpueENK1SeBpw2aS/TSjxTec00SXOtDT85nyhWZxPvAYxNvbUWHvGgEHG2EqSovPm
         eUdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6I/WUAbKX/2xIRovP1o6dIbTyg3XMSmOxB7qEipERZw=;
        b=kXUnC/KdcLigVgmrNMYauyMrd4CJaZn8QWy4iDRlDxWEMX9Usj3scp1aAevLmVb0X7
         flPLYmGmvcFac8EOWHMrZ0wPgmAm5YZXAcOqhAlE/cGmKOM07IgLU+fZ//rJvoX006+/
         KWogK70tCUeMqgetK2ABTqPyAAh7MCecotCkvoxXOWcJFelZbRpXJ1Jb7LknUrUXQdaU
         YXvV8JsOhb5FH2tG3dAIn7mULPi/qN6oGUho9Sa9sGMfe/+1V2NbDxPVY6+eaM/8UQC4
         hY9Rf2oKKHZsbXOw5DlC1eA50T5m+MpmDav3jJ04w4mm45fYr4NDUcT6gEoxKImDEOEt
         vdcQ==
X-Gm-Message-State: AOAM533dGrhAglatLx7gcb9zcknq3nDYfV/Spto+JfpUyfIWE8tbJ19k
	CoGJZ9Hr3+qkws3VtsQec+k=
X-Google-Smtp-Source: ABdhPJwbBJGUuZT5jEoAkvc+yx4mChjuWpB2KffayrteS+1VHss1CCudrVwmzfQofYselN0OJq4YQg==
X-Received: by 2002:a19:408e:: with SMTP id n136mr11325257lfa.417.1605120814811;
        Wed, 11 Nov 2020 10:53:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls327303lfn.0.gmail; Wed, 11 Nov
 2020 10:53:33 -0800 (PST)
X-Received: by 2002:a19:dca:: with SMTP id 193mr9388375lfn.107.1605120813620;
        Wed, 11 Nov 2020 10:53:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120813; cv=none;
        d=google.com; s=arc-20160816;
        b=e7KKScEn8W//l1eVASnryP7dsUwLdoR9pAxVhb2InNqWSaGAsMINIQywUrVWkG2nJe
         myB42r4bzyTB2aEKQmZyZ5x94LnB64Nkklup/VikENcC32llDWB9aiR4LVmIDsAZgccA
         e06pFRzaXflHOvnVZY4+Fe0/lFKdUNmbogFTJdxxZnFQ/AI+X3MvPNbmNdT8QDBsrsXa
         zwp5hq3tTu1vLvpGCGzXY34bXA0XQFmUM78Yz402pRghBjrGjUoj8Z4yuUE7AU18xVKl
         6zd4vYKuE+YGVfZa8l6MBcs1hg+eVg1V/ok2GIKv09H+i70br2xZq0Ay7Fr0DYd6smbz
         ohmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BsqGYO3Z3LmOG3+gEI3hEN4Yp+SLkMxnpyJBNBk4sQ4=;
        b=UEesrNldV1SRKuMixqG3cWqJajT7m4SAKewj0i7I4Dn+BehNHTvFwb+N7+oW57J9fG
         yYk+66ONnmgAk0n0SogQ5yUmlOCcGPsOkEoYucTJtxYetAiB4rWpKv/g3YmSkii2s1Rs
         k+dnmML3ZL20AgpH7WyTW07XbwGlFamMGYlSkufcwf3gea6qEpqYyTFSMcg5re6/ncvO
         6I/5sFr/2fYTsFrscNIcDOoUmvtxY7zcl7Gt5wnp/1rdOEQcLgweqrcOfxVUoyM/3X2c
         y8pfg/6vLutJ4UPaiM3Sp59YDpqWttvSNAzHlLlJjNHOInK8tMwIkfB0sxPUUqxEov75
         G5qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mJji5oqY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q16si81628ljp.8.2020.11.11.10.53.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:53:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id a3so3278470wmb.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:53:33 -0800 (PST)
X-Received: by 2002:a1c:66c4:: with SMTP id a187mr5688966wmc.186.1605120812851;
        Wed, 11 Nov 2020 10:53:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c185sm3646674wma.44.2020.11.11.10.53.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 10:53:32 -0800 (PST)
Date: Wed, 11 Nov 2020 19:53:26 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 14/20] kasan, mm: rename kasan_poison_kfree
Message-ID: <20201111185326.GP517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <ee33aa1d9c57c3f2b2c700e8f2c6c24db8703612.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ee33aa1d9c57c3f2b2c700e8f2c6c24db8703612.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mJji5oqY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Rename kasan_poison_kfree() to kasan_slab_free_mempool() as it better
> reflects what this annotation does.

This function is again so simple, and now it seems it's mempool
specific, can't we just remove it and open-code it in mempool.c?

> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
> ---
>  include/linux/kasan.h | 16 ++++++++--------
>  mm/kasan/common.c     | 16 ++++++++--------
>  mm/mempool.c          |  2 +-
>  3 files changed, 17 insertions(+), 17 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 779f8e703982..534ab3e2935a 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -177,6 +177,13 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned
>  	return false;
>  }
>  
> +void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
> +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +{
> +	if (kasan_enabled())
> +		__kasan_slab_free_mempool(ptr, ip);
> +}
> +
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
>  				       void *object, gfp_t flags);
>  static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
> @@ -217,13 +224,6 @@ static inline void * __must_check kasan_krealloc(const void *object,
>  	return (void *)object;
>  }
>  
> -void __kasan_poison_kfree(void *ptr, unsigned long ip);
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> -{
> -	if (kasan_enabled())
> -		__kasan_poison_kfree(ptr, ip);
> -}
> -
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static inline void kasan_kfree_large(void *ptr, unsigned long ip)
>  {
> @@ -263,6 +263,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  {
>  	return false;
>  }
> +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>  				   gfp_t flags)
>  {
> @@ -282,7 +283,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
>  {
>  	return (void *)object;
>  }
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
>  static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
>  
>  #endif /* CONFIG_KASAN */
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 819403548f2e..60793f8695a8 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -336,6 +336,14 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  	return ____kasan_slab_free(cache, object, ip, true);
>  }
>  
> +void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +{
> +	struct page *page;
> +
> +	page = virt_to_head_page(ptr);
> +	____kasan_slab_free(page->slab_cache, ptr, ip, false);
> +}
> +
>  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
>  	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> @@ -427,14 +435,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  						flags, true);
>  }
>  
> -void __kasan_poison_kfree(void *ptr, unsigned long ip)
> -{
> -	struct page *page;
> -
> -	page = virt_to_head_page(ptr);
> -	____kasan_slab_free(page->slab_cache, ptr, ip, false);
> -}
> -
>  void __kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>  	if (ptr != page_address(virt_to_head_page(ptr)))
> diff --git a/mm/mempool.c b/mm/mempool.c
> index f473cdddaff0..b1f39fa75ade 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
>  static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  {
>  	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
> -		kasan_poison_kfree(element, _RET_IP_);
> +		kasan_slab_free_mempool(element, _RET_IP_);

This is already a kasan-prefixed function, so if
kasan_slab_free_mempool() is only ever called in this function, we
should just call kasan_slab_free() here directly with the 2 extra args
it requires open-coded.

>  	else if (pool->alloc == mempool_alloc_pages)
>  		kasan_free_pages(element, (unsigned long)pool->pool_data);
>  }

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111185326.GP517454%40elver.google.com.
