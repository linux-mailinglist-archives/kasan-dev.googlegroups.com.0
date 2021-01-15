Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VMQ2AAMGQEBIZDDIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 083152F7C56
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:19:47 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id z22sf3100041ljj.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:19:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610716786; cv=pass;
        d=google.com; s=arc-20160816;
        b=OrxEKTKx4XTDDjHxliK792LQSAvs6w0eq2dV7WHWvd28KlFZwL3CqEUGbo89ap1H4+
         DWkSZvC6NWCYxJ3bH2bgfrF/Q7mk/VKibATg3jEq23xEPnKKwy5UGXecxcftUxbepSnv
         h6Mnetq0ly4aITkAxyUL35ogUAGnCgyXwsF2n5SiXgl6idqG2BVt7jBFh1rotkbZqghF
         aTvb+xQyZ1fVzypGi4PxvvdNc3oUijiq+5sWGBlDILZQAvhGTBTHICSrlrxATQ9tNjSg
         Q/hxT3LA9zIjmLdDQRqR4jrr0QhuWoZtoQLEkgaR3/t1ReH/cB4YmsySDpOFIKV/JYhe
         K8lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fuZ/YXnj7eV/i5Z5bYBFc7+uiRtMg1GO1ojfS+y6Jxg=;
        b=fWSVJZ29IsWlpxTSBAW3b+h44FUCCgUAG2uKxUvtPqSl6bLKlr+T6Hoc4JbJuWdO18
         87HcjXfqMkV9mlh8Gg2ZRcCwlztVOqVVqLTj15S9z1Le/RVYo/kXIxptBDS9XZ/l7vaf
         /QdZP3aHK6IXC6aF8EMVgvN4Rk+N4c0Kp9Ajs4PS0dWejKCQvCsvVksxB1H74o3cxGpB
         I+1/O4lwlMPhZs2+0XgdRJAo8D+2h/0WOodXETUzBql7E2Pt+vhxkpCN/Em+PFioeldD
         Ck0L31IMDbI+WLx51rXS0qAaWI+WHbpSMutxoFn5smCvmz4EP0WV+wZAUwG+Hyb4VSQ+
         IpPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QXqqruHI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fuZ/YXnj7eV/i5Z5bYBFc7+uiRtMg1GO1ojfS+y6Jxg=;
        b=XUCMInErMF73s7GGrzSMftpHmuRp/xC9hq5T9WiXZKW2sDscKgZTr6vpuzOkjVS+Ai
         evnf5ybzPuckICWdTN80rLqFVNEQRd0Uk3E7lkqyLWGsxRqwfU8lOisl5M1XaIL9mBKZ
         ngf/wi7/FlYX/kf0CCXBS7fgPMJbZpVhZJyYvGGZukA8I+KfMMc6goH0X9tctH9KGwiP
         xeN42GLHXbD3CZ8baeQYo6oUSEx1Z/2MSqOv+GTwv7c6/4ORgG0URZTh0m282a5EGwF9
         QEbXqr7MBlr3uTsUYcgSif7UKTUQsIdgw9qy7w3yicYs3TVY7LzTuzG9wGSaMQsEFh8o
         Wb9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fuZ/YXnj7eV/i5Z5bYBFc7+uiRtMg1GO1ojfS+y6Jxg=;
        b=dG+/S+OdrMQMiMsTwOqsxHe/ts/LmEKuP86gQNBiK1ZN5eV7hayKhlvjPzc/GirrIn
         OHOO7POGs68X4kdV/jfF1ilh82B3sB6eZFB9wZgTBh7Y9vz9uIePQiBuFbJ+K03nv70E
         WnlnQR+Qt5tJJ3SG9+6DvteC7YeYEajKfNlrFZp8YN53wQD0kLQAWQLcdNEx1z/1kE3U
         J1rzOmSQJz+uSjdljLbjS0ggD2TOZb3R/t24vj4xf5QC2gXJeA45A4FQ/4J+XBDOmhQL
         EN4+8QGmqFbpoAPuj/EImXYuH0UAkIZc6naw4rg6OJftEsFiYC1rjIRO4DqhKtCEJLJ8
         RSew==
X-Gm-Message-State: AOAM533noa1DosSjaPRiV2Rcj8QZPxLcg2fB21grO5yOk0TgurRuwt5+
	a/PLIesqMNYWwOJ25XsWuvY=
X-Google-Smtp-Source: ABdhPJzPC0zBw/hF+cvN/Y6/DijyYd5MDtErrHwiJbvSmVOkaJEuiJ/utJa6zqyPTf8yhwIccnWlEQ==
X-Received: by 2002:a05:6512:3ea:: with SMTP id n10mr5585466lfq.535.1610716786575;
        Fri, 15 Jan 2021 05:19:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls2470567lfu.3.gmail; Fri,
 15 Jan 2021 05:19:45 -0800 (PST)
X-Received: by 2002:a19:ab01:: with SMTP id u1mr5562387lfe.466.1610716785396;
        Fri, 15 Jan 2021 05:19:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610716785; cv=none;
        d=google.com; s=arc-20160816;
        b=A0bLuVeI98GHYsqvzGlvCXwx3lcKijuvvQy/PVGG2YkeE5VU2priqE09uJ/t2l5gPs
         3HO5zkHQLWPnIlUYakXABG9JbhCMOMzUc1K3BzL4bA4eRmvMV3zm3feLIfM6SG+Rwf8T
         gCE17YuFPvxUBKTESgVkC15gjRWyazmD54YC5Ayx/D/LHpr/+k6yS+yh8IRWnj1IYCx8
         qC11DhrDAU2jkWmvWZbL2VyfN2MWd7CDFrmKtkoO/fKhu7q1Ltq6U/1lepz+Y/C4Qxm4
         yDDbwLog3wImCTFl4qjObayq/k6Eat59EdsQziG3gxGnvosSfaPJIVqQdYYBE2YsqIEL
         66Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5KScXesbEjxL3jaiuXSfmiGP49GRLi2XSqWfLcjiqag=;
        b=bzwdhSYJksXnhSkbejVQzWqu7sGo1q5M52g0kgwaD78uo3w8mRxk1INTGxwpD0b2z8
         mMkJD4IzQzWcOPYT8jG78NsvYeq+6mLyDEDRsQ7SNE1DZcBcXIrUNYNcQNE04/h4Cayr
         SSSP8GF/FJ1jHIq655dcmExt7FIAhGVQGMB2ay1dYgHpEHHW3GRO+b9YmeLB4XXhZsj/
         bAvpUIsksXfju1kiCl3aro9nYN4n+y9RQ4F9qdX8ROsYOl+xfMxscrvUL1KNrftLJPwP
         kX8ivoyNaLtZChR7LZicYA1hD+/+EL1KKp7tUMeqQ+GMmdkA7LJTIbVPXcovwFt7GE/1
         Ud6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QXqqruHI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id i18si353995lfp.2.2021.01.15.05.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:19:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id k10so7329491wmi.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:19:45 -0800 (PST)
X-Received: by 2002:a1c:4c7:: with SMTP id 190mr8760735wme.32.1610716784979;
        Fri, 15 Jan 2021 05:19:44 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id a8sm12661374wmd.6.2021.01.15.05.19.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jan 2021 05:19:44 -0800 (PST)
Date: Fri, 15 Jan 2021 14:19:38 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 11/15] kasan: move _RET_IP_ to inline wrappers
Message-ID: <YAGWavYGrpZXVF4M@elver.google.com>
References: <cover.1610652890.git.andreyknvl@google.com>
 <03fae8b66a7f4b85abadc80a2d216ac4db815444.1610652890.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <03fae8b66a7f4b85abadc80a2d216ac4db815444.1610652890.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QXqqruHI;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> Generic mm functions that call KASAN annotations that might report a bug
> pass _RET_IP_ to them as an argument. This allows KASAN to include the
> name of the function that called the mm function in its report's header.
> 
> Now that KASAN has inline wrappers for all of its annotations, move
> _RET_IP_ to those wrappers to simplify annotation call sites.
> 
> Link: https://linux-review.googlesource.com/id/I8fb3c06d49671305ee184175a39591bc26647a67
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Much nicer!

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan.h | 20 +++++++++-----------
>  mm/mempool.c          |  2 +-
>  mm/slab.c             |  2 +-
>  mm/slub.c             |  4 ++--
>  4 files changed, 13 insertions(+), 15 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5e0655fb2a6f..bba1637827c3 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -181,19 +181,18 @@ static __always_inline void * __must_check kasan_init_slab_obj(
>  }
>  
>  bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> -static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> -						unsigned long ip)
> +static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
>  {
>  	if (kasan_enabled())
> -		return __kasan_slab_free(s, object, ip);
> +		return __kasan_slab_free(s, object, _RET_IP_);
>  	return false;
>  }
>  
>  void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
> -static __always_inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +static __always_inline void kasan_slab_free_mempool(void *ptr)
>  {
>  	if (kasan_enabled())
> -		__kasan_slab_free_mempool(ptr, ip);
> +		__kasan_slab_free_mempool(ptr, _RET_IP_);
>  }
>  
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> @@ -237,10 +236,10 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
>  }
>  
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
> -static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
> +static __always_inline void kasan_kfree_large(void *ptr)
>  {
>  	if (kasan_enabled())
> -		__kasan_kfree_large(ptr, ip);
> +		__kasan_kfree_large(ptr, _RET_IP_);
>  }
>  
>  bool kasan_save_enable_multi_shot(void);
> @@ -273,12 +272,11 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>  {
>  	return (void *)object;
>  }
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> -				   unsigned long ip)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
>  {
>  	return false;
>  }
> -static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
> +static inline void kasan_slab_free_mempool(void *ptr) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>  				   gfp_t flags)
>  {
> @@ -298,7 +296,7 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
>  {
>  	return (void *)object;
>  }
> -static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> +static inline void kasan_kfree_large(void *ptr) {}
>  
>  #endif /* CONFIG_KASAN */
>  
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 624ed51b060f..79959fac27d7 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
>  static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  {
>  	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
> -		kasan_slab_free_mempool(element, _RET_IP_);
> +		kasan_slab_free_mempool(element);
>  	else if (pool->alloc == mempool_alloc_pages)
>  		kasan_free_pages(element, (unsigned long)pool->pool_data);
>  }
> diff --git a/mm/slab.c b/mm/slab.c
> index d7c8da9319c7..afeb6191fb1e 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3421,7 +3421,7 @@ static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
>  		memset(objp, 0, cachep->object_size);
>  
>  	/* Put the object into the quarantine, don't touch it for now. */
> -	if (kasan_slab_free(cachep, objp, _RET_IP_))
> +	if (kasan_slab_free(cachep, objp))
>  		return;
>  
>  	/* Use KCSAN to help debug racy use-after-free. */
> diff --git a/mm/slub.c b/mm/slub.c
> index 75fb097d990d..0afb53488238 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1514,7 +1514,7 @@ static inline void *kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
>  static __always_inline void kfree_hook(void *x)
>  {
>  	kmemleak_free(x);
> -	kasan_kfree_large(x, _RET_IP_);
> +	kasan_kfree_large(x);
>  }
>  
>  static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
> @@ -1544,7 +1544,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>  
>  	/* KASAN might put x into memory quarantine, delaying its reuse */
> -	return kasan_slab_free(s, x, _RET_IP_);
> +	return kasan_slab_free(s, x);
>  }
>  
>  static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> -- 
> 2.30.0.284.gd98b1dd5eaa7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YAGWavYGrpZXVF4M%40elver.google.com.
