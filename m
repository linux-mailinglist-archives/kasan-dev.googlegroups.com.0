Return-Path: <kasan-dev+bncBCKLZ4GJSELRBZOIXSVQMGQECLU4VVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFD48055C4
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 14:23:50 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40b4c9c3cffsf40358635e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 05:23:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701782629; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHsjrAfwIT4zfiCqQ52pxCHUgfhUqcTlAgUmR+7po59dILoxAPrzmKLnfrgIw4AoCs
         UN7CFBMZQsuclZTIKbp0ktWQxQKiZlYui2z8C/o887pKkDjKO9WimQ6s8/y8aQk0aA6L
         nSEK2pelTUh18wrm5GnpSvbB2CYlK13+o9Yi+i6rhEgLuh28aCpodhjKrHBT1q53aOGr
         esgeKhbzb2/KaixyN6v7/QEC8JYdDUC63GBY/OA1Wu/xo/WT7mRo8bdcP9A8m0mMwxaL
         K3rItkEBEu8cX/ry1EO8NKA+P2+qbLb5Xs55VxrLTPR6vbf2DWL6BwyhSTuK1+QM6jWu
         slOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=SauCotV0/A8vTyz15SHotgNvrn8wasxa1jIzAndUWZg=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=iL9jywWc+ZnhTj5HiBpVKHQdl06+EEXLpEvSs6XEb+7g/mujCZWaBbLw9C30o1ep+u
         W+MgohoD7ofXLm/uEmor0DyVPlcoJOJ4FudIB8JniwxRR8glgl8Dwgs04zpg4yE1rYuR
         jOtlF65mOfm3PS/3cPeT6Pxqp28Y0Z574S4GIwCGogabYoQ4ew79RO4P9NrfOe3qwuTe
         jscEjln0FoUwltsONCkGSEPiNvyzLv3AnSgeLOfaDbIy2Sluiz9kNDMvpxcAZng3Fa4A
         cYNbhrecQR3K53+EAaSP54a0NqEWNQTlxu7uWmFptcUQVhLL8csikYkxPE46pb+R2Zm9
         1kRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mDZ6ph0o;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.177 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701782629; x=1702387429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SauCotV0/A8vTyz15SHotgNvrn8wasxa1jIzAndUWZg=;
        b=kaDA86d5z/0Vvij1w1TzqP4UNan5tUBvVn1WwKwcG93ViwU6YDoXeyWXHq+yHkGz/W
         rLWYtWCzvbo6Xg4gZp7SF6dih6aEOtpLVa67sERbEqDE+sgnG2hdf5ynsfX5wBjlOt2G
         g0DDat6unmBUg3ti4BC+wGhcd7iz9F4es3gJ0vCOKP8i8C8DF5iYFAGBddYZfB/r3rOL
         hf6x+2sNqSzopeLMKUwgAB5XrRwDdo74im8schnT1RYIW64zk+1Zl+5x9VuXz8w3ry1v
         kQyA2Cb9+cmK9ACy30vjFXgQdS6pRGhG8ibHQKNn1FmjzIQS7ENZfDCW60A/4HqVWPOb
         sR2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701782629; x=1702387429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=SauCotV0/A8vTyz15SHotgNvrn8wasxa1jIzAndUWZg=;
        b=SqxNpH0JygH6UKCDU/GcHzC+DdndBH390KsEjfE1GUTughCECpIm8iufAPe1PuyKHg
         A9e/7BFt1IS39tvYeTEnEgvE5rY1q1dMtw8/hxfRF1G6gjMXBsAx7/G2xtW4i29PpAIg
         sMh1mgT77m4gWjsjt5m+vMpYAD8BVRORu0rDtTyHDvx16e1WUDKI5NdBtKGrrISsFTel
         1cpXw4gD/NmP/A2gZoJJ49LuP8AzvcMT4aDZ2lGMfflI3f/vyYIK2UcsiQvEAMbRaLTH
         RWpFbsuoMngU/yAGR7ypuctysRgGto0KgZF+xW1APLxVcf2rfDYzeBT0Xz5mqNQjUhMD
         pDnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyqyo5/vhn7U9/RLEpgXs30kHzP4Yc4hFLBUogAla0vhw2kdI4W
	L4T+ojGhRV1yW2wE9p6Os44=
X-Google-Smtp-Source: AGHT+IEwTzwAtw3ba+yh2AzXbCIW0LPlQvxPIPvp4rkW+3AHo+RSIT6gOybxoCFzkyIBLcauwkZ+UA==
X-Received: by 2002:a05:600c:20cb:b0:40b:5e59:f747 with SMTP id y11-20020a05600c20cb00b0040b5e59f747mr1669216wmm.185.1701782629311;
        Tue, 05 Dec 2023 05:23:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce95:0:b0:40c:98b:ae85 with SMTP id q21-20020a7bce95000000b0040c098bae85ls1207432wmj.1.-pod-prod-08-eu;
 Tue, 05 Dec 2023 05:23:47 -0800 (PST)
X-Received: by 2002:a7b:c7c6:0:b0:40c:ab6:219b with SMTP id z6-20020a7bc7c6000000b0040c0ab6219bmr977024wmk.112.1701782627444;
        Tue, 05 Dec 2023 05:23:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701782627; cv=none;
        d=google.com; s=arc-20160816;
        b=PUbnMk56geem7hA/9Zvogvs3RnHbqCR7plLctiKuTjtX4pd/9/7mNqyJl8Q5ZRSniT
         caLN7aCCzW1bAuaBZESz7yTOe6gRLqU5vEO6wklljHRoBD6ZyEQ7jgXB9szbxL2/LjQ7
         emTnTkV6C+grtHfdBzJ7ZdIQNTzGy8OFFWCACT25cCsJ3W43PS9gwG2IFSD2eZJMx+fb
         b+RQcuxBcUmKmoZQkiZObLhoM8GhPj6TJIhy25ZpJ//5MCg61YhJDgNlHppxCBAa6h0A
         fpB8JeuT2YRW/WOIZhgkEDHg0gMipIgyP8KRyMyAU/Org+M5tQS7jHexEnG+RCVrkrY0
         q15w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=6Y3aGufX1vl5A2ALGYiBVD+TybG4OsFZRCv9diM79A8=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=0x7b7hCtJCNNSI5xJExoY49+wCu5VQaLF2MyMGVuc0SaoVlM/SZvhMiR83WIPZduF9
         wVSdVMf727JlsiVA1paPaCEAp2fcs41s1fZDOOP8eT9JE1kdsztPCWca5nz163zHjkgO
         OoDeU8s4pkMCbAej7dqJEf/jsBybttaFSwwxR2aTHu8w7GQRsFHy0moryPUr6L5lVgHT
         uLGIkfJyXai5Dxu2ClWC7feUF+G6U638kLgQrNs/VldZmPNju3sdJE9DIV8ndmyGkN9a
         m1xBzXJgZl+Kg7hSIlo0bamTiUUUdotJrojcmMN0hA/QDu3C+SWRS4Xqf4JlAz7zpdNq
         uiIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mDZ6ph0o;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.177 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta0.migadu.com (out-177.mta0.migadu.com. [91.218.175.177])
        by gmr-mx.google.com with ESMTPS id bg17-20020a05600c3c9100b0040b473eceb3si745064wmb.2.2023.12.05.05.23.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 05:23:47 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.177 as permitted sender) client-ip=91.218.175.177;
Message-ID: <93adcdc0-6f32-45fa-b311-34a27ff94290@linux.dev>
Date: Tue, 5 Dec 2023 21:23:38 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 3/4] mm/slub: handle bulk and single object freeing
 separately
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-3-88b65f7cd9d5@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-3-88b65f7cd9d5@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mDZ6ph0o;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.177 as
 permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2023/12/5 03:34, Vlastimil Babka wrote:
> Currently we have a single function slab_free() handling both single
> object freeing and bulk freeing with necessary hooks, the latter case
> requiring slab_free_freelist_hook(). It should be however better to
> distinguish the two use cases for the following reasons:
> 
> - code simpler to follow for the single object case
> 
> - better code generation - although inlining should eliminate the
>   slab_free_freelist_hook() for single object freeing in case no
>   debugging options are enabled, it seems it's not perfect. When e.g.
>   KASAN is enabled, we're imposing additional unnecessary overhead for
>   single object freeing.
> 
> - preparation to add percpu array caches in near future
> 
> Therefore, simplify slab_free() for the single object case by dropping
> unnecessary parameters and calling only slab_free_hook() instead of
> slab_free_freelist_hook(). Rename the bulk variant to slab_free_bulk()
> and adjust callers accordingly.
> 
> While at it, flip (and document) slab_free_hook() return value so that
> it returns true when the freeing can proceed, which matches the logic of
> slab_free_freelist_hook() and is not confusingly the opposite.
> 
> Additionally we can simplify a bit by changing the tail parameter of
> do_slab_free() when freeing a single object - instead of NULL we can set
> it equal to head.
> 
> bloat-o-meter shows small code reduction with a .config that has KASAN
> etc disabled:
> 
> add/remove: 0/0 grow/shrink: 0/4 up/down: 0/-118 (-118)
> Function                                     old     new   delta
> kmem_cache_alloc_bulk                       1203    1196      -7
> kmem_cache_free                              861     835     -26
> __kmem_cache_free                            741     704     -37
> kmem_cache_free_bulk                         911     863     -48
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Looks good to me.

Reviewed-by: Chengming Zhou <zhouchengming@bytedance.com>

Thanks!

> ---
>  mm/slub.c | 59 +++++++++++++++++++++++++++++++++++------------------------
>  1 file changed, 35 insertions(+), 24 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 0742564c4538..ed2fa92e914c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2037,9 +2037,12 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>  /*
>   * Hooks for other subsystems that check memory allocations. In a typical
>   * production configuration these hooks all should produce no code at all.
> + *
> + * Returns true if freeing of the object can proceed, false if its reuse
> + * was delayed by KASAN quarantine.
>   */
> -static __always_inline bool slab_free_hook(struct kmem_cache *s,
> -						void *x, bool init)
> +static __always_inline
> +bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  {
>  	kmemleak_free_recursive(x, s->flags);
>  	kmsan_slab_free(s, x);
> @@ -2072,7 +2075,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
>  		       s->size - s->inuse - rsize);
>  	}
>  	/* KASAN might put x into memory quarantine, delaying its reuse. */
> -	return kasan_slab_free(s, x, init);
> +	return !kasan_slab_free(s, x, init);
>  }
>  
>  static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> @@ -2082,7 +2085,7 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  
>  	void *object;
>  	void *next = *head;
> -	void *old_tail = *tail ? *tail : *head;
> +	void *old_tail = *tail;
>  
>  	if (is_kfence_address(next)) {
>  		slab_free_hook(s, next, false);
> @@ -2098,8 +2101,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  		next = get_freepointer(s, object);
>  
>  		/* If object's reuse doesn't have to be delayed */
> -		if (likely(!slab_free_hook(s, object,
> -					   slab_want_init_on_free(s)))) {
> +		if (likely(slab_free_hook(s, object,
> +					  slab_want_init_on_free(s)))) {
>  			/* Move object to the new freelist */
>  			set_freepointer(s, object, *head);
>  			*head = object;
> @@ -2114,9 +2117,6 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  		}
>  	} while (object != old_tail);
>  
> -	if (*head == *tail)
> -		*tail = NULL;
> -
>  	return *head != NULL;
>  }
>  
> @@ -4227,7 +4227,6 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
>  				struct slab *slab, void *head, void *tail,
>  				int cnt, unsigned long addr)
>  {
> -	void *tail_obj = tail ? : head;
>  	struct kmem_cache_cpu *c;
>  	unsigned long tid;
>  	void **freelist;
> @@ -4246,14 +4245,14 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
>  	barrier();
>  
>  	if (unlikely(slab != c->slab)) {
> -		__slab_free(s, slab, head, tail_obj, cnt, addr);
> +		__slab_free(s, slab, head, tail, cnt, addr);
>  		return;
>  	}
>  
>  	if (USE_LOCKLESS_FAST_PATH()) {
>  		freelist = READ_ONCE(c->freelist);
>  
> -		set_freepointer(s, tail_obj, freelist);
> +		set_freepointer(s, tail, freelist);
>  
>  		if (unlikely(!__update_cpu_freelist_fast(s, freelist, head, tid))) {
>  			note_cmpxchg_failure("slab_free", s, tid);
> @@ -4270,7 +4269,7 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
>  		tid = c->tid;
>  		freelist = c->freelist;
>  
> -		set_freepointer(s, tail_obj, freelist);
> +		set_freepointer(s, tail, freelist);
>  		c->freelist = head;
>  		c->tid = next_tid(tid);
>  
> @@ -4283,15 +4282,27 @@ static void do_slab_free(struct kmem_cache *s,
>  				struct slab *slab, void *head, void *tail,
>  				int cnt, unsigned long addr)
>  {
> -	void *tail_obj = tail ? : head;
> -
> -	__slab_free(s, slab, head, tail_obj, cnt, addr);
> +	__slab_free(s, slab, head, tail, cnt, addr);
>  }
>  #endif /* CONFIG_SLUB_TINY */
>  
> -static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
> -				      void *head, void *tail, void **p, int cnt,
> -				      unsigned long addr)
> +static __fastpath_inline
> +void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
> +	       unsigned long addr)
> +{
> +	bool init;
> +
> +	memcg_slab_free_hook(s, slab, &object, 1);
> +
> +	init = !is_kfence_address(object) && slab_want_init_on_free(s);
> +
> +	if (likely(slab_free_hook(s, object, init)))
> +		do_slab_free(s, slab, object, object, 1, addr);
> +}
> +
> +static __fastpath_inline
> +void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
> +		    void *tail, void **p, int cnt, unsigned long addr)
>  {
>  	memcg_slab_free_hook(s, slab, p, cnt);
>  	/*
> @@ -4305,7 +4316,7 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
>  #ifdef CONFIG_KASAN_GENERIC
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
>  {
> -	do_slab_free(cache, virt_to_slab(x), x, NULL, 1, addr);
> +	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
>  }
>  #endif
>  
> @@ -4349,7 +4360,7 @@ void kmem_cache_free(struct kmem_cache *s, void *x)
>  	if (!s)
>  		return;
>  	trace_kmem_cache_free(_RET_IP_, x, s);
> -	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, _RET_IP_);
> +	slab_free(s, virt_to_slab(x), x, _RET_IP_);
>  }
>  EXPORT_SYMBOL(kmem_cache_free);
>  
> @@ -4395,7 +4406,7 @@ void kfree(const void *object)
>  
>  	slab = folio_slab(folio);
>  	s = slab->slab_cache;
> -	slab_free(s, slab, x, NULL, &x, 1, _RET_IP_);
> +	slab_free(s, slab, x, _RET_IP_);
>  }
>  EXPORT_SYMBOL(kfree);
>  
> @@ -4512,8 +4523,8 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  		if (!df.slab)
>  			continue;
>  
> -		slab_free(df.s, df.slab, df.freelist, df.tail, &p[size], df.cnt,
> -			  _RET_IP_);
> +		slab_free_bulk(df.s, df.slab, df.freelist, df.tail, &p[size],
> +			       df.cnt, _RET_IP_);
>  	} while (likely(size));
>  }
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93adcdc0-6f32-45fa-b311-34a27ff94290%40linux.dev.
