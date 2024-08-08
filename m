Return-Path: <kasan-dev+bncBCT7LKPERQDRBYND2K2QMGQEIDGK75A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E248994B9C5
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 11:37:39 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1fca868b53csf7409945ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2024 02:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723109858; cv=pass;
        d=google.com; s=arc-20160816;
        b=uAY7Urp29eStdpua9gfU+pqRH/r/5K1GA8U+5PSYJU/47kfxwKnJ9zgbEjYTajLYbj
         A6NBP9I83YbpngairRCbyqaq7/toqEB0h8klYT3nsRcdTaYhu8HeD2VIFvnMa9GZhsNO
         zZVM6vgTitXMlxT8Jjtops2Tp91kr6rrqn+OCTxQDg0MOm9k+UAgEyqhmfIdHkvPP+MZ
         2vPqHVW6oSvRmo7InG3J3IeIVh26igshiwJ+o7k4GCladFBa4wQ7NO+kzpuGhzDmnYR1
         E7t+W3g8xZx4aDKCUkbCL0ILfus20uCNtW24/xbE9Xr6g2UdffoRt1/C4UpM355j0ZHa
         3CyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=gbzdT7MVNz2xCsSPcxFu1y8GkGE7WXXiSWFtm6Ae8ls=;
        fh=x2ouyP+R0UJEhKuBPRauIE27zJbeqH9RciQxLD1jGJ0=;
        b=pgL3yhBaxwPcsQ+hoACj+UfIPJ8zMulWSGbEB4Ow8pXxA/ga/210o+RnaSrJbsQqoe
         pe4bH4ygmJiOLSZPvhMwk62LSk1pjkRIUiZcR8SGLVWy29DBbz1qbjgiymJMc2Gu59dO
         Vl3t3Akv56LwA/Y2azOHmEs8t8kblbqfooxGJjQsq/d8oYxeOWmT5ZHUOvVuEJu2fpXs
         w3P4XuuTWCeUeZIaGyS+T5NyMqYpcidYtITauXtFsFh+u115hF+8iag4mTOFzPHDoftB
         gxqty5nzcahdHRUAcrct4X5VxvgGr2IQXxvSKK5Es2lVqDWrdVQUYxUB257Hb1H5acfd
         AbDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ruanjinjie@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=ruanjinjie@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723109858; x=1723714658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gbzdT7MVNz2xCsSPcxFu1y8GkGE7WXXiSWFtm6Ae8ls=;
        b=Xb6KHdkzTbIS0pAf5r4++m5fP/Q7/nob9OVskeLOxnWPmHM12Be++gmFKvUnlZ/+3g
         9QfgKbM0T+PCtGQWP4wu8ynJxUDGG0aki5+Zd8iSnaHnahIgipwKE/PkVlZxzbBJoPDt
         ILYYQymKfEW/hC4yI8qQC/wB6mRqM3D0vFOZ8IbIVlUGBNzbuDAwbtgnjD/YmmHsAoK0
         yEhlyOk+RumG/rwZ2Fp23lDiyaCfrwqUgNGN++MyhC5QG9/bD1xqgCx2eIYhQZc6t8S3
         bv8iRg0qkaVb4bzm+u4yHwzg9m0hNq2v4u4reqjY4XkcN7oveg4Nv4SJUbTO53unKptf
         pJLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723109858; x=1723714658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gbzdT7MVNz2xCsSPcxFu1y8GkGE7WXXiSWFtm6Ae8ls=;
        b=U+w/kOq/LUMGT8ohZknnVG1iwUHvF+/bNK/qgffengMHQOMcUosyqGJFDPs6gnC0bC
         bStzG8ifpGwnpiKcAyB03MVJ+Lu5jnzMuqg39NQ6Matf5L+wJnt6NSbd279PHYy0iw22
         tnkXxr8FPi7UjGeuia9P1mNS3BHJH6Z4TNnmB3BE7R5pPwfgSBEV4gloTSgTNXSuhBgj
         fopCQOLvxcQ2r7+B0qBDKCu/G/N9hn+UaPk7Z/4PNptTTy7lAVAxsxNLWBreGAW1BXhI
         ijJtABo4cksP5afTwk16cw8lz/xskl77HSQZnBEiBEPrRnoDaAA5jdI0HL+1rVni/7CD
         +Vpw==
X-Forwarded-Encrypted: i=2; AJvYcCXEsPVLUgZbFxXr0zCCQw8FehZ7sit8S1hzT0a7cg0oLtpZc44hF+XX1se3pnQQyNBRN1Q4fVUjKjgukzKqCheUzcN0gGf70g==
X-Gm-Message-State: AOJu0YytX6ZDRlFKqNlWVG3IAy/SUNubAfLQfVuEjrkjwrn1afta19Py
	5u0jJAeva+QdqbAeAJ19Zs/jxhxGo9XBlyqdJe+rxCzF5z2qVr8Q
X-Google-Smtp-Source: AGHT+IEk7/pu7nr9l6ar9ZQqGHQProoiNjjK6b8DdXt/oJl0JR4geuWY+hUSDHJGbYl4R8742AYUoA==
X-Received: by 2002:a17:902:d4c2:b0:1ff:1bd:7e61 with SMTP id d9443c01a7336-20095252872mr12311005ad.14.1723109857891;
        Thu, 08 Aug 2024 02:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:1f7:1d41:9224 with SMTP id
 d9443c01a7336-20090625167ls5565725ad.1.-pod-prod-05-us; Thu, 08 Aug 2024
 02:37:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8GTmzloos51Wdv2wZfIqPhhYGC8Oi3Fwr1RIzR2Z2TZZRrOydfZ65A0leRrSIoV3wGZ+9m5cR5aC64MvwxafQB4sU3tcpf752tw==
X-Received: by 2002:a17:902:d508:b0:1fb:d335:b0bf with SMTP id d9443c01a7336-20095252f2emr15034805ad.25.1723109856613;
        Thu, 08 Aug 2024 02:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723109856; cv=none;
        d=google.com; s=arc-20160816;
        b=MxLAxXfJwnK9/whqULrRATI4Zj6Puo6zJekuNvjY0YRqDelz3jw2e86tXnblS8sSxl
         6GnBaN/6ulaSh9k9PEeiz4QUXGg+JpZHlXN5dY8bUWnLltP9TfFq1ZgT5jgBLVJRPl+i
         UzgxbWyHOpKHzoXdvxvLFmWWM/Vi7nMQIanavuaJFj3s7E57h/R9CgYslvCA8/Vh/p94
         vkHejVt7FXf3C9s1g+Bw9cov/PGJRzXSCPRCf/ZY4RsDfFDe9FO6l4L/yvQtJ2qsbAy2
         lonpAC4p+0gh3YkAiNhlUsQyeOHSEK7Sp1jN2U1StCosGcJNlmbOf2oLX7yeIeT0slEw
         Dyag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=62wOabOstf4lwV3t77AY3EOluNfI9D5JFi6YbAPl2XY=;
        fh=w7WGD/F95HLv/kjcAlxeJ9/1DyKl2fKDRfQGweFJBR8=;
        b=wR9oF9mggRn0Kw8yKRplELcsP4+8UoD3tYcF60dMWir1u7pUFUIp6R2yyUVLhbIejp
         JDMIY+lTc2+XLjXwXnpEUDh+8xr+TNRn/90Se/2E6ryKT/RH7+DVccaX2AWUgAeMuiAU
         4ulhKJC+PSAhyYOby4S8dtpUxSTJcV++YfNppOubHp+WUhI2EfamTRWaspTPR/n+Wa+c
         CNsk8ZE8HYhi8bB4gQTNEZtRKulGl58cFd/c67g5yRkHiZnnrNgfOE9I1uRcfDT96w/Q
         N8oJdrE8kNi2554VfpQdlBtm+9d0a1xLY4uxhhwwhlwQDRNX34o+zeH99bLjO1YWwBBu
         RNgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ruanjinjie@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=ruanjinjie@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga06-in.huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20064527131si3022745ad.7.2024.08.08.02.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2024 02:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ruanjinjie@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from mail.maildlp.com (unknown [172.19.88.234])
	by szxga06-in.huawei.com (SkyGuard) with ESMTP id 4Wfhjr4173z1xv1M;
	Thu,  8 Aug 2024 17:35:44 +0800 (CST)
Received: from kwepemi100008.china.huawei.com (unknown [7.221.188.57])
	by mail.maildlp.com (Postfix) with ESMTPS id 41FF71400CB;
	Thu,  8 Aug 2024 17:37:33 +0800 (CST)
Received: from [10.67.109.254] (10.67.109.254) by
 kwepemi100008.china.huawei.com (7.221.188.57) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Thu, 8 Aug 2024 17:37:31 +0800
Message-ID: <945e5c43-c5c8-5520-8d0d-b76b7d87f24f@huawei.com>
Date: Thu, 8 Aug 2024 17:37:31 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.0
Subject: Re: [PATCH 3/4] mm/slub: handle bulk and single object freeing
 separately
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka
 Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo
 Kim <iamjoonsoo.kim@lge.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander
 Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-3-88b65f7cd9d5@suse.cz>
From: "'Jinjie Ruan' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-3-88b65f7cd9d5@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.109.254]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemi100008.china.huawei.com (7.221.188.57)
X-Original-Sender: ruanjinjie@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ruanjinjie@huawei.com designates 45.249.212.32 as
 permitted sender) smtp.mailfrom=ruanjinjie@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Jinjie Ruan <ruanjinjie@huawei.com>
Reply-To: Jinjie Ruan <ruanjinjie@huawei.com>
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



On 2023/12/5 3:34, Vlastimil Babka wrote:
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


Hi, everyone,

I found many kmemleaks call trace as follow on linux-next, and it occurs
only after Linux 6.11-rc1, and I tried to locate the problem patch, but
it didn't work.

How to reproduce: with following config open
	CONFIG_HAVE_DEBUG_KMEMLEAK=y
	CONFIG_DEBUG_KMEMLEAK=y
	CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=y

unreferenced object 0xffff4913c0ddb380 (size 32):
  comm "kworker/R-acpi_", pid 65, jiffies 4294893729
  hex dump (first 32 bytes):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    00 25 94 c1 13 49 ff ff 00 00 00 00 00 00 00 00  .%...I..........
  backtrace (crc f9d57280):
    [<00000000c0652f06>] kmemleak_alloc+0x34/0x40
    [<000000006227a848>] __kmalloc_cache_noprof+0x270/0x2f8
    [<000000008acd203e>] kmem_cache_free+0x124/0x410
    [<00000000e43531e7>] __cleanup_sighand+0x94/0xc0
    [<0000000078680548>] release_task+0x828/0x1070
    [<00000000c0f8c5d5>] do_exit+0x111c/0x1edc
    [<00000000367ccb22>] kthread_exit+0x58/0x60
    [<00000000bc4738b5>] kthread+0x298/0x374
    [<00000000a533ef0f>] ret_from_fork+0x10/0x20


unreferenced object 0xffff4913c14d0fc0 (size 32):
  comm "softirq", pid 0, jiffies 4294894408
  hex dump (first 32 bytes):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    00 c0 a4 c5 13 49 ff ff 00 00 00 00 00 00 00 00  .....I..........
  backtrace (crc ad845771):
    [<00000000c0652f06>] kmemleak_alloc+0x34/0x40
    [<000000006227a848>] __kmalloc_cache_noprof+0x270/0x2f8
    [<000000008acd203e>] kmem_cache_free+0x124/0x410
    [<00000000e575b5fb>] mempool_free_slab+0x1c/0x28
    [<00000000b5df13a3>] mempool_free+0xd0/0x314
    [<000000000480d4fb>] bio_free+0x150/0x1bc
    [<000000000c247f54>] bio_put+0x3f8/0x950
    [<000000003916cfe2>] end_bio_bh_io_sync+0xc0/0x128
    [<000000001e99ce6a>] bio_endio+0x4d4/0x6d0
    [<0000000085eb0fe3>] blk_update_request+0x41c/0x1064
    [<000000007e079da2>] blk_mq_end_request+0x50/0x80
    [<0000000067fcfa3f>] virtblk_request_done+0x154/0x2b4
    [<00000000c2d49a49>] blk_complete_reqs+0xa8/0xe8
    [<000000006559344d>] blk_done_softirq+0x20/0x2c
    [<000000001c82c05d>] handle_softirqs+0x2b8/0xbd4
    [<00000000924bc46d>] __do_softirq+0x14/0x20


unreferenced object 0xffff4913c573a2c0 (size 32):
  comm "kworker/u16:0", pid 67, jiffies 4294894505
  hex dump (first 32 bytes):
    60 4e 01 c6 13 49 ff ff 00 00 00 00 00 00 00 00  `N...I..........
    00 c0 92 c7 13 49 ff ff 00 00 00 00 00 00 00 00  .....I..........
  backtrace (crc 8c85f9b3):
    [<00000000c0652f06>] kmemleak_alloc+0x34/0x40
    [<000000006227a848>] __kmalloc_cache_noprof+0x270/0x2f8
    [<000000008acd203e>] kmem_cache_free+0x124/0x410
    [<000000006285099d>] fput+0x2a0/0x334
    [<00000000e50ddea7>] path_openat+0x120c/0x1f70
    [<00000000986ab24f>] do_filp_open+0x154/0x328
    [<00000000ea1348f1>] do_open_execat+0xa4/0x224
    [<00000000e94e18f5>] alloc_bprm+0x20/0x964
    [<00000000b6ff006b>] kernel_execve+0x7c/0x2d4
    [<000000007deddead>] call_usermodehelper_exec_async+0x1e0/0x3c8
    [<00000000a533ef0f>] ret_from_fork+0x10/0x20
unreferenced object 0xffff4913c2c627c0 (size 32):
  comm "softirq", pid 0, jiffies 4294895572
  hex dump (first 32 bytes):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    00 00 1c c5 13 49 ff ff 00 00 00 00 00 00 00 00  .....I..........
  backtrace (crc 320469d7):
    [<00000000c0652f06>] kmemleak_alloc+0x34/0x40
    [<000000006227a848>] __kmalloc_cache_noprof+0x270/0x2f8
    [<000000008acd203e>] kmem_cache_free+0x124/0x410
    [<00000000e575b5fb>] mempool_free_slab+0x1c/0x28
    [<00000000b5df13a3>] mempool_free+0xd0/0x314
    [<000000000480d4fb>] bio_free+0x150/0x1bc
    [<000000000c247f54>] bio_put+0x3f8/0x950
    [<000000003916cfe2>] end_bio_bh_io_sync+0xc0/0x128
    [<000000001e99ce6a>] bio_endio+0x4d4/0x6d0
    [<0000000085eb0fe3>] blk_update_request+0x41c/0x1064
    [<000000007e079da2>] blk_mq_end_request+0x50/0x80
    [<0000000067fcfa3f>] virtblk_request_done+0x154/0x2b4
    [<00000000c2d49a49>] blk_complete_reqs+0xa8/0xe8
    [<000000006559344d>] blk_done_softirq+0x20/0x2c
    [<000000001c82c05d>] handle_softirqs+0x2b8/0xbd4
    [<00000000924bc46d>] __do_softirq+0x14/0x20

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/945e5c43-c5c8-5520-8d0d-b76b7d87f24f%40huawei.com.
