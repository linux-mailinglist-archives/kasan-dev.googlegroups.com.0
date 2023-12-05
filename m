Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBJGDXOVQMGQE6MT4IQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B455804CAD
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 09:39:02 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1fad1eeb333sf4939298fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 00:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701765541; cv=pass;
        d=google.com; s=arc-20160816;
        b=B9yOROIkHjP7H+R4rTZIuW1uuOYiniopsamX2WoEhaOp8MGD0batfSkbKAI0LuL4LN
         IvA0NnbJx9asJ18/m+5uBdk8s6fNT4qfj6uCSGzKnhl9v9TS3HAR3+gMRtHz5dEcFfkG
         wRO8eZB4YCnIVqBu9vEb8zbTs8eNDp0CcuW9hjefP6Vab6P46cWHI84cjiihdhv4YlOS
         4iUSegqNhROg+ZFWQ7M9zjNEQe2utyufaO9Lzqv9v+WT7diK6tQBbzzgDx3Wsc8lF57r
         qFe1x9/Unl++24lc8CZ+5ROPozhK3Cq3VWtaSgpdwMGl+jtVmN3be8PsaTDb1D6Vggwz
         Sn4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=lFFu+W0qKXAnPWMJWerbKYBqYeBs2rRTWZtgirYpGsM=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=ZXeTRUfItNR5pi4ATsTxgfQzaogM4QaO+5T3jm3ToNkbu+vvTDqx40XGctlAfewVOP
         m6/QjiH2dLVqrXnRvlv9M+KsXJ0wrE2BWC0by3Ke/36JcAWmtjSBWzfiPeB9kUGHaTbS
         qSpjoRf+OpHuj3ua8WuM9bBiSx3j3HcjJr3tmiXipO+d8RQXxXQJw7wImRB+eFEqf++f
         QxC8WAwnQ0OAdtlSDdWd8wT7Lq+uTtaGIigzQSR6tq2yXxkoc/w3syl7Q19+VQZ6B99h
         dUYND+qa9cYzzxap/TaSmxKtgtG24esBwYA6vb4lFtgMHT3/S1b+5cKO46a7JJzPrR/2
         snOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y0kl5WBE;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lFFu+W0qKXAnPWMJWerbKYBqYeBs2rRTWZtgirYpGsM=;
        b=C9w7TsDAxlpds4gFlBMV0zDPXhamjAOMrDkKKyW1CF8AfmuQLbTupKxnb+vdrQqna1
         CJrWIqzEu5NTHIXsqy2yZxYxQ75AMzscBfZ913q21XBBbG9dCvL0Q5I53I3rjo87Scfn
         EJ7p6PeI2h3v09HsPixIqzR8kh3YpYdwDsOsVUaF4byT7bOA/wm9qk72te2sWUzI1O18
         6WkmR4di8gRKj2kGnbnxhAJGKoo1EFroENc6UbaRBdEuMfthaCPw0fOiWuBTfKKXCbXL
         04cs0vpXOl5BjLD2UjPQHOwnPCkQdOYJD0gJwxvaCvMGAKFmuKQEfvVgPqaSI7mDPbnh
         yqyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=lFFu+W0qKXAnPWMJWerbKYBqYeBs2rRTWZtgirYpGsM=;
        b=VuNl2yDTkXEOxFbX9iDbmTXtD/P2elcd5NJ1NBo9hHo37uj3epqSyXO9uenMd1u4Lv
         hw/2kx06lrv1DN30AUESmuTqZlNVNB23wDdSGt45UoYEN+R1wHCxmB3BqDNPk2nfMayA
         3SlIqLfKjI/XV3B8n18UTaIKUUfVq3Ofl6pa2goxhksNXQO6eKYMM8eCeoNC01qDIHLA
         3lR5Cjc0wBGfTXqgjyMIHwXFGC+P91t1kI4uTRfH3qI0+X4WsKjHuOr2zw21HJoikq4A
         /PU3zxC9zInvS+6/MPDYyIW6k1un5+UM1cUT7GZ15PYv+3gZoVLj0eMsyokM1RWZp+Pe
         HPJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701765541; x=1702370341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lFFu+W0qKXAnPWMJWerbKYBqYeBs2rRTWZtgirYpGsM=;
        b=taSeOy6UsXCTRnun79l5utsDiP7/tuZkOrkLnqJ0Ny6sU+1CzsBURY3xtbE84Qp3K2
         9+Wb1YSXNOmOAhd/BIkoLnUbUE/qpbLr+TEELFgObdnN/GM1d1bKaIChW0Hm/zJBEOZW
         KzhfAnxsXlVGSM1JaaDHhKSQ/3yoQDrmLpZBnfLn2qhXoflIPm7vFCHC4XhTmL8g0q+7
         nf0sROgHo4YyCqsQXGoxrCXTQsVGj8rlXZMlGvuTCuTQmkPzebIXWpdQP+bn8wxQcb9R
         za1w/844VrL/PactVkB/y3msWKQEcDbxh2aUakYw789KqodWNazraPdiYDboxIisNmOF
         s9TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzc4nCHZSogRZeTUkXtLipP/nQ5BL13d42yJx9pDKErXxr044k5
	mj1Bn5fpzhjxxfrCuSD+Isg=
X-Google-Smtp-Source: AGHT+IEIu1wwq9p9ax/68P/EeluAodYJTT5BB03Cszi3u5ephO2uBHlpCrB2lelAXXDbeLBAij7S7Q==
X-Received: by 2002:a05:6871:aa07:b0:1fa:1579:906 with SMTP id wq7-20020a056871aa0700b001fa15790906mr7016229oab.12.1701765540912;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:718a:b0:1fb:1b99:3a67 with SMTP id
 d10-20020a056870718a00b001fb1b993a67ls1480181oah.2.-pod-prod-03-us; Tue, 05
 Dec 2023 00:39:00 -0800 (PST)
X-Received: by 2002:a05:6870:3911:b0:1fa:f1fc:f655 with SMTP id b17-20020a056870391100b001faf1fcf655mr3917692oap.7.1701765540646;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
Received: by 2002:a05:6808:1a0d:b0:3b3:ed04:dbd0 with SMTP id 5614622812f47-3b8a856eed1msb6e;
        Mon, 4 Dec 2023 20:38:41 -0800 (PST)
X-Received: by 2002:a92:dc10:0:b0:35d:5995:7990 with SMTP id t16-20020a92dc10000000b0035d59957990mr6686381iln.42.1701751120570;
        Mon, 04 Dec 2023 20:38:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701751120; cv=none;
        d=google.com; s=arc-20160816;
        b=S5o9DMOy9x1/DDLFThm3oOZC73bdeV9vnDRTJzAqwzoOwRHitn1ztmOOje+ltC3UUE
         9nxcIrGsM6IFk9BA0LFYgTspJAg3EvLbLZ2SLaFDqI5pNHm7aPuwIAOXbRSU0uKunzlk
         d/cjKSoenmwECrxtqFMd4b9+058POspjd+66k8VfNxPrKxGUP83n2zOiZfkd47kIUD4Q
         ATbOlxIJypNtahlsVbyXphZ6oS3MbWuasZn30jNQKYOtrfAtThdX8L3jklX5rY/lcw2H
         s6+4Ni4eRNJhX8xOyXs40aciEoX6zQHqB4n0fqgbQ5mVGt2c9u/5v0vPWpyWMe0qQMeF
         pxFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z8za1LL9JYBxMQqZEFu+Ip+HiV0+LDHs+kobZXAkLSM=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=Q7W0KLJS5awjrf4A+mxFMw9cvKp0DkBqhwm8odIvBYzc34HJWdZ6t6BUEEVwGg1yrN
         MjrOcziqWipBarAi1CwChK+XKclnEU0m5X0zxEcTvfnlDMtKg62+PigoJWD+aaIPMet1
         D5s/Go98icG6FOM+MV7dpq4qqFuEwyeYTYGjDLW8LoKAsABLhRWH3JybcfhvWlJwftEJ
         fGk9SH3ZL+DpTD8INNjFWaWjVSCrZ7H8QLMCeYxtnd3l8VF8c728c28bJrkdbaBZKEvr
         +Q0DqV8IYganTYlNvcU3MiaBpNraXAoLh5ilm62aQ+/SzQfsBHjU5WL43ZCc7m+gUYg7
         dEWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y0kl5WBE;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id l9-20020a056638144900b00468ec5fbeadsi521951jad.3.2023.12.04.20.38.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Dec 2023 20:38:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-6ce47909313so1227190b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Dec 2023 20:38:40 -0800 (PST)
X-Received: by 2002:a05:6a20:1586:b0:18f:97c:5b84 with SMTP id h6-20020a056a20158600b0018f097c5b84mr2423300pzj.82.1701751119663;
        Mon, 04 Dec 2023 20:38:39 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id c13-20020a170903234d00b001cfcf3dd317sm9212738plh.61.2023.12.04.20.38.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 20:38:38 -0800 (PST)
Date: Tue, 5 Dec 2023 13:38:21 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 16/21] mm/slab: move kfree() from slab_common.c to
 slub.c
Message-ID: <ZW6pPdvjOfaMmWxu@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-16-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-16-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Y0kl5WBE;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Mon, Nov 20, 2023 at 07:34:27PM +0100, Vlastimil Babka wrote:
> This should result in better code. Currently kfree() makes a function
> call between compilation units to __kmem_cache_free() which does its own
> virt_to_slab(), throwing away the struct slab pointer we already had in
> kfree(). Now it can be reused. Additionally kfree() can now inline the
> whole SLUB freeing fastpath.
> 
> Also move over free_large_kmalloc() as the only callsites are now in
> slub.c, and make it static.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h        |  4 ----
>  mm/slab_common.c | 45 ---------------------------------------------
>  mm/slub.c        | 51 ++++++++++++++++++++++++++++++++++++++++++++++-----
>  3 files changed, 46 insertions(+), 54 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 5ae6a978e9c2..35a55c4a407d 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -395,8 +395,6 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller);
>  void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
>  			      int node, size_t orig_size,
>  			      unsigned long caller);
> -void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller);
> -
>  gfp_t kmalloc_fix_flags(gfp_t flags);
>  
>  /* Functions provided by the slab allocators */
> @@ -559,8 +557,6 @@ static inline int memcg_alloc_slab_cgroups(struct slab *slab,
>  }
>  #endif /* CONFIG_MEMCG_KMEM */
>  
> -void free_large_kmalloc(struct folio *folio, void *object);
> -
>  size_t __ksize(const void *objp);
>  
>  static inline size_t slab_ksize(const struct kmem_cache *s)
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index bbc2e3f061f1..f4f275613d2a 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -963,22 +963,6 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>  	slab_state = UP;
>  }
>  
> -void free_large_kmalloc(struct folio *folio, void *object)
> -{
> -	unsigned int order = folio_order(folio);
> -
> -	if (WARN_ON_ONCE(order == 0))
> -		pr_warn_once("object pointer: 0x%p\n", object);
> -
> -	kmemleak_free(object);
> -	kasan_kfree_large(object);
> -	kmsan_kfree_large(object);
> -
> -	mod_lruvec_page_state(folio_page(folio, 0), NR_SLAB_UNRECLAIMABLE_B,
> -			      -(PAGE_SIZE << order));
> -	__free_pages(folio_page(folio, 0), order);
> -}
> -
>  static void *__kmalloc_large_node(size_t size, gfp_t flags, int node);
>  static __always_inline
>  void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
> @@ -1023,35 +1007,6 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
>  }
>  EXPORT_SYMBOL(__kmalloc_node_track_caller);
>  
> -/**
> - * kfree - free previously allocated memory
> - * @object: pointer returned by kmalloc() or kmem_cache_alloc()
> - *
> - * If @object is NULL, no operation is performed.
> - */
> -void kfree(const void *object)
> -{
> -	struct folio *folio;
> -	struct slab *slab;
> -	struct kmem_cache *s;
> -
> -	trace_kfree(_RET_IP_, object);
> -
> -	if (unlikely(ZERO_OR_NULL_PTR(object)))
> -		return;
> -
> -	folio = virt_to_folio(object);
> -	if (unlikely(!folio_test_slab(folio))) {
> -		free_large_kmalloc(folio, (void *)object);
> -		return;
> -	}
> -
> -	slab = folio_slab(folio);
> -	s = slab->slab_cache;
> -	__kmem_cache_free(s, (void *)object, _RET_IP_);
> -}
> -EXPORT_SYMBOL(kfree);
> -
>  /**
>   * __ksize -- Report full size of underlying allocation
>   * @object: pointer to the object
> diff --git a/mm/slub.c b/mm/slub.c
> index cc801f8258fe..2baa9e94d9df 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4197,11 +4197,6 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
>  	return cachep;
>  }
>  
> -void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
> -{
> -	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
> -}
> -
>  /**
>   * kmem_cache_free - Deallocate an object
>   * @s: The cache the allocation was from.
> @@ -4220,6 +4215,52 @@ void kmem_cache_free(struct kmem_cache *s, void *x)
>  }
>  EXPORT_SYMBOL(kmem_cache_free);
>  
> +static void free_large_kmalloc(struct folio *folio, void *object)
> +{
> +	unsigned int order = folio_order(folio);
> +
> +	if (WARN_ON_ONCE(order == 0))
> +		pr_warn_once("object pointer: 0x%p\n", object);
> +
> +	kmemleak_free(object);
> +	kasan_kfree_large(object);
> +	kmsan_kfree_large(object);
> +
> +	mod_lruvec_page_state(folio_page(folio, 0), NR_SLAB_UNRECLAIMABLE_B,
> +			      -(PAGE_SIZE << order));
> +	__free_pages(folio_page(folio, 0), order);
> +}
> +
> +/**
> + * kfree - free previously allocated memory
> + * @object: pointer returned by kmalloc() or kmem_cache_alloc()
> + *
> + * If @object is NULL, no operation is performed.
> + */
> +void kfree(const void *object)
> +{
> +	struct folio *folio;
> +	struct slab *slab;
> +	struct kmem_cache *s;
> +	void *x = (void *)object;
> +
> +	trace_kfree(_RET_IP_, object);
> +
> +	if (unlikely(ZERO_OR_NULL_PTR(object)))
> +		return;
> +
> +	folio = virt_to_folio(object);
> +	if (unlikely(!folio_test_slab(folio))) {
> +		free_large_kmalloc(folio, (void *)object);
> +		return;
> +	}
> +
> +	slab = folio_slab(folio);
> +	s = slab->slab_cache;
> +	slab_free(s, slab, x, NULL, &x, 1, _RET_IP_);
> +}
> +EXPORT_SYMBOL(kfree);
> +
>  struct detached_freelist {
>  	struct slab *slab;
>  	void *tail;

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

nit: mm/kfence/report.c checks if a function name starts with
"__kmem_cache_free" which is removed by this patch.

> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZW6pPdvjOfaMmWxu%40localhost.localdomain.
