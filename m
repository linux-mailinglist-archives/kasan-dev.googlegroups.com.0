Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBNUVXOVQMGQEBUJ6UEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CAE3804AD9
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 08:01:12 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-58d95645871sf5821846eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 23:01:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701759671; cv=pass;
        d=google.com; s=arc-20160816;
        b=wJB7hhE5jDrZFY2OnVqKquVs+MVi9K39/KttzLbTsdoBFBLr2nTLoNN5IGHCEZyLYa
         QvneZw70U8OGiB1Wkx/sPqNN6ENUT4oTpC8RiQjpME/u28wDhWGujYM5tlguHN1SHyRz
         7+rlonQ5m7f4RhY6svQi2IoGFL1c8S6vfGVbFCTSj4Q+ae78ZRR6bLK8VOcwur1CAhiu
         x4QO7DpMTvWDTi0DiFnlwPeoUK9EeZHBFBKuR4BwqU97pVDLkN68hE7MpOxkggKSZnks
         GLQCTPrUNTRlGIU++cJJRgqju6l3yEtDm9sY0wu4V6WSr3/7JOy2dqt9LeO+k2P4yAo1
         IDrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=+4++gz6R7jdJhLpjEwOFlusWy6k22fCRaNUDIqcmNPk=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=Lw+YroeWlN5tmI33PdBMu8sS/dUHE4QDsXVLP3kkSRWmRF0GDb81NN4RSTePt74aGk
         PGgplF6QyNbuGl8Vlzh+6BV+ZGB+cCWxQppUo0X92ZyPQEwOWrY1SCA1t4u+oH6CK5Ut
         0m3mXtpBPR0avtDPvYHDr2pVX/VmWBZIPd4NHoObLSLc/bftxPOiFMJcEZdirJTsLTAg
         jxGu14dC/G7tvCDONeDoAQMp2JtMZcdpQO4c3RmoMiBmr+RFvsjXds1DyHc/7GZTG8J+
         jTYuma9D8P1Ym+xm6BLBIIvN6mMlGv/ZKu2G8Ro0qrS7cQNnw9MHzbX7o1K3VleDGDCG
         jF/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ClnEG7/k";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701759671; x=1702364471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+4++gz6R7jdJhLpjEwOFlusWy6k22fCRaNUDIqcmNPk=;
        b=HDGvZUDalEu3dhm/2pFoTFpmvkh/nOWV8ZdfmgA4z0ztosD6qAFTftAMxxJyIa4Rxd
         24faUywWbU7aSi/yqQL04YoC6DWS9Nkil58EYNKJ1Hmt9exkPNPa8jP0GHtdkJeFsIE8
         IApixQXpGWts7VXYgui+OBUN7YkrDhVUy+lgaBN2qBMYbYV4mYs/7MjQxaHdeyuB4WfY
         MK4KdZUJcs6xUbUKtUZbGKnoRwdOTYLontMQfit1LUcHxHR85NQeLK8K1/Wzp75P2UGM
         xV2kfVA+z+NBeBGBIAT5IxrzGr7kfpkwEswlWG6fdiAtRXuGd1tOZWzFSFwOeWc/h6YY
         650Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701759671; x=1702364471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+4++gz6R7jdJhLpjEwOFlusWy6k22fCRaNUDIqcmNPk=;
        b=ioa0DIX97LvqIr1Hw+EmvjcpeyGSjbRG42M972gmgfEtwPfBmFuzsg0k1OHPn4c06L
         jBFKy+dvpxf8ZIfdGNq/KD2f3oYfJ8/uoN+OTL7vVhjiSq8yQ+ryMtWKON8npu16vATr
         G1gxS2uZLh63iNdlV7piNVenYZs468EQv2h52DdnuR0kSI8ai8EAdXdTBoqxs0MMFBoB
         QbE80MgeoyY3DHY41k+GrllMqyFxkhDLFsr8XroC8q2rEGEW4cSXErzaSZ+9p6sfrVLW
         21MJgFuVs2Z41wGqGUYukuPODian2fryOZtGqEqFw0IVmjguS9MtJlO3YbbkE4lYz1Fz
         4JUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701759671; x=1702364471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+4++gz6R7jdJhLpjEwOFlusWy6k22fCRaNUDIqcmNPk=;
        b=WPt2ncEaNnTMlsRqx+8FVo/QmpN/OFb6871uRBzSVTSU/rkxZsQpIgxQlxh8967s4r
         DOpZ+/RBAd2RYalPZf/8klUtlXG1/AyxYLJhm+EghyfLpQ/cxckhzWO9nk5uNlcfBwo9
         /7EPwV0rzSUPG2EIAfwFK9c2hMxq/kxp9BlJG1HD/wSgMUE2megECLYUsGm6SVNy5LbU
         R6+V16YJ7LjMXMg3PM1qYdSdeNa+9DPf+Jc9g2NPI11np05Wn8+w1MpiKyzqrHLEj0uk
         SHW2dX4ilbT55dqkqDtaTY6jsugffNc9BiiUJkMv49szx/Otf2LHvQYL4XIByMwbkdwH
         JwqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxA1atyyHuyvgEiJU+07wEDgQ7+WPx0EJrCmJwh9N7YpjZJdfoy
	qaEAdeswOF+ZWNktFN+I6mg=
X-Google-Smtp-Source: AGHT+IH/TlHEDBYel1Ch7IgbGvBEUOlztfz3CqDgsfd3Nny3c/UDhCghJ1Q0aInbmKJ4G7lPjKSU+Q==
X-Received: by 2002:a05:6870:332c:b0:1fb:75b:2b9d with SMTP id x44-20020a056870332c00b001fb075b2b9dmr2818328oae.89.1701759670735;
        Mon, 04 Dec 2023 23:01:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6b9b:b0:1fb:17f2:5fa4 with SMTP id
 ms27-20020a0568706b9b00b001fb17f25fa4ls342873oab.1.-pod-prod-00-us; Mon, 04
 Dec 2023 23:01:10 -0800 (PST)
X-Received: by 2002:a05:6871:72a:b0:1fb:153d:9e2e with SMTP id f42-20020a056871072a00b001fb153d9e2emr990457oap.5.1701759670434;
        Mon, 04 Dec 2023 23:01:10 -0800 (PST)
Received: by 2002:a05:6808:1783:b0:3b8:5d96:faea with SMTP id 5614622812f47-3b8a855323amsb6e;
        Mon, 4 Dec 2023 19:54:09 -0800 (PST)
X-Received: by 2002:a05:6808:10c2:b0:3b8:b063:894d with SMTP id s2-20020a05680810c200b003b8b063894dmr3135998ois.91.1701748448380;
        Mon, 04 Dec 2023 19:54:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701748448; cv=none;
        d=google.com; s=arc-20160816;
        b=ZIj9VCDmtuHMVdc+GEn1bKEVEa2+K67p/9KAKAdkfcYxxzFtVyrtwFLI0CAOCKUw+/
         HQVLoQ//O1LsTtnwmo7jCML5zSjhWnOeOUaHzBGVrXHf3+hwD5DcrVRcIeqaNyv3IlWG
         CYh0HCo2KxqqJBqlNldkK9mGm8BgFYhF/XOYmmOoPR7cR3wtxJXziBkkFqboG4s2CR+y
         GX1Pf9ytBN3ksfxY+6OrNdCQidvqJufeAlALFpodNzOJDZ2Zuz3J50ixaI5Q6FqT1kt0
         On5q8ZDAGpPHIWrRftbuXHUw5agDOeYVRSsZOI5RLTY2jUkTuJ5YgGi1FmHgtqnq/wJ0
         9BXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mAbPD6wQF1oZm18W+YGadKrbUnABiAjudnkBSiNtMNk=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=DOjKCmjWR/JHUH6d1UYR7ThKNlBSVd4G+n+kDOcRO76Gl++DmQDexEbTmAhdinW3Wa
         yI4QFwZRUy3R16wHy8zmsWSNiPRweWxrlL0g/fPdPDfteCsWPKAF3zjKQo5NzYAVfYrX
         dTmwCDnOxnvKjEN4CqxBp9O4Gt4uXL6FYSQURpks2zu1RyAeAnTdcEI5LZ5nzZnDAJJS
         1lhe5fIZxq2MEXxcT8ELKDuRQek8Fr6tesIuWruphIHcnoUaEf+IKY6ZmouVUDwwLK81
         SDUbcnGpuMvgYHTTxUJqeaZanMLdjjguVGFULlxt7ZTVGdpXD8yMcQ5ukbFjrSV4saX6
         KGVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ClnEG7/k";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id gt12-20020a0568082e8c00b003aef18f3442si1110566oib.0.2023.12.04.19.54.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Dec 2023 19:54:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1d0538d9bbcso33144495ad.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Dec 2023 19:54:08 -0800 (PST)
X-Received: by 2002:a17:902:f54c:b0:1d0:6ffd:e2b0 with SMTP id h12-20020a170902f54c00b001d06ffde2b0mr6599717plf.74.1701748447380;
        Mon, 04 Dec 2023 19:54:07 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id i8-20020a17090332c800b001b8b2a6c4a4sm9168837plr.172.2023.12.04.19.54.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 19:54:06 -0800 (PST)
Date: Tue, 5 Dec 2023 12:53:51 +0900
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
Subject: Re: [PATCH v2 01/21] mm/slab, docs: switch mm-api docs generation
 from slab.c to slub.c
Message-ID: <ZW6ez8IvvS9ojnZx@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-1-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-1-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="ClnEG7/k";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a
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

On Mon, Nov 20, 2023 at 07:34:12PM +0100, Vlastimil Babka wrote:
> The SLAB implementation is going to be removed, and mm-api.rst currently
> uses mm/slab.c to obtain kerneldocs for some API functions. Switch it to
> mm/slub.c and move the relevant kerneldocs of exported functions from
> one to the other. The rest of kerneldocs in slab.c is for static SLAB
> implementation-specific functions that don't have counterparts in slub.c
> and thus can be simply removed with the implementation.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  Documentation/core-api/mm-api.rst |  2 +-
>  mm/slab.c                         | 21 ---------------------
>  mm/slub.c                         | 21 +++++++++++++++++++++
>  3 files changed, 22 insertions(+), 22 deletions(-)
> 
> diff --git a/Documentation/core-api/mm-api.rst b/Documentation/core-api/mm-api.rst
> index 2d091c873d1e..af8151db88b2 100644
> --- a/Documentation/core-api/mm-api.rst
> +++ b/Documentation/core-api/mm-api.rst
> @@ -37,7 +37,7 @@ The Slab Cache
>  .. kernel-doc:: include/linux/slab.h
>     :internal:
>  
> -.. kernel-doc:: mm/slab.c
> +.. kernel-doc:: mm/slub.c
>     :export:
>  
>  .. kernel-doc:: mm/slab_common.c
> diff --git a/mm/slab.c b/mm/slab.c
> index 9ad3d0f2d1a5..37efe3241f9c 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3491,19 +3491,6 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_bulk);
>  
> -/**
> - * kmem_cache_alloc_node - Allocate an object on the specified node
> - * @cachep: The cache to allocate from.
> - * @flags: See kmalloc().
> - * @nodeid: node number of the target node.
> - *
> - * Identical to kmem_cache_alloc but it will allocate memory on the given
> - * node, which can improve the performance for cpu bound structures.
> - *
> - * Fallback to other node is possible if __GFP_THISNODE is not set.
> - *
> - * Return: pointer to the new object or %NULL in case of error
> - */
>  void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
>  {
>  	void *ret = slab_alloc_node(cachep, NULL, flags, nodeid, cachep->object_size, _RET_IP_);
> @@ -3564,14 +3551,6 @@ void __kmem_cache_free(struct kmem_cache *cachep, void *objp,
>  	__do_kmem_cache_free(cachep, objp, caller);
>  }
>  
> -/**
> - * kmem_cache_free - Deallocate an object
> - * @cachep: The cache the allocation was from.
> - * @objp: The previously allocated object.
> - *
> - * Free an object which was previously allocated from this
> - * cache.
> - */
>  void kmem_cache_free(struct kmem_cache *cachep, void *objp)
>  {
>  	cachep = cache_from_obj(cachep, objp);
> diff --git a/mm/slub.c b/mm/slub.c
> index 63d281dfacdb..3e01731783df 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3518,6 +3518,19 @@ void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
>  			       caller, orig_size);
>  }
>  
> +/**
> + * kmem_cache_alloc_node - Allocate an object on the specified node
> + * @s: The cache to allocate from.
> + * @gfpflags: See kmalloc().
> + * @node: node number of the target node.
> + *
> + * Identical to kmem_cache_alloc but it will allocate memory on the given
> + * node, which can improve the performance for cpu bound structures.
> + *
> + * Fallback to other node is possible if __GFP_THISNODE is not set.
> + *
> + * Return: pointer to the new object or %NULL in case of error
> + */
>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
>  {
>  	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
> @@ -3822,6 +3835,14 @@ void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
>  	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
>  }
>  
> +/**
> + * kmem_cache_free - Deallocate an object
> + * @s: The cache the allocation was from.
> + * @x: The previously allocated object.
> + *
> + * Free an object which was previously allocated from this
> + * cache.
> + */
>  void kmem_cache_free(struct kmem_cache *s, void *x)
>  {
>  	s = cache_from_obj(s, x);
> 

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZW6ez8IvvS9ojnZx%40localhost.localdomain.
