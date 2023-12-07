Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBWWAYSVQMGQELLBZGRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 59B52807DE9
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 02:31:08 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-35d695ad674sf5091135ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 17:31:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701912667; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLsczXI8UYWLU9Sl1QlPI1/tCEqfFib7mdLxHxUUmVF/oS6pmLnbx6o2Go3hHws2Lm
         Ih9pBemW+Rvn3LSel9GkGWrgieq6tk+vaKJbgWTifs8Swbe7lF52q+sRxyLXExe4irFT
         9qjyk4fa9iIv7q/MA6E951KUcbE7bm7ux8GcGcE1X6mpBOdeniz54XNtwy54HGJBXc9h
         OqZDb6072k6kG7SstKHse/L6wNHL/ps4zUddgyWqbsGacSO+u1wvnoDvK5iDS/OP9oIf
         52aZdi+YTzimSEtZ2v+5I6rx6b/MAwn+mrJI1uDCL26VQyT/vuxkgjsyEDut+HhMyuFl
         k9NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=E20CEODmYxlO6rR8lUq9P1pt6uWqermmHOS1OIbC0ZA=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=q30yuvd6eNo3zOM6VBt7GZw9CQ4kzDxms5tJfzXRSyVAFCIVgwTifwcgorusrw2Gih
         D+woX8Jo2eq8x5flDPxJOJX/BdOgVKI7O2f3ycC+0XvQd3JzX3ozAb1aEG2sb4M+F/dk
         4FZfg6kyveLFQSXzTfJSwesewIjFGbV9uFjC6hycWtNy8JLdAuRHSCuPDdeq3l4U5MsI
         VNbwsXgy35rlmj4b45YtV1ZesFLAS5caO5Dy1DlhjRbX3R1EXwPjxKSXHPQlH3xkIQ5c
         Rpvw3AO21UZgyElNuyM6HPQ+AM6z1+BlXYcbdNzdEK/cgE5xRNigbQE+kx666eXQ/X38
         FfnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BrVITiQp;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2001:4860:4864:20::2d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701912667; x=1702517467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E20CEODmYxlO6rR8lUq9P1pt6uWqermmHOS1OIbC0ZA=;
        b=dSd/iwQVacTGi9e9BBs7etU/zFnq61JYTUxZ6cAi/JfreRim4FeAAZsWF5+BystGEt
         DVhOVFI2bDOEk5ad/TUXVjwPQ8d+D/QPFkZi592yjnDdN3/kzr0lkzEN/pYzpZIErWn4
         pAmJ1kHwy4w3hA924Va4/j6ecNyTf0aVeGTHxs4tl4aLdfDYtoDq+vDL7o/E+LKnRVf5
         z61muH4waqIHRZE4N2+2P/TbI5XIhNTObu2cYMziLRgZQOVLn93JAAkXzwFNXXsDDsh4
         /mBQYVTDeTBRo/VEVY97uVlXeT34csGEh5h7krW1GLuhHbRLc5HHuBaSE/BWRChsNVFB
         8qKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701912667; x=1702517467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=E20CEODmYxlO6rR8lUq9P1pt6uWqermmHOS1OIbC0ZA=;
        b=fYAarSx6yrtinjg9/HIUgpv2O8i2+KhjxeCtBL6M6ZZIBa8uv7dIB8W7HsiRVhALNZ
         RR9B7BFfR5fbi15bovYb77fjNdA185npIHPkkWCav/1qD0c9sveA3GSqTCTmgI8kyhUh
         qHE54tR48e3p9Z2s41bufr6k1y2eF0VakJj1pWcmmKgQMBsR2S+x+MLJmB9Jn7ocm3ek
         GBsCfVrBJKp6ReDxZyHq2Lv99WJ8YwfjnWmfrEgqFLwCVCuQL5INnvTdeCVVjtxHqNp/
         6xVVXWqlw8Nh3s0wPMhiKM1X7fl/A758/rYiREfjIuwRBAorTSSIQ8nio31JcHFuPdg6
         E/GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701912667; x=1702517467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E20CEODmYxlO6rR8lUq9P1pt6uWqermmHOS1OIbC0ZA=;
        b=oCSBD7Cl4UmPCQ80KOSIH730vetPQDl0Y4v2rsAPWZEQ/qghgnNMcXR7/rGDe0xTve
         jozWXyCvKC34I/gYmN4K6iWKDAtW0hX9EjfBy1XfKcd0h8UXHYcIN1qCiM9d9fXC8fKd
         kuWNL0gdUMHU+Udlly5GZPbRrCFFE1hY+p3bm8GfiNcmcaaV//V0Yu9javXgwLcMlJFI
         5OMpzj1igRu3L6pSWoT+VkqYhp/cD2T5ihskv560lqMk+emRPrpgI/Tjfi/pfvtZZs89
         PJ07Az+tQnxFyAnk9tqBW8aiJI55cV8lXHpOxsE3KQe0nCG5Fbxp26rdBhEXMOy8e5KL
         6avg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwrcuiEn2LMCf+5uO4WlrGxCGFcqA02h/kZN/+QUDpumkeJl9nk
	8kI93GBX2H8MyFRryhwS4d0=
X-Google-Smtp-Source: AGHT+IH2klqyzl86HyBvGu9bmfgUHWzld9deY0kVuw9Omkojl8SAqp+Bm5BXow9I/ygs60L6c6JjQA==
X-Received: by 2002:a92:740a:0:b0:35d:7c26:8d86 with SMTP id p10-20020a92740a000000b0035d7c268d86mr2077646ilc.74.1701912666978;
        Wed, 06 Dec 2023 17:31:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1785:b0:35d:7c0c:b961 with SMTP id
 y5-20020a056e02178500b0035d7c0cb961ls391685ilu.1.-pod-prod-02-us; Wed, 06 Dec
 2023 17:31:06 -0800 (PST)
X-Received: by 2002:a05:6e02:1041:b0:35d:7179:3e71 with SMTP id p1-20020a056e02104100b0035d71793e71mr1876957ilj.127.1701912665978;
        Wed, 06 Dec 2023 17:31:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701912665; cv=none;
        d=google.com; s=arc-20160816;
        b=eRzeG9ML3Bp6lquzxOgATXUqAxXaSdgP8A/I83d3R4fcNWXi2OI4oF8/YncFfLW/vO
         1c/9FaABJQW9qkWhRPY9GZHzK59Z7D1jeZBBX+7ITMle3brMw8NN0t7Cpy9Zb5xrpKcl
         cSXt3zwyYhkzo5qoZbUVs87AYj6q10uS7XckfX6nzRnetvL4ZXuwf4oE6rQ/2FKYaI54
         YfgPlgQAbC/g8XGJKoJDE67GAX4wkiyMslg6M4Bg/pmHdahGE2ukmMqQxLE5Uui2cr8n
         IwQNi/O+bSZIKk0h/pJKr3+O67CqDtO3ZL/ef/YcC/0hB2crEwOP77pvEhpTVj5cpM5T
         liUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FC4kVPBMR3jCsCH7t301OXLH/yq0oHM2fZo2MjvGfcg=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=RxlMQMEu/iV5XiAkIqUrXUxaDC6fW3ymauWUEP7di1pTVsIEm8n2fBsWKJYS94UlX9
         17McO1yVPLWC2x5hODYPvKIDxAFQRdY0HNmwQM3+g1CYebi/txtUv0F2gYqbGoSXWBDh
         FyRS+j5gO4DhXE3lTpy7UWdhhcajG1GhqtIt2LWeihQgGMEDbgmtHEkY56rl8zwlXsWb
         5PiiKk0jTiJ3EkkdPNUI9wqbwFFbfKrl9r0p1YY1KDsCPt4t6yduSGmzQuZY6HhGnIdB
         2nFoMpZa4NdNr0supXtNUXUvvYqy2izhI3p3w0av5Fp+mZKTrCRvomT4Ox8/Exm6B7cZ
         FUMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BrVITiQp;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2001:4860:4864:20::2d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x2d.google.com (mail-oa1-x2d.google.com. [2001:4860:4864:20::2d])
        by gmr-mx.google.com with ESMTPS id a8-20020a92a308000000b0035c823a9411si14309ili.3.2023.12.06.17.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 17:31:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2001:4860:4864:20::2d as permitted sender) client-ip=2001:4860:4864:20::2d;
Received: by mail-oa1-x2d.google.com with SMTP id 586e51a60fabf-1fb37f25399so301270fac.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 17:31:05 -0800 (PST)
X-Received: by 2002:a05:6870:9d9b:b0:1fb:75a:779d with SMTP id pv27-20020a0568709d9b00b001fb075a779dmr1959822oab.78.1701912665309;
        Wed, 06 Dec 2023 17:31:05 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id i16-20020a056a00005000b006cde2889213sm158443pfk.14.2023.12.06.17.30.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 17:31:04 -0800 (PST)
Date: Thu, 7 Dec 2023 10:30:57 +0900
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
Subject: Re: [PATCH v2 18/21] mm/slab: move kmalloc() functions from
 slab_common.c to slub.c
Message-ID: <ZXEgUVrUuIHlgsec@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-18-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-18-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BrVITiQp;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2001:4860:4864:20::2d
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:29PM +0100, Vlastimil Babka wrote:
> This will eliminate a call between compilation units through
> __kmem_cache_alloc_node() and allow better inlining of the allocation
> fast path.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h        |   3 --
>  mm/slab_common.c | 119 ----------------------------------------------------
>  mm/slub.c        | 126 +++++++++++++++++++++++++++++++++++++++++++++++++++----
>  3 files changed, 118 insertions(+), 130 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 7d7cc7af614e..54deeb0428c6 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -416,9 +416,6 @@ kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
>  	return kmalloc_caches[kmalloc_type(flags, caller)][index];
>  }
>  
> -void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
> -			      int node, size_t orig_size,
> -			      unsigned long caller);
>  gfp_t kmalloc_fix_flags(gfp_t flags);
>  
>  /* Functions provided by the slab allocators */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 31ade17a7ad9..238293b1dbe1 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -936,50 +936,6 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>  	slab_state = UP;
>  }
>  
> -static void *__kmalloc_large_node(size_t size, gfp_t flags, int node);
> -static __always_inline
> -void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
> -{
> -	struct kmem_cache *s;
> -	void *ret;
> -
> -	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
> -		ret = __kmalloc_large_node(size, flags, node);
> -		trace_kmalloc(caller, ret, size,
> -			      PAGE_SIZE << get_order(size), flags, node);
> -		return ret;
> -	}
> -
> -	if (unlikely(!size))
> -		return ZERO_SIZE_PTR;
> -
> -	s = kmalloc_slab(size, flags, caller);
> -
> -	ret = __kmem_cache_alloc_node(s, flags, node, size, caller);
> -	ret = kasan_kmalloc(s, ret, size, flags);
> -	trace_kmalloc(caller, ret, size, s->size, flags, node);
> -	return ret;
> -}
> -
> -void *__kmalloc_node(size_t size, gfp_t flags, int node)
> -{
> -	return __do_kmalloc_node(size, flags, node, _RET_IP_);
> -}
> -EXPORT_SYMBOL(__kmalloc_node);
> -
> -void *__kmalloc(size_t size, gfp_t flags)
> -{
> -	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
> -}
> -EXPORT_SYMBOL(__kmalloc);
> -
> -void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
> -				  int node, unsigned long caller)
> -{
> -	return __do_kmalloc_node(size, flags, node, caller);
> -}
> -EXPORT_SYMBOL(__kmalloc_node_track_caller);
> -
>  /**
>   * __ksize -- Report full size of underlying allocation
>   * @object: pointer to the object
> @@ -1016,30 +972,6 @@ size_t __ksize(const void *object)
>  	return slab_ksize(folio_slab(folio)->slab_cache);
>  }
>  
> -void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
> -{
> -	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
> -					    size, _RET_IP_);
> -
> -	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
> -
> -	ret = kasan_kmalloc(s, ret, size, gfpflags);
> -	return ret;
> -}
> -EXPORT_SYMBOL(kmalloc_trace);
> -
> -void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
> -			 int node, size_t size)
> -{
> -	void *ret = __kmem_cache_alloc_node(s, gfpflags, node, size, _RET_IP_);
> -
> -	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
> -
> -	ret = kasan_kmalloc(s, ret, size, gfpflags);
> -	return ret;
> -}
> -EXPORT_SYMBOL(kmalloc_node_trace);
> -
>  gfp_t kmalloc_fix_flags(gfp_t flags)
>  {
>  	gfp_t invalid_mask = flags & GFP_SLAB_BUG_MASK;
> @@ -1052,57 +984,6 @@ gfp_t kmalloc_fix_flags(gfp_t flags)
>  	return flags;
>  }
>  
> -/*
> - * To avoid unnecessary overhead, we pass through large allocation requests
> - * directly to the page allocator. We use __GFP_COMP, because we will need to
> - * know the allocation order to free the pages properly in kfree.
> - */
> -
> -static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
> -{
> -	struct page *page;
> -	void *ptr = NULL;
> -	unsigned int order = get_order(size);
> -
> -	if (unlikely(flags & GFP_SLAB_BUG_MASK))
> -		flags = kmalloc_fix_flags(flags);
> -
> -	flags |= __GFP_COMP;
> -	page = alloc_pages_node(node, flags, order);
> -	if (page) {
> -		ptr = page_address(page);
> -		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
> -				      PAGE_SIZE << order);
> -	}
> -
> -	ptr = kasan_kmalloc_large(ptr, size, flags);
> -	/* As ptr might get tagged, call kmemleak hook after KASAN. */
> -	kmemleak_alloc(ptr, size, 1, flags);
> -	kmsan_kmalloc_large(ptr, size, flags);
> -
> -	return ptr;
> -}
> -
> -void *kmalloc_large(size_t size, gfp_t flags)
> -{
> -	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
> -
> -	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
> -		      flags, NUMA_NO_NODE);
> -	return ret;
> -}
> -EXPORT_SYMBOL(kmalloc_large);
> -
> -void *kmalloc_large_node(size_t size, gfp_t flags, int node)
> -{
> -	void *ret = __kmalloc_large_node(size, flags, node);
> -
> -	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
> -		      flags, node);
> -	return ret;
> -}
> -EXPORT_SYMBOL(kmalloc_large_node);
> -
>  #ifdef CONFIG_SLAB_FREELIST_RANDOM
>  /* Randomize a generic freelist */
>  static void freelist_randomize(unsigned int *list,
> diff --git a/mm/slub.c b/mm/slub.c
> index 2baa9e94d9df..d6bc15929d22 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3851,14 +3851,6 @@ void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_lru);
>  
> -void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
> -			      int node, size_t orig_size,
> -			      unsigned long caller)
> -{
> -	return slab_alloc_node(s, NULL, gfpflags, node,
> -			       caller, orig_size);
> -}
> -
>  /**
>   * kmem_cache_alloc_node - Allocate an object on the specified node
>   * @s: The cache to allocate from.
> @@ -3882,6 +3874,124 @@ void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_node);
>  
> +/*
> + * To avoid unnecessary overhead, we pass through large allocation requests
> + * directly to the page allocator. We use __GFP_COMP, because we will need to
> + * know the allocation order to free the pages properly in kfree.
> + */
> +static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
> +{
> +	struct page *page;
> +	void *ptr = NULL;
> +	unsigned int order = get_order(size);
> +
> +	if (unlikely(flags & GFP_SLAB_BUG_MASK))
> +		flags = kmalloc_fix_flags(flags);
> +
> +	flags |= __GFP_COMP;
> +	page = alloc_pages_node(node, flags, order);
> +	if (page) {
> +		ptr = page_address(page);
> +		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
> +				      PAGE_SIZE << order);
> +	}
> +
> +	ptr = kasan_kmalloc_large(ptr, size, flags);
> +	/* As ptr might get tagged, call kmemleak hook after KASAN. */
> +	kmemleak_alloc(ptr, size, 1, flags);
> +	kmsan_kmalloc_large(ptr, size, flags);
> +
> +	return ptr;
> +}
> +
> +void *kmalloc_large(size_t size, gfp_t flags)
> +{
> +	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
> +
> +	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
> +		      flags, NUMA_NO_NODE);
> +	return ret;
> +}
> +EXPORT_SYMBOL(kmalloc_large);
> +
> +void *kmalloc_large_node(size_t size, gfp_t flags, int node)
> +{
> +	void *ret = __kmalloc_large_node(size, flags, node);
> +
> +	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
> +		      flags, node);
> +	return ret;
> +}
> +EXPORT_SYMBOL(kmalloc_large_node);
> +
> +static __always_inline
> +void *__do_kmalloc_node(size_t size, gfp_t flags, int node,
> +			unsigned long caller)
> +{
> +	struct kmem_cache *s;
> +	void *ret;
> +
> +	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
> +		ret = __kmalloc_large_node(size, flags, node);
> +		trace_kmalloc(caller, ret, size,
> +			      PAGE_SIZE << get_order(size), flags, node);
> +		return ret;
> +	}
> +
> +	if (unlikely(!size))
> +		return ZERO_SIZE_PTR;
> +
> +	s = kmalloc_slab(size, flags, caller);
> +
> +	ret = slab_alloc_node(s, NULL, flags, node, caller, size);
> +	ret = kasan_kmalloc(s, ret, size, flags);
> +	trace_kmalloc(caller, ret, size, s->size, flags, node);
> +	return ret;
> +}
> +
> +void *__kmalloc_node(size_t size, gfp_t flags, int node)
> +{
> +	return __do_kmalloc_node(size, flags, node, _RET_IP_);
> +}
> +EXPORT_SYMBOL(__kmalloc_node);
> +
> +void *__kmalloc(size_t size, gfp_t flags)
> +{
> +	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
> +}
> +EXPORT_SYMBOL(__kmalloc);
> +
> +void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
> +				  int node, unsigned long caller)
> +{
> +	return __do_kmalloc_node(size, flags, node, caller);
> +}
> +EXPORT_SYMBOL(__kmalloc_node_track_caller);
> +
> +void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
> +{
> +	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE,
> +					    _RET_IP_, size);
> +
> +	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
> +
> +	ret = kasan_kmalloc(s, ret, size, gfpflags);
> +	return ret;
> +}
> +EXPORT_SYMBOL(kmalloc_trace);
> +
> +void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
> +			 int node, size_t size)
> +{
> +	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, size);
> +
> +	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
> +
> +	ret = kasan_kmalloc(s, ret, size, gfpflags);
> +	return ret;
> +}
> +EXPORT_SYMBOL(kmalloc_node_trace);
> +
>  static noinline void free_to_partial_list(
>  	struct kmem_cache *s, struct slab *slab,
>  	void *head, void *tail, int bulk_cnt,
> 
> -- 

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEgUVrUuIHlgsec%40localhost.localdomain.
