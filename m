Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB3NDR6NQMGQECTBN5CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B189617FA9
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 15:36:30 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id t9-20020a5b03c9000000b006cff5077dc9sf2339268ybp.3
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 07:36:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667486189; cv=pass;
        d=google.com; s=arc-20160816;
        b=uB/VDzS4unh04EdcsHO/DBcAHUdFOH8wiRH3WAue/i3/FHE1DseFOLuXgZZxC5BsB3
         tgREa5HfZktVq15cIfE0RGRpXR8/qgtHahG+LVcWPRSTBR7opWYE1vL0wzGBKXbu/Ji3
         ragiU4Yr05/tr7lllDETCNDtcLTWWGSWcE4+unjMjDugHt7ukQ7kVkpAreqTBftN/UMq
         fM4obdfcX5q9sELBSufB1qnlACEarchUcY7+QBdQtSasVSc5/IDd42pZUukx1yuK3mX8
         Gf4xmjZM/TcDuDUicOWRiBsEKg7V1+ziu1J/y6uOW0m6UfO6PwXo1XoX6SXJWdHdndGY
         E13w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=6TljYPmvNCxy6eqX6WNrqPiK/alo5tkLVqEYfmF+IvQ=;
        b=Asyyjvl7aY01vfrMWzcbyozhrJ5g618ifTZNDtsdWI9EFeQrybVazuv9h7uPC+dNWp
         rX96MWV/Xn6eJ0Efga7ZXNxrPU3WjMpS7kXXknFcgjYxLEtXDANkUcSsEEJmO+8HUDwt
         340uODZu9Qd00sd//4o43VZSYjMbDEUlsEkCThuR8TOmdd6SJFMwaeBMzSRW5Qp1BMvy
         wgbMY2EsOndh3rdPDPvANrGUF6mGQUjJmiNCdW2Lw9cAKLnvqQEGg8iv0B1A0fKW14lI
         M44nAVh/3ENNeJB9ufELj6HfpkJvv027ezX9ZCT9ndryvInMnUgRysR4OIQLYzE2qepV
         fxTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="N4Ta5MP/";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6TljYPmvNCxy6eqX6WNrqPiK/alo5tkLVqEYfmF+IvQ=;
        b=a1qLFmKwgLXh7rTGhYtJLWeOK1pVKPXBI4tDmqxUP40DVjxLtine+W/3AuJ7FzERAn
         i2iRTxx7vMT3O46JROPdnl+sGoMliiQigDpdNiNBgkXpmTo6oKShblelKddgeuIKxIE+
         Zk3NCy1nO4Lw0rjKwtm4k0mkEUYBEYcXQbIVtawpsYdgUmh2UxJepoMCBPbpAbf6mFxs
         gy7ARdTmm0g+cNpD4BHXvoIDJOQy2ReGeX9Ilt5EWyhSlTjsWIZnGFqoz5RnjLF1AHh3
         rgRGP8VrS6f95ItHQtp6K/+t//muqPrvWg2OIRYh+KLP/iWby2MygjtzpRe/EyQO7G3M
         39/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=6TljYPmvNCxy6eqX6WNrqPiK/alo5tkLVqEYfmF+IvQ=;
        b=OO6Q6wBV8eFVWhKMQmKS9WZA68OXE19IXqLELi446M/WhuZrojOmJ4RLAV23wuXx7Q
         PtAiJKTzr+sL7VTIPlq6iAK9xquOnXn4t9lp4THkT8ldjrACChRo146w3Yvufp0448Rn
         9fWi8og1p0K7Zk1xFOvaM9RhCXft32XJKCYcxVn6Je76kw50qSaLUNS16GjXKh4UPKn+
         DuKU2NiZCuP9Ony/pWLz6HzwPIJ7B9QFUIr1xABh8N9re3VaKNIhp5EMz63c9EUVaH5D
         JRyTRzawoMoaLk4VVxx3RdK2Gh9A7wE1l0LFwDQlcKHVs3PsJu2kcG3EIBSP7Dp26aNH
         CWwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6TljYPmvNCxy6eqX6WNrqPiK/alo5tkLVqEYfmF+IvQ=;
        b=fRxUe5gEohdk02kI6DbKS8O2JZND1H3P169jx9ZzOzXcoawvDhEwHxFh0n/L//LLIP
         cv7UdvisRmj+wtWsX47ZQhdpqq4RYxT5jvNFWNjdCsEwmuOenzc+XmPsr+8IZd7JyWEa
         vQIup3Vmibw9ZfJXWOw4c/LvCLC9yVyFy7t0dY1jAAJ20XjNddip/JAxO952zJFHwT/i
         iSE0XXWQicUJD79TjnNi8wRGnFXdTuA+CikPxcgikDQOYydEz/hGojrFbqll0CvOszXu
         KhUZElNAsIiVPl6vZALcEQfDFw9xNvxETLxX29V7uX6MGnCc3+dROVeajQUSbaCX0OkY
         hbGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0L1lhCFRmPOui4I/yFkEZKahGpv5v8jBcK9deOxEd0HlpD4HVe
	fMyJ2aGR5gqHK2MdGnaX6q4=
X-Google-Smtp-Source: AMsMyM4wuQ063SYjK9FzqhU7rN7UPZub6fC72NVsuOVvL09vFfsdZmtx8RV/sr/kzK75FPvG+E2Bkw==
X-Received: by 2002:a25:d70f:0:b0:6ca:1c0b:4767 with SMTP id o15-20020a25d70f000000b006ca1c0b4767mr29159071ybg.239.1667486189312;
        Thu, 03 Nov 2022 07:36:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d446:0:b0:367:447d:fe68 with SMTP id w67-20020a0dd446000000b00367447dfe68ls799417ywd.3.-pod-prod-gmail;
 Thu, 03 Nov 2022 07:36:28 -0700 (PDT)
X-Received: by 2002:a81:a191:0:b0:368:e6ad:ae7b with SMTP id y139-20020a81a191000000b00368e6adae7bmr28061398ywg.236.1667486188770;
        Thu, 03 Nov 2022 07:36:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667486188; cv=none;
        d=google.com; s=arc-20160816;
        b=LXO4lsmlyhNiWl7MnoJbSIPYva2ElXWsmW8TwtuawRfvbX/F/Ir9jCG6oREtQiN8Hs
         Ys8VYFBy5Nkpy/MQSQcbaewO0jGs6bQNiSvWNOWliKqN831ukqU1KDGECh3F5uJU2RW8
         GU63j8UTmazlKrLvPdL33S7wAQPjWkvj+mAmjXJ92zznX3WQFmFeLZh8aD/BGhoX780R
         bkrcdKWcYkoQxY7wkxh5Niwp8wjtQ5GCi3/FeVZF7lew9QAEiSmM+shJMbrCTiDwcTXm
         m4y5Qd7FPOULc7EGF7KQi2u6uDHOD7bSjkdoOD3u9VPRHF1zU1xLH4WbBqe45oFd7k+y
         zSwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SGnUSCPqCRbqwfTPIsUS28tudEAjZuU81okBvbtR/vY=;
        b=NMsRID1HwiKyAwGLmGN5JjWdBQQYaoJ2OpyYe/rYSWiK8L8c6pC+nVIsh/HS2QpQrT
         whTc4pnXfX4EV6aKjw4WZFh45xXdu5mg/qmo2NwpEP1/V9O6ZxBQ9ca6U1JW5u9jEdZ0
         HSvtdUxNHn+A8I4WImbI1NYLLhWsQ90l1CXgRG+zTpDJP+pDdcb9Z4M+eDYq85abRWuc
         cwivYQPJCRRWKuaAe2uik94GFgvAcvlwz+wtcMTw4Qprs1UeVSOVrcZrmUVtDeMihfZV
         tDYddWvKxOwqadS+E0l518ua2ZiWkyMRvrXJ4qdStqLvuS9ABNqLFusV3EyiJig5PhdR
         yDIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="N4Ta5MP/";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id g6-20020a816b06000000b0036c251a1626si55835ywc.4.2022.11.03.07.36.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Nov 2022 07:36:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id s196so1836093pgs.3
        for <kasan-dev@googlegroups.com>; Thu, 03 Nov 2022 07:36:28 -0700 (PDT)
X-Received: by 2002:a05:6a00:340f:b0:56d:b039:202 with SMTP id cn15-20020a056a00340f00b0056db0390202mr16913722pfb.2.1667486187927;
        Thu, 03 Nov 2022 07:36:27 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id h2-20020a056a00000200b00562cfc80864sm850829pfk.36.2022.11.03.07.36.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Nov 2022 07:36:26 -0700 (PDT)
Date: Thu, 3 Nov 2022 23:36:19 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	John Thomson <lists@johnthomson.fastmail.com.au>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2PR45BW2mgLLMwC@hyeyoo>
References: <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz>
 <Y2NXiiAF6V2DnBrB@feng-clx>
 <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz>
 <Y2PNLENnxxpqZ74g@feng-clx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y2PNLENnxxpqZ74g@feng-clx>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="N4Ta5MP/";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52a
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

On Thu, Nov 03, 2022 at 10:16:12PM +0800, Feng Tang wrote:
> On Thu, Nov 03, 2022 at 09:33:28AM +0100, Vlastimil Babka wrote:
> [...]
> > >> AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
> > >> slab_pre_alloc_hook() will happen to return NULL and we bail out from
> > >> slab_alloc_node(). But this is a side-effect, not an intended protection.
> > >> Also the CONFIG_TRACING variant of kmalloc_trace() would have called
> > >> trace_kmalloc dereferencing s->size anyway even before this patch.
> > >> 
> > >> I don't think we should add WARNS in the slab hot paths just to prevent this
> > >> rare error of using slab too early. At most VM_WARN... would be acceptable
> > >> but still not necessary as crashing immediately from a NULL pointer is
> > >> sufficient.
> > >> 
> > >> So IMHO mips should fix their soc init, 
> > > 
> > > Yes, for the mips fix, John has proposed to defer the calling of prom_soc_init(),
> > > which looks reasonable.
> > > 
> > >> and we should look into the
> > >> CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.
> > > 
> > > You mean check if the pointer is NULL and bail out early. 
> > 
> > No I mean here:
> > 
> > #else /* CONFIG_TRACING */
> > /* Save a function call when CONFIG_TRACING=n */
> > static __always_inline __alloc_size(3)                                   
> > void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
> > {       
> >         void *ret = kmem_cache_alloc(s, flags);
> >                     
> >         ret = kasan_kmalloc(s, ret, size, flags);
> >         return ret;
> > }
> > 
> > we call kmem_cache_alloc() and discard the size parameter, so it will assume
> > s->object_size (and as the side-effect, crash if s is NULL). We shouldn't
> > add "s is NULL?" checks, but fix passing the size - probably switch to
> > __kmem_cache_alloc_node()? and in the following kmalloc_node_trace() analogically.
>  
> Got it, thanks! I might have missed it during some rebasing for the
> kmalloc wastage debug patch.

That was good catch and I missed too!
But FYI I'm suggesting to drop CONFIG_TRACING=n variant:

https://lore.kernel.org/linux-mm/20221101222520.never.109-kees@kernel.org/T/#m20ecf14390e406247bde0ea9cce368f469c539ed

Any thoughts?

> 
> How about the following fix?
> 
> Thanks,
> Feng
> 
> ---
> From 9f9fa9da8946fd44625f873c0f51167357075be1 Mon Sep 17 00:00:00 2001
> From: Feng Tang <feng.tang@intel.com>
> Date: Thu, 3 Nov 2022 21:32:10 +0800
> Subject: [PATCH] mm/slub: Add missing orig_size parameter for wastage debug
> 
> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
> kmalloc") was introduced for debugging kmalloc memory wastage,
> and it missed to pass the original request size for kmalloc_trace()
> and kmalloc_node_trace() in CONFIG_TRACING=n path.
> 
> Fix it by using __kmem_cache_alloc_node() with correct original
> request size.
> 
> Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  include/linux/slab.h | 9 +++++++--
>  1 file changed, 7 insertions(+), 2 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 90877fcde70b..9691afa569e1 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -469,6 +469,9 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignm
>  							 __alloc_size(1);
>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
>  									 __malloc;
> +void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node,
> +				size_t orig_size, unsigned long caller) __assume_slab_alignment
> +									 __malloc;
>  
>  #ifdef CONFIG_TRACING
>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
> @@ -482,7 +485,8 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
>  static __always_inline __alloc_size(3)
>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>  {
> -	void *ret = kmem_cache_alloc(s, flags);
> +	void *ret = __kmem_cache_alloc_node(s, flags, NUMA_NO_NODE,
> +					    size, _RET_IP_);
>  
>  	ret = kasan_kmalloc(s, ret, size, flags);
>  	return ret;
> @@ -492,7 +496,8 @@ static __always_inline __alloc_size(4)
>  void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
>  			 int node, size_t size)
>  {
> -	void *ret = kmem_cache_alloc_node(s, gfpflags, node);
> +	void *ret = __kmem_cache_alloc_node(s, gfpflags, node,
> +					    size, _RET_IP_);
>  
>  	ret = kasan_kmalloc(s, ret, size, gfpflags);
>  	return ret;
> -- 
> 2.34.1
> 
> 
> 

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2PR45BW2mgLLMwC%40hyeyoo.
