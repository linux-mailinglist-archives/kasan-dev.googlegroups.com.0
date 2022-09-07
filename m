Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBZXC4KMAMGQEO7MGTMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AB1D5B07B3
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 16:57:43 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-3451e7b0234sf81477287b3.23
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 07:57:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662562662; cv=pass;
        d=google.com; s=arc-20160816;
        b=lKfNCFaLefDloEKzwhxsZil6HBlbfdkDBY6L5JKtJn5elMfqsSF3lmbnpSApwnmyJm
         C6XQqcFUETDVRGjp0jot7bm37T1ZUsBIFNCeUddecFVM+0XeuaasY/M7ybTAFG8h4Y+h
         +g1AbAmxYjhPIyvxWDgiLyCO6Xh27Gtcqhqz/l28J1crqvFXJgggKVn/0r4QuXc2xp+C
         uQ46jqyxoLYw6Z/Q1DgcLGYyXFKfe4m4F9GHNj36kIaj3LYdm1kA+wnY39vHq70gZnJg
         lriMg+5KD1SjYRH2OZbqZ3BE+dsBqeS0IGejDFfjmlgG6pYraKc1FtC67EzZCqRzqAH9
         9Cgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=OjdNWyXhtxWjY2aLtqBlhjh7Mdq8G14GxF8TpkxVGck=;
        b=T2Bw6rHXk56CuEpFCVakP7Fb4UrE85QAKQ3l2dX0IRFev3EEhz+OcDbu4rIf9zBdcZ
         7BdfxGebRScjS2TDixxbHjUgM2uHXfiPa+BMwUA2VXznG/ZkjtJlcMIjTOgWKYDOz3fP
         Cct6KvT+8hhVA31Vvk78SPoBmSOk3qWlx4AKGP1UXMGQ0zh6S4yDyeac6ggRhNhgkrbo
         ouY+FdLChcuMyaQqbkgNwwZ23nduno/+PTVvYEPRT9wG1xd1uJ1DWymKeydVaxjRzG/I
         NmbxNVo17nsssYse6cL54is1CyMxJiEeb4t/Mw/4zKylTn8rlH/5G+SeLwjqMAe3bUQg
         K8Mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=kN++HlIn;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=OjdNWyXhtxWjY2aLtqBlhjh7Mdq8G14GxF8TpkxVGck=;
        b=UWuwSRuH4bsW0KoRSr8ra+Ar3fMIMJmTKiwHCEgGPBeXNeu60MKPxVUwoQ0fR0hbqV
         ZOAZ4jlygfQB2IKMHGCkDkQ+PNYS3l97hoxACvExJLgbHbtulTtz4PBalxJZTj6R4IgD
         zHIjPjcuGhr7JI28eIJN7rN2cH0yn6Vhf75PJQGUBbrSfQqMuLt3xRSlowizmK8u2SS/
         zIVmZ44x0t4TuIaao6DQa6fpVBbxDFVsl7HctWyowRD/r1GcKiqcxVKoVuUZYCF0wrBE
         y7gL1GgvyjU9h1dciZ7cYlzRhLCu1NFqH4WvFi3g5xwKf1i3YEdjDYkBIPdOHLg/XXZ6
         PQUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=OjdNWyXhtxWjY2aLtqBlhjh7Mdq8G14GxF8TpkxVGck=;
        b=AziRahx1AYPxcjYw4XTWci4UI9N9ys9Sxi+csLdkyvyv+T6Av/WFvn3eE05EMF4UnQ
         gLmJ1nekHpoEW9mj4M8IqYJUd9KHpgialjwY4lBcozhN5jUoodKd/JvRPkMCaieO6JW6
         Lp5Xj+sPOdWiiPMdUOP9DVn39GeVYbyqQBAC3iNY+V+nhmyLGJ1N2Y5I79jezxsqY5wp
         t/4f2292l5TY2at/f+1qzFABeDUABxXlOmh1ZewxpMDK4GBRAUkPnWX51vJVxq7W3tur
         MOBsn81cjoUq33ypiS07BgRr6Hb4U9mKVWB1n6cR/ZIOtbbpWB80bBb9XYdyz/UHMLC0
         WEKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=OjdNWyXhtxWjY2aLtqBlhjh7Mdq8G14GxF8TpkxVGck=;
        b=wI2qLTrOF5Oz7T/y872yJf9sKQyo0/MWOy0B2Xd2pB0PCM7tgyRh9/UeL0bq/geqOO
         CHNQQX7NQnWdc788ZDK1hEXXCuDTN77fmNU8kipHpH3uDc0o/2rvGDS/bXLVW/ty66QI
         GZrWxm+dzRYE9ezK1DXKsQIRt7t30QZNYYLYAwYi6mCkmSoKVkuNJ5cAn5fc2M0McgqB
         yOFiYNQLxDC8GUnBr5kZPbM6+Zf9u8sjjsBqTq5grC5LJ1S5LVNWukXzE3gdJsUFA9OP
         e6KexyXuRL0/9qeHOp/ovzAjEMSm2pvOz7NkzB11M3m07IfMeCakno7s7tPQ2NurY8tm
         xgCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1t0x0l9owfyxr08fF2kKkH1sW0Y8I5EbnC4DjRv7OZ9c9ORv46
	wgD9RopFkhXGqO5R4za/bTo=
X-Google-Smtp-Source: AA6agR4s5iQfbUsio0B5m9LEn3DZA4WMr8DPFji9sxdVoB/iOoWZci7qDlinGdaoybbupB+L0hFoIQ==
X-Received: by 2002:a0d:f5c6:0:b0:32e:3bcf:d68b with SMTP id e189-20020a0df5c6000000b0032e3bcfd68bmr3383355ywf.236.1662562662178;
        Wed, 07 Sep 2022 07:57:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:b2c9:0:b0:33c:eda4:8ce0 with SMTP id q192-20020a81b2c9000000b0033ceda48ce0ls7349867ywh.0.-pod-prod-gmail;
 Wed, 07 Sep 2022 07:57:41 -0700 (PDT)
X-Received: by 2002:a81:6d43:0:b0:345:1d33:b514 with SMTP id i64-20020a816d43000000b003451d33b514mr3363810ywc.178.1662562661632;
        Wed, 07 Sep 2022 07:57:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662562661; cv=none;
        d=google.com; s=arc-20160816;
        b=YVvtaRwE4Zg/vz7e2Fq0x5imQMECrfU8ptpj1nN1S9KAWVUEwyRqIHafR2igVX5gbQ
         1N1WijC/mUJ3i7qV7dDKrd5g5pjkgdisws5AK5FpdVISCxBssEl8MydYRWv+xtxB04MJ
         K1oxasJzAE/ea5TO0BUgkAX9vhsgoVDQ9W7T3oBuXdn2MKOtW9PSnVCoOiopgyCJbezL
         Ktpt0p0iNRAM6HOh5in1ZHoch6HU/Vj1/E7JCTfGJLbtUY9JRK62O5KnzxHsLy8CfAlH
         PecGjk1SYEkW864s8ySK/YPLwKoPDLNuF/SmhBXcoaAzgy0wCxr+kg7r2/iizDjvMKIB
         eZiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dn715j7z9j3EMcSnevzvQwvbS4cOIJSxg6vaem3HAEM=;
        b=jrkVjDDXRPn9ybAzZaNuw0KZDJWRSrCLT8dVKSSIw24oiDNCkr/xouPfV6zbj/8WTG
         Yo7/2kuiCRrE/LKywanh2NIqEiJchkdWQ6vlDwfLKqtCGwZgCkWL9DzrivNH1rwS4qvH
         wnmpwjcJSaWNSetWNvb+z6spTeAp3d8xvKO858Z+9goCEyyjlclyda2fiIIXh05cGR0e
         c8gH/WxCl3LvbQKrZ5R+aOc/4eY1/JstkKgbm/05fJ3/48FX0CGI3fXQUG19Nf6mpekF
         BCPvFK7kybRr0diuQt/0JzvfDAo2rINbJH1pnTkkahhVXyUF1CL8z6TpMwdCQLpnia/1
         vVCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=kN++HlIn;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id l64-20020a25cc43000000b006a790068256si1590875ybf.1.2022.09.07.07.57.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 07:57:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id s206so13844878pgs.3
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 07:57:41 -0700 (PDT)
X-Received: by 2002:a63:485a:0:b0:41d:ed37:d937 with SMTP id x26-20020a63485a000000b0041ded37d937mr3845615pgk.336.1662562660933;
        Wed, 07 Sep 2022 07:57:40 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id f28-20020a63511c000000b00422c003cf78sm4122866pgb.82.2022.09.07.07.57.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 07:57:39 -0700 (PDT)
Date: Wed, 7 Sep 2022 23:57:34 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v5 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
Message-ID: <YxixXhscutM0nw66@hyeyoo>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-3-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907071023.3838692-3-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=kN++HlIn;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52e
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

On Wed, Sep 07, 2022 at 03:10:21PM +0800, Feng Tang wrote:
> kzalloc/kmalloc will round up the request size to a fixed size
> (mostly power of 2), so the allocated memory could be more than
> requested. Currently kzalloc family APIs will zero all the
> allocated memory.
> 
> To detect out-of-bound usage of the extra allocated memory, only
> zero the requested part, so that sanity check could be added to
> the extra space later.
> 
> For kzalloc users who will call ksize() later and utilize this
> extra space, please be aware that the space is not zeroed any
> more.

Can this break existing users?
or should we initialize extra bytes to zero when someone called ksize()?

If it is not going to break something - I think we can add a comment of this.
something like "... kzalloc() will initialize to zero only for @size bytes ..."

> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.c | 6 +++---
>  mm/slab.h | 9 +++++++--
>  mm/slub.c | 6 +++---
>  3 files changed, 13 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/slab.c b/mm/slab.c
> index a5486ff8362a..73ecaa7066e1 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3253,7 +3253,7 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
>  	init = slab_want_init_on_alloc(flags, cachep);
>  
>  out:
> -	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init, 0);
>  	return objp;
>  }
>  
> @@ -3506,13 +3506,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	 * Done outside of the IRQ disabled section.
>  	 */
>  	slab_post_alloc_hook(s, objcg, flags, size, p,
> -				slab_want_init_on_alloc(flags, s));
> +				slab_want_init_on_alloc(flags, s), 0);
>  	/* FIXME: Trace call missing. Christoph would like a bulk variant */
>  	return size;
>  error:
>  	local_irq_enable();
>  	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
>  	kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index d0ef9dd44b71..20f9e2a9814f 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -730,12 +730,17 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>  
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  					struct obj_cgroup *objcg, gfp_t flags,
> -					size_t size, void **p, bool init)
> +					size_t size, void **p, bool init,
> +					unsigned int orig_size)
>  {
>  	size_t i;
>  
>  	flags &= gfp_allowed_mask;
>  
> +	/* If original request size(kmalloc) is not set, use object_size */
> +	if (!orig_size)
> +		orig_size = s->object_size;

I think it is more readable to pass s->object_size than zero

> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_alloc and initialization memset must be
> @@ -746,7 +751,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  	for (i = 0; i < size; i++) {
>  		p[i] = kasan_slab_alloc(s, p[i], flags, init);
>  		if (p[i] && init && !kasan_has_integrated_init())
> -			memset(p[i], 0, s->object_size);
> +			memset(p[i], 0, orig_size);
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, flags);
>  	}
> diff --git a/mm/slub.c b/mm/slub.c
> index effd994438e6..f523601d3fcf 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3376,7 +3376,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>  	init = slab_want_init_on_alloc(gfpflags, s);
>  
>  out:
> -	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>  
>  	return object;
>  }
> @@ -3833,11 +3833,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	 * Done outside of the IRQ disabled fastpath loop.
>  	 */
>  	slab_post_alloc_hook(s, objcg, flags, size, p,
> -				slab_want_init_on_alloc(flags, s));
> +				slab_want_init_on_alloc(flags, s), 0);
>  	return i;
>  error:
>  	slub_put_cpu_ptr(s->cpu_slab);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
>  	kmem_cache_free_bulk(s, i, p);

>  	return 0;
>  }
> -- 
> 2.34.1
>

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxixXhscutM0nw66%40hyeyoo.
