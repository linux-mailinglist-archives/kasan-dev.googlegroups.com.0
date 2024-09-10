Return-Path: <kasan-dev+bncBAABBFVUQC3QMGQEHSHHXZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 590FD973100
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 12:06:16 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-6b41e02c293sf187894737b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 03:06:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725962774; cv=pass;
        d=google.com; s=arc-20240605;
        b=ICU0QOLjLs5+iVDNFBSauJRklzGPfT6r2VDmTdF+gDUMMFOn5m+vYOVxtDtH8weUvg
         CxgXEh42BUsSM5Zd7nS8SvRrWgQGMDSgA7rzFOVX7l8vNFRXsNMUvFDedlXEzN/9O93L
         3G+oo8FPm8Yfxi6wSoy2/JRYH5aB29iX8yTnr8T6Sg53k6+bgKZOPYJP4pWSddEOdJju
         rPZyUONT2vfGq3THvAbPjftIQAGWH6Evfv5nt2nr3BSxPAJQoNoxqH5JIoCyky8+mU4c
         vhk4UnVvGwdzYJ4hAwOqlgq6Hgt9Cnodbh9ymus+k/G+pScLzuvYvsutawuuXYw7kAHw
         nt/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yLj54LKOmkjLFAy/ljWV8U5q94kSmY3WeWMx/VEhh+o=;
        fh=S9uJ2MEBrp9yokP7NlyAm6GbU/U7xOSIyDorhhfRhN0=;
        b=DGaSNyJbroyltIhoY1U426aYOFrUDW3xCc607Ygq0NkCxJ0U4oXvDuOChuGICuqH7c
         Y539tordjWPBEjvjuifBrqMgv2FbTKvyvrP3LV6Xl9XS0GYAEuPNA3yQ/eIgJzVWR44K
         QxTadhavGipyuakn93ic8DZYm2r+GioGy75AuS5Cl/OGJtm4wZAubpDTgWTU5mFHX1Ie
         fU1JJ/Qowb86enm1BcKPMfgTjvja2EskjAsLHhVeaCihKm0xohGfIXTkGp4L5f/bD2Ne
         hKJ3vw/7Q6zF2F/vXupgS0tiW/FHwCOniHjdLkLEJKvN2cM5NKflg0+qSwYe5yUsldku
         +yVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cP9NOIs2;
       spf=pass (google.com: domain of dakr@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725962774; x=1726567574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yLj54LKOmkjLFAy/ljWV8U5q94kSmY3WeWMx/VEhh+o=;
        b=YUeIg02hausLsxRPymZMnS7daPSzDbTf8AtM5dOaliVOPaZiLPY9cd6w6K+y2FdSbp
         8ciNcPraz+UDjX08fDyKIDmfX6PBCnugMiui0AaH8BT8dlpb+svikb1k+wBSQj9J/wRg
         24WYaOHoV3ITGFv5Pcjp2PPX88TeTCLoU6s+9Kn+f56yD89TbAk/X/uamDtXzbAdrzWh
         /yfKAGRFoq4Xh+qt++X3mglPMBMjz19lyyvSRXFmiDJN4ey+Wi59ElQiyhkureaWrwl1
         8R2KTeEsYDLwVftI3HjRL/nCHS5z728Otth6bnJKqkUe6jfXe4ophbXs+arV2EQlrixQ
         ih0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725962774; x=1726567574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yLj54LKOmkjLFAy/ljWV8U5q94kSmY3WeWMx/VEhh+o=;
        b=Cx+alXvHmKpZkePHFPnALxks66HZMRGPArP8j0BvFiQwuFmU4DAfKD2ucKw2jprJ4X
         laPwTq71eV6aK/RJzRgvjCGCPXzCTQtfvI2l36AIsKVp+fvAKnn/jUk0EAq2DD/dXPtt
         LdirF6SiJQ3u1bVm83KmcX3CMbs6sqeUFZdf+0ynk7VHSZwKhu5fPvGQEaz4FyRMk2RA
         mvgbXcC8EgiC3qrMOBE1wFfFga69KzadietTBAEKJkvEUkmhWtAxJos7ULCIebLIptJk
         HjCMhwRZGBuUw5ISq+1qqAVjz4Ttn+exKOtD45qYmbjopYTtsNXn6L391qRNnceJbLl1
         oGXA==
X-Forwarded-Encrypted: i=2; AJvYcCX4KTrawgIFiFLbf1DRBDhloJmpXfAsxmo7rc0yss+gRvxcm9RXRi1pWgnnBDlekRACsimXaA==@lfdr.de
X-Gm-Message-State: AOJu0Yzcfajip2qEDVrywV7tW5INEYgbfBz8XN1mIw5e1LiVCLKwIzxY
	o3YU5kjkD+vJqOMBkmZrvBdHezbRqDq1559YhiFFQ8SEM6ETzGmz
X-Google-Smtp-Source: AGHT+IEIK/NfVUogFV1mQAXkf0lAQP3W2Eu7xFCVOMV8dTmFBR89pJP29Y79E3xoxufgmc3BILIGUg==
X-Received: by 2002:a05:6902:2407:b0:e16:6b7e:94b5 with SMTP id 3f1490d57ef6-e1d34a6ee6dmr12784355276.48.1725962774438;
        Tue, 10 Sep 2024 03:06:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1146:b0:e0b:e5b2:98ba with SMTP id
 3f1490d57ef6-e1d33aa4d03ls348674276.0.-pod-prod-04-us; Tue, 10 Sep 2024
 03:06:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUC0sV+EJzR6pvVSeL4ALEeA+er2F8Q4Oj4EtyDzcCQPtfFY3u9F0UYdypT2VlJibri7OSgX+8BuEc=@googlegroups.com
X-Received: by 2002:a05:6902:c0a:b0:e13:e932:6f51 with SMTP id 3f1490d57ef6-e1d34a6fe94mr13037003276.50.1725962773600;
        Tue, 10 Sep 2024 03:06:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725962773; cv=none;
        d=google.com; s=arc-20240605;
        b=lEMPHfxhO7k5pfGvDvWJy6IvlimHBK4+BI+BDOXmawEbFWPwrQ4eG+AMg+Mqec3mx8
         uLbeVU4isFwdTEs7AjG60vPg2+TXjzy134g8H++rC0FZWQfB4oh4cqqsMIzgq8ZlTNxd
         hgUUOVW5djAnixepGko46XhwpAfVhSp/gbxrGz3fyCURwR+U3Lkbs6e57bIiCVUgKqNf
         HVz7jGAqGpV83PM7/vaWvo9HmVfpodl+avw+S9LkvEayIzcT7SBYB2elVq4o8h27mX0m
         0CH+aL4GHjM5FfzALs8dVjJxBFW9GO7o921SVbN4j+M5IIpkwsIGrk5VT4EAD8fyIy9M
         99bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Tiri5qlTCVkug9N1Dqz9t/5YibWAEAfeNKGEKHFZkcw=;
        fh=p/5McWUtjK+qScMwUrO14iqiNHfhg8r/y+oykbgK3/0=;
        b=IIFixa8w1uhinAKmuzsAEQ6SObJJIX3imFB/qyoAmbZk9QEBHQbEVuwpgg8iZ/qhJa
         RWIPOCMo+2MZLbERDV0ppG9/Ff/6KQiAO6TNhsizcv4IklDrW1MZk2tiISjEGro9c+XO
         GFp705O2pOFMtcQ0PQ/xIIK0OgjOcKGDimFMYjQwfDwdN0mUL+hekxnoItsbt47RtRWz
         07baLyzi5zyfcx2Q8s0Tl7Rrz2e5wi/U6Wgk6BWaHQ3xgVv7x1jgZKVKtygHt0ce3ZgU
         S04ZPNYoU3bCrKWsgOLdFC+ntkVTFbov+l54xjS6vHztnDaPqYlBsgAsNJ/KnN5iFUMD
         qvcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cP9NOIs2;
       spf=pass (google.com: domain of dakr@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6db9640b5e8si500557b3.1.2024.09.10.03.06.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Sep 2024 03:06:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dakr@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 7EAA9A444E8;
	Tue, 10 Sep 2024 10:06:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 77D24C4CEC6;
	Tue, 10 Sep 2024 10:06:08 +0000 (UTC)
Date: Tue, 10 Sep 2024 12:06:05 +0200
From: "'Danilo Krummrich' via kasan-dev" <kasan-dev@googlegroups.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 3/5] mm/slub: Improve redzone check and zeroing for
 krealloc()
Message-ID: <ZuAaDbSMtpLVJPrY@pollux>
References: <20240909012958.913438-1-feng.tang@intel.com>
 <20240909012958.913438-4-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240909012958.913438-4-feng.tang@intel.com>
X-Original-Sender: dakr@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cP9NOIs2;       spf=pass
 (google.com: domain of dakr@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=dakr@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Danilo Krummrich <dakr@kernel.org>
Reply-To: Danilo Krummrich <dakr@kernel.org>
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

On Mon, Sep 09, 2024 at 09:29:56AM +0800, Feng Tang wrote:
> For current krealloc(), one problem is its caller doesn't know what's
> the actual request size, say the object is 64 bytes kmalloc one, but
> the original caller may only requested 48 bytes. And when krealloc()
> shrinks or grows in the same object, or allocate a new bigger object,
> it lacks this 'original size' information to do accurate data preserving
> or zeroing (when __GFP_ZERO is set).
> 
> And when some slub debug option is enabled, kmalloc caches do have this
> 'orig_size' feature. So utilize it to do more accurate data handling,
> as well as enforce the kmalloc-redzone sanity check.
> 
> The krealloc() related code is moved from slab_common.c to slub.c for
> more efficient function calling.

I think it would be good to do this in a separate commit, for a better diff and
history.

> 
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab_common.c |  84 -------------------------------------
>  mm/slub.c        | 106 +++++++++++++++++++++++++++++++++++++++++++++++
>  2 files changed, 106 insertions(+), 84 deletions(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index ad438ba62485..e59942fb7970 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1297,90 +1297,6 @@ module_init(slab_proc_init);
>  
>  #endif /* CONFIG_SLUB_DEBUG */
>  
> -static __always_inline __realloc_size(2) void *
> -__do_krealloc(const void *p, size_t new_size, gfp_t flags)
> -{
> -	void *ret;
> -	size_t ks;
> -
> -	/* Check for double-free before calling ksize. */
> -	if (likely(!ZERO_OR_NULL_PTR(p))) {
> -		if (!kasan_check_byte(p))
> -			return NULL;
> -		ks = ksize(p);
> -	} else
> -		ks = 0;
> -
> -	/* If the object still fits, repoison it precisely. */
> -	if (ks >= new_size) {
> -		/* Zero out spare memory. */
> -		if (want_init_on_alloc(flags)) {
> -			kasan_disable_current();
> -			memset((void *)p + new_size, 0, ks - new_size);
> -			kasan_enable_current();
> -		}
> -
> -		p = kasan_krealloc((void *)p, new_size, flags);
> -		return (void *)p;
> -	}
> -
> -	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
> -	if (ret && p) {
> -		/* Disable KASAN checks as the object's redzone is accessed. */
> -		kasan_disable_current();
> -		memcpy(ret, kasan_reset_tag(p), ks);
> -		kasan_enable_current();
> -	}
> -
> -	return ret;
> -}
> -
> -/**
> - * krealloc - reallocate memory. The contents will remain unchanged.
> - * @p: object to reallocate memory for.
> - * @new_size: how many bytes of memory are required.
> - * @flags: the type of memory to allocate.
> - *
> - * If @p is %NULL, krealloc() behaves exactly like kmalloc().  If @new_size
> - * is 0 and @p is not a %NULL pointer, the object pointed to is freed.
> - *
> - * If __GFP_ZERO logic is requested, callers must ensure that, starting with the
> - * initial memory allocation, every subsequent call to this API for the same
> - * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
> - * __GFP_ZERO is not fully honored by this API.
> - *
> - * This is the case, since krealloc() only knows about the bucket size of an
> - * allocation (but not the exact size it was allocated with) and hence
> - * implements the following semantics for shrinking and growing buffers with
> - * __GFP_ZERO.
> - *
> - *         new             bucket
> - * 0       size             size
> - * |--------|----------------|
> - * |  keep  |      zero      |
> - *
> - * In any case, the contents of the object pointed to are preserved up to the
> - * lesser of the new and old sizes.
> - *
> - * Return: pointer to the allocated memory or %NULL in case of error
> - */
> -void *krealloc_noprof(const void *p, size_t new_size, gfp_t flags)
> -{
> -	void *ret;
> -
> -	if (unlikely(!new_size)) {
> -		kfree(p);
> -		return ZERO_SIZE_PTR;
> -	}
> -
> -	ret = __do_krealloc(p, new_size, flags);
> -	if (ret && kasan_reset_tag(p) != kasan_reset_tag(ret))
> -		kfree(p);
> -
> -	return ret;
> -}
> -EXPORT_SYMBOL(krealloc_noprof);
> -
>  /**
>   * kfree_sensitive - Clear sensitive information in memory before freeing
>   * @p: object to free memory of
> diff --git a/mm/slub.c b/mm/slub.c
> index 4cb3822dba08..d4c938dfb89e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4709,6 +4709,112 @@ void kfree(const void *object)
>  }
>  EXPORT_SYMBOL(kfree);
>  
> +static __always_inline __realloc_size(2) void *
> +__do_krealloc(const void *p, size_t new_size, gfp_t flags)
> +{
> +	void *ret;
> +	size_t ks;
> +	int orig_size = 0;
> +	struct kmem_cache *s;
> +
> +	/* Check for double-free before calling ksize. */
> +	if (likely(!ZERO_OR_NULL_PTR(p))) {
> +		if (!kasan_check_byte(p))
> +			return NULL;
> +
> +		s = virt_to_cache(p);
> +		orig_size = get_orig_size(s, (void *)p);
> +		ks = s->object_size;
> +	} else
> +		ks = 0;
> +
> +	/* If the object doesn't fit, allocate a bigger one */
> +	if (new_size > ks)
> +		goto alloc_new;
> +
> +	/* Zero out spare memory. */
> +	if (want_init_on_alloc(flags)) {
> +		kasan_disable_current();
> +		if (orig_size < new_size)
> +			memset((void *)p + orig_size, 0, new_size - orig_size);
> +		else
> +			memset((void *)p + new_size, 0, ks - new_size);
> +		kasan_enable_current();
> +	}
> +
> +	if (slub_debug_orig_size(s) && !is_kfence_address(p)) {
> +		set_orig_size(s, (void *)p, new_size);
> +		if (s->flags & SLAB_RED_ZONE && new_size < ks)
> +			memset_no_sanitize_memory((void *)p + new_size,
> +						SLUB_RED_ACTIVE, ks - new_size);
> +	}
> +
> +	p = kasan_krealloc((void *)p, new_size, flags);
> +	return (void *)p;
> +
> +alloc_new:
> +	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
> +	if (ret && p) {
> +		/* Disable KASAN checks as the object's redzone is accessed. */
> +		kasan_disable_current();
> +		if (orig_size)
> +			memcpy(ret, kasan_reset_tag(p), orig_size);
> +		kasan_enable_current();
> +	}
> +
> +	return ret;
> +}
> +
> +/**
> + * krealloc - reallocate memory. The contents will remain unchanged.
> + * @p: object to reallocate memory for.
> + * @new_size: how many bytes of memory are required.
> + * @flags: the type of memory to allocate.
> + *
> + * If @p is %NULL, krealloc() behaves exactly like kmalloc().  If @new_size
> + * is 0 and @p is not a %NULL pointer, the object pointed to is freed.
> + *
> + * If __GFP_ZERO logic is requested, callers must ensure that, starting with the
> + * initial memory allocation, every subsequent call to this API for the same
> + * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
> + * __GFP_ZERO is not fully honored by this API.
> + *
> + * When slub_debug_orig_size() is off,  since krealloc() only knows about the

I think you want to remove ' since ' here.

> + * bucket size of an allocation (but not the exact size it was allocated with)
> + * and hence implements the following semantics for shrinking and growing
> + * buffers with __GFP_ZERO.
> + *
> + *         new             bucket
> + * 0       size             size
> + * |--------|----------------|
> + * |  keep  |      zero      |
> + *
> + * Otherwize, the original allocation size 'orig_size' could be used to

Typo in 'otherwise'.

> + * precisely clear the requested size, and the new size will also be stored as
> + * the new 'orig_size'.
> + *
> + * In any case, the contents of the object pointed to are preserved up to the
> + * lesser of the new and old sizes.
> + *
> + * Return: pointer to the allocated memory or %NULL in case of error
> + */
> +void *krealloc_noprof(const void *p, size_t new_size, gfp_t flags)
> +{
> +	void *ret;
> +
> +	if (unlikely(!new_size)) {
> +		kfree(p);
> +		return ZERO_SIZE_PTR;
> +	}
> +
> +	ret = __do_krealloc(p, new_size, flags);
> +	if (ret && kasan_reset_tag(p) != kasan_reset_tag(ret))
> +		kfree(p);
> +
> +	return ret;
> +}
> +EXPORT_SYMBOL(krealloc_noprof);
> +
>  struct detached_freelist {
>  	struct slab *slab;
>  	void *tail;
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuAaDbSMtpLVJPrY%40pollux.
