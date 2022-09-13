Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBDMKQGMQMGQECKRSXZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 60A215B69EA
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 10:53:35 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id q8-20020a4a3008000000b004729d16a564sf5565396oof.14
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 01:53:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663059214; cv=pass;
        d=google.com; s=arc-20160816;
        b=CuKDWZ6o5G/bS6CFzwN4YVYmpt/yog48oIRxOFN75QTPSnDRzqc6lXpjFpPvqrISVQ
         OEaht8PgBB38C7xY5SocYB8YdHYmafBw8wcq59lN3MO6Pe4LWgiR+JQc6jFl1zKfg88a
         CoASTgaqkjdJ3ONaA/3FprGLQQ24180JGvytOh9J0l946pkeC58EG+8zwhg/UIRc5Q2Z
         gtzrE4rGK8xGzDlOulAzK7uIFvsAGmfLklI2EKk1egSk1PB+sdcqwNR4e+r0PegqOhnT
         2vYHxDKLg2ektTYT8aWmmo15XUxw+6oB2rMY6s3CGhnc/0l7rGVy/Ob/R2BZJLSSstOj
         XlMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=VCha2pfEen2tV5knedyI9dDgp8eGrEhZbwudxoHwuy0=;
        b=WK1bIQrt01jWwK0E4KyIt00ggcc3ucxL7jS8a23PuMZkooF5nkkweE7nEOxzFPzHsS
         8OKTbBD1oHp/1uMkic13z26yb09wW+FMU7ChAoAPcIyEfoXwag5jmu3L29BCN+2Y062r
         UqmbkTGqYe26qMGC5kibY9KP9ofKo7pqtwVKHvB4u8pS5UQ6IIbvLGeq1ulgrthkAuvI
         HSuZkuu2DeuKSmp3IlhGrPp/hRIcr8vJHrSmaFMVKjvVIa8mJLmkVHHRuiycSHgvOaHe
         blKPXXZwhSOt9IkiVoYNk5H3ZAybP3rWqAZJOy9N/FU4DXdHXsbzn21Rzh2s0Ry72osI
         BEpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="R/7fEVh0";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=VCha2pfEen2tV5knedyI9dDgp8eGrEhZbwudxoHwuy0=;
        b=lLe/f+ZohqQBLhwQykQovgyqKQVhhY4j5awe3egdvYlmY8FyW6NT5JuUFo2AChxSDe
         sDV3vbTuNEFTsC9922SzwXGujNsGGzqJkyVSv2OXhZSPE4DSVLxESr9EPP9A88nJrp8+
         eEN5jdrmRmmGde1ZaXq+TnDBzBEpDsiT5YzxjzphvGJAXwsIZgFWj09aXdE48z6I98xB
         68l+ID0U+j//NH6lze80VatzT27TVjiFw7NzZypplbY43cMY64S3QFeqti5smuCpjH9w
         DKFzd8m1nryxfGA+lE5kzMPW3NyJBk798k7UYQGfFE2S64Ej7wnv2QT/039AyX1S818Z
         QWvw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=VCha2pfEen2tV5knedyI9dDgp8eGrEhZbwudxoHwuy0=;
        b=YUWrzVPO7IuRWj5ryoBtEWnF1+WOdpOA5Ax2u5ZA/unjBz0Dzx/OIS9zZhiWQ/IPh2
         lXoJnWr2anwq8OuCQEVmxR/rNaUAlf3WQBHcTN9CkwV6OIhgOHQYFfx23VGr6Vz2azlS
         7gpRIcltCSmU1VYpiHBbaRvYLRqfH10LSS7HeeMuVj5lTcKtpLOKOsv5NwbtgMll15Z9
         no54fbKgupCtouP4eBzGN4ZPWDJjy8Smo4vI/8VvFHMtTMNX0SoXnos8Gm4UBoiPAaVv
         /DzUl81oAy6Yi8xLGaRIsYARHh/aFvT44U7Mg82XKnri4T3XBdioHVjDDs0JP7EKtSuR
         r9KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=VCha2pfEen2tV5knedyI9dDgp8eGrEhZbwudxoHwuy0=;
        b=5VWHkh6s4Ph0JaEIvMQJSDvxR/Km1X8Wj54jRnWxqpUW+yodufx5xwF27McjTnD4tl
         67O8uUKCvJHsnQ6vMVQrDd3YDwM4bywSBZIbYrTlzForSC+S5YXGi49aifNPFQv2JiTy
         SAPViao3261/9u08YmGqa85lxidlJNVBipKTImJG2LS+xiUhb4Q7vUAUnp+ahwBjX9xf
         nHFELnNau81/l7C7hwuBsoBY8zJ+MN0nN+UVB4M0B2iRLyLz56YZQplKBZyYx8E1v+gH
         NAXdq1xR+00U6Sx8CsyaTnGIk3NoBARLr7WwxyYNRB6qPEzgxVFO99GZFwMX0rVju2Fh
         tY/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2Fi/Ad1DRxRM1+22WNTz1Vz9ZaaN5Fj82dAQRq/CzKzyzUMb44
	/ktJQR3WIVWg+hcQDtoJyzQ=
X-Google-Smtp-Source: AA6agR77X5/znQ/fcy1XwYSHivPmyrMSTmu2cgBTSQ4+ROYKvOKJirKe0zZl3N+fyqw8HM0ls08m4g==
X-Received: by 2002:a05:6808:1a11:b0:343:1ae:87d2 with SMTP id bk17-20020a0568081a1100b0034301ae87d2mr981639oib.281.1663059214001;
        Tue, 13 Sep 2022 01:53:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:6c4:b0:34f:df0b:2e1e with SMTP id
 m4-20020a05680806c400b0034fdf0b2e1els520314oih.8.-pod-prod-gmail; Tue, 13 Sep
 2022 01:53:33 -0700 (PDT)
X-Received: by 2002:a05:6808:20a7:b0:34f:bad6:78f8 with SMTP id s39-20020a05680820a700b0034fbad678f8mr1052816oiw.140.1663059213585;
        Tue, 13 Sep 2022 01:53:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663059213; cv=none;
        d=google.com; s=arc-20160816;
        b=C0z/KST9o3OdpNzRSRICoDUknprs1teSBx3Pr0TS20n/MWbpHJuXhCMtRGKUi9d/TY
         xH/1kzlA5wd5RQEaaocRyUkoDXcUOAZ0JcmEK8NZk+Kif8uWDV7B3qIe0USxVVu2zH9e
         Rwd4iH/MD+gKlyqj0F3AM4yoGDcx856ydletGHO+6/qd8nTnsl1dMLwszDPMRzswIUvm
         o4fV9M3bgJrTG0Y8Hhfc9iR1y10mLIXpgYHpH2VnylPrjSBL8O/dMwLBt2sHCWkL/wf+
         53iIR7pbNVtiUSrcAugszTb7kgO9ONTPkjki7JSZ9lQsLh4mVZXqs9Cm9gZcYngBdUnk
         y5RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4TPm3yDLRTUXMkcwAeJgiJwg94hbEBwyJGZBnuCnHu4=;
        b=CaGUziSMF6BHxR3ZtwdiVIOTtlBdWFv0+xZdk+O2piJgvomtgg1jyFZXUznohDDayw
         VbVdtdEqU2c43AEV6sQdbZ9pTpO5RK6ASrsndB0L1IfllU5QOUqilv1zHbe1wsMyZsUE
         ekgVyHqoQJ4Em/+YYkGmMd5aykstTaoBj3OlQGFCwkjHG1Kpp+mMpmJd/TiEQBrNJGvk
         io+wHQnRBoj584v/0+jA4b7rQfAE/2o6NLsvPS3mXmxngG4ylWT76YY+JjXKhsDJxspz
         +0ChaiV5xamC1AX/1FJ9h7cJZPcNPr0YWgUESnLqmqVPBEswZpfb6vU5aY7I4KF/KecB
         U6Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="R/7fEVh0";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id k67-20020aca3d46000000b0034480be185csi446062oia.4.2022.09.13.01.53.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Sep 2022 01:53:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id m3so10609039pjo.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Sep 2022 01:53:33 -0700 (PDT)
X-Received: by 2002:a17:902:d48d:b0:178:306d:f75c with SMTP id c13-20020a170902d48d00b00178306df75cmr9442090plg.73.1663059212848;
        Tue, 13 Sep 2022 01:53:32 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id l19-20020a639853000000b0043957e4f85asm16626pgo.12.2022.09.13.01.53.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Sep 2022 01:53:31 -0700 (PDT)
Date: Tue, 13 Sep 2022 17:53:25 +0900
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
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 4/4] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
Message-ID: <YyBFBb8f3ZN+jRTf@hyeyoo>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-5-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220913065423.520159-5-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="R/7fEVh0";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1031
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

On Tue, Sep 13, 2022 at 02:54:23PM +0800, Feng Tang wrote:
> kmalloc will round up the request size to a fixed size (mostly power
> of 2), so there could be a extra space than what is requested, whose
> size is the actual buffer size minus original request size.
> 
> To better detect out of bound access or abuse of this space, add
> redzone sanity check for it.
> 
> And in current kernel, some kmalloc user already knows the existence
> of the space and utilizes it after calling 'ksize()' to know the real
> size of the allocated buffer. So we skip the sanity check for objects
> which have been called with ksize(), as treating them as legitimate
> users.
> 
> In some cases, the free pointer could be saved inside the latter
> part of object data area, which may overlap the redzone part(for
> small sizes of kmalloc objects). As suggested by Hyeonggon Yoo,
> force the free pointer to be in meta data area when kmalloc redzone
> debug is enabled, to make all kmalloc objects covered by redzone
> check.
> 
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.h        |  4 ++++
>  mm/slab_common.c |  4 ++++
>  mm/slub.c        | 51 ++++++++++++++++++++++++++++++++++++++++++++----
>  3 files changed, 55 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 3cf5adf63f48..5ca04d9c8bf5 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -881,4 +881,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
>  }
>  #endif
>  
> +#ifdef CONFIG_SLUB_DEBUG
> +void skip_orig_size_check(struct kmem_cache *s, const void *object);
> +#endif
> +
>  #endif /* MM_SLAB_H */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8e13e3aac53f..5106667d6adb 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1001,6 +1001,10 @@ size_t __ksize(const void *object)
>  		return folio_size(folio);
>  	}
>  
> +#ifdef CONFIG_SLUB_DEBUG
> +	skip_orig_size_check(folio_slab(folio)->slab_cache, object);
> +#endif
> +
>  	return slab_ksize(folio_slab(folio)->slab_cache);
>  }
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 6f823e99d8b4..546b30ed5afd 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -812,12 +812,28 @@ static inline void set_orig_size(struct kmem_cache *s,
>  	if (!slub_debug_orig_size(s))
>  		return;
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +	/*
> +	 * KASAN could save its free meta data in object's data area at
> +	 * offset 0, if the size is larger than 'orig_size', it could
> +	 * overlap the data redzone(from 'orig_size+1' to 'object_size'),
> +	 * where the check should be skipped.
> +	 */
> +	if (s->kasan_info.free_meta_size > orig_size)
> +		orig_size = s->object_size;
> +#endif
> +
>  	p += get_info_end(s);
>  	p += sizeof(struct track) * 2;
>  
>  	*(unsigned int *)p = orig_size;
>  }
>  
> +void skip_orig_size_check(struct kmem_cache *s, const void *object)
> +{
> +	set_orig_size(s, (void *)object, s->object_size);
> +}
> +
>  static unsigned int get_orig_size(struct kmem_cache *s, void *object)
>  {
>  	void *p = kasan_reset_tag(object);
> @@ -949,13 +965,27 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
>  static void init_object(struct kmem_cache *s, void *object, u8 val)
>  {
>  	u8 *p = kasan_reset_tag(object);
> +	unsigned int orig_size = s->object_size;
>  
> -	if (s->flags & SLAB_RED_ZONE)
> +	if (s->flags & SLAB_RED_ZONE) {
>  		memset(p - s->red_left_pad, val, s->red_left_pad);
>  
> +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +			orig_size = get_orig_size(s, object);
> +
> +			/*
> +			 * Redzone the extra allocated space by kmalloc
> +			 * than requested.
> +			 */
> +			if (orig_size < s->object_size)
> +				memset(p + orig_size, val,
> +				       s->object_size - orig_size);
> +		}
> +	}
> +
>  	if (s->flags & __OBJECT_POISON) {
> -		memset(p, POISON_FREE, s->object_size - 1);
> -		p[s->object_size - 1] = POISON_END;
> +		memset(p, POISON_FREE, orig_size - 1);
> +		p[orig_size - 1] = POISON_END;
>  	}
>  
>  	if (s->flags & SLAB_RED_ZONE)
> @@ -1103,6 +1133,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  {
>  	u8 *p = object;
>  	u8 *endobject = object + s->object_size;
> +	unsigned int orig_size;
>  
>  	if (s->flags & SLAB_RED_ZONE) {
>  		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> @@ -1112,6 +1143,17 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
>  			endobject, val, s->inuse - s->object_size))
>  			return 0;
> +
> +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +			orig_size = get_orig_size(s, object);
> +
> +			if (s->object_size > orig_size  &&
> +				!check_bytes_and_report(s, slab, object,
> +					"kmalloc Redzone", p + orig_size,
> +					val, s->object_size - orig_size)) {
> +				return 0;
> +			}
> +		}
>  	} else {
>  		if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
>  			check_bytes_and_report(s, slab, p, "Alignment padding",
> @@ -4187,7 +4229,8 @@ static int calculate_sizes(struct kmem_cache *s)
>  	 */
>  	s->inuse = size;
>  
> -	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
> +	if (slub_debug_orig_size(s) ||
> +	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
>  	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
>  	    s->ctor) {
>  		/*
> -- 
> 2.34.1
> 

For the slab part:

Looks good to me.
Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks!

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyBFBb8f3ZN%2BjRTf%40hyeyoo.
