Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBIVZ5OMAMGQEONCF36Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A20BC5B2ED5
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 08:26:43 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id c2-20020a6bec02000000b00689b26e92f0sf718577ioh.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 23:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662704802; cv=pass;
        d=google.com; s=arc-20160816;
        b=yaakLI00UcYTLZ+k+3GnbrB0BJJ2Y9Xe7Di8fOf0Bc0j7/n9XbRmg/HIzkcjD+fQWJ
         KwfOk+/iDJQDmbJt4Ro8zDqRvzXrwD1aQVhNsXhKR1fg6pz/xTqRKBb5+kx03j4UmgNf
         uZcbRj5o3GWlUKkI90+7F4pnvbwKRknnItYdOjsUqss94gLynkOuUXIpQcrVWapRJAkK
         lzB/IqsDZBLPf8NdZeqY9tNsOIGB+BPM+npfPtjcX3g+YiTGkBGc7C1CxggenxWxGn+0
         mRyg+vv3UH9RDfILTRQ1NonXnM499VyZPYMricgXJNHOzWm3lgXVhiTP+N7UIUaLZnOm
         LEmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=ZRq9smSiAvH4m4ZT2LrNTYGaDy/5JZERLJiLFjY2+c4=;
        b=xWOz/5/4czMA4VUPLDWYZ0TyOnRM5yi02q/k682NSrT2CnerbfN37HsK4mYssRL/TC
         rU1987VTCjnfQf8d+p7i/BQ0tc7K/SdHOlrFiRO2lBZHF7Pxj9qxpkeoE4I66/NOIpE7
         DAfNb2BoFPqaON6ZOEHWreM5vyv0t3C5qcumv6NoqFxwK13Gn1u2+aiNs5yeKMMHxByj
         v6ENGZfx408hL1SNYlcN6qStqGUuj/R1gUA7Fmgt9tk5YkRnjYEICAq6qDbmIjNd1co3
         7d03entYYDAXgBrNbRorXER8HHDoPE26qNyyDirE8zSpBlqWtIKUyPDun23yGzIem8S8
         Q3Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BD6vwE4U;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=ZRq9smSiAvH4m4ZT2LrNTYGaDy/5JZERLJiLFjY2+c4=;
        b=KXPWHdT5e9zj7Lru8sXzTpjFuw9bogNSS1NgiZ8uU/gAw5/jQyElHF9dY+yPURMMk7
         vRdWJ3uBzlEAtoEQPdYf9hBpetkznqb+8UZVfQbeDTs7E9kilPPeqwfn/e7cbTE5FJsf
         aGSLug3xGZrs1XEC3hjqjCEzVPVrmgUqzX22EsOsI/SGl0t+JaiRRDWreq7pvC+og3Ng
         l9OMOKvU4hCdg1ML8J8yYNSBiAFn+4pDazetKiI02O7qmjehw2hn7Lkczt8tFeHZKWx2
         aWfIa5fjx73+hPahCLormmKnjSbMnwBBT7Z0c7wq9ofeJrpqhLZhYjM71jSSJcop1i94
         pOng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=ZRq9smSiAvH4m4ZT2LrNTYGaDy/5JZERLJiLFjY2+c4=;
        b=ltsXlBAZuwV9SWrAZNX3zNQ9HA8BRzUQiQB50gIjhbR2U3rC/nQENtxUtOCJF0Nn7v
         9XnD0yBKCePSe2aKPp7EpIU1SygofpKnrc7JvFhr4gez21XVFbvPFs3+a7vqvhjOo5k4
         MFCAZbT3GClHWvjG1i3U+CJ+Xg8C2wi0xhDNvWpQ1bPpLhMYAl4rokgLHmMXNHVacSMq
         2JJ5livj6dcbqnjhHmOA7BBerLWgppmMaK2f9Bp4GVarsaPJlQOk0ms8gYIgvr+D/IAB
         eZayCVtlhOd6GbpaJdUMtOimV3G85sndHtwyy7uRkFp1FfV6+QwH8m9EMoZzcJjje58u
         W2kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ZRq9smSiAvH4m4ZT2LrNTYGaDy/5JZERLJiLFjY2+c4=;
        b=kC7L17slcLoqYQ0B2mFUKyT8+/r6Lmdhd+NaRujcMmWpaH8dhOOrPtqHpTNJv4VBxd
         hizP0IPe42veCooM7kcgpRBqKzliPgz2rkw6UiVIcQxZePGnSWyNsTmfC3GvA4zJmRU2
         HH8JRWLetuVmuq3iRxwBc2yNyoXrhdmDTvGkSSxAII6G5s7WytfI2GRwkrFPNktrVtiF
         aVZhouSGfijT3wniBiIOK1h2+ZcjWrdc6vtFvKik6xi7qn6Dgh5WDGPzGjLQJI0VHQPe
         Ru8g02IngJbSPZRt4EAy5MuXKw5+ZFri6y2YaPp1a5HUptnsOpkaM/gGw7PX6Wg7Edc+
         9ADA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3UDQZEaE2OaJnPE+rDVBBV073oVi87v+4OZHvbEsmoTabcqdkW
	F7ZR9T8skX6Oz4pm6i59G3w=
X-Google-Smtp-Source: AA6agR5so38pjHVaqTTpkz0Prd95iS7zz8qiXCJUBZZvH2TlFv3od3DK7SnjE+xLfHzrxPi1LDH+aQ==
X-Received: by 2002:a05:6e02:501:b0:2e9:1b4c:3134 with SMTP id d1-20020a056e02050100b002e91b4c3134mr3398105ils.205.1662704802109;
        Thu, 08 Sep 2022 23:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1084:b0:2ea:b529:b26f with SMTP id
 r4-20020a056e02108400b002eab529b26fls1024957ilj.7.-pod-prod-gmail; Thu, 08
 Sep 2022 23:26:41 -0700 (PDT)
X-Received: by 2002:a05:6e02:1cae:b0:2f1:d173:1558 with SMTP id x14-20020a056e021cae00b002f1d1731558mr3638349ill.234.1662704801508;
        Thu, 08 Sep 2022 23:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662704801; cv=none;
        d=google.com; s=arc-20160816;
        b=tW3an3H2YahbGSmblJOH5P5C3F+Zeq5XkYS+DOfFug86DgvRCHcmtCr8Zuy2lwfIh4
         49fZCoQtMbItEafApNAfnAy9FC6ypFd//5RcGO6xzbgWjALCnCuTQKixfnUCdz6l8lK6
         CSSnxAr4tMMBu3sFdpQ2pHtSu0shGLsXfz+nO7Whgp5NVMhn8BVUXRIMPOjvZSxf3XQz
         patdrumTrNdqcGIHzxkqcfPTBmxkSRG7lwkWEpWy5GLUqARwuk2Oi4UP1rp0otLN7KtT
         s7/JVa7JFHwsVbRl8tZUfuKdypMemcomFJl4UtXrhVqmrESHwXE56MlKVFKfbh3fULAM
         Re3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qtjHXgBD9/OnG3oahRLo2zpObrPNyAlnYWRTg6DVoSc=;
        b=Rrr/Ni3lBJsAa5lKJNf7+xfy6mjSEpJ2Ox9A0mAnuXUouezJ3rjcp5SmPMf1SUWcHq
         x83Wcp38JFy9Ua0IAqQ2ecGjS5WkyMxBW54Q6C5nUEGAMpJAFG++up2a0PoHr4xp2WWb
         hsIDq0a6buDKlh1u0xw0x9Km3JKA5CePJTRNvGOUYexe2LPSDj1lFkPzR5FmOyW/I9Gt
         p3r+JJY7EX1BNVn+pB0+/hWEty8dhMqInG2j0W06x30Sd0DjJf9aLDUW0NV96BsP6jG0
         527rc4hPMOHUrGbwEuAYDPp3Dw/gHtAHGtgsfceTMgO7cIgfgSDI4XHMTA9Mc9f+QyCI
         e9Mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BD6vwE4U;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id n8-20020a056e02148800b002eb7fbf5c8esi25491ilk.2.2022.09.08.23.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Sep 2022 23:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id o4so620446pjp.4
        for <kasan-dev@googlegroups.com>; Thu, 08 Sep 2022 23:26:41 -0700 (PDT)
X-Received: by 2002:a17:902:f7d2:b0:176:ca6b:eadb with SMTP id h18-20020a170902f7d200b00176ca6beadbmr12523610plw.173.1662704801103;
        Thu, 08 Sep 2022 23:26:41 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id 63-20020a620542000000b005367c28fd32sm741728pff.185.2022.09.08.23.26.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Sep 2022 23:26:40 -0700 (PDT)
Date: Fri, 9 Sep 2022 15:26:34 +0900
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
Subject: Re: [PATCH v5 4/4] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
Message-ID: <Yxrcmk6hSvHBCGNo@hyeyoo>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-5-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907071023.3838692-5-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=BD6vwE4U;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102e
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

On Wed, Sep 07, 2022 at 03:10:23PM +0800, Feng Tang wrote:
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
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.h        |  4 ++++
>  mm/slab_common.c |  4 ++++
>  mm/slub.c        | 57 +++++++++++++++++++++++++++++++++++++++++++++---
>  3 files changed, 62 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 20f9e2a9814f..0bc91b30b031 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -885,4 +885,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
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
> index f523601d3fcf..2f0302136604 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -812,12 +812,27 @@ static inline void set_orig_size(struct kmem_cache *s,
>  	if (!slub_debug_orig_size(s))
>  		return;
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +	/*
> +	 * KASAN could save its free meta data in the start part of object
> +	 * area, so skip the redzone check if kasan's meta data size is
> +	 * bigger enough to possibly overlap with kmalloc redzone
> +	 */
> +	if (s->kasan_info.free_meta_size_in_object * 2 >= s->object_size)
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
> @@ -949,13 +964,34 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
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
> +			unsigned int zone_start;
> +
> +			orig_size = get_orig_size(s, object);
> +			zone_start = orig_size;
> +
> +			if (!freeptr_outside_object(s))
> +				zone_start = max_t(unsigned int, orig_size,
> +						s->offset + sizeof(void *));
> +
> +			/*
> +			 * Redzone the extra allocated space by kmalloc
> +			 * than requested.
> +			 */
> +			if (zone_start < s->object_size)
> +				memset(p + zone_start, val,
> +					s->object_size - zone_start);
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
> @@ -1103,6 +1139,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  {
>  	u8 *p = object;
>  	u8 *endobject = object + s->object_size;
> +	unsigned int orig_size;
>  
>  	if (s->flags & SLAB_RED_ZONE) {
>  		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> @@ -1112,6 +1149,20 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
>  			endobject, val, s->inuse - s->object_size))
>  			return 0;
> +
> +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +			orig_size = get_orig_size(s, object);
> +
> +			if (!freeptr_outside_object(s))
> +				orig_size = max_t(unsigned int, orig_size,
> +						s->offset + sizeof(void *));
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
> -- 
> 2.34.1
> 

Looks good, but what about putting
free pointer outside object when slub_debug_orig_size(s)?

diff --git a/mm/slub.c b/mm/slub.c
index 9d1a985c9ede..7e57d9f718d1 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -970,22 +970,15 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 		memset(p - s->red_left_pad, val, s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
-			unsigned int zone_start;
-
 			orig_size = get_orig_size(s, object);
-			zone_start = orig_size;
-
-			if (!freeptr_outside_object(s))
-				zone_start = max_t(unsigned int, orig_size,
-						s->offset + sizeof(void *));
 
 			/*
 			 * Redzone the extra allocated space by kmalloc
 			 * than requested.
 			 */
-			if (zone_start < s->object_size)
-				memset(p + zone_start, val,
-					s->object_size - zone_start);
+			if (orig_size < s->object_size)
+				memset(p + orig_size, val,
+				       s->object_size - orig_size);
 		}
 	}
 
@@ -1153,9 +1146,6 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			orig_size = get_orig_size(s, object);
 
-			if (!freeptr_outside_object(s))
-				orig_size = max_t(unsigned int, orig_size,
-						s->offset + sizeof(void *));
 			if (s->object_size > orig_size  &&
 				!check_bytes_and_report(s, slab, object,
 					"kmalloc Redzone", p + orig_size,
@@ -4234,7 +4224,8 @@ static int calculate_sizes(struct kmem_cache *s)
 	 */
 	s->inuse = size;
 
-	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
+	if (slub_debug_orig_size(s) ||
+	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
 	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
 	    s->ctor) {
 		/*

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxrcmk6hSvHBCGNo%40hyeyoo.
