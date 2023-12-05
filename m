Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBJGDXOVQMGQE6MT4IQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id C5FB3804CB0
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 09:39:02 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1d0c7387757sf335405ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 00:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701765541; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pk3HLvH1KC24QTPyDlkIGlwU3ModIkM2Tb4RB5cXG51m2ZM14CA7zwkergX/YN0U8A
         cEFgfUah0LtdUFEKi8mu5+rS8hmtr5//3GgB7+0JvwhzMy8cFX0Jg+rQy4MriTrten2L
         SV+o3JSXKiiqQMP4IOPsFl3ApxWDGVlr0jdgLNPsTGjFibt+1woTsFH0eTJbAT/qhu92
         xTkSehRhN5v9g6QiFI5I+kM01oqMydgsGYd55aM1oyETJmdP0K7pc4jJfodgou5eA9Q4
         6oFEp4f8frAmlLb5iIo4ajwf+8NJcNtvKr7EfnEqfDIwyPAPbRgwb0COBbqV/2TZFO3/
         DMDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=q/BGapiabg6/9xSbthSxsfagRQdNECuef6XV4AT3xZs=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=wXodEDiTurd5Cq9gPYAt2kFHdUke/LJWNWKc4qnycPqlBVDlEThMa6rD0rY7hYGrZ2
         QPUZBgWOxC4BPnC/6ONY8PCIw7f4JSoXDQRXjiJ7xKTb45CXfcI6Ry83wa2Rz4MJguW2
         z46utuuHntpnCsyfJOR/RTQilvysWZuQsGpgZi9OOHHlqDkbsJHKepNZj7SH4ZTTvcy4
         RnDJyXfkq5JJfkdPOiW3v3T5iQfAvwROX2YH+IkjCdPxCiHWZXoGBk5gFbiEEUv4fvW0
         Onjn4RL6MkakddF5QssORMv1LPrs25s2KFkvbMNml7V+MOZEbidPTxQnV8aWWseOKQgB
         rdKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FNh0wLAs;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q/BGapiabg6/9xSbthSxsfagRQdNECuef6XV4AT3xZs=;
        b=p64+CKSw3wAm4wgoxJBNaQ0QLnMX8J8RqFDTavyqx0t11IcSPur3jXaF83mWvS77Wq
         SZubj7WkZ21iNrnbC3zPyFKFq/x/adkaADLzfYTjjNjFaIqxBEIRjle9XfXlA486XvnF
         XQw7J19LW6ElQLRRMPGTrjoEvsg5iNUKtJeA2McnEuw20D9zGx8scAoVxrhq19WcJDtv
         fkQTroIqrd8ZbRbyyzbTheshx8Z1H5v1FAw5urb1DGtDfEHJrl2ccsG6+8JliicuWmuQ
         g+ve3mBpYjq08vqwIkGc5tUyLFErtES9Io2+BQ1jqfT7WwpgM8eAnB5q7ziDRRe/qEyV
         wdug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=q/BGapiabg6/9xSbthSxsfagRQdNECuef6XV4AT3xZs=;
        b=FWJDjPEy3Zs3ndmnahBwH+psMLlZk4I6ql2vmzVIan5h2BjtjLDsZfNM4DAB2UKR3Z
         wauyNweWW97WWG+XYZmX6/bFw8aU1oMXeOhcNUSIQlIOZJQEQaHEdp8QsVOR9lowxapV
         qyNpfreThHUAR4093eyjBmGOilpolWUiRG3YDxZKI3H7tMHwNe421zx1aX4lHWf6n2Pc
         N+DZF4XbQw0jJKW6CB0I1YwBtpD3+myeGA5WggMFp52r4qmuJzRkzAhPFnWtT/+WUwbX
         5MriAesiTvTDszbJ884P0hpkIuM3z4ThZjdbkR8sUkjGJdK4FgNCNwlEhgNinnEexpNr
         usCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701765541; x=1702370341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q/BGapiabg6/9xSbthSxsfagRQdNECuef6XV4AT3xZs=;
        b=oVEt/zY6ueI+DXrZz3nZ3wn/kiMl0gFO/2bIJxpWTfn+DaVsS063XkMtvWEz5RM/mM
         3BXjyf3/TS3OMJ57ph7FDmyrDESI4snJ1exh/TF+/PpZtsCzIZ0CikQJENrXeVYX+cH1
         xF6/ihBOIFKdzBdHqAVGgiuV8RUgiaKySm9Bp2Cb1D0+yzdo7HsCIzBBF0pL4lqfUB+5
         1hlFQ69OVA5fLVJLVfZHCPnDAAbe9RwmO+7j3ntm9IfPEtKzFqUnzVEh5Mqn/0mmzndn
         sZGRMzoEDpe2c0Rs1vNx+aTf5CBJl7+xOa/m/f9pqewV7phrRBAzVdzsALmQwdHhlQ9G
         SpUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyRyi8d9Cys3m60YaQLKHUHQ3hyRgumEPdotCCkCogxCQZtjMqe
	WcKD19PjyKN4juiO4z4D0/M=
X-Google-Smtp-Source: AGHT+IFfFofSe6q6Wno0t78nIQPUMDVQ3YKrY2glQGCjTsDs5tT+UvbwkDMlO60ibD5Ah2nkprPbcQ==
X-Received: by 2002:a17:902:7408:b0:1d0:4512:7ad2 with SMTP id g8-20020a170902740800b001d045127ad2mr764120pll.15.1701765540943;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7908:b0:1fb:2a88:39cb with SMTP id
 hg8-20020a056870790800b001fb2a8839cbls2373664oab.0.-pod-prod-01-us; Tue, 05
 Dec 2023 00:39:00 -0800 (PST)
X-Received: by 2002:a05:6871:111:b0:1fa:de88:1f3d with SMTP id y17-20020a056871011100b001fade881f3dmr3988900oab.1.1701765540646;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
Received: by 2002:a05:6808:1394:b0:3a8:4c6f:5bc7 with SMTP id 5614622812f47-3b8a84f7e1amsb6e;
        Mon, 4 Dec 2023 20:27:17 -0800 (PST)
X-Received: by 2002:a05:6830:6d15:b0:6d8:74e2:6f4a with SMTP id dz21-20020a0568306d1500b006d874e26f4amr6382860otb.70.1701750437174;
        Mon, 04 Dec 2023 20:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701750437; cv=none;
        d=google.com; s=arc-20160816;
        b=BLQSasg1LEDfHHikUeXTx0P3FttWmeesY8cjfX7VoDUiPrGSpiY+oKo6nxeaVo62/Z
         WOv2XtI1E/1cq+9LVsmxzRpXiEdBu98clhpvGe9MDsKw4kbSgBKUwvK59PPq6hH6kT8f
         HEO92gQnCnW4hW6v3iC561tlhhMA97QLnwXGSPkKV8NVj5vi82dkxxiCIEhDcqh3sYCc
         LPftwLuwISwl/4f44/UOMdVZawAZnIeQ5T5PyUsKysSLQM0tjM+6e//98c+esbPQZijd
         qTGR/X+nLVV7jyejBtRLLLWJuLj3aQssle9SwWybkkO4pVlZTHE4uusq56B0nyAK/WqY
         FXvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ECB8bTrkothGumH+K2V0Img+vaTChlA6bV4xhaiY7v4=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=KfF11ehqqxXzCowQa1Bb+haiDa9fBv3q8r7SvFVmMW95BfoEIRv0Jghy6zo4jjNhcu
         WFsyl12y7MSfv53CADEnJdM+GFYwpnX55uc7ZCmA8Ck8xOQwzCbC+G8Ii3yqsRi0VDho
         b3bCeULUBdaaBihPB8QIRJZGRBsTkkP2jOQaK9bxwmtcl1RKPC5hInMHE3aUcrJ4Y2KX
         qgs7Wo8OUCLzDkladHjdFgCRJ14NTaVAa9Yh407TN1AMQlaSplWxzLod0E74adqImR3U
         cWV6D1ukVQFjlU40/mP9Zo6lWxZHZ1YBLmE9HbED4lPlvDvUsi7yanM2Lqfqv1A6dTmf
         Q+sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FNh0wLAs;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id z22-20020a81ac56000000b005c8d2a55cb5si1314899ywj.4.2023.12.04.20.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Dec 2023 20:27:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1d053c45897so34503405ad.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Dec 2023 20:27:17 -0800 (PST)
X-Received: by 2002:a17:903:1109:b0:1d0:6ffd:9e10 with SMTP id n9-20020a170903110900b001d06ffd9e10mr5482369plh.98.1701750436129;
        Mon, 04 Dec 2023 20:27:16 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id u9-20020a17090341c900b001d087d2c42fsm3831273ple.24.2023.12.04.20.27.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 20:27:15 -0800 (PST)
Date: Tue, 5 Dec 2023 13:26:52 +0900
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
Subject: Re: [PATCH v2 03/21] KASAN: remove code paths guarded by CONFIG_SLAB
Message-ID: <ZW6mjFlmm0ME18OQ@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FNh0wLAs;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::633
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

On Mon, Nov 20, 2023 at 07:34:14PM +0100, Vlastimil Babka wrote:
> With SLAB removed and SLUB the only remaining allocator, we can clean up
> some code that was depending on the choice.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/kasan/common.c     | 13 ++-----------
>  mm/kasan/kasan.h      |  3 +--
>  mm/kasan/quarantine.c |  7 -------
>  3 files changed, 3 insertions(+), 20 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 256930da578a..5d95219e69d7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -153,10 +153,6 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>   * 2. A cache might be SLAB_TYPESAFE_BY_RCU, which means objects can be
>   *    accessed after being freed. We preassign tags for objects in these
>   *    caches as well.
> - * 3. For SLAB allocator we can't preassign tags randomly since the freelist
> - *    is stored as an array of indexes instead of a linked list. Assign tags
> - *    based on objects indexes, so that objects that are next to each other
> - *    get different tags.
>   */
>  static inline u8 assign_tag(struct kmem_cache *cache,
>  					const void *object, bool init)
> @@ -171,17 +167,12 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>  	if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
>  		return init ? KASAN_TAG_KERNEL : kasan_random_tag();
>  
> -	/* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
> -#ifdef CONFIG_SLAB
> -	/* For SLAB assign tags based on the object index in the freelist. */
> -	return (u8)obj_to_index(cache, virt_to_slab(object), (void *)object);
> -#else
>  	/*
> -	 * For SLUB assign a random tag during slab creation, otherwise reuse
> +	 * For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU,
> +	 * assign a random tag during slab creation, otherwise reuse
>  	 * the already assigned tag.
>  	 */
>  	return init ? kasan_random_tag() : get_tag(object);
> -#endif
>  }
>  
>  void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8b06bab5c406..eef50233640a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -373,8 +373,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
>  void kasan_save_free_info(struct kmem_cache *cache, void *object);
>  
> -#if defined(CONFIG_KASAN_GENERIC) && \
> -	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> +#ifdef CONFIG_KASAN_GENERIC
>  bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
>  void kasan_quarantine_reduce(void);
>  void kasan_quarantine_remove_cache(struct kmem_cache *cache);
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index ca4529156735..138c57b836f2 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -144,10 +144,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  {
>  	void *object = qlink_to_object(qlink, cache);
>  	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> -	unsigned long flags;
> -
> -	if (IS_ENABLED(CONFIG_SLAB))
> -		local_irq_save(flags);
>  
>  	/*
>  	 * If init_on_free is enabled and KASAN's free metadata is stored in
> @@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
>  
>  	___cache_free(cache, object, _THIS_IP_);
> -
> -	if (IS_ENABLED(CONFIG_SLAB))
> -		local_irq_restore(flags);
>  }
>  
>  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZW6mjFlmm0ME18OQ%40localhost.localdomain.
