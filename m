Return-Path: <kasan-dev+bncBAABBLWDXOVQMGQEMZEYHZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C16A804CB3
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 09:39:11 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1fb1c742f0bsf3345449fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 00:39:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701765550; cv=pass;
        d=google.com; s=arc-20160816;
        b=MbtnJAPDAeeChcu2J4er1/VcECAgQJqqtf1DpLMe+k2T8oIQ0iCF5gmQjvbhqhVxYU
         5tdJz9s44bDggigX4VszLb8F/oXECCFpxz1BGdL/2B+LB1cy37PE6xg2QGunigJOxTZn
         QcjL3UeAVfPAvprIkblsYm6oD02Dh2uqrm9pAmSLiMcJ4UhtAN8D9sMklGX27GRiNenG
         BPTRqqbUh450k9P9bgmZWlaFH1qyXHhTBArBFA2l6QXuBk01kG56UyAjdONZsR4VdIyY
         wKej5DsCX7r8Yu/i4rKZZ2A5IPYMcqQQSRoR29/23aBbljegBdF4+Nr7QFfVv/n9LGUo
         vHzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=KVeY9AyrCWgSPJP2supGZQr+7E7/4GMw8ELW4/7M6Jo=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=RVlfbssxmY6yMMJ54vsTFJm4FFi68FXqZufSTJahbLHNBKwOv5OBmPj8XJ0AyWR/dc
         DnTiGpKyDhBd8pcTH4BlO3v2kRqe+3jbuE09puTBCghT0kCGnzZ16/C2b5YaAi6XxDOK
         jOq5cKeXhANPyAEQbyCFW+ZJ6999lIOv6MacLeeu4/UzcfYwDeVv65+7s10KylvGG7hJ
         O+/iwlXt/ehzHumEWQQivvZ338L3BLI+iV6uAO+TPN5ATFDpPiGhUB/N2Vz8TtU6DFK6
         3dv57ea3dUGFxB1FDcSdQ3t4AXUDUUOBXmdQeSytMs2rAWKa04NbhBEZYOXilKNQ3RhY
         WbLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AtV3fzAe;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701765550; x=1702370350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=KVeY9AyrCWgSPJP2supGZQr+7E7/4GMw8ELW4/7M6Jo=;
        b=AoGyWc/usFhaEhGwgVsPwcEsuIClaCP833UStIBXX/tgajwd2afVfsBL6pH1rkHWO4
         pDfBcwebyBg8NXEjtHsoZKdHGDK5LcfKu3UlbWRutP8fjKm+riXEPMDmg8oXYdgIMQgh
         X4P30dxpQwza9/XJ8p/rL4zUF4rZ6aB1dewt+bLygdWWhJWkwVFx80Rz40YdmvosUJPc
         zdPel6urXIaUcrjKqnXNfojFUqnSi6o8ZZs9DO6KVz5kesTnJv/vFNS2dgda6gzOcJtj
         bLKCtC6jUhCZrK1ovc+aqDnctwSZR806KASVO/EOr5AQaZxwwyVM8a3/9KKWlOeLEjhG
         ac0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701765550; x=1702370350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KVeY9AyrCWgSPJP2supGZQr+7E7/4GMw8ELW4/7M6Jo=;
        b=NU49NtOH4o4DnzgnGztHc7kO3qyGSLmONYm6S5UKf1ECm84zz+H7rkWH/Fj2wId8a8
         WbKlSwWTFqXnMANAbcVsf3wfnXxxSBiHJVKtndaVdWicaHL79iSfNozVNGXU16gl2avW
         8SAyyVBy23MNNhWVlA2ojW7S/yC4f2ykC1r1xZm7U9o+fFI20UAVA7wwdkWQuAabgxaV
         p+Apc3HFKQcGH353/m1YyhU022aamRPcmi9aKoHDRfGLVGEsy45vK5VIwcMEgBUHCocN
         xz5Qor5AEmVZY9y6nbsb2rXMDlZCZ7IwTMaTacltpXQ++8lxAic3h6TtRq9cmwZt6cLx
         fijw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxwjdMt0Ylry48wGMVRzPApKLgO62ioE6PbjE30hxhCJ6Hsiw32
	uAeuPJXGLAR5N0DvzI2Y4/8=
X-Google-Smtp-Source: AGHT+IGd0/A+FQUU60QvhVzF6at94ZVEzSdfwBGrU0JScMt0nJZwqNWJoIFKjoW/0xdgcAf5MyeENg==
X-Received: by 2002:a05:6870:9709:b0:1fa:f387:e0ab with SMTP id n9-20020a056870970900b001faf387e0abmr5788515oaq.46.1701765550150;
        Tue, 05 Dec 2023 00:39:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:171c:b0:1fb:3148:c486 with SMTP id
 h28-20020a056870171c00b001fb3148c486ls250229oae.2.-pod-prod-04-us; Tue, 05
 Dec 2023 00:39:10 -0800 (PST)
X-Received: by 2002:a05:6870:d891:b0:1fa:fc3e:7891 with SMTP id oe17-20020a056870d89100b001fafc3e7891mr4496238oac.0.1701765549925;
        Tue, 05 Dec 2023 00:39:09 -0800 (PST)
Received: by 2002:a05:620a:3182:b0:77d:cfff:33fb with SMTP id af79cd13be357-77f1ae4b27cms85a;
        Tue, 5 Dec 2023 00:19:35 -0800 (PST)
X-Received: by 2002:a05:600c:2346:b0:40b:5e59:ccdb with SMTP id 6-20020a05600c234600b0040b5e59ccdbmr248026wmq.188.1701764373952;
        Tue, 05 Dec 2023 00:19:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701764373; cv=none;
        d=google.com; s=arc-20160816;
        b=nAocyZxYpv28Dzl3L66QEomcYQIW/5/CJ1uJRrYV/gynNGksylmnfVSkIp7gFcb4Dt
         8iee3/yV/3GdcgAxMr6G0EHMz2CGbK9Tp22tkQ7hCn2W4GRVI+fwLIYS34eDSN8/KvG2
         pUv8BBT/csQoOnSR5ZgPwhMC65jyXDeD4Z7Cu7Rol5U9jf6b4ZVWO/NXRGdSQrYgMWCn
         8TGwacfncnyjEeMGnmAXWvF/39bHzts1uB80FUh4AjhpndT+rMc1caahhAbhvcT6dDiO
         s/Ae+fGE7g+hd2z5S9QO5DiHnKyJTpdc1m3bKq9AEp1xEtUrR8o0Mq1NC+NIiE0kxlZG
         VnXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=1msEm8akAYRx9kjUOA91nsxPgIb6zvoJEQIqcVegQCI=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=INNhe55v3wi61de+A2x14auaR7E3wvOIrMV1q+91My3smwPYaw/1I5vK3FxOb+aN4M
         gu5oi5Jhi5/bTMMtyEAvGmuenIm+c2L+Z36K+N40b5hnPrdN97XmypMqK5OUhGyEx12u
         XWgh1XF2ZeWXw4OMNtnlfGgBenvHa76UsUuGpKFDBZw9qYgMjm6MLORvEB8OCy+VR3qg
         A8KIFVlCiRVy/EHcgSXe12iUrUND/h+eJiHHtuolandnofkWXpRhxlmDSCqWjSTMKe6j
         Q3cmbFiJBW40A66XBIpPyCRRXHPpUwuRzegudWdafRuiN3+c2PHyjFy/sRFUMDruHHwR
         e1Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AtV3fzAe;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta0.migadu.com (out-170.mta0.migadu.com. [2001:41d0:1004:224b::aa])
        by gmr-mx.google.com with ESMTPS id n18-20020a5d4012000000b0033352382817si140231wrp.2.2023.12.05.00.19.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 00:19:33 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) client-ip=2001:41d0:1004:224b::aa;
Message-ID: <30f88452-740b-441f-bb4f-a2d946e35cf5@linux.dev>
Date: Tue, 5 Dec 2023 16:19:27 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 2/4] mm/slub: introduce __kmem_cache_free_bulk() without
 free hooks
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-2-88b65f7cd9d5@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-2-88b65f7cd9d5@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AtV3fzAe;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates
 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2023/12/5 03:34, Vlastimil Babka wrote:
> Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
> objects that were allocated before the failure, using
> kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
> hooks (KASAN etc.) and those expect objects that were processed by the
> post alloc hooks, slab_post_alloc_hook() is called before
> kmem_cache_free_bulk().
> 
> This is wasteful, although not a big concern in practice for the rare
> error path. But in order to efficiently handle percpu array batch refill
> and free in the near future, we will also need a variant of
> kmem_cache_free_bulk() that avoids the free hooks. So introduce it now
> and use it for the failure path.
> 
> As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
> parameter, remove it.

The objects may have been charged before, but it seems __kmem_cache_alloc_bulk()
forget to uncharge them? I can't find "uncharge" in do_slab_free(), or maybe
the bulk interface won't be used on chargeable slab?

Thanks.

> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 33 ++++++++++++++++++++++++++-------
>  1 file changed, 26 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index d7b0ca6012e0..0742564c4538 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4478,6 +4478,27 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
>  	return same;
>  }
>  
> +/*
> + * Internal bulk free of objects that were not initialised by the post alloc
> + * hooks and thus should not be processed by the free hooks
> + */
> +static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
> +{
> +	if (!size)
> +		return;
> +
> +	do {
> +		struct detached_freelist df;
> +
> +		size = build_detached_freelist(s, size, p, &df);
> +		if (!df.slab)
> +			continue;
> +
> +		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
> +			     _RET_IP_);
> +	} while (likely(size));
> +}
> +
>  /* Note that interrupts must be enabled when calling this function. */
>  void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  {
> @@ -4499,7 +4520,7 @@ EXPORT_SYMBOL(kmem_cache_free_bulk);
>  
>  #ifndef CONFIG_SLUB_TINY
>  static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> -			size_t size, void **p, struct obj_cgroup *objcg)
> +					  size_t size, void **p)
>  {
>  	struct kmem_cache_cpu *c;
>  	unsigned long irqflags;
> @@ -4563,14 +4584,13 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
>  
>  error:
>  	slub_put_cpu_ptr(s->cpu_slab);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
> -	kmem_cache_free_bulk(s, i, p);
> +	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  
>  }
>  #else /* CONFIG_SLUB_TINY */
>  static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> -			size_t size, void **p, struct obj_cgroup *objcg)
> +				   size_t size, void **p)
>  {
>  	int i;
>  
> @@ -4593,8 +4613,7 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
>  	return i;
>  
>  error:
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
> -	kmem_cache_free_bulk(s, i, p);
> +	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
>  #endif /* CONFIG_SLUB_TINY */
> @@ -4614,7 +4633,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	if (unlikely(!s))
>  		return 0;
>  
> -	i = __kmem_cache_alloc_bulk(s, flags, size, p, objcg);
> +	i = __kmem_cache_alloc_bulk(s, flags, size, p);
>  
>  	/*
>  	 * memcg and kmem_cache debug support and memory initialization.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/30f88452-740b-441f-bb4f-a2d946e35cf5%40linux.dev.
