Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBN5XYSVQMGQERWYT3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E9B66807DA1
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 02:11:20 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-58dc2d926e7sf197785eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 17:11:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701911480; cv=pass;
        d=google.com; s=arc-20160816;
        b=AnDa5HJlSugOPTCQmRH9uTve54j8NfQdV7stIPx70RUQLu6O05U5+uTUlm2RbloPBc
         C8bd39k97v7ffLwVlPDDREvfIDvgoimJcfrwPas2orDB2vzQZTmaqRlU67d4qEN5IFdO
         EctHewKR+by8CJfrQXJfzlN7TK8kmc6HutrrlW8A2M6bet/YQyL9wBhy6k3ynHnAIn2v
         stEPOKdsX29qBFegJqf8Tcl5zImJk7PC8aqLXfxprnyPqxirYlB0DQ5mspPphNBT0KOA
         64tM1p8l2tlhOb6TdX3TnWK17iPrH4wLz/QmZa5P7oAHwvf6xTTzPkOH8QL1r6Awfu9S
         K2qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=q/jgzZjqXMFEIwXjb/mEq0qFGa8r4S7F322Cyb3QJFQ=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=NyEm8uJ+lVqQ6tIOK4gtKSY01AUT7ZgWec2rMx9IfejLdnbqLwt8/Er1R7dU8wKG8y
         92ja2VixQ4kVEApKTGg+Eh6fwkKJ6chuMNFuadJn3euJ4thn4opIRj3AMyKzZIe2MHFO
         m1yey3VrITX3biYR56LqLn0RRLIJ60ifh6YIyYI9q4WSDGyWn/qkKvRStO+/aKYEBckY
         eoqRnlpB74aK5sILEGuIEuGbZDfemuEd4DBL5u879sJN7fZyqZ3LGMvgSsMbAyNWDOGW
         cDfxqfO9DJAUoQhnp73IlwvArLiCF/Ay/gcMKPBUtsCrBllBlWLBRuaOooZpD4VOEbj8
         P+vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=amzHPPww;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701911480; x=1702516280; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q/jgzZjqXMFEIwXjb/mEq0qFGa8r4S7F322Cyb3QJFQ=;
        b=Cz/y9ESnO/vP8mpEMNItAcDdAcMF2dpsOtp5wmCOgK8M3/mnd+6MWx7LAGpEfA9aH3
         pu6jo3142PGpR3D/4KD4BuE/73zVKSjwbJlkxCYXhyOYQN2O+tJRArUH3NbYE3VEvqIj
         LyvUQxOcM3Bbf9rES0fTA8J9dNxCAPoTlxRwycMY02k91mjtPHyRRMf0Tf6z/gHHKuaf
         tJdsQOcaG6yTT+BBjYe+JXp8JMqDeAAnJI13+fQHPhYjnwD9jVdjr+M84KCWQL1v9KlH
         B+y1CN16qQWApDWVLYeomZWWW6zLjL4ni0HTrHhW6Ja89hZTjX3+EgfFGL3OfZWUIo66
         ajUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701911480; x=1702516280; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=q/jgzZjqXMFEIwXjb/mEq0qFGa8r4S7F322Cyb3QJFQ=;
        b=cK1exHLXavPR3KPFNDBSGdhmRUMq1hq375I3gfTAvjlzcRUBobLXUvYHLFYA4vsOEB
         x32S+lp8s/CJ//auFw2uKJa0f5cwIOpJhIOH1X2x7jvCqpKTuZmWgBxy1HKRim6aVT8R
         BLuYB74czBmy1h/whYYgMFzTLryV+xWkLRK6leiZGByUlEhI3QlFYw9mrPkHoqHp3ueP
         d5uYMUFAHszY2IT2gVkcfzuel45jLZwzyQc+ntN+B5IS2FvAvYzYKFxJ8+PVrRQd1eRm
         Ox53Bnyph2SBDL9kRH4vDgUpJU2wJhiVMp4QpiebX5gCK6HhLJ5KwqPQOpgFZPmAGt7t
         Y0kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701911480; x=1702516280;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q/jgzZjqXMFEIwXjb/mEq0qFGa8r4S7F322Cyb3QJFQ=;
        b=HieMPjnTW4SARvnvBsNTHZwFi53+cIqCb6316nYDwLGlx6auLKRblDqtK7t05NZcax
         yKxolpT1Lt+TU/X+pu0izdu9kAOfrxyyIJOxw0gqNY7sVUmumgP4nz/luYLwPo+f32OR
         749DV1dgqi+7jJg62GBpNFnGcab+iaZ8Qwz0uvYOIN8oX9YWKHAUQXHtgLky1jNrDN/6
         eF34Rgz74HXq8kEW7yceEnpOWb1P7EZZO7eKD/I9Ur4e6flvtjlMmIqqi9E31ENli3Kp
         cxMHfT1UnXrh7Hq7OIQ/aze1NrpIwISbykBUlMkaJ4ABo+UkZsvLSRuKdmixH2xTdMg/
         mFtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwsiKkDTxX7eL2EEa3dtY5SqQbFj63Lzb/DmEAqDVH4fnGUP9Wb
	E6Jv1Oub4w+PReKx3F7P44Y=
X-Google-Smtp-Source: AGHT+IE+XOPuaemmZXbd4rHs9/tRqy4zv6gQNcrGcczocHEu3rtsE0Aq1/gTBQviTAKwHihjGZQuWg==
X-Received: by 2002:a05:6820:1ac8:b0:58d:6c99:fde8 with SMTP id bu8-20020a0568201ac800b0058d6c99fde8mr2125705oob.8.1701911479597;
        Wed, 06 Dec 2023 17:11:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2219:b0:587:9477:19 with SMTP id
 cj25-20020a056820221900b0058794770019ls555509oob.2.-pod-prod-07-us; Wed, 06
 Dec 2023 17:11:18 -0800 (PST)
X-Received: by 2002:a05:6808:1149:b0:3b8:b063:9b69 with SMTP id u9-20020a056808114900b003b8b0639b69mr2274368oiu.91.1701911478630;
        Wed, 06 Dec 2023 17:11:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701911478; cv=none;
        d=google.com; s=arc-20160816;
        b=vXsR21wtDQf3mHRkCwXwNo5i1Duq3s0LtfyILKJZSkN0Yljq0XEJrU8ir3DSphP2qr
         Lr40bkwIxHWyfSxc1ZENOoKvuE7I+ewikyn3EJb3ujZVJaQMLHxM1hZjlrmfy03xLwaH
         APA1jf9B0bCxJe2vTS6GM7ziE7Q6bA9OnqfojyxNavlx9NmnXiB+de+0Yc7ceS07WD/U
         GtRTUucgoHog08MFDC07+UN2YeY0zPx6QriEsfyRarBW42bNwOw8p3skGTdp7lylop9K
         MV5mhoDz5UUnehckIRfvy7HlzDVPxadBBRYOJuqi/yEGbwz3m/87LLkSlfygvDNLIVsB
         sWVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=O2iQ4GZaNaP4TLuVf9scG6OMfAEhFr0GcB530VPLhoU=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=piSnDiBbtWF8tw+mnBG4qavMflQSponilyheRidpz2KzWayPjougZHAAbHwg8vqRj1
         2qDT8Jmt4Y7bNp3lPKEKxdL3IMKk24NBITy0PGKtxzuJa7KE1XfbNfEw1lG4rukZUwZs
         rarafvAvOFVA/By14PSEpbRGMQNC3rtV1Ul596IyeIlgiBiPHHA9lUbBkhOf3SPZeQnk
         FU+SPVB2vnobbvUV07YW9vfOhxHgR4t1+5vEOsDSNgELbW1sZl4PLMeqK+GbpkHwuBuv
         0+I/m1gFcmOwdJUUOcFB7++wfE2VXE8kqdpNDgL2UUShGyzk1jSDUpdocHlhxpzqenPY
         QT4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=amzHPPww;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc34.google.com (mail-oo1-xc34.google.com. [2607:f8b0:4864:20::c34])
        by gmr-mx.google.com with ESMTPS id bk22-20020a0568081a1600b003b8979bb6c1si20795oib.4.2023.12.06.17.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 17:11:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) client-ip=2607:f8b0:4864:20::c34;
Received: by mail-oo1-xc34.google.com with SMTP id 006d021491bc7-59067f03282so90625eaf.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 17:11:18 -0800 (PST)
X-Received: by 2002:a05:6358:4320:b0:16e:27b5:3b25 with SMTP id r32-20020a056358432000b0016e27b53b25mr1981299rwc.31.1701911478109;
        Wed, 06 Dec 2023 17:11:18 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id p2-20020aa78602000000b006be5af77f06sm141705pfn.2.2023.12.06.17.11.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 17:11:17 -0800 (PST)
Date: Thu, 7 Dec 2023 10:11:02 +0900
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
Subject: Re: [PATCH v2 15/21] mm/slab: move struct kmem_cache_node from
 slab.h to slub.c
Message-ID: <ZXEbpvUpmhOBZvuH@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-15-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-15-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=amzHPPww;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::c34
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

On Mon, Nov 20, 2023 at 07:34:26PM +0100, Vlastimil Babka wrote:
> The declaration and associated helpers are not used anywhere else
> anymore.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h | 29 -----------------------------
>  mm/slub.c | 27 +++++++++++++++++++++++++++
>  2 files changed, 27 insertions(+), 29 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index a81ef7c9282d..5ae6a978e9c2 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -588,35 +588,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
>  	return s->size;
>  }
>  
> -
> -/*
> - * The slab lists for all objects.
> - */
> -struct kmem_cache_node {
> -	spinlock_t list_lock;
> -	unsigned long nr_partial;
> -	struct list_head partial;
> -#ifdef CONFIG_SLUB_DEBUG
> -	atomic_long_t nr_slabs;
> -	atomic_long_t total_objects;
> -	struct list_head full;
> -#endif
> -};
> -
> -static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
> -{
> -	return s->node[node];
> -}
> -
> -/*
> - * Iterator over all nodes. The body will be executed for each node that has
> - * a kmem_cache_node structure allocated (which is true for all online nodes)
> - */
> -#define for_each_kmem_cache_node(__s, __node, __n) \
> -	for (__node = 0; __node < nr_node_ids; __node++) \
> -		 if ((__n = get_node(__s, __node)))
> -
> -
>  #ifdef CONFIG_SLUB_DEBUG
>  void dump_unreclaimable_slab(void);
>  #else
> diff --git a/mm/slub.c b/mm/slub.c
> index 844e0beb84ee..cc801f8258fe 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -396,6 +396,33 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
>  #endif
>  }
>  
> +/*
> + * The slab lists for all objects.
> + */
> +struct kmem_cache_node {
> +	spinlock_t list_lock;
> +	unsigned long nr_partial;
> +	struct list_head partial;
> +#ifdef CONFIG_SLUB_DEBUG
> +	atomic_long_t nr_slabs;
> +	atomic_long_t total_objects;
> +	struct list_head full;
> +#endif
> +};
> +
> +static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
> +{
> +	return s->node[node];
> +}
> +
> +/*
> + * Iterator over all nodes. The body will be executed for each node that has
> + * a kmem_cache_node structure allocated (which is true for all online nodes)
> + */
> +#define for_each_kmem_cache_node(__s, __node, __n) \
> +	for (__node = 0; __node < nr_node_ids; __node++) \
> +		 if ((__n = get_node(__s, __node)))
> +
>  /*
>   * Tracks for which NUMA nodes we have kmem_cache_nodes allocated.
>   * Corresponds to node_state[N_NORMAL_MEMORY], but can temporarily
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEbpvUpmhOBZvuH%40localhost.localdomain.
