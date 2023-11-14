Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGGDZWVAMGQERFQ4ALA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 796F97EAF97
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 13:01:30 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7a67ff977ecsf518002939f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 04:01:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699963289; cv=pass;
        d=google.com; s=arc-20160816;
        b=ylv+yXTw13gyesK5/8h3buq/uM6Rpl/yPV2v8f07CUn0loGPDDyMyRuThuC8cgeajk
         ng18MHnV1dq5yRq/IcOMe58m7djjqKEc7gu5yzCeqXXNevtRVG7ZyqsAkXlbl22HIeCD
         VdnYk+Sz6ybbj6XfHRVevmjr8sJOoBdmJp3F0/Vg1m8obfjvSUVsILXUKfMz3aBJ/cYi
         5QhzSvEGnj7lO4lvXZMsni4+sehm9JiCvoWBK/xTuPVzKsSxRlRzm2fjorWjcWHBpmbm
         CcJe5/4Z0TezkcZJRPNBUbMhpd51z2px4U96EfTh0xFTcnFYCv5M9ijAWnPf0eRu6tCD
         UtVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GRkqxG2giiDvkrLqPhYlTZvtofsj7D0NVeegTu6PVsU=;
        fh=7lms69YJbSIPw5FCAAcrqHFjiMw73kPZyaKLhvdNeuY=;
        b=wTuThW/2ov2k0G8dPInbQBU/Nm3k1ZgwFLvjPKrk111h5Rm/AUewBxJM9WBVKnIwYz
         eJkVPwlfmGpUHkmzQtRdoRTs8hzozuPwjNgQ4dA2x08FVkfFAxdbk88/Rv2lRj8QvYTW
         o+yrvc2N7uRKU5P157a3wfOI2RqxjU9yeBT6dFwD+SrqRFKmC6umSytAXk2ts1Gg/WLo
         hUU88Xc9mxz9+tQJMiL5pBO5Ak49Z3lhyGVBuRfyHSH36Ntd9tdUuTlWulOC2gVfUDzF
         b0YGYMUHrcQFKAmWlejN/dWk46/Av8ocwYs/rOYI5jTW9fzX9N50sSohNhX/cQsUa0J7
         Th/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KsQzLqJk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699963289; x=1700568089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GRkqxG2giiDvkrLqPhYlTZvtofsj7D0NVeegTu6PVsU=;
        b=bZ18z+he0Zn2SdmX3K0vi5Xf6bDh+YrloOT9nhJab86Yk7+8atqaaM5J+PWLrI2OOZ
         A5H+yL2AYHl0JbV3QzA/hC5gsL6JUlPjPHDW6/kg4Oidfb7U2i16mCSGuZCvtk5XDwVx
         XO+YErORlEGoO69Cnfi7pWO/KAQW35BJHD4esoB/wCIDZSAcIVQrvgjqY4FDqGoCbZyt
         XVVc7lYsyMpzN8LylNV1eGSY/Uat7m7IzNBSIWreMQ9I4+pR0l+D7gNFScXtfdM+RyGn
         X2lOFR6lGwiElmuJ9LKksperZRXayY6+Hz8IT3DdW4/ToSw1DpdoZMD18uV7KhuzpUgv
         8Dzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699963289; x=1700568089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GRkqxG2giiDvkrLqPhYlTZvtofsj7D0NVeegTu6PVsU=;
        b=l4Mzv5twSNgSYbJuFHhU/eNQ2ycacfl9GsWngI7MhMfhBRK3JAgPBj0lZ24Qys+yUk
         WObf1+ZlmEc1NOXKoI+oqPFb2xYXbTjI2sice1/kViH765LHTgLlsOvdF8PdkQBj9rvu
         vvX/5eRxjwK2/jxvzq4+tD5HRWBaTDpW++XcgMkP5jWcYq7wtl7SL/+HkjegRDVHpEtg
         aKjfTydPdlNgnHcRtW9oyRED+cy5NciTk1Sa9S2W/S1qjH9P33SXBh4jfxq8TP55YRQY
         H+6qxTUIZhWtsgPmefR//SMRtdFVT8Ght0Yi4bhT7UZgQMr3E2jR+MCf1HIyMeVvjXZ8
         IKSw==
X-Gm-Message-State: AOJu0YxbMrHnBAHmHOD83tDAf22ZBYPlus0xCW029JeE82dzBiapmDGq
	r77t7TPPD0qDNrMI/T8Lg5I=
X-Google-Smtp-Source: AGHT+IHZogfHnRU9uOGAg8iQ77ipy7hG9IdD2A9EVEla9yOsz1r8wFGVVxOlgETN4Rf49rNZrLz7NA==
X-Received: by 2002:a05:6e02:1bcf:b0:357:438f:6ecf with SMTP id x15-20020a056e021bcf00b00357438f6ecfmr12728147ilv.13.1699963288937;
        Tue, 14 Nov 2023 04:01:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c56c:0:b0:359:6bf2:7ab6 with SMTP id b12-20020a92c56c000000b003596bf27ab6ls3495534ilj.2.-pod-prod-09-us;
 Tue, 14 Nov 2023 04:01:28 -0800 (PST)
X-Received: by 2002:a92:cd8a:0:b0:357:a08b:566d with SMTP id r10-20020a92cd8a000000b00357a08b566dmr12346874ilb.29.1699963287862;
        Tue, 14 Nov 2023 04:01:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699963287; cv=none;
        d=google.com; s=arc-20160816;
        b=mcOydgkXlfx5/ANFmv4K6DekEup7/++fR9dQmE420pdFr7RSjWzJZ0PNhdKqhZD3qH
         V9CqeCoBiUZxJvC/t5o68M5euWlrcUgcKIgY191TL6VGK+4B+7C4zHTCq3jQXFax14pN
         zRZYw42Lxm+SJUifjY5X/W8eQE3x53GUtWuTpzDDlM13WAF8BH/Y3Cl1Gw4Ac3QvxB59
         2fzyLjX3JsbFDbrm5SLUhY37Yiyu7CdenwqOREuyLn0J4aMep+3H1X80ZXvbBDNqr4QR
         IJ12nfKYR8aOs5YzGsLd5srgPCkSc0bUz1qCH0XCtIuTShtu+0z+j2EKjHKDU5SlEdyB
         FqeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w+cNKD/DZD2lkmgn//C/a4VZOCUEay1a0fxR4tTnP1Y=;
        fh=7lms69YJbSIPw5FCAAcrqHFjiMw73kPZyaKLhvdNeuY=;
        b=qZjm0JVJyitFoY8pGKw4KvlDUdWuGt0LYbD2CG4iqpxz1COhqiYZPopiAv5H65Qf/i
         YTi/3AzBH0wj5ZNgchsoZiBTdknFMbPJHGJtyDnFYzJm/qlAEUgWkXTq68Ghfq+NDASR
         yPJg9XLA9dwt3UVdQMfIYgch89JdzJRnPxzSfZLHxLwxRaF/K+ltaISQE6frLl51VeRq
         jmU4NwvWPhle65XJAXbWTDi/aPL6HN0QDuqdM09MLO2dNi8xFwPUajanZcWSbVaHp+ro
         ePcsko6oFzU5MvKcA9bi368Jr+d/UaAwIyBlZFroaAP+uuP6apDx3UWtzEt0vR/nNJ79
         Vt9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KsQzLqJk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id cx20-20020a056638491400b00439ca012a0bsi1001921jab.6.2023.11.14.04.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Nov 2023 04:01:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id 71dfb90a1353d-4abf80eab14so2521277e0c.2
        for <kasan-dev@googlegroups.com>; Tue, 14 Nov 2023 04:01:27 -0800 (PST)
X-Received: by 2002:a05:6122:1689:b0:4ac:593b:e9f4 with SMTP id
 9-20020a056122168900b004ac593be9f4mr9715321vkl.9.1699963287127; Tue, 14 Nov
 2023 04:01:27 -0800 (PST)
MIME-Version: 1.0
References: <20231113191340.17482-22-vbabka@suse.cz> <20231113191340.17482-24-vbabka@suse.cz>
In-Reply-To: <20231113191340.17482-24-vbabka@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Nov 2023 13:00:00 +0100
Message-ID: <CANpmjNOy+K_jBkaZ9_+He9tT83PaYLama517YvQ1TH13ayg3vg@mail.gmail.com>
Subject: Re: [PATCH 02/20] KASAN: remove code paths guarded by CONFIG_SLAB
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KsQzLqJk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 13 Nov 2023 at 20:14, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> With SLAB removed and SLUB the only remaining allocator, we can clean up
> some code that was depending on the choice.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Marco Elver <elver@google.com>

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
>                                         const void *object, bool init)
> @@ -171,17 +167,12 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>         if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
>                 return init ? KASAN_TAG_KERNEL : kasan_random_tag();
>
> -       /* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
> -#ifdef CONFIG_SLAB
> -       /* For SLAB assign tags based on the object index in the freelist. */
> -       return (u8)obj_to_index(cache, virt_to_slab(object), (void *)object);
> -#else
>         /*
> -        * For SLUB assign a random tag during slab creation, otherwise reuse
> +        * For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU,
> +        * assign a random tag during slab creation, otherwise reuse
>          * the already assigned tag.
>          */
>         return init ? kasan_random_tag() : get_tag(object);
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
> -       (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
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
>         void *object = qlink_to_object(qlink, cache);
>         struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> -       unsigned long flags;
> -
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_save(flags);
>
>         /*
>          * If init_on_free is enabled and KASAN's free metadata is stored in
> @@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>         *(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
>
>         ___cache_free(cache, object, _THIS_IP_);
> -
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_restore(flags);
>  }
>
>  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
> --
> 2.42.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOy%2BK_jBkaZ9_%2BHe9tT83PaYLama517YvQ1TH13ayg3vg%40mail.gmail.com.
