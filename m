Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUGPTSVQMGQE76SIPOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id AA3587FD623
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 13:00:17 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id 71dfb90a1353d-4abd0306062sf2099714e0c.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 04:00:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701259216; cv=pass;
        d=google.com; s=arc-20160816;
        b=KxNDohEOvfeTDNq9SBsCCNcFHYmDFJJhJGd9NnMh2CFs8XjcQ3ay2a6Qv0+HukY0+9
         nQjSWtuCm8ai6PVXB+DkWKdGFHKQlFGdXtMPupdb6WvXPyybQqfWRMayGlqLhyecy/Ln
         VR73fqv4G9F2XZ3zC99CpImYvg3cVfS5XFUY2tC3Yo8Xt7CvC8IdNAJBS4AomnPGQxEw
         5i+QnITmRmVFTDpW+pGQWXVwd74v0eHIQ5tEsYaXc5DBHqd7STDTgUTp4s/VkxFz9z5W
         IjmJAr+XD1xC3Gq8utyYXxx6mw3U4GBrhI6hsxFtnR/zutermhy1oLYyl0Wy+n/ItB34
         f8FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TsG+uBUQSqziuZAYeqXfdlw1LxNmw9CE8/EaJPkz3BY=;
        fh=BCNYuPqol1vLzLo/yJnM/ouRZane89kp7ezRxw3G5Zc=;
        b=pn9RyQuuJcp3dqUbko3RYjl3qXd9mTgCgTdRpORwGcXTUWA949UZzDzfyk3DEG68Lk
         VD3WyCRwXZhWtAp2uLqMaon3+rMLZBXyX9kPWuN1VglzFacgtc4J9vld9DgbiFtndbE/
         oUipvlZAY6r6UQI7epiWeLd/LdbwGClsWmElMtTujAZWedkY1WIEHPOhuqOIOQcYA2Hh
         VgJVhxadO8S6a9TD8TXtA15UN0gdoN8pvLT81VG0GKVRk5dBsvKMdMureba/vNvrMQuk
         HrUIDf5y4dRVl0NYKuIBjWt9Miz358qi8rTuV/g7ixoMXDW1rhI68fkNBlyOjc79L9Ev
         BKaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L0qKD8U5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701259216; x=1701864016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TsG+uBUQSqziuZAYeqXfdlw1LxNmw9CE8/EaJPkz3BY=;
        b=eShSit9qrIQtZNhB7pFi3g6pFgtVRaUHz7WY23W5jJgnv29a5gIWFd801PaEutFzji
         gecRMknXBO57Gusfkp7Psq3sBOkvLM1mPGQsTn1Q3JWLD+4qal1QXg4aMofGMMgINN6f
         aUrufrd6d2NwNgJ47u3PBW32cKdmQJ2TB/pkN2eR/F1tCeXmd5MZPXHEJntIYCx6k8eD
         1EPDrN0JT5OFkfl56Qnka2rJGGFWZwvjV4YZNEi2qsE8hvGISDvvwHhxF9dL2GrfjxPX
         G+zTicTd/1Rrk7E9mxb4Dc0T+JBs4QDp4gyC2Nw3SWB/MSa02pDqTVJc4cuBfXvd/cOc
         AqNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701259216; x=1701864016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TsG+uBUQSqziuZAYeqXfdlw1LxNmw9CE8/EaJPkz3BY=;
        b=jdCxIDUTK//lXJWMQBQopGoIqHOa9sfQ9qrHoVe71QqF7F2tPewFqjOYMPyJ+1qORG
         RrXnMTN3lAWPaU/jn76tonz3SmXX8C8br7EsTLJdHgK2rrzlsGnCa3FfFeY12akSppDC
         CdyAGKPBwZKIPChlEMjoI9zIqA+ZIS26dYwV0CIPdFliYrXz977DFvr0Y3uFgVkb7r8g
         aEL0CohogxnqZlZxYQt8Bh67odZ0JchlZWoGkb5GxPxbLdex1t731ag2aKUWHTRQQOUv
         gnl9voqeWHnPeIPxHJrOFB9ih7ryqjz+8gQtw1+Q+AQIvQ474IKjyQw1l26rq3V7xeKa
         6qFA==
X-Gm-Message-State: AOJu0Yw6/0YAFY4ahkq15sJIjgj7hQxAWAigUUY77WLlCXwUOrNvof/o
	FpLf9CYmlNtKz2q2/bN/z8c=
X-Google-Smtp-Source: AGHT+IEyk4QNW+xMVV9crRxkscBXaIXyecskoLd1hpwbox+YcbekcHY4W/Qg/yK/4IMxdsijdxjtDA==
X-Received: by 2002:a1f:4ac2:0:b0:495:cace:d59c with SMTP id x185-20020a1f4ac2000000b00495caced59cmr14630051vka.0.1701259216416;
        Wed, 29 Nov 2023 04:00:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5dce:0:b0:423:8c6b:503a with SMTP id e14-20020ac85dce000000b004238c6b503als1987715qtx.1.-pod-prod-07-us;
 Wed, 29 Nov 2023 04:00:15 -0800 (PST)
X-Received: by 2002:a05:6122:208f:b0:48d:1b20:268e with SMTP id i15-20020a056122208f00b0048d1b20268emr20414959vkd.10.1701259215570;
        Wed, 29 Nov 2023 04:00:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701259215; cv=none;
        d=google.com; s=arc-20160816;
        b=MvyjqPyx+IrPbrIPoJzwYr85Cd9Ef3auAPSiUbhTsO1I5zcVcASGAKp3OP6YpAwCB8
         iR7U1Tw5NH4zbalukGOiYK8vbQZEbcX4YEntt7MVslj6Z2vEdXoPrwcoghEKFalW3RpL
         2S/s+tx9VhZx6OHHeG/6VeVuglYKftfyjlQB4R1Fvvzq78Y0GZkoY5Ov4gyK/1Tb0hAE
         VsPQmBX4JjLFOd7xsgDE8rbhsn3u0TvsdNV9ixjkW1K2fL/lXRbb2CH6Y3CF3t2WnSgS
         J3+ZozHkVGjke1j7E7pll5RLJm2/3C6bal7bxAxq6zlpBdG3OD9V5j4oTQcrF/1sd+Vy
         C5Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nPXPu1JYkKeWx1IZ2D0WOSznovDcK9NZrhDXsB39l8g=;
        fh=BCNYuPqol1vLzLo/yJnM/ouRZane89kp7ezRxw3G5Zc=;
        b=wiPbPyrFK7EYtFbc5WRhC9apYOz5lJT0zBUsL7zG8gqxv3FKb89OCpC1RHsa72WYl5
         o7nYT0qHr7NvY8sBy8CL0HrX/lArOy2wt4mqLx+VV+CxFynCsxIrDg6DN3kujzBZRDYb
         S9PLWIr2d4LecgIFdhbi1snxWbQoBkfJ9Ti1pDW8WF7ryYNAt+IFgsf4ZwaGeDT5vkyO
         UDdtE97HFySIJ/ZNVOWAV4smsueXLv/kveR6f8SGGLDBmUm4xJMI75i9hoPI8J5cDFZG
         kFKiAkglWoXd67Kw1kHP0CQBaFXfdLQWWpecj+e2mevQFN2pQ/lAP5gCxlK8g2XRkF7k
         Arfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L0qKD8U5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x935.google.com (mail-ua1-x935.google.com. [2607:f8b0:4864:20::935])
        by gmr-mx.google.com with ESMTPS id ge31-20020a0561224e1f00b004abd0f58a5esi1691934vkb.2.2023.11.29.04.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 04:00:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) client-ip=2607:f8b0:4864:20::935;
Received: by mail-ua1-x935.google.com with SMTP id a1e0cc1a2514c-7bb3e55c120so1953187241.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 04:00:15 -0800 (PST)
X-Received: by 2002:a05:6102:5108:b0:460:621c:d14b with SMTP id
 bm8-20020a056102510800b00460621cd14bmr20684204vsb.20.1701259215088; Wed, 29
 Nov 2023 04:00:15 -0800 (PST)
MIME-Version: 1.0
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz> <20231129-slub-percpu-caches-v3-4-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-4-6bcf536772bc@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Nov 2023 13:00:00 +0100
Message-ID: <CANpmjNN-RCZEzU8tLsUVGLtuDgXMRjddOW3fj6bEzCw2+FSiNg@mail.gmail.com>
Subject: Re: [PATCH RFC v3 4/9] mm/slub: free KFENCE objects in slab_free_hook()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	maple-tree@lists.infradead.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=L0qKD8U5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as
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

On Wed, 29 Nov 2023 at 10:53, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> When freeing an object that was allocated from KFENCE, we do that in the
> slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
> the cpu slab, so the fastpath has to fallback to the slowpath.
>
> This optimization doesn't help much though, because is_kfence_address()
> is checked earlier anyway during the free hook processing or detached
> freelist building. Thus we can simplify the code by making the
> slab_free_hook() free the KFENCE object immediately, similarly to KASAN
> quarantine.
>
> In slab_free_hook() we can place kfence_free() above init processing, as
> callers have been making sure to set init to false for KFENCE objects.
> This simplifies slab_free(). This places it also above kasan_slab_free()
> which is ok as that skips KFENCE objects anyway.
>
> While at it also determine the init value in slab_free_freelist_hook()
> outside of the loop.
>
> This change will also make introducing per cpu array caches easier.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Tested-by: Marco Elver <elver@google.com>

> ---
>  mm/slub.c | 21 ++++++++++-----------
>  1 file changed, 10 insertions(+), 11 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 7d23f10d42e6..59912a376c6d 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1772,7 +1772,7 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
>   * production configuration these hooks all should produce no code at all.
>   *
>   * Returns true if freeing of the object can proceed, false if its reuse
> - * was delayed by KASAN quarantine.
> + * was delayed by KASAN quarantine, or it was returned to KFENCE.
>   */
>  static __always_inline
>  bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> @@ -1790,6 +1790,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>                 __kcsan_check_access(x, s->object_size,
>                                      KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>
> +       if (kfence_free(kasan_reset_tag(x)))
> +               return false;
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_free and initialization memset's must be
> @@ -1819,22 +1822,25 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>         void *object;
>         void *next = *head;
>         void *old_tail = *tail;
> +       bool init;
>
>         if (is_kfence_address(next)) {
>                 slab_free_hook(s, next, false);
> -               return true;
> +               return false;
>         }
>
>         /* Head and tail of the reconstructed freelist */
>         *head = NULL;
>         *tail = NULL;
>
> +       init = slab_want_init_on_free(s);
> +
>         do {
>                 object = next;
>                 next = get_freepointer(s, object);
>
>                 /* If object's reuse doesn't have to be delayed */
> -               if (slab_free_hook(s, object, slab_want_init_on_free(s))) {
> +               if (slab_free_hook(s, object, init)) {
>                         /* Move object to the new freelist */
>                         set_freepointer(s, object, *head);
>                         *head = object;
> @@ -3619,9 +3625,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
>
>         stat(s, FREE_SLOWPATH);
>
> -       if (kfence_free(head))
> -               return;
> -
>         if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>                 free_to_partial_list(s, slab, head, tail, cnt, addr);
>                 return;
> @@ -3806,13 +3809,9 @@ static __fastpath_inline
>  void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>                unsigned long addr)
>  {
> -       bool init;
> -
>         memcg_slab_free_hook(s, slab, &object, 1);
>
> -       init = !is_kfence_address(object) && slab_want_init_on_free(s);
> -
> -       if (likely(slab_free_hook(s, object, init)))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
>                 do_slab_free(s, slab, object, object, 1, addr);
>  }
>
>
> --
> 2.43.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-RCZEzU8tLsUVGLtuDgXMRjddOW3fj6bEzCw2%2BFSiNg%40mail.gmail.com.
