Return-Path: <kasan-dev+bncBDW2JDUY5AORBIFM52NQMGQEJ5VVQWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F9916327A0
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 16:15:46 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id f12-20020a170902ce8c00b0018928092ec9sf1482837plg.22
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 07:15:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669043745; cv=pass;
        d=google.com; s=arc-20160816;
        b=cl8/QrIy8/zTWbh4T9pSBugPknPBkV/Eqy7NcFZ/c3H6lqBKZ3X/mNsE4L/0QJxC/1
         O8+y7qa3DTOu01bc2XU8QG7srU4nsU43bqauFct3oBHKDVf/7XW1Fcv/rVpRksQ/tjFw
         9rh1BcuCGkt2Tu7g+x/T0hlAPGPfjrOpBlXcCh/BMd1/41NEbnbQttG5iJXr4Nk55oTb
         33MwH8MimV9xzyDqiLJTfI6ZEZPeClbE9li4g+j0mWDiDqF7bN/iQ5aTe+etdYc562TS
         kXSYIIJVDf7qzcFQ1yoq3haGcpvl++PrZuIaEE0j3z9pFzY1kZDw3DdO6vTFhfEO5Rxx
         SrQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=W6Al67zma72yVzRMX3AN+OBqyNm287bZurm2vHA2VU8=;
        b=ZQ1b0U+QkJEgt5y4o8S+aDfy7lW3Nxj473EY26ib/IKdZN6i+LGp28J3FkqfgSc6ps
         Bri6KKO4uzZiN54v4GyZ5CGdAoob7x5p7h8BlN9S9S04yP6JL75VVRsSyJZxcBEwFNqB
         wMQXhFlYoILtel4nqHH9W+pyO9PiwpHMY5IV2qGPeljDvTn8hvMEn3L/XMmWuQAm+HdH
         QrPYUXY27pNPNFqsYykqsQQkZnTfpCZSK53XrLB1okpmkXNhhQyazlNNC2MbjrPKjIJp
         YJEGQ4L97U43kDkdAjs3q1mM/t8S7nC1M2N4BegROPLFPGe18QCRmK6CK6P4Z3EuYsRQ
         DNqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RFEzHslJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W6Al67zma72yVzRMX3AN+OBqyNm287bZurm2vHA2VU8=;
        b=EysY5HrlyZwqyS4+oE6yBrQc+zBDjCAfISMkkm1yvxqvJlnEMJNHChQEVNy5W3Qdeo
         dBmKm2K4+aBEhTnrmzb1GFAgoPb7i+JIEa40xPhs/9luJWtzI6Ml7gIJDLkl8MNFyvNJ
         FH37SEiomhzBIQgefQDPRNoKrpa2gBjqiLcPT9W30x5iI4TFxobp0fAjY56tSjBFLj4f
         LweFUxe2X5jmPIn86jYf+lZtkVr7wKR9cJG+YX5/0WeLYnbOoBhD37BgI2xhHm+8moGW
         oL09SaZl2Fx3nd8uxlBMGVICxVS7+jfEDI8E3PGpWLxtws6/Pk9g38NrITujngPnHQE1
         87ig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=W6Al67zma72yVzRMX3AN+OBqyNm287bZurm2vHA2VU8=;
        b=aO97T200ojPITDKI7QrUzuiwohCSppksnJRGAjuF7678+xbN/wwowTHuvBKudkQ+Zx
         VvNi3eM0hB8uMenszu7gB95BcTB+IQjFbpvtDF8qn2C4j+wz3tPqkKgOwx2cc6mgxBMo
         itWB12TliIYcJ07aXIrtxZexmvWWseV/WFhGx8WPG+ALLg4K5uBWTtSO8KtX/Jie71Cf
         xErbiJQ+1cjvP9DvluPqny6U2QPBXP62FIusu7nIwVKdsvXOmdxKEDnBnox3gLK5RTUz
         98pbWOvyMduesuG3tBreKxkxVmLDgfFnCkXsQTqiy2FcvGCHndq/2l1+T7pP8M5wr+zE
         zBKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W6Al67zma72yVzRMX3AN+OBqyNm287bZurm2vHA2VU8=;
        b=KSI0in2b0AuO4rsSJIFoop+HVjo7npjfy0r5Lx8d/T4h3twYKLJbn68NI8+lFCMl4I
         kwlC9tgwnUwCCA5Fp/OgDsIuWBSqCmMeiFWMhM96757UTH6+58D6oBJYA6SOkk2Pomz3
         n1sWiUEYEk1Xi2b4QQTl1NmPIuZZDUUVpXLLwVmNXBas3ibCjlMhC535aBvPW+O1rtux
         fnUL/Spbvuwo/iErEFMgdYB1ppZ5sVh/Nh4eE3nJ1yTGMbd71wYsY+O6mJou4MHFXHtv
         eCA/qUEgz0DBtsvWz11UZ8Rx4XQveIZkHRqvJLRruQpeCFnW3WAwVFsxGCnpnQJ4FM00
         HnJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmcLt6yIXVV4VpqcyG2B/4kv9yOfvvd21oc/aYI7b8Enxh/wZ4K
	//BdaO4+WpGii9eDKKJZ2zk=
X-Google-Smtp-Source: AA0mqf7Xv2SLbI23V53q90V9OUtmwo/HuvAM9rvOnTTMXOgeJ2PJIapqYLRhHJekRD9jlA1+qweBCg==
X-Received: by 2002:a17:903:44e:b0:176:a9d6:ed53 with SMTP id iw14-20020a170903044e00b00176a9d6ed53mr18524plb.5.1669043744801;
        Mon, 21 Nov 2022 07:15:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2014:b0:186:9fc5:6c01 with SMTP id
 s20-20020a170903201400b001869fc56c01ls5666508pla.6.-pod-prod-gmail; Mon, 21
 Nov 2022 07:15:44 -0800 (PST)
X-Received: by 2002:a17:902:b691:b0:188:5240:50ec with SMTP id c17-20020a170902b69100b00188524050ecmr7644799pls.168.1669043744056;
        Mon, 21 Nov 2022 07:15:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669043744; cv=none;
        d=google.com; s=arc-20160816;
        b=wTCc3SniT+DCuGm0M8v4oeaTAdOQxLZKXx6aRTJmx/YOwtYq7dU2DY0wbXjS7B/jgW
         l8d9fr+qu/6spxphqsBhwEE4Mlv05LxorKK7Ph9HyKqt/tqTU+I/yh7RKyhfOqfTYu1o
         ioFEisNHz7j0ahnbLNyJN+ed3TrGM1BJLgM7U1LXJwLU8tpXfprOqC+qRwp7Rm7rYRYw
         8wLEthfiyTnI3E5vY3oswiPpJcvui+sm1l6ybDzaFVZ28SVabi+be9WybAAoJsj/ltzk
         Oej8Zvb3XTJ0h5U+wdC6estR3CJbZlsSKaKBZPsfUqN3B9qcILi8PWu7tC9WFS2bgWhF
         1Jaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j4iomL/SuFm2qP/FaY1uaLFvnC19GQTDr6IrFZRdHZA=;
        b=tq4vu2vFQ8xqUAGILwnciZwd8YXr/OekKw5cyfSYADrSKpOfi++rJ+WCf99HjvCNGP
         +dVuCysbvoSToXyFNdEd0lJ52RkG+TuuIiV6bRV1RP6mkyUHp0Lw06FpNHxSjYzO0a7N
         zdx0dgG0cS1qKgBRlnzBLXFckVt9EiOP26Pn2VTL1THCTaSxTKx6qfs+9/F0eyT3xknC
         oB7LT9mYzPmwd54akbS2Ed01t6XHTWUVxHU5aOMjnH/udmN+XY8Z+KOYLDD9a2sVpD99
         oMXQC10QshrtNrwrMXuJsoq3qTSkEcJA8HhW0IeWvttFpvH5GHcjdE/QMjVjy1NYVg6b
         L1bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RFEzHslJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id p16-20020a170902e75000b00188c5696675si683631plf.6.2022.11.21.07.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Nov 2022 07:15:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id v3-20020a17090ac90300b00218441ac0f6so13370482pjt.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Nov 2022 07:15:44 -0800 (PST)
X-Received: by 2002:a17:90a:5883:b0:218:f84:3f98 with SMTP id
 j3-20020a17090a588300b002180f843f98mr27389810pji.238.1669043743578; Mon, 21
 Nov 2022 07:15:43 -0800 (PST)
MIME-Version: 1.0
References: <20221121135024.1655240-1-feng.tang@intel.com> <20221121135024.1655240-2-feng.tang@intel.com>
In-Reply-To: <20221121135024.1655240-2-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 21 Nov 2022 16:15:32 +0100
Message-ID: <CA+fCnZenKqb9_a2e5b25-DQ3uAKPgm=+tTDOP+D9c6wbDSjMNA@mail.gmail.com>
Subject: Re: [PATCH -next 2/2] mm/kasan: simplify is_kmalloc check
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RFEzHslJ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Nov 21, 2022 at 2:53 PM Feng Tang <feng.tang@intel.com> wrote:
>
> Use new is_kmalloc_cache() to simplify the code of checking whether
> a kmem_cache is a kmalloc cache.
>
> Signed-off-by: Feng Tang <feng.tang@intel.com>

Hi Feng,

Nice simplification!

> ---
>  include/linux/kasan.h | 9 ---------
>  mm/kasan/common.c     | 9 ++-------
>  mm/slab_common.c      | 1 -
>  3 files changed, 2 insertions(+), 17 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dff604912687..fc46f5d6f404 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -102,7 +102,6 @@ struct kasan_cache {
>         int alloc_meta_offset;
>         int free_meta_offset;
>  #endif
> -       bool is_kmalloc;
>  };

We can go even further here, and only define the kasan_cache struct
and add the kasan_info field to kmem_cache when CONFIG_KASAN_GENERIC
is enabled.

>
>  void __kasan_unpoison_range(const void *addr, size_t size);
> @@ -129,13 +128,6 @@ static __always_inline bool kasan_unpoison_pages(struct page *page,
>         return false;
>  }
>
> -void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
> -static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
> -{
> -       if (kasan_enabled())
> -               __kasan_cache_create_kmalloc(cache);
> -}
> -
>  void __kasan_poison_slab(struct slab *slab);
>  static __always_inline void kasan_poison_slab(struct slab *slab)
>  {
> @@ -252,7 +244,6 @@ static inline void kasan_poison_pages(struct page *page, unsigned int order,
>                                       bool init) {}
>  static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
>                                         bool init) { return false; }
> -static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
>  static inline void kasan_poison_slab(struct slab *slab) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>                                         void *object) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1f30080a7a4c..f7e0e5067e7a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -122,11 +122,6 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
>                              KASAN_PAGE_FREE, init);
>  }
>
> -void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
> -{
> -       cache->kasan_info.is_kmalloc = true;
> -}
> -
>  void __kasan_poison_slab(struct slab *slab)
>  {
>         struct page *page = slab_page(slab);
> @@ -326,7 +321,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>         kasan_unpoison(tagged_object, cache->object_size, init);
>
>         /* Save alloc info (if possible) for non-kmalloc() allocations. */
> -       if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
> +       if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
>                 kasan_save_alloc_info(cache, tagged_object, flags);
>
>         return tagged_object;
> @@ -372,7 +367,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
>          * Save alloc info (if possible) for kmalloc() allocations.
>          * This also rewrites the alloc info when called from kasan_krealloc().
>          */
> -       if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
> +       if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
>                 kasan_save_alloc_info(cache, (void *)object, flags);
>
>         /* Keep the tag that was set by kasan_slab_alloc(). */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8276022f0da4..a5480d67f391 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -663,7 +663,6 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
>
>         create_boot_cache(s, name, size, flags | SLAB_KMALLOC, useroffset,
>                                                                 usersize);
> -       kasan_cache_create_kmalloc(s);
>         list_add(&s->list, &slab_caches);
>         s->refcount = 1;
>         return s;
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZenKqb9_a2e5b25-DQ3uAKPgm%3D%2BtTDOP%2BD9c6wbDSjMNA%40mail.gmail.com.
