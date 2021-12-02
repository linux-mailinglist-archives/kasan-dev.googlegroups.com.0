Return-Path: <kasan-dev+bncBDW2JDUY5AORBDP7UOGQMGQEN6UF7CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id F0E354668F5
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 18:17:02 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id r199-20020a6b2bd0000000b005e234972ddfsf131605ior.23
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 09:17:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638465422; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wye+jjsNFmvMiVcXR/aZ7DLuqWk8my7t8mOb13QZ82DCxlq/1jP26j/GTZgQDt+EGv
         3qVWKsbJQPXSVETcZLOWl6StYfUpisoZH1GF1DegYLip/B3eHiGovCdcnzG2V53IILx8
         oMhH2Nsqfj6b5TLef+U4BppQkM94VddWw+nVatZVG1kBWquiXugNkEcVQcj1pmr+iZeN
         cp89HV1EXrddbTmPFwy6fSm4vGqp4K2nd6TrzeYQNAAicZArfwQTvy52IED4cXfuQDP6
         m9HZ1V6MFnYF9kOJwwJW0osxQOho9TtsFkIb9w9E4zzMzU943ygorOKRP3b/GBT+81R6
         JDUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=CfcJtpIB21G78HBPiK/Ast8Tyus917yI2QpZ9kdEQog=;
        b=iSQDQ4bBihB/GyGUbOH+664c6nr/ljaTQNcm69Cz3uCFi7AI+C37Cs0B5ZG3PZC+mk
         ihmQb7RKxdVc/uwGr6gWobJdzq54au11o/n2p0myt3jrQ97sC7EkOfilQGqk6t0X/NWN
         pDXe9pTBLO2jqcG61ta7HXCgEQ7BrKvIN96kmPe6M8VKhon4D2JOxNnSIR+150QdPJZx
         Us07sEQ35CSP5//6cq7Jgz5h4eV5V4sbv0uYT1sbe7sad049f8YkrGGAfyBxCo6AX949
         IEXL9MmGvCfo9Avt4j7891Kug2ECV4Zduh+XTCVJFbxxbTKgJQX2g6WV6Hr1dK8hqdQ3
         tDvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bFNdUTFd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CfcJtpIB21G78HBPiK/Ast8Tyus917yI2QpZ9kdEQog=;
        b=PHChrwB5H5tPHXWbJk2DdULeUzyODWf6JmPiSIZl+MF7a280Lmt7GLgWwD286LnW4E
         sTUTQntqhwivPknBH920l3hWXZuHbk2rtOikSl2jW3b8VXWOIi++rgTQjZrWglDgcz80
         CQICHyjgkMynRNAydL9ehn3EJn8mL3abWOQTN1WgvqO76gMi3jO5gKiJQ1S1chGPHSX7
         cv7jVOjHGCjAG+PubhsbTxJZb94ou6qU0EBqL39d0c8a2F8kxDTc4AYzbv2v0njZk5YG
         aCM68Zqq+2dpEGcQU6EM22gIed/kdhEiUEKWGsQ1wBFjY5QYoim9DdOgjurivF8uHMNJ
         9NRw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CfcJtpIB21G78HBPiK/Ast8Tyus917yI2QpZ9kdEQog=;
        b=geZlTi8JZx7mjOiG1YFeJri7+vn1UTwACq01Ri7xKzrtBL/pUWUAo/hSBMCqamIcql
         AAy6oLzgnBJ1oNT0wiIP6pdeodMbjmRMggP8PLIAzpB7Sa0OY5keMChiSEELsqJ7QqZP
         UVfzKcQm/hOJsJGLXe5uzW5XsvW2wV4urdoPz/3XHOklQGtJ8YR/h23vGGYDwyhBP8Do
         yuvDnq3BWSSkWJeRAqO2QLJiQysr6CB96W9ilcYe+x8hIFY3qGWKVccm4LshQ/PWGE/G
         mao+JTMhznK9DrgnGIWkrH5deQzimXRiUqteEev530R4ASXixcZxwD7d07wJSuhoTYdi
         K8uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CfcJtpIB21G78HBPiK/Ast8Tyus917yI2QpZ9kdEQog=;
        b=xfDGdoEa71QlESCKFDkbjWyFfcLHtAfkTDFISeeAIhrOoIJ+skgJuo0Uh1ErC2mwJD
         /ToMB++y6K8SV5VYTjFi4+N2Q2X0pMbFphKZvfOU6FJszpWm1Quz0n0PdsZPo3MFYVdd
         mGVEAuyBDLTPhyZUglAh+FRbmoe/wNDdT49QbGKXh5TLGGTTetaY53/gNVlSj5Bwarcb
         2bt1xLxulzaBBH4fSI8cXwmgdBcbnU1xFADfOv5gKmzcaR3cjzbRGVGyrND1IKwc0zcz
         G4ps4IWiGMNrYN5QS/EGxAfNmMnXEC6plISdFnHrWBjN6OdtMN8oN9US7Ugp41V/W83q
         Pm8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531M8KnJFGpGk4OvlpDrwoC9vsnKUMFukWfH5y5S2xMf3hfx0VlS
	2BdKE9Q9iXV0kiYoytfMGi0=
X-Google-Smtp-Source: ABdhPJzhffrfVp0mYdntIt73v4YE2Za8gMyURCVZOgt3HuJ57e2XFz1JqIPKr+C3fqKVcE4EuPJ/hA==
X-Received: by 2002:a05:6602:27c2:: with SMTP id l2mr16252638ios.147.1638465422001;
        Thu, 02 Dec 2021 09:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2188:: with SMTP id j8ls1185922ila.2.gmail; Thu, 02
 Dec 2021 09:17:01 -0800 (PST)
X-Received: by 2002:a92:cda6:: with SMTP id g6mr15695728ild.83.1638465421588;
        Thu, 02 Dec 2021 09:17:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638465421; cv=none;
        d=google.com; s=arc-20160816;
        b=KuWYCbpPSwSEr7OSL5cWWArcHIBezWXBS4i+FP+5gKokwId1dA8FGHvL/4tJtBFQlU
         q6a1iqdUkSZn0E/KM7f6YTO1f4D4JT6bFqWWQGj6I/ygSJ/lkpPhTtJhbrTBSI/NPUW1
         1IzqMWM8IzGweFMjDhQ7Se65v4tgb/uUiUOsloc4myHUfhoAqG88YaJaQ/SvIBUccmhZ
         Oprw0vjJgcs86EmuAAr4F8lNkZQZBHRG2v0l5MOFyFVvq3tC8+hzh1qtcsOvUbVoVv9h
         XrmVjtZbETsmaku6YPFun3x7494mVkKCGuaZib6VbaCS6ZUOFf5+l4TtrGu8dENanFrT
         CYyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+VlhgbxZ//E40UP4VkdcPEO+gAtVu81nLcN2Mja4zCg=;
        b=LRpYcG3JYZ/JtRmsi0JMzOQnja9edhzAymRkbmD6VT8Tx9MPjQAU0VEl2UQNaXHysn
         1c3VoH81XgmhqOBU8RKMeaDZgkoN2W1ev2xbeddaRMBQBIawtr6zOw71/xkCDSIKS4ys
         n7NHOkJ6tnmHMQRq4DdPW8h4ArOtbqPeSLLmiicDrqYKkmsfaaFP3kJKtnZZF63//sxo
         qVS+wWWJOxiAPNbIfNvbmYbEJhYqo3HBFw27iV6aK6Uu+rR/khUYACOa2OBt8mhvSmHy
         iZ9bC7a6I9rYnleksjxY5wG///tIrsDYzSEteBxGBThBA4u5RgvY7868My5gDE7ihVXZ
         CnqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bFNdUTFd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id l7si86478ilh.5.2021.12.02.09.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 09:17:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id x10so327150ioj.9
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 09:17:01 -0800 (PST)
X-Received: by 2002:a5e:d502:: with SMTP id e2mr17468976iom.118.1638465421406;
 Thu, 02 Dec 2021 09:17:01 -0800 (PST)
MIME-Version: 1.0
References: <20211201181510.18784-1-vbabka@suse.cz> <20211201181510.18784-26-vbabka@suse.cz>
In-Reply-To: <20211201181510.18784-26-vbabka@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 2 Dec 2021 18:16:50 +0100
Message-ID: <CA+fCnZd8oD2nEB0C+D73mQqJobaVY_82gnU9Lfu_JydDZ21sQQ@mail.gmail.com>
Subject: Re: [PATCH v2 25/33] mm/kasan: Convert to struct folio and struct slab
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Linux Memory Management List <linux-mm@kvack.org>, 
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=bFNdUTFd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36
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

On Wed, Dec 1, 2021 at 7:15 PM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> From: "Matthew Wilcox (Oracle)" <willy@infradead.org>
>
> KASAN accesses some slab related struct page fields so we need to convert it
> to struct slab. Some places are a bit simplified thanks to kasan_addr_to_slab()
> encapsulating the PageSlab flag check through virt_to_slab().
> When resolving object address to either a real slab or a large kmalloc, use
> struct folio as the intermediate type for testing the slab flag to avoid
> unnecessary implicit compound_head().
>
> [ vbabka@suse.cz: use struct folio, adjust to differences in previous patches ]
>
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: <kasan-dev@googlegroups.com>
> ---
>  include/linux/kasan.h  |  9 +++++----
>  mm/kasan/common.c      | 23 +++++++++++++----------
>  mm/kasan/generic.c     |  8 ++++----
>  mm/kasan/kasan.h       |  1 +
>  mm/kasan/quarantine.c  |  2 +-
>  mm/kasan/report.c      | 13 +++++++++++--
>  mm/kasan/report_tags.c | 10 +++++-----
>  mm/slab.c              |  2 +-
>  mm/slub.c              |  2 +-
>  9 files changed, 42 insertions(+), 28 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d8783b682669..fb78108d694e 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -9,6 +9,7 @@
>
>  struct kmem_cache;
>  struct page;
> +struct slab;
>  struct vm_struct;
>  struct task_struct;
>
> @@ -193,11 +194,11 @@ static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
>         return 0;
>  }
>
> -void __kasan_poison_slab(struct page *page);
> -static __always_inline void kasan_poison_slab(struct page *page)
> +void __kasan_poison_slab(struct slab *slab);
> +static __always_inline void kasan_poison_slab(struct slab *slab)
>  {
>         if (kasan_enabled())
> -               __kasan_poison_slab(page);
> +               __kasan_poison_slab(slab);
>  }
>
>  void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> @@ -322,7 +323,7 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
>                                       slab_flags_t *flags) {}
>  static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> -static inline void kasan_poison_slab(struct page *page) {}
> +static inline void kasan_poison_slab(struct slab *slab) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>                                         void *object) {}
>  static inline void kasan_poison_object_data(struct kmem_cache *cache,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6a1cd2d38bff..7c06db78a76c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -247,8 +247,9 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  }
>  #endif
>
> -void __kasan_poison_slab(struct page *page)
> +void __kasan_poison_slab(struct slab *slab)
>  {
> +       struct page *page = slab_page(slab);
>         unsigned long i;
>
>         for (i = 0; i < compound_nr(page); i++)
> @@ -401,9 +402,9 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
>
>  void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  {
> -       struct page *page;
> +       struct folio *folio;
>
> -       page = virt_to_head_page(ptr);
> +       folio = virt_to_folio(ptr);
>
>         /*
>          * Even though this function is only called for kmem_cache_alloc and
> @@ -411,12 +412,14 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>          * !PageSlab() when the size provided to kmalloc is larger than
>          * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
>          */
> -       if (unlikely(!PageSlab(page))) {
> +       if (unlikely(!folio_test_slab(folio))) {
>                 if (____kasan_kfree_large(ptr, ip))
>                         return;
> -               kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
> +               kasan_poison(ptr, folio_size(folio), KASAN_FREE_PAGE, false);
>         } else {
> -               ____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
> +               struct slab *slab = folio_slab(folio);
> +
> +               ____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
>         }
>  }
>
> @@ -560,7 +563,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>
>  void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
>  {
> -       struct page *page;
> +       struct slab *slab;
>
>         if (unlikely(object == ZERO_SIZE_PTR))
>                 return (void *)object;
> @@ -572,13 +575,13 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>          */
>         kasan_unpoison(object, size, false);
>
> -       page = virt_to_head_page(object);
> +       slab = virt_to_slab(object);
>
>         /* Piggy-back on kmalloc() instrumentation to poison the redzone. */
> -       if (unlikely(!PageSlab(page)))
> +       if (unlikely(!slab))
>                 return __kasan_kmalloc_large(object, size, flags);
>         else
> -               return ____kasan_kmalloc(page->slab_cache, object, size, flags);
> +               return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
>  }
>
>  bool __kasan_check_byte(const void *address, unsigned long ip)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 5d0b79416c4e..a25ad4090615 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -330,16 +330,16 @@ DEFINE_ASAN_SET_SHADOW(f8);
>
>  static void __kasan_record_aux_stack(void *addr, bool can_alloc)
>  {
> -       struct page *page = kasan_addr_to_page(addr);
> +       struct slab *slab = kasan_addr_to_slab(addr);
>         struct kmem_cache *cache;
>         struct kasan_alloc_meta *alloc_meta;
>         void *object;
>
> -       if (is_kfence_address(addr) || !(page && PageSlab(page)))
> +       if (is_kfence_address(addr) || !slab)
>                 return;
>
> -       cache = page->slab_cache;
> -       object = nearest_obj(cache, page_slab(page), addr);
> +       cache = slab->slab_cache;
> +       object = nearest_obj(cache, slab, addr);
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         if (!alloc_meta)
>                 return;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index aebd8df86a1f..c17fa8d26ffe 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -265,6 +265,7 @@ bool kasan_report(unsigned long addr, size_t size,
>  void kasan_report_invalid_free(void *object, unsigned long ip);
>
>  struct page *kasan_addr_to_page(const void *addr);
> +struct slab *kasan_addr_to_slab(const void *addr);
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index d8ccff4c1275..587da8995f2d 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -117,7 +117,7 @@ static unsigned long quarantine_batch_size;
>
>  static struct kmem_cache *qlink_to_cache(struct qlist_node *qlink)
>  {
> -       return virt_to_head_page(qlink)->slab_cache;
> +       return virt_to_slab(qlink)->slab_cache;
>  }
>
>  static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e00999dc6499..3ad9624dcc56 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -150,6 +150,14 @@ struct page *kasan_addr_to_page(const void *addr)
>         return NULL;
>  }
>
> +struct slab *kasan_addr_to_slab(const void *addr)
> +{
> +       if ((addr >= (void *)PAGE_OFFSET) &&
> +                       (addr < high_memory))
> +               return virt_to_slab(addr);
> +       return NULL;
> +}
> +
>  static void describe_object_addr(struct kmem_cache *cache, void *object,
>                                 const void *addr)
>  {
> @@ -248,8 +256,9 @@ static void print_address_description(void *addr, u8 tag)
>         pr_err("\n");
>
>         if (page && PageSlab(page)) {
> -               struct kmem_cache *cache = page->slab_cache;
> -               void *object = nearest_obj(cache, page_slab(page),      addr);
> +               struct slab *slab = page_slab(page);
> +               struct kmem_cache *cache = slab->slab_cache;
> +               void *object = nearest_obj(cache, slab, addr);
>
>                 describe_object(cache, object, addr, tag);
>         }
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 06c21dd77493..1b41de88c53e 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -12,7 +12,7 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
>  #ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
> -       struct page *page;
> +       struct slab *slab;
>         const void *addr;
>         void *object;
>         u8 tag;
> @@ -20,10 +20,10 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
>
>         tag = get_tag(info->access_addr);
>         addr = kasan_reset_tag(info->access_addr);
> -       page = kasan_addr_to_page(addr);
> -       if (page && PageSlab(page)) {
> -               cache = page->slab_cache;
> -               object = nearest_obj(cache, page_slab(page), (void *)addr);
> +       slab = kasan_addr_to_slab(addr);
> +       if (slab) {
> +               cache = slab->slab_cache;
> +               object = nearest_obj(cache, slab, (void *)addr);
>                 alloc_meta = kasan_get_alloc_meta(cache, object);
>
>                 if (alloc_meta) {
> diff --git a/mm/slab.c b/mm/slab.c
> index 785fffd527fe..fed55fa1b7d0 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -2605,7 +2605,7 @@ static struct slab *cache_grow_begin(struct kmem_cache *cachep,
>          * page_address() in the latter returns a non-tagged pointer,
>          * as it should be for slab pages.
>          */
> -       kasan_poison_slab(slab_page(slab));
> +       kasan_poison_slab(slab);
>
>         /* Get slab management. */
>         freelist = alloc_slabmgmt(cachep, slab, offset,
> diff --git a/mm/slub.c b/mm/slub.c
> index 61aaaa662c5e..58f0d499a293 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1961,7 +1961,7 @@ static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
>
>         slab->slab_cache = s;
>
> -       kasan_poison_slab(slab_page(slab));
> +       kasan_poison_slab(slab);
>
>         start = slab_address(slab);
>
> --
> 2.33.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Great job with the overall struct page refactoring!

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd8oD2nEB0C%2BD73mQqJobaVY_82gnU9Lfu_JydDZ21sQQ%40mail.gmail.com.
