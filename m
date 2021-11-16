Return-Path: <kasan-dev+bncBDW2JDUY5AORBGXSZ2GAMGQEKA5CSWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id BB039453361
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 14:58:51 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id l3-20020a170902f68300b00142892d0a86sf7735832plg.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 05:58:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637071130; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7MOAEKUO/YCSpovGx/VLy/E5NCg+skfbeARmLKID1Z4IrcEaCaDRwu4glRRxsHp6C
         YMBgC0B3gp+eBfJrita1AZ3HHst3VFgZ2YWnEwvbKSiieWhk00cuJUk/aP/hlYWOPHOc
         y/FjMyETbC1IEXoRzLk5nSAQgHvD0ff80U0MoEMXa0hHeNOP75JF5/56RC64TiUQHkwQ
         Zp/WcCLPO5xPPE7zbwCIIuoUrWLrP5SrmUabZ7NTsA4MAH0F6YAMvdljXVNEadlyg2TG
         y2s1LIWPk3QJlm2ruPld/kAvPBmPFto58ogQxvzShqQ6JITjzJWK004qlRyNFaqY1+1x
         HJCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=mHKMyaOTWGyQY2qCWIzw3wVZP9oM/uvtr3ATvwx43sU=;
        b=TWxtLLv2dtKhvcQYDu6DGrcp1zPhDHs5uW8mJbS2yXfIRjAL3A2BSr1nE5oWe7g1+w
         VBQPj43B4qGiBRcbyPMV1zoKYTvxVKA4GcMAIWt0G68vYLnjVsUbXmt4nE39NLS6+eKj
         7yWRYIQUAfSgc62a89UY0pAYn77a6OMk15GpYzuh/e6DCcLlErrW1m1aNzkYIqILDETQ
         jfrO+tXQ/wUs7Lj/wrytPR/Fipp0nX50tw0DhY424/318YhAkGfLB0drnQM10yjikyvR
         oZI/5f8f+w1ESSiGgPCvwj3GzKiNDWzV8sSbGbK7rOWh+RDPSTpv7INAv8uNpDjOru71
         X0Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YhQGez7Z;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mHKMyaOTWGyQY2qCWIzw3wVZP9oM/uvtr3ATvwx43sU=;
        b=iHQU4Dvrz+3BsEAQ50iIO5gq9ksLjG83uLAta74Or8YnAsweuNHJS6k7Rc074Q0YTu
         NauNFwlI21oThIgsISuakmAp2vx6DBIyV6jpz5Xhxf+2upcDgCXmHywfoVR0Ahs/LSDe
         Z2oeDsCEy7GLoRr/FOXm0sVD4cQ568G6+3HAbN6mpZULhCR88buuilApVMV5g6jnOx73
         n9Rkim+a/AGheRLPnkjU2+LLY9bv8Tn368g3T/ohzDP/wMVcPMaErEVvzWYzooqipD4y
         foL6JRQdnlYDcTnNlfkOieP8L4BY9mejyBYN02EUjDSvqe0Cr3lZbzQikOW/LsS0P3ng
         me5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mHKMyaOTWGyQY2qCWIzw3wVZP9oM/uvtr3ATvwx43sU=;
        b=Y8KquAFaxAg09IdLhaHU5wCNPiVjoEe+8boR95WB0nmQhhLQQy2DdlkiFGoRczxr8x
         hWwkqhQZaZmcF26ZchRnLzB0R6+QDhfVXDNCQ4K0qf4MZpju87J+LBE7IJqbJfGQgH3F
         Z/in/Q/GyZKcUGvsr0m7g4c9tycUdXXXYO7wBMqk2yLhKeZO7GRZzqqgT+jICpoEtdxE
         TahzxkFh3MFTgX+Cq73lhVhqrbFgxktzcUB5BYgD0HSjkdxnjjkVa8E9D4r0J8KIoowB
         Tn1A4jl2Q1M5YWa1xYsJE6mILu7pzGayh5vCnB2LOfEa62ylYFC2Qgj7L0ahvf5/taRD
         TTqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mHKMyaOTWGyQY2qCWIzw3wVZP9oM/uvtr3ATvwx43sU=;
        b=oaE7P15VnhKHUKkfcSjxeh9+FE+cencSoaEpx4F7VozL7yHGrQyQFlM3h7AMooPaNH
         08EEOKnkHboTwziAyAHed3RANmiSsHXbQAcUqa+HN6BFMn3EZ0KKypL4rXfyiUPIbBHa
         ZiynqOG9Wayu2pUPAjIvI9qEGTOsTe+rBD/W6YFK4myNvj/sIqSQw8dXay5eXnmv7tjX
         +hd4INz1UnZVlvkhme5uYWL+10kw4wdXhIl3tFLSCwq8y6Cu1JZ9gkzVeR1rBh0vHguz
         Qiil7P/vg5FOzxaxJ3ha20pkoh8NAS/axcgj+UPb7D43C23BXSdJBqUlMTU+sF3oYQcO
         uvhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533qBrCUE+zHkstJrHHl07a571c3nacc9ITKA8N1QumSjBrpf2c3
	0hWy7cJrJSKGOkvDJLNv750=
X-Google-Smtp-Source: ABdhPJylipx0QKPSDDnb90GRfbycZsXcDT7pemYhUu90gvadT+pdqL9v+zBbtarzlSkaAjTv7dw+pw==
X-Received: by 2002:a17:90b:1e45:: with SMTP id pi5mr77226712pjb.146.1637071130100;
        Tue, 16 Nov 2021 05:58:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5d0:: with SMTP id u16ls11363905plf.0.gmail; Tue,
 16 Nov 2021 05:58:49 -0800 (PST)
X-Received: by 2002:a17:90a:1913:: with SMTP id 19mr76121656pjg.174.1637071129538;
        Tue, 16 Nov 2021 05:58:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637071129; cv=none;
        d=google.com; s=arc-20160816;
        b=EqeEXQ+3uQAtdG8wPSpAP+RPfeCL+Sx8xyDk1Z2SEUzq73cKP/iXDvkqgJlt9bk6vK
         Vi/l1xdeqi1np86Ki4rVB6YJR7txYR+82FaweA6LsbrqcjtONsmhuwQZhutAEIXqzIcP
         2dPW3Me43prvmJrauxzAcNeUQKo0WnXlucE6Vsgq1SvEUEagiZ4Orkw/ZbxlCXVZq/aK
         JEr5tDo/Tbn6J/5pVNTuVMbxc9iHUf1eLjI2ovZlcQRbZKZZ+3oG6YIUCaUg8vzBzm89
         BMryjYpalifs79kQJxpVHWgtdJjg30ju3HgP/eo3XxyUxhs6WZroioI5ltIhAHLDWnmc
         C7Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qqHRd5/kP7nubr/AolAWBPrvtHO20YsmQv6P748g4qo=;
        b=gYm6uPMdWIOBwIFFPsJ+k+YtSWCj6avcWNhfPKErxF1pzMUxqeejhQCUp1Vjzr5Nr3
         NeSIUHj+6PspB2JX4Yuf9tSAngDjgVAl0YtKhbN3cQhUNjWCEypPAnSK/8PIk9jFenxf
         XFjyLNt9gaCOBE3f9iG++1lznnp08n+cQPDRzbYnUO518aOHI3OjzigCL+B3YN4rvtlc
         prxyM6VOQN7IIMoiwvTfdgrCh4icmf0ErrdbYLRqSwHGstQNZbjVioBT6zh7os47thal
         s9ycwDTwjp0sHUywkLFO6eEK/5nyhdlG4ZXERlrIG71s3lcoextMHioSzdYEEbnWyHdP
         zb1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YhQGez7Z;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id y2si410460pjp.2.2021.11.16.05.58.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 05:58:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id e144so26182501iof.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 05:58:49 -0800 (PST)
X-Received: by 2002:a02:ceb9:: with SMTP id z25mr5646891jaq.121.1637071129010;
 Tue, 16 Nov 2021 05:58:49 -0800 (PST)
MIME-Version: 1.0
References: <20211116001628.24216-1-vbabka@suse.cz> <20211116001628.24216-25-vbabka@suse.cz>
In-Reply-To: <20211116001628.24216-25-vbabka@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 16 Nov 2021 14:58:38 +0100
Message-ID: <CA+fCnZfJTbx7rp7gaRYPt5m_fQtJkVCpviDB2KpO_Qmhk_MmaQ@mail.gmail.com>
Subject: Re: [RFC PATCH 24/32] mm/kasan: Convert to struct slab
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Linux Memory Management List <linux-mm@kvack.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YhQGez7Z;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c
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

On Tue, Nov 16, 2021 at 1:16 AM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> From: "Matthew Wilcox (Oracle)" <willy@infradead.org>
>
> KASAN accesses some slab related struct page fields so we need to convert it
> to struct slab. Some places are a bit simplified thanks to kasan_addr_to_slab()
> encapsulating the PageSlab flag check through virt_to_slab().
>
> [ vbabka@suse.cz: adjust to differences in previous patches ]
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
>  mm/kasan/common.c      | 21 +++++++++++----------
>  mm/kasan/generic.c     |  8 ++++----
>  mm/kasan/kasan.h       |  1 +
>  mm/kasan/quarantine.c  |  2 +-
>  mm/kasan/report.c      | 12 ++++++++++--
>  mm/kasan/report_tags.c | 10 +++++-----
>  mm/slab.c              |  2 +-
>  mm/slub.c              |  2 +-
>  9 files changed, 39 insertions(+), 28 deletions(-)
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
> index 6a1cd2d38bff..f0091112a381 100644
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
> +       folio = page_folio(virt_to_page(ptr));

This is a bit confusing: the series, and this patch in particular, is
supposedly about adding struct slab, but here struct folio suddenly
appears. It makes sense to adjust the patch description.

Also, perhaps a virt_to_folio() helper would be handy to replace
virt_to_head_page()?

>
>         /*
>          * Even though this function is only called for kmem_cache_alloc and
> @@ -411,12 +412,12 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
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
> +               ____kasan_slab_free(folio_slab(folio)->slab_cache, ptr, ip, false, false);
>         }
>  }
>
> @@ -560,7 +561,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>
>  void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
>  {
> -       struct page *page;
> +       struct slab *slab;
>
>         if (unlikely(object == ZERO_SIZE_PTR))
>                 return (void *)object;
> @@ -572,13 +573,13 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
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
> index e00999dc6499..7df696c0422c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -149,6 +149,13 @@ struct page *kasan_addr_to_page(const void *addr)
>                 return virt_to_head_page(addr);
>         return NULL;
>  }

Please add a line between the functions.


> +struct slab *kasan_addr_to_slab(const void *addr)
> +{
> +       if ((addr >= (void *)PAGE_OFFSET) &&
> +                       (addr < high_memory))
> +               return virt_to_slab(addr);
> +       return NULL;
> +}
>
>  static void describe_object_addr(struct kmem_cache *cache, void *object,
>                                 const void *addr)
> @@ -248,8 +255,9 @@ static void print_address_description(void *addr, u8 tag)
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
> index adf688d2da64..5aa601c5756a 100644
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
> index 981e40a88bab..1ff3fa2ab528 100644
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfJTbx7rp7gaRYPt5m_fQtJkVCpviDB2KpO_Qmhk_MmaQ%40mail.gmail.com.
