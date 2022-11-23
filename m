Return-Path: <kasan-dev+bncBDW2JDUY5AORBQNW7CNQMGQERBTAXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A45A635ED1
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 14:08:19 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id s187-20020a1ff4c4000000b003b8128789cfsf6047990vkh.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 05:08:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669208898; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQ/zMYb6dp1y5MH71rzycBm4dnwjBRErFaaiQ0JytA7b3R6h+iXyIch/rWqXOGbaDg
         Bxfcj08FZpPQ0O7ytXsxCfJq7OKkEv2D8yA80fNANnuVSg5oxtaKZGoQDsWOz29GD7AF
         gClCtn0uWIcf725uAbQRCKL3gzQM73ng0Hm9OQRpIkr0isQ+75s9eNJ3L7N36U5Lpj/x
         eGk4icm40z6KZXck8wC84l7NtfO/m/n5iJObyp3VZnCsWkIHQv3a16wOE+TuJGHSHoDM
         ifIJi3oLa+ynOBvx+BydkKddHweUlQ5siMpjhpkDSYuHQwXNqcrSEEfv4R27ukom3zbc
         jELQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Cve9nBSvNFC3m853Cnp4l3TqBph7oxqlXjI4VxxtYds=;
        b=VXmVyK8GOJmYMrRm3H6nnBqLXkVCKhW3IGxkx+Cv2LRVmjqGE2aa1Iq6W7F/Zu5nRd
         VdO6UitpwhYORp4ezdkAGXTj+6ZvTSvqi2XKLtf6lY93uxyib+qCkJ3715rzZz1Z3Blj
         8FE2kF5CCku44COCaSTkTMNPtdgrn5aRQXUQoM6eU8nLa0u4FeFe17Yh3kYdsPXgrYYw
         SrR19DUoFe5cX+Qo3O+uXbem/VyOphs3CJAxM6EQg3+UXdTa41Jhp5E7CK8i7b0jMQtX
         rhJyO1Re3zXftV67poicnVfw/ZNtpijQv7JWORfFjpcsVwfEYRfGG2xYOeXuTgTvdChh
         YiGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PlqoSWMc;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cve9nBSvNFC3m853Cnp4l3TqBph7oxqlXjI4VxxtYds=;
        b=YaeZZhnRToRAbgSIhzm5uhpo6eUSYnVaWHyJ+n9CgYAhnosVC5gurMHVxbHWsrvNAQ
         SwiK70xLSAtn8QtBAlFuG5lTElJUG8HWQvmPwfKH9Lw1EGR6tA0vKBEY/L2oMWnmonNb
         HXI/HP8M37yZYzrwBnh5msZDnpXznyWIlUHIrnA8oUPLuCvERP1BUtBuQQLl15LmJc4T
         BgWzZXTWsKivXxksz3dH6BYrVBcCC8ye1bm/qn0o4LdhKP8t0jQDUo6ABa1IZa3/kvZy
         hiYfcBi52kOOuwwKxJBkekJvU+Zj7QHo/aloDGAyGxumGLXm9I9j/DG1RVvTgs9AG4GG
         AXhQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=Cve9nBSvNFC3m853Cnp4l3TqBph7oxqlXjI4VxxtYds=;
        b=aWV2XRFfu6kLy3gyB5tuihlFMM0gOp9xymIqBwd+JpBVy/XyAkBEAVQamBNUtsOMQb
         Y18CN7J3FyE0e4xCHBrZWFbjhgzNn1UQ/7CIh9VdtQ2pFG3pDIcQ2Nu8rvdMuz+qOKfY
         Pu1YO62y5/9sGmx+0lMCEAx/9ZRL5ZYx63Ya1sm0OCsK4Y7edqGBWMJdyYMbmNkvMx3S
         D+a7OBZoFVrGYIXmTLq3wJ6Eh+oFbbTeSvrSvsDYwAnRLhID9oLaEpmRBevan2tjiY7H
         vKLoaCxTsPN4BQG9tQZJuOEKMV8TuRDMe7Wgo2uFqURZSLWrrkYGrnV8bIOCLmVgCVqS
         CObA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cve9nBSvNFC3m853Cnp4l3TqBph7oxqlXjI4VxxtYds=;
        b=zlISP72M5xoS8YQy17OFSN7vj8FhU4Jca2nCgIA5dP3rWNfSuvq9aaOx0QzRJ9JZhl
         3A1eHuvO/aJAKfTHUU4rWqRxEPOZUZKOjn7786DXtVvJdc7ri8fomBGn6xiSKlLLnKwY
         55vyYhyUYWNJumf1rw+Qd4fMgHdWmhq/XYZURXld8AcfKqF6rV3DIykX6bipx5gy6afe
         0gX1PWwOpavrDJhZ5Kb0vpz/GctsraRtqbpliGv9V9tjupLTx1HopDOHjnQSGh5Vs2ML
         PMkBRl7PHdfVu4pIg1Gx830+RQhdR13otFfUfYDipz+SmZW4vHIbhVyCmHDjHjd3i3vQ
         BA1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk0WrEOvTagtTGJs+UfD07OlZ36D28bL0lVJFPrgDRNXSck49GZ
	f5yTyfk4yLp4irbT9pXKwEA=
X-Google-Smtp-Source: AA0mqf6fjlQwBlFtCPGVJsHhMS4MXLHQYasJCN/tqY+d34JU+9RSRyixIoosixVeU+uJwE45GWQB1g==
X-Received: by 2002:ab0:718a:0:b0:3d8:3b97:162e with SMTP id l10-20020ab0718a000000b003d83b97162emr6478572uao.118.1669208898019;
        Wed, 23 Nov 2022 05:08:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9dcd:0:b0:3aa:d905:adbb with SMTP id g196-20020a1f9dcd000000b003aad905adbbls1898924vke.5.-pod-prod-gmail;
 Wed, 23 Nov 2022 05:08:17 -0800 (PST)
X-Received: by 2002:a05:6122:b6d:b0:3b8:53e6:6ad0 with SMTP id h13-20020a0561220b6d00b003b853e66ad0mr5543902vkf.41.1669208897425;
        Wed, 23 Nov 2022 05:08:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669208897; cv=none;
        d=google.com; s=arc-20160816;
        b=SZmo+YC1hRONygnsEopG7s3OsB8Id4By4q3s965TCHG6gUYZ/j24mUxIQadOmfuGdi
         oz38sPd+PK6FZzPlcOX0IK9G+/AXxknt23G5wGB0YirX2yBdw1OJFaejqtHrGuVL6rV+
         D7JWPautg2NGutk2uf1fgEhsco4+cs8zVheeyWOm7vfUN1+MTjb67woF07EguTL64Imb
         49DWsu4WYBsn50Z7QYdhAiGhDJPS/L1W19Hldri3WIitxyn/PBCS68L2nVHzswXUBcMG
         erVyAAJxJ14IzvnySNxuG5jz/d8077MdRDrLqWKfxvpy8C61OAImh/8d8pG07Mq9rOkR
         IThg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xWi6mZ6IeIfeEPlOxAtZAyKjM4+f66dl3p7cvZ+Vbjw=;
        b=xG+3KGxcdlSYRGAGB4Hg9ft0AWhZt2rSGA+gbvDo12oroSm8sG1BNcwEcJGou1fPR8
         +YhZh35wuitceeoT2ynmZzQ2O7JggaHeCvIp5UT8HWx0mdYzawv3jRw0iAYR3mpb2dn7
         aPdVh6Ij0KLVO4n+PvOqYJaalEIlj/XGhPcjIOQPvMhwY2HKp2ET3PdlpbV4Eya4id4/
         mLD/3h6wCAc1KeImKh16qfQcmMHd4GVyJw0EP/z5wyiKn7Y+kwNVsCkk/AiuGCGm3YLe
         fEgLCfKAB0qCMgXjSyq/TkecOo6+sAfFVvqSWgEwKYaGeYAaHRi9V14s2kqCR/7yR2yN
         fwlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PlqoSWMc;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id a13-20020ab03c8d000000b0040ac33271e7si2549188uax.2.2022.11.23.05.08.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Nov 2022 05:08:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id w23so16554235ply.12
        for <kasan-dev@googlegroups.com>; Wed, 23 Nov 2022 05:08:17 -0800 (PST)
X-Received: by 2002:a17:90a:fc7:b0:218:aefe:60e3 with SMTP id
 65-20020a17090a0fc700b00218aefe60e3mr15715903pjz.47.1669208896980; Wed, 23
 Nov 2022 05:08:16 -0800 (PST)
MIME-Version: 1.0
References: <20221123123159.2325763-1-feng.tang@intel.com> <20221123123159.2325763-2-feng.tang@intel.com>
In-Reply-To: <20221123123159.2325763-2-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 23 Nov 2022 14:08:05 +0100
Message-ID: <CA+fCnZdCvsk-PST__zFrH0h1QNVYATEUAdLkq7WJpN-NXYj6EA@mail.gmail.com>
Subject: Re: [PATCH v2 -next 2/2] mm/kasan: simplify and refine kasan_cache code
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
 header.i=@gmail.com header.s=20210112 header.b=PlqoSWMc;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c
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

On Wed, Nov 23, 2022 at 1:35 PM Feng Tang <feng.tang@intel.com> wrote:
>
> struct 'kasan_cache' has a member 'is_kmalloc' indicating whether
> its host kmem_cache is a kmalloc cache. With newly introduced
> is_kmalloc_cache() helper, 'is_kmalloc' and its related function can
> be replaced and removed.
>
> Also 'kasan_cache' is only needed by KASAN generic mode, and not by
> SW/HW tag modes, so refine its protection macro accordingly, suggested
> by Andrey Konoval.
>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
> Changlog:
>
>   Since v1
>   * Use CONFIG_KASAN_GENERIC instead of CONFIG_KASAN for 'kasan_cache',
>     as suggested by Andrey Konovalov
>
>  include/linux/kasan.h    | 22 +++++-----------------
>  include/linux/slab_def.h |  2 +-
>  include/linux/slub_def.h |  2 +-
>  mm/kasan/common.c        |  9 ++-------
>  mm/slab_common.c         |  1 -
>  5 files changed, 9 insertions(+), 27 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dff604912687..0ff382f79f80 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -96,15 +96,6 @@ static inline bool kasan_has_integrated_init(void)
>  }
>
>  #ifdef CONFIG_KASAN
> -
> -struct kasan_cache {
> -#ifdef CONFIG_KASAN_GENERIC
> -       int alloc_meta_offset;
> -       int free_meta_offset;
> -#endif
> -       bool is_kmalloc;
> -};
> -
>  void __kasan_unpoison_range(const void *addr, size_t size);
>  static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
>  {
> @@ -129,13 +120,6 @@ static __always_inline bool kasan_unpoison_pages(struct page *page,
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
> @@ -252,7 +236,6 @@ static inline void kasan_poison_pages(struct page *page, unsigned int order,
>                                       bool init) {}
>  static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
>                                         bool init) { return false; }
> -static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
>  static inline void kasan_poison_slab(struct slab *slab) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>                                         void *object) {}
> @@ -303,6 +286,11 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
>
>  #ifdef CONFIG_KASAN_GENERIC
>
> +struct kasan_cache {
> +       int alloc_meta_offset;
> +       int free_meta_offset;
> +};
> +
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
>  slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
> index f0ffad6a3365..39f7f1f95de2 100644
> --- a/include/linux/slab_def.h
> +++ b/include/linux/slab_def.h
> @@ -72,7 +72,7 @@ struct kmem_cache {
>         int obj_offset;
>  #endif /* CONFIG_DEBUG_SLAB */
>
> -#ifdef CONFIG_KASAN
> +#ifdef CONFIG_KASAN_GENERIC
>         struct kasan_cache kasan_info;
>  #endif
>
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> index f9c68a9dac04..4e7cdada4bbb 100644
> --- a/include/linux/slub_def.h
> +++ b/include/linux/slub_def.h
> @@ -132,7 +132,7 @@ struct kmem_cache {
>         unsigned int *random_seq;
>  #endif
>
> -#ifdef CONFIG_KASAN
> +#ifdef CONFIG_KASAN_GENERIC
>         struct kasan_cache kasan_info;
>  #endif
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1f30080a7a4c..6e265beefc27 100644
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
> +       if (kasan_stack_collection_enabled() && !is_kmalloc_cache(cache))
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdCvsk-PST__zFrH0h1QNVYATEUAdLkq7WJpN-NXYj6EA%40mail.gmail.com.
