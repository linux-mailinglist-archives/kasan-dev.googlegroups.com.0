Return-Path: <kasan-dev+bncBDW2JDUY5AORB6P6UOGQMGQEVIDQGWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 443834668F2
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 18:16:43 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id v67-20020a4a5a46000000b002c9c5da9902sf295656ooa.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 09:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638465402; cv=pass;
        d=google.com; s=arc-20160816;
        b=RximM5u+9xfJIKWCMTnBcpLNRwl6iDsRC7LAdlqKTolLPfSc4c6OImRzTgNE5eP0SS
         ziPKaUpeKyOmCDjYDC0utr0uoPa9tqCpkVplM9iw+IZ+/9W2SpoVeDC5E3zvnOcUjhkc
         Cwulhm6oghDW0oJhqtEHybnTLMI315l4ymGii9M3COT9c7jYxtRHR/GIK3uxuFFD8Gb8
         yTAk9npbHszZyXu4VRqGmFwxxffRg7mB/KV9xq8SLB91Z7TUrGqe2Cl6FcV0jw02JIOY
         +hr5Z/MrAC2ExonBj0iX2tAYONmrqKBKLxeNF7Trv6RscmngDYHTz/I9PjA1C/kxys8Z
         TIeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=WKM3nO81+NEfjyimHEuQx6x2BQwONvHlfoOAWq3vEB4=;
        b=g7/QnrFJFGlTCvDQ/4MBB3AT3RjAsb7HrxmEOofkifnogt+5VBYWVamaHULC73BlwM
         7Ov7Np/mAsNPnKzBFnbItYMT6Ah4W7SgLeVC0UHphMqvjPn4oe/ASba55dKf0XizjdzY
         FEkOto88WFjeuTsMLFoXxydd3Ys2wpJaFbEBlqIcQzgwf9VBrGaQcNx7LSMqdQSKDsG8
         CixSLfeCE0kVy4FGxYMdIA68MODChGetfCCXgR1vUzLrtTcvcPdheGFonLMN8AIgQ/kt
         Ck0M6VvUVLC6rjE5cxP4LylgP5Sc5YD15ujmYw06Al3md9QHwCQes7lYzIKpsWjFj++3
         nfYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UywBNeDh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WKM3nO81+NEfjyimHEuQx6x2BQwONvHlfoOAWq3vEB4=;
        b=rNIddQYXnpv7gp3SYZIme6sG08/b7/kTjZ2qVJ3RQn+hAV8nl2Vwlbe9tLZp4Y9QH3
         k5Q0EaMW0bJLtRqaqzuWH6asIje4/J3hy4d+4KdCmxETIc3HlCQY6/KNpoIU9kVAV+Zu
         dTRtv9f4XX1zcK53HONo59TnChqJYuPZMYNtkOrCIsAQs16wbilW/rk6YXFafNOLl/6v
         ye6T3iKXyHuo1DuZFtmFS28aAJaXalDdPocChlifzdwUFy+aNDCLfForFVBHjXS+hPUX
         G95/BZUfjEYwxDK+4FUatZOQ7mHXk2CG8ByscDKvL50oxAC461BZN7Ect4409yvRuXqy
         yOkQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WKM3nO81+NEfjyimHEuQx6x2BQwONvHlfoOAWq3vEB4=;
        b=qx3JHzkhVJfdK872zNCBt0BqYP/GuetPnD42TSMy7LwuBdmG5rMwTyZSY8lJ+UsZhX
         cpVVnz3vxrf1q9t5bPvQ67a08g9dBdzcZ3zJtPq7wvetniketmuehQTwb/ux+1ZQLi3B
         tlRNyvo+gKnVJ5SMZoSXlOxWnqYO3o7tlLpDfJDZe7WtikFFtTn3gD7AYf5yemlQ2Pv/
         Oo4hm2uO8zyhSKOo9nIAcAGoFyHq9eiabivDdIIIiveY+30hMrvdocmXOuAmIOlggiWr
         QkO8AbdCe9vhW+AvrSuAd6py466Xs/TwdM1nSXaGHWP/F+uboE3/FqESUwMgl+jgKhp6
         p0sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WKM3nO81+NEfjyimHEuQx6x2BQwONvHlfoOAWq3vEB4=;
        b=FcL2LK7LaZRThntSYOCNGvnOJDT1WVQ1OYOGF+X+K6+kgJLR82zrgvaypT0Pi2u3IX
         rbHTi3hGB/L7VfOvK2qeEda5OMBcRn5uTuiboyb6+KB7IAzDSWSZCZCyIqVX/6Yc+rnd
         RQPZIbxzpLJ7bH8EUm3RAeQVgnAA4eT9Aj5aaZqlN2yz28w5MUq5D0dP2u6NFyjDCBM2
         9QphuRXQNoR07r05qtI69WpiB4Z7qC4LUKle8BwY6IriB/yENrHFDnCdk17vZpn32XKy
         yMHB7FdBC37AdSTumqN5yfacFIfpY4GyyJjPvMCLQqp++d+2p5aw8R3dUsA1d4Gi7GsV
         tYPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gOfVJhTXlgpU7hg1YfzVKU2lLQ5B5DoUR36ZSkwYwGaKksEtk
	G9s573XfrK1HYKintLtZdvI=
X-Google-Smtp-Source: ABdhPJwdjCIbedTQznGpqTUDA0nv6z/LMp4XAxUDwk0NsPKZ8pHfS4SrYTfK5oMMGi0VW/cPh8wEiA==
X-Received: by 2002:a05:6808:2205:: with SMTP id bd5mr5391966oib.12.1638465401928;
        Thu, 02 Dec 2021 09:16:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:457:: with SMTP id 81ls2295438otc.5.gmail; Thu, 02 Dec
 2021 09:16:41 -0800 (PST)
X-Received: by 2002:a05:6830:169a:: with SMTP id k26mr12405957otr.64.1638465401530;
        Thu, 02 Dec 2021 09:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638465401; cv=none;
        d=google.com; s=arc-20160816;
        b=vXCRLrMJ03xs22JWD70JfVNsrTZucHjmn2f3dJI2u4g13gS8PhG1Ns6mN3IXUXSdoU
         xuZGevMrVwLXSqTQedRLDT7c2BZ6kMRPXlt1mN9EFS6uJ0H4/DHjjMy+e1SvW/xmp4qn
         OJiZp3Hyx4Wri00WEbzF7Jn43cW4VtzQS6wpGekID1jAFf7zHqPP6OS9d4qwPPIbyUMI
         I5zQyK2ek6VG4K1vD9k1IW/drJxswM9bNC2onC/2l949MLXvZV+4Tm6JaAGVSA2QK+S+
         VcElgijk4KvJxqcRDQyV6F70K5XbWAlntpjcRUTgbbS7SiI0+Z0xZQLs9IN9EsSzEjkX
         NskQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lqxAvKi8tWp1/JO0UH9Z9yhi0w/MGkVjeIMI/FGNOwg=;
        b=p5FC5fUgSSCKGvoGGTnC1Iaa5bs3dXbkdxcKYj4ob8apICoo/EbL0cSWRPl+8QTxno
         dfpzOrD6AHYA9BQsCxW0a3u3IBdEoE8GdgKobeBg4YPS8uVw2lF9qJ57ACQxK7d83XHU
         IW6wfokMk8JzyXhxd6DRVlch0EAYTUbm6hcq3gbXYwDa/5DY3XZTAwvuGAA8p2EjSMlf
         CZN7h3wPJX9lvn3whdv1MPvqYuMjebnbjv+/AvkoiqEdC46zyayNbtM7Xyv+KaxcIjnP
         lnaCCzO2aZyNRXTqxeFVeT6x7ITZP+S8VItoPEIHCe2jv5sAWLLUGtprvWQMdISps/c0
         fwCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UywBNeDh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id s16si18725oiw.4.2021.12.02.09.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 09:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id v23so298181iom.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 09:16:41 -0800 (PST)
X-Received: by 2002:a02:ceb9:: with SMTP id z25mr19762621jaq.121.1638465401268;
 Thu, 02 Dec 2021 09:16:41 -0800 (PST)
MIME-Version: 1.0
References: <20211201181510.18784-1-vbabka@suse.cz> <20211201181510.18784-23-vbabka@suse.cz>
In-Reply-To: <20211201181510.18784-23-vbabka@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 2 Dec 2021 18:16:30 +0100
Message-ID: <CA+fCnZfj4mngOf9roarq6RFQLgkcGhcM1aFMi7OjJek3T4sgYA@mail.gmail.com>
Subject: Re: [PATCH v2 22/33] mm: Convert struct page to struct slab in
 functions used by other subsystems
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Linux Memory Management List <linux-mm@kvack.org>, 
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev, 
	Julia Lawall <julia.lawall@inria.fr>, Luis Chamberlain <mcgrof@kernel.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Vladimir Davydov <vdavydov.dev@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UywBNeDh;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31
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
> KASAN, KFENCE and memcg interact with SLAB or SLUB internals through functions
> nearest_obj(), obj_to_index() and objs_per_slab() that use struct page as
> parameter. This patch converts it to struct slab including all callers, through
> a coccinelle semantic patch.
>
> // Options: --include-headers --no-includes --smpl-spacing include/linux/slab_def.h include/linux/slub_def.h mm/slab.h mm/kasan/*.c mm/kfence/kfence_test.c mm/memcontrol.c mm/slab.c mm/slub.c
> // Note: needs coccinelle 1.1.1 to avoid breaking whitespace
>
> @@
> @@
>
> -objs_per_slab_page(
> +objs_per_slab(
>  ...
>  )
>  { ... }
>
> @@
> @@
>
> -objs_per_slab_page(
> +objs_per_slab(
>  ...
>  )
>
> @@
> identifier fn =~ "obj_to_index|objs_per_slab";
> @@
>
>  fn(...,
> -   const struct page *page
> +   const struct slab *slab
>     ,...)
>  {
> <...
> (
> - page_address(page)
> + slab_address(slab)
> |
> - page
> + slab
> )
> ...>
>  }
>
> @@
> identifier fn =~ "nearest_obj";
> @@
>
>  fn(...,
> -   struct page *page
> +   const struct slab *slab
>     ,...)
>  {
> <...
> (
> - page_address(page)
> + slab_address(slab)
> |
> - page
> + slab
> )
> ...>
>  }
>
> @@
> identifier fn =~ "nearest_obj|obj_to_index|objs_per_slab";
> expression E;
> @@
>
>  fn(...,
> (
> - slab_page(E)
> + E
> |
> - virt_to_page(E)
> + virt_to_slab(E)
> |
> - virt_to_head_page(E)
> + virt_to_slab(E)
> |
> - page
> + page_slab(page)
> )
>   ,...)
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Julia Lawall <julia.lawall@inria.fr>
> Cc: Luis Chamberlain <mcgrof@kernel.org>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Johannes Weiner <hannes@cmpxchg.org>
> Cc: Michal Hocko <mhocko@kernel.org>
> Cc: Vladimir Davydov <vdavydov.dev@gmail.com>
> Cc: <kasan-dev@googlegroups.com>
> Cc: <cgroups@vger.kernel.org>
> ---
>  include/linux/slab_def.h | 16 ++++++++--------
>  include/linux/slub_def.h | 18 +++++++++---------
>  mm/kasan/common.c        |  4 ++--
>  mm/kasan/generic.c       |  2 +-
>  mm/kasan/report.c        |  2 +-
>  mm/kasan/report_tags.c   |  2 +-
>  mm/kfence/kfence_test.c  |  4 ++--
>  mm/memcontrol.c          |  4 ++--
>  mm/slab.c                | 10 +++++-----
>  mm/slab.h                |  4 ++--
>  mm/slub.c                |  2 +-
>  11 files changed, 34 insertions(+), 34 deletions(-)
>
> diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
> index 3aa5e1e73ab6..e24c9aff6fed 100644
> --- a/include/linux/slab_def.h
> +++ b/include/linux/slab_def.h
> @@ -87,11 +87,11 @@ struct kmem_cache {
>         struct kmem_cache_node *node[MAX_NUMNODES];
>  };
>
> -static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
> +static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *slab,
>                                 void *x)
>  {
> -       void *object = x - (x - page->s_mem) % cache->size;
> -       void *last_object = page->s_mem + (cache->num - 1) * cache->size;
> +       void *object = x - (x - slab->s_mem) % cache->size;
> +       void *last_object = slab->s_mem + (cache->num - 1) * cache->size;
>
>         if (unlikely(object > last_object))
>                 return last_object;
> @@ -106,16 +106,16 @@ static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
>   *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
>   */
>  static inline unsigned int obj_to_index(const struct kmem_cache *cache,
> -                                       const struct page *page, void *obj)
> +                                       const struct slab *slab, void *obj)
>  {
> -       u32 offset = (obj - page->s_mem);
> +       u32 offset = (obj - slab->s_mem);
>         return reciprocal_divide(offset, cache->reciprocal_buffer_size);
>  }
>
> -static inline int objs_per_slab_page(const struct kmem_cache *cache,
> -                                    const struct page *page)
> +static inline int objs_per_slab(const struct kmem_cache *cache,
> +                                    const struct slab *slab)
>  {
> -       if (is_kfence_address(page_address(page)))
> +       if (is_kfence_address(slab_address(slab)))
>                 return 1;
>         return cache->num;
>  }
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> index 8a9c2876ca89..33c5c0e3bd8d 100644
> --- a/include/linux/slub_def.h
> +++ b/include/linux/slub_def.h
> @@ -158,11 +158,11 @@ static inline void sysfs_slab_release(struct kmem_cache *s)
>
>  void *fixup_red_left(struct kmem_cache *s, void *p);
>
> -static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
> +static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *slab,
>                                 void *x) {
> -       void *object = x - (x - page_address(page)) % cache->size;
> -       void *last_object = page_address(page) +
> -               (page->objects - 1) * cache->size;
> +       void *object = x - (x - slab_address(slab)) % cache->size;
> +       void *last_object = slab_address(slab) +
> +               (slab->objects - 1) * cache->size;
>         void *result = (unlikely(object > last_object)) ? last_object : object;
>
>         result = fixup_red_left(cache, result);
> @@ -178,16 +178,16 @@ static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
>  }
>
>  static inline unsigned int obj_to_index(const struct kmem_cache *cache,
> -                                       const struct page *page, void *obj)
> +                                       const struct slab *slab, void *obj)
>  {
>         if (is_kfence_address(obj))
>                 return 0;
> -       return __obj_to_index(cache, page_address(page), obj);
> +       return __obj_to_index(cache, slab_address(slab), obj);
>  }
>
> -static inline int objs_per_slab_page(const struct kmem_cache *cache,
> -                                    const struct page *page)
> +static inline int objs_per_slab(const struct kmem_cache *cache,
> +                                    const struct slab *slab)
>  {
> -       return page->objects;
> +       return slab->objects;
>  }
>  #endif /* _LINUX_SLUB_DEF_H */
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8428da2aaf17..6a1cd2d38bff 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -298,7 +298,7 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>         /* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
>  #ifdef CONFIG_SLAB
>         /* For SLAB assign tags based on the object index in the freelist. */
> -       return (u8)obj_to_index(cache, virt_to_head_page(object), (void *)object);
> +       return (u8)obj_to_index(cache, virt_to_slab(object), (void *)object);
>  #else
>         /*
>          * For SLUB assign a random tag during slab creation, otherwise reuse
> @@ -341,7 +341,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>         if (is_kfence_address(object))
>                 return false;
>
> -       if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
> +       if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
>             object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
>                 return true;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 84a038b07c6f..5d0b79416c4e 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -339,7 +339,7 @@ static void __kasan_record_aux_stack(void *addr, bool can_alloc)
>                 return;
>
>         cache = page->slab_cache;
> -       object = nearest_obj(cache, page, addr);
> +       object = nearest_obj(cache, page_slab(page), addr);
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         if (!alloc_meta)
>                 return;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0bc10f452f7e..e00999dc6499 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -249,7 +249,7 @@ static void print_address_description(void *addr, u8 tag)
>
>         if (page && PageSlab(page)) {
>                 struct kmem_cache *cache = page->slab_cache;
> -               void *object = nearest_obj(cache, page, addr);
> +               void *object = nearest_obj(cache, page_slab(page),      addr);
>
>                 describe_object(cache, object, addr, tag);
>         }
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 8a319fc16dab..06c21dd77493 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -23,7 +23,7 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
>         page = kasan_addr_to_page(addr);
>         if (page && PageSlab(page)) {
>                 cache = page->slab_cache;
> -               object = nearest_obj(cache, page, (void *)addr);
> +               object = nearest_obj(cache, page_slab(page), (void *)addr);
>                 alloc_meta = kasan_get_alloc_meta(cache, object);
>
>                 if (alloc_meta) {
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 695030c1fff8..f7276711d7b9 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -291,8 +291,8 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>                          * even for KFENCE objects; these are required so that
>                          * memcg accounting works correctly.
>                          */
> -                       KUNIT_EXPECT_EQ(test, obj_to_index(s, page, alloc), 0U);
> -                       KUNIT_EXPECT_EQ(test, objs_per_slab_page(s, page), 1);
> +                       KUNIT_EXPECT_EQ(test, obj_to_index(s, page_slab(page), alloc), 0U);
> +                       KUNIT_EXPECT_EQ(test, objs_per_slab(s, page_slab(page)), 1);
>
>                         if (policy == ALLOCATE_ANY)
>                                 return alloc;
> diff --git a/mm/memcontrol.c b/mm/memcontrol.c
> index 6863a834ed42..906edbd92436 100644
> --- a/mm/memcontrol.c
> +++ b/mm/memcontrol.c
> @@ -2819,7 +2819,7 @@ static struct mem_cgroup *get_mem_cgroup_from_objcg(struct obj_cgroup *objcg)
>  int memcg_alloc_page_obj_cgroups(struct page *page, struct kmem_cache *s,
>                                  gfp_t gfp, bool new_page)
>  {
> -       unsigned int objects = objs_per_slab_page(s, page);
> +       unsigned int objects = objs_per_slab(s, page_slab(page));
>         unsigned long memcg_data;
>         void *vec;
>
> @@ -2881,7 +2881,7 @@ struct mem_cgroup *mem_cgroup_from_obj(void *p)
>                 struct obj_cgroup *objcg;
>                 unsigned int off;
>
> -               off = obj_to_index(page->slab_cache, page, p);
> +               off = obj_to_index(page->slab_cache, page_slab(page), p);
>                 objcg = page_objcgs(page)[off];
>                 if (objcg)
>                         return obj_cgroup_memcg(objcg);
> diff --git a/mm/slab.c b/mm/slab.c
> index f0447b087d02..785fffd527fe 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -1560,7 +1560,7 @@ static void check_poison_obj(struct kmem_cache *cachep, void *objp)
>                 struct slab *slab = virt_to_slab(objp);
>                 unsigned int objnr;
>
> -               objnr = obj_to_index(cachep, slab_page(slab), objp);
> +               objnr = obj_to_index(cachep, slab, objp);
>                 if (objnr) {
>                         objp = index_to_obj(cachep, slab, objnr - 1);
>                         realobj = (char *)objp + obj_offset(cachep);
> @@ -2530,7 +2530,7 @@ static void *slab_get_obj(struct kmem_cache *cachep, struct slab *slab)
>  static void slab_put_obj(struct kmem_cache *cachep,
>                         struct slab *slab, void *objp)
>  {
> -       unsigned int objnr = obj_to_index(cachep, slab_page(slab), objp);
> +       unsigned int objnr = obj_to_index(cachep, slab, objp);
>  #if DEBUG
>         unsigned int i;
>
> @@ -2717,7 +2717,7 @@ static void *cache_free_debugcheck(struct kmem_cache *cachep, void *objp,
>         if (cachep->flags & SLAB_STORE_USER)
>                 *dbg_userword(cachep, objp) = (void *)caller;
>
> -       objnr = obj_to_index(cachep, slab_page(slab), objp);
> +       objnr = obj_to_index(cachep, slab, objp);
>
>         BUG_ON(objnr >= cachep->num);
>         BUG_ON(objp != index_to_obj(cachep, slab, objnr));
> @@ -3663,7 +3663,7 @@ void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
>         objp = object - obj_offset(cachep);
>         kpp->kp_data_offset = obj_offset(cachep);
>         slab = virt_to_slab(objp);
> -       objnr = obj_to_index(cachep, slab_page(slab), objp);
> +       objnr = obj_to_index(cachep, slab, objp);
>         objp = index_to_obj(cachep, slab, objnr);
>         kpp->kp_objp = objp;
>         if (DEBUG && cachep->flags & SLAB_STORE_USER)
> @@ -4181,7 +4181,7 @@ void __check_heap_object(const void *ptr, unsigned long n,
>
>         /* Find and validate object. */
>         cachep = slab->slab_cache;
> -       objnr = obj_to_index(cachep, slab_page(slab), (void *)ptr);
> +       objnr = obj_to_index(cachep, slab, (void *)ptr);
>         BUG_ON(objnr >= cachep->num);
>
>         /* Find offset within object. */
> diff --git a/mm/slab.h b/mm/slab.h
> index 7376c9d8aa2b..15d109d8ec89 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -483,7 +483,7 @@ static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
>                                 continue;
>                         }
>
> -                       off = obj_to_index(s, page, p[i]);
> +                       off = obj_to_index(s, page_slab(page), p[i]);
>                         obj_cgroup_get(objcg);
>                         page_objcgs(page)[off] = objcg;
>                         mod_objcg_state(objcg, page_pgdat(page),
> @@ -522,7 +522,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s_orig,
>                 else
>                         s = s_orig;
>
> -               off = obj_to_index(s, page, p[i]);
> +               off = obj_to_index(s, page_slab(page), p[i]);
>                 objcg = objcgs[off];
>                 if (!objcg)
>                         continue;
> diff --git a/mm/slub.c b/mm/slub.c
> index f5344211d8cc..61aaaa662c5e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4342,7 +4342,7 @@ void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
>  #else
>         objp = objp0;
>  #endif
> -       objnr = obj_to_index(s, slab_page(slab), objp);
> +       objnr = obj_to_index(s, slab, objp);
>         kpp->kp_data_offset = (unsigned long)((char *)objp0 - (char *)objp);
>         objp = base + s->size * objnr;
>         kpp->kp_objp = objp;
> --
> 2.33.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfj4mngOf9roarq6RFQLgkcGhcM1aFMi7OjJek3T4sgYA%40mail.gmail.com.
