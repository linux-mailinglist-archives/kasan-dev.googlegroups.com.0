Return-Path: <kasan-dev+bncBDW2JDUY5AORBAHUZ2GAMGQE2KVYJKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BFB6645337F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:02:41 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id x16-20020a25b910000000b005b6b7f2f91csf32488277ybj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 06:02:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637071360; cv=pass;
        d=google.com; s=arc-20160816;
        b=yaRasb5SxZgiw44GIN7oO78gfVxXGvR1D86Rd+ccdIGbwzI+SaWRhkrCqVw9+i+1Ky
         lpExl98HwbJmtZjAQy0uqRuge3iSsPiooJBuxGE4UgJX99X+ivWG397RLxoxAAfnJM3Y
         STtjZvwgop2b1cBntUDKTLQB9vUhDyOxzJ1h13JJjmIartpEljcze5njyo3T0A1FoYR9
         qXbUaXmwKri1cZlI59p5OKg8nITsJU8CczrJFV7VnCe9nJa72phPNtxsVE71a+9PqnJY
         ubKVrGcEMD0lO0+SDUlKKLdxwtLN3MSrCG5x4AVtKnCvdvDaLkTu7lunLO8PpXL0pFbs
         nFdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=m+1czDVId8QmlpGdq8izG3UrPeVy7LARUEKVth8FYNE=;
        b=o/A+8V8ZHQ13l9a7UwFLLvq/3qjm/KSPUpl04BFu5nZkAUrq66+3PxnVbfB7zjD2Ae
         OCefQLGTnb5fvuVPi4fOl371bTYNIwGSuMisDt3RU+nwTqgDC9hOHlLLyuquwLc/vzBK
         fpc2B6KhbTLlzhrpqw/7q4V5rVOuUYLfGbguXy4/fctk7khlKCUwpYOHsfORtlAPAT3F
         TfoHtREG2aCIkh8Fq6QcVOuqd8EBUL871H65vANGFtbD/Jmb3wxLaljxnfayLmG0F0b+
         etuCX6Hd0/1vlRBJxHBROgm7hZEpzrr05YyIp+vA6nQLUMKYN9sKvFsWVhrA5lVjqkOl
         IYxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=eEf8LRN9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m+1czDVId8QmlpGdq8izG3UrPeVy7LARUEKVth8FYNE=;
        b=j8iqOfprO/ebfjCcXI3+Kji55I3VexGChlEZkjU13v3+wKzM8klZR22DY9CJM3F/v5
         sFTpFlGuIZ1ZgO6D/5LEVQTZEvQPTU6vJP73By0C1Kysm1LbDi3OXXgGE1do+zVeo3DT
         aMZEauWOS/mMH7DF/HhAlkaqkyo3XcKc0CrqJNmRP1mgL8xtkap+FopqzS2yKyk1zJjQ
         QN9YVWnKyWyDMNI0l7qXw961X9jF1adGy7ASE6BOliq+OdkfH2lWMNV13B809hk4cZZk
         zKgiElazYdc2rYAl0p7pj4a4WVZ551bQJarjHK3XOrnz/jLAhS12OWCdO+u3YGDOZQ16
         tPCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m+1czDVId8QmlpGdq8izG3UrPeVy7LARUEKVth8FYNE=;
        b=FHgbS2WrKxO7Di6YYDW2U1t374yYJCZ1f7kvWtP1JmJKm4lUtc926HhrYf3G1hlLXV
         Lgf4EJLSSnpWrztgDQa37frRfDWA/Rgw2TOkn3V0lABQaT4PCDIGMyWQpAyMej8ShjzD
         GC5jUkE5/c9Bgu+tCYvumrIjA2F4dMeVsLV91L2j883uDeYvc28bMrNG4atLvXQnJSDz
         bq7+QtXvfm7ittc+rMaKn+tpEQ0bCVw8shEo6/7wOa2kvYJQb8mA190Kw4JVN/9lUfAh
         f21xlyUu3YyoucLUs17f1sekQoyt07xqClaTFGm/HNWlNlbuADr9KNCWlN5sdaPopZSh
         E/Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m+1czDVId8QmlpGdq8izG3UrPeVy7LARUEKVth8FYNE=;
        b=hqvjhE7rbv8+xd0K+yaJ96lYNftIRYZo3/+NE0ENVWN7rCagbskbIlECh9AdP4L/7X
         xL4MzrrkbZvM2gm+h6t1xz0kSHSQAfOPmPlrCawtAMQFvyPRDCXO56aWxp3GSpMMInTv
         jKiSn5kvFdKqIgmoXurAU8DNPEOy+9kTV2IpkJTCVppJHwp82E7RGOaibv4j0yIwCYAe
         RGrSSC14dgUy7kCb48a+kg9aU9psBhmGdMf02kOmzXb+PsfhrS0+DVqvlNmqwO62lKnS
         sAoPhoaULKoNwV5qod3i+4TCNq7R2XVKK1VfOPMA1MB7dl9KtoQunVG3WPVlxV1Hc/6W
         d7gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zTTanyEXTxxSD600XuNm8zNoU8uF3tjfHfQJ00vinAe3Y8vEP
	bDf6etlvbGjXCZzPjYbbegg=
X-Google-Smtp-Source: ABdhPJwvbVl1FxMgYaiyXug6JvnQ8TD0rcfL/nCuajDdgspZows7D5RgQ9jn5su/wo9eVC+OP4zXsg==
X-Received: by 2002:a25:a381:: with SMTP id e1mr8234582ybi.273.1637071360644;
        Tue, 16 Nov 2021 06:02:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e64a:: with SMTP id d71ls11342073ybh.7.gmail; Tue, 16
 Nov 2021 06:02:40 -0800 (PST)
X-Received: by 2002:a25:ade0:: with SMTP id d32mr8545757ybe.510.1637071360141;
        Tue, 16 Nov 2021 06:02:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637071360; cv=none;
        d=google.com; s=arc-20160816;
        b=GC+6HfjJMr0fnbRHt90t0Z5WT+mtcQtzd0Ds1o3f618tGM5FtGZepqiGTZoPdWnu63
         pBSr84z/sbx65M0X6JsodkFQbD10IlGbemmGlKn1iYCIRr2j20QKtc+IcDXPv1NV2cdQ
         vpSPhfrc8juYCJs1OJ70PyY+0VMRSUg+Z27RRyPptSW25a/lhEMIbDM3CqmS4MZsgaR8
         S+FuDltbrF5dkyye0NmTryTpY4IVR17a5hgVJZlmDdNmrx2PC0DZHIDvE5c8S/W7jb2I
         8Kik+EinkOfgj/3p3Vfq+VzA4vCXmySvQFtQ+mjV4/W7RRunx2+YLT+lMRJQ2q4APkdd
         lZHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bx+LOZiINaT1HDexzncKyUqsxvfo5/luW+zVzz6pEqU=;
        b=AmXceWRD6X7k9WwPb8w4HTGEvLf/2AIoM66KAQw2OKmuHxP92Pd0iGQbHIerqqM4Qq
         N0Mhifj1BROHptBsfcARcYcJGAsJHQTS1tWhg7Dbj8mf1WlQFacE+bEnJYYJb1GXHiFd
         adywWORuZe0lYpppa2Xm1sqw9YAXdTqShPXu3fIztuxQTfptSTj/ly37piOy2+ChgOPt
         pGLcUwpVydXqXctbiTM4+x0MiXHeeeTdtqTein6db85AKsohI+ZLYXnB/MaTJgmU1m6h
         1zoPERDFRzA72oM4FY/Sy7JV31ppI+fg49IfVQ9yeLrRi2WsUw2GYDYvS0OFahda4wie
         QKkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=eEf8LRN9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id a38si1293758ybi.4.2021.11.16.06.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 06:02:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id m11so20519848ilh.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 06:02:40 -0800 (PST)
X-Received: by 2002:a05:6e02:1525:: with SMTP id i5mr4704714ilu.81.1637071359840;
 Tue, 16 Nov 2021 06:02:39 -0800 (PST)
MIME-Version: 1.0
References: <20211116001628.24216-1-vbabka@suse.cz> <20211116001628.24216-22-vbabka@suse.cz>
In-Reply-To: <20211116001628.24216-22-vbabka@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 16 Nov 2021 15:02:29 +0100
Message-ID: <CA+fCnZd_39cEvP+ktfxSrYAj6xdM02X6C0CxA5rLauaMhs2mxQ@mail.gmail.com>
Subject: Re: [RFC PATCH 21/32] mm: Convert struct page to struct slab in
 functions used by other subsystems
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Linux Memory Management List <linux-mm@kvack.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Julia Lawall <julia.lawall@inria.fr>, 
	Luis Chamberlain <mcgrof@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Vladimir Davydov <vdavydov.dev@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=eEf8LRN9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c
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

The tab before addr should be a space. checkpatch should probably report this.

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
> index 781605e92015..c8b53ec074b4 100644
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
> index 78ef4d94e3de..adf688d2da64 100644
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
> @@ -4182,7 +4182,7 @@ void __check_heap_object(const void *ptr, unsigned long n,
>
>         /* Find and validate object. */
>         cachep = slab->slab_cache;
> -       objnr = obj_to_index(cachep, slab_page(slab), (void *)ptr);
> +       objnr = obj_to_index(cachep, slab, (void *)ptr);
>         BUG_ON(objnr >= cachep->num);
>
>         /* Find offset within object. */
> diff --git a/mm/slab.h b/mm/slab.h
> index d6c993894c02..b07e842b5cfc 100644
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
> index 7759f3dde64b..981e40a88bab 100644
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd_39cEvP%2BktfxSrYAj6xdM02X6C0CxA5rLauaMhs2mxQ%40mail.gmail.com.
