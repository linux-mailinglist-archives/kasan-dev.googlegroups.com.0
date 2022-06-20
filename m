Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP7RYGKQMGQEPYBGR6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 321E6551ACF
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:17 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-101b3601c5dsf5336823fac.19
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732416; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEpN3BZSWrs8x6yWmroC8T91/WkraJ5qaSU+7ayl6Okro2WPdH/f/lMeOqs3nAoh67
         Q06oqs4Y2fKHaHn9WrYY3ahuhTu02M7sL6pC8Utp+P9/SEWSR63EdQeaMk11K3kejw3c
         vqO57GKK9h2Tqmv211SSqSBHsYkGv947txe2WQbKJad6RkOXUXStXWIjLZuVZ6yN51ak
         YuaI+coIeZhq07Siru+AmbzZVx6vm6BiNNXrj8UuYZqEShBLv5vhjyj2ZM8XTBCOPUVf
         b3kpzH9lM59KbumvehvDi4UOZj6YOeE49kSUAWP0j2KoEvnLGCSb25xvQlIveGc7fMKg
         dOng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4yz1ofZrS8i91+WQ42A/327HwKXInJB1vYbjC2LHhF0=;
        b=UQAV2tjQpGwyMDTIuCAopj6CaYuiGQWu6XX0/9XKUH7GI3GUh8p6TN4l+l5KdQQ77P
         6USiMcoCfdrrSfO43FtAmvWU3B+IYH4ibKj9/pDnfrc2pKsXwrxK3J2zlurB8jj59djO
         9qivRDMBn8UCVwxDOTQqLatVKmCvZI7E5U5UHpg4KHkBz2ihBE0AOtmYa5pcyj9KaDyi
         scjUGiNyR+uays8QevH6Lev1s9tjjVLIJSZVBezREPfxauB/HI5x90IjcX1LC+pQ+KCO
         0WijQmpvnljjdfj1fPEVacj8lwJQlxiulvQGvYcfpM6rvHGrQGFKUyj3GEICKnuhjmeH
         ykQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gqJJODRW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4yz1ofZrS8i91+WQ42A/327HwKXInJB1vYbjC2LHhF0=;
        b=WND3l0H0oQRTjJByMDx1FrnOff/tN+J4sTq2zPNEFPQi1XL5+XZjxtpdnuM1JfhND0
         ljI3ov+q/7n8eUQgbI75V7ilgitvaltIrSTPSwraYqhzlSMsZFdQ4kY/wqiyyien1cV+
         vcilzuAiYNn1qSw/vQ+Ie7IDCrlDKWJgIAAbAkzofJBR32+uyzxIag/7/kGJMR0EfH6s
         uMjNJ8SkSq8rExnf0mBYKCHmTWxzLYNVN+QwjGL4w0gNv5iHTTLaSmxiMRezp6MXh2Df
         b3szWoQiLJZHLTvIz6Nv+rv8D7kZJ3yCKXkVBsEnTjjay78qho3MEOPOrQY1pF4hsJhe
         zwSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4yz1ofZrS8i91+WQ42A/327HwKXInJB1vYbjC2LHhF0=;
        b=Dc6ctE4Y9sEtXxiO+BEnoH4x2IfPjI30RuuiyrfKmhC9SLsiwxh0AANGdniylZ88BL
         TAKmhrZEOv1o31YKeq0dApDP4WiS3mu4Nho/huJh4wTucardES3gkKbmVvVYiXRyP6OG
         nDh/ffl8PDbvS5DVpbnbL+ay1ZPCLZaBEPs3MJ4857EtTsOGew7NJ3o9vLhgmiMzX2qs
         zn1NRZM4CgDAuFaKLFF5UJgkuFdFNeV/unLSiWw3fcrO6xrsCiWr5+VZms9ppeTfCbnp
         q+ryX0tadmk8EpFPStFwYMmFkyAFTOWqdAnmYU/opmbrnn7VLAi4t2vcQsqpChqj+Sj6
         1M0A==
X-Gm-Message-State: AJIora83IzD58KjhLnZidif2+G1fOf/EtKbiQHwrEjID/Kp3JjkkDcWV
	9thyxxyN8H2/A8LgWkMgyug=
X-Google-Smtp-Source: AGRyM1uVImnq1a4TAezhrHuz+ACGbcXFmqZm9n+IYAJUDvv/9FaluQDZqfBrhRtqpQe3BA0rfTkchw==
X-Received: by 2002:a05:6870:3920:b0:101:d628:b053 with SMTP id b32-20020a056870392000b00101d628b053mr4051741oap.111.1655732415832;
        Mon, 20 Jun 2022 06:40:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4604:0:b0:60b:8d36:6a1d with SMTP id y4-20020a9d4604000000b0060b8d366a1dls2311322ote.8.gmail;
 Mon, 20 Jun 2022 06:40:15 -0700 (PDT)
X-Received: by 2002:a9d:2c5:0:b0:60c:2bf9:1dbd with SMTP id 63-20020a9d02c5000000b0060c2bf91dbdmr9582944otl.254.1655732415395;
        Mon, 20 Jun 2022 06:40:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732415; cv=none;
        d=google.com; s=arc-20160816;
        b=E6n9ok7tnePGzkRZ3Iaz+p8BJS0IBkiQbypKcviaF1gNAO7x7Pgw3dR+RUcnn6oelQ
         bFAYAzzOUM3UGHP0W58dw774gUPMG2ISJyzI/YZcTxq2ibvRoAVL0u1oTbBBN/bn6jUk
         EN4uJOVxnLnv7ENoWfTBGmCZT5CCQFyBruSd5SL1KBT8rQqna/BpAWQZwodRE4FeSnFB
         37twbfMohfTF4Y82IDCzPNQGs5GIWgaGRh9qx44HTQtMgZQhgP5tzgY5ctY0rLbZIjKx
         MCwun20PkrXxncYC/lSRnvJYByV5XP6nO0IsbDiBlm0FgJpUvgjUBxTHl2EclthgQW//
         DUZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o4db5qe9nfedraUSjBeWLX6x7hDJFPJYx1QIcCVkfBw=;
        b=hhpRXehSC3G/6kNA6mfpYnfWgUQm18SGTjLwvOEJ0QSyLxWxP+F9tgiuEQOyeEKr/Y
         5JOpZ3RcPa+zDIRimE4gLv083FJ95d2zs+g+PaHCGfmTWtcz7G/SKAGjrh6IHXdJRArE
         AyI7qc0SAErsVVF43w/Jw1+e/UjOCR+DK75a+EZnK64DYmXjWZ7/a7iDXo6EG0ibRr/0
         eA8lMJJxUGnomnV9YxVc+/xpyh49/tjknSPWi7ojRWv7sr+bmNQZg24HM5UqyzflpGbK
         /N4baFgnvAi8PP/s23drtTONXMHoQEbVj+Bg3IxNtm8lRgzrYDwx4IepHF5qM/5h5g7+
         6Pnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gqJJODRW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id d1-20020a056830044100b0060bade020f3si567464otc.5.2022.06.20.06.40.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id r3so19025412ybr.6
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:15 -0700 (PDT)
X-Received: by 2002:a25:c5cb:0:b0:668:c187:9d0 with SMTP id
 v194-20020a25c5cb000000b00668c18709d0mr16817150ybe.609.1655732414865; Mon, 20
 Jun 2022 06:40:14 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <ae1389c0717d1875077ee3f6cd4beb5b7e046ae0.1655150842.git.andreyknvl@google.com>
In-Reply-To: <ae1389c0717d1875077ee3f6cd4beb5b7e046ae0.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:39 +0200
Message-ID: <CANpmjNNdz58SKo0P8grXsP7ik_2wOiiJEbiN3ycGMrR1Xw9w7A@mail.gmail.com>
Subject: Re: [PATCH 04/32] kasan: split save_alloc_info implementations
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gqJJODRW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Mon, 13 Jun 2022 at 22:15, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Provide standalone implementations of save_alloc_info() for the Generic
> and tag-based modes.
>
> For now, the implementations are the same, but they will diverge later
> in the series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/common.c  | 13 ++-----------
>  mm/kasan/generic.c |  9 +++++++++
>  mm/kasan/kasan.h   |  1 +
>  mm/kasan/tags.c    |  9 +++++++++
>  4 files changed, 21 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a6107e8375e0..2848c7a2402a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -423,15 +423,6 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>         }
>  }
>
> -static void save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> -               kasan_set_track(&alloc_meta->alloc_track, flags);
> -}
> -
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>                                         void *object, gfp_t flags, bool init)
>  {
> @@ -462,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>
>         /* Save alloc info (if possible) for non-kmalloc() allocations. */
>         if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
> -               save_alloc_info(cache, (void *)object, flags);
> +               kasan_save_alloc_info(cache, (void *)object, flags);
>
>         return tagged_object;
>  }
> @@ -508,7 +499,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
>          * This also rewrites the alloc info when called from kasan_krealloc().
>          */
>         if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
> -               save_alloc_info(cache, (void *)object, flags);
> +               kasan_save_alloc_info(cache, (void *)object, flags);
>
>         /* Keep the tag that was set by kasan_slab_alloc(). */
>         return (void *)object;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 03a3770cfeae..98c451a3b01f 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -358,6 +358,15 @@ void kasan_record_aux_stack_noalloc(void *addr)
>         return __kasan_record_aux_stack(addr, false);
>  }
>
> +void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (alloc_meta)
> +               kasan_set_track(&alloc_meta->alloc_track, flags);
> +}
> +
>  void kasan_save_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 6df8d7b01073..610057e651d2 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -284,6 +284,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
> +void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
>  void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>                                 void *object, u8 tag);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index b453a353bc86..1ba3c8399f72 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -17,6 +17,15 @@
>
>  #include "kasan.h"
>
> +void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (alloc_meta)
> +               kasan_set_track(&alloc_meta->alloc_track, flags);
> +}
> +
>  void kasan_save_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae1389c0717d1875077ee3f6cd4beb5b7e046ae0.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNdz58SKo0P8grXsP7ik_2wOiiJEbiN3ycGMrR1Xw9w7A%40mail.gmail.com.
