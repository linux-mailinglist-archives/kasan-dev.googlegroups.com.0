Return-Path: <kasan-dev+bncBCMIZB7QWENRBOGB436AKGQEKEMNNKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 88D3029D115
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 17:47:53 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id z8sf3970164ilh.13
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 09:47:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603903672; cv=pass;
        d=google.com; s=arc-20160816;
        b=UgN2dd7hpm1w/uJGZVNp8j843TIRzg2OZ0ygaODsFfW7m1631n39pTU2lkaRt1WSot
         x9gkth7PUiZDqt2fjjDnAYRZ9M6gd92o6EWvsorSoV3IprlUS1j1F8QUKVcbYigORab3
         +k8Tr/nNYipxt1+PEhvWJEjO26ykIMM0mbso9WZsQF9vDESgtChJssgW6cX/TpFvZbUh
         h+VMPybbRw14ftSm/Rpg1fTljGrtxOzq67qc+isj0nOw0FveHS/B2T+hK17tOGXhB1hc
         dc6+BL9HKGVBFGChyVE7DWdbNvcEToLv5HsYhFUmBC29BEg5wIS6l+EMOe6xTkLMk/XQ
         JAbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w+QnT8Eit5qZTwFrYUjNNpyW6kXEBk/Kg77Hq+90DFQ=;
        b=ViNEA72/U3Mm2Wmrtbvm2YH9MGVW9Q/L7fI+wf2KPAWZoQgrSAy+dgTZ/cxr4ub5hq
         zyEd0OaeeUK2Swu6D35VFseoVOYVwSDumOrn7Yha8dg2i1u98QRFvKodpbxGBFxhJgyP
         0p2ZNICPhOYYZV/6jW4WfGi97QdzrLxJxTPfrqItKNwImOtwgIm6kERRoKaOY3TsQVLf
         Vv1UOeHYpXvK9J/5WF9n0sU45F2+AyT3NiSxP4HvBnL6pRTcl5/jdh02grPiomVPL8JH
         nj87OJ9MyGw0D57+fe3JN60NBaBka3Oe76lOggXJru2siB9wHgOdrZuRL2NBiTCLpg37
         sw5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jzDu0zGY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+QnT8Eit5qZTwFrYUjNNpyW6kXEBk/Kg77Hq+90DFQ=;
        b=Wxo66IbxJjsnfkMkHDVsGVuhH/+DFikDiitt/lU5zPx9r+5bHbJmWbAWV0iK+t5ySA
         v+WtWO8XUUDooQeA4fD+3r91qJTOanWqnxouB5Zm1WQp+U6nU7ZRg6NCl0hcqdKDFmmu
         bXEVHLhZX8c1lPhpNNP7Y7OiqiViaNMy0eyQ/I/37WAV0Ez9Jld2u8NtekLiXx7yHm5h
         /UXgKHlnzp7y2MtvgFFQKvIrUJjWyzRaFzQXPakTvybHkeYbfbB8p3UluzyI8XJJxTZN
         1/hH+MSgdCGuevhQ+UoDdwtY3xC3Z8bVWuBJaid6es7rZ9hN/hlzAXOAut9+NSAieVpm
         2bgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+QnT8Eit5qZTwFrYUjNNpyW6kXEBk/Kg77Hq+90DFQ=;
        b=Vl+AtqiTXbJ1okBHquDdAW3rlJGyevMKyRx/9FUHNqykJEm/BQzOb4ceURMqtvQ5Bh
         BHCwHNxtCkV9klGD7v/tQO6Valq8i8vxFdEsKydu+CScVken5iRbv4XqGp/dISWeWgT+
         5COiPOAexi0eASGOI7uTmTBLvlNcnOZisY3/DMTG8bKLXgVD/8fkqWzYkUGWW/SSW9D+
         IsvP3vZEcYBCalyBmyMk7xQ34L7XL9oJfgT86wAuKoADLzlHALHTMpUbuyAwkzVk0T+O
         B463w4Y8h6bnYxDEhIsFXXV3Yf6lWxpPSddMA7bJnAB7F5Kk+drYSJl4xYWt7y3o37h9
         CH3A==
X-Gm-Message-State: AOAM532/dFYb3ozl7dd1k8yIeSM0SB0pCueYJXXKs9vyPvLLHaGvqoB5
	kBkfKEKqXNlE/m5sStvRAJs=
X-Google-Smtp-Source: ABdhPJx7zceQJOcFd1/gr8SxA0nCnZ40Guduxe15mTFaiThK+O7pnLEv0Y9S00yXsU0l9Xo8uxPufA==
X-Received: by 2002:a92:5f5b:: with SMTP id t88mr6805034ilb.170.1603903672179;
        Wed, 28 Oct 2020 09:47:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8a05:: with SMTP id w5ls879745iod.0.gmail; Wed, 28 Oct
 2020 09:47:51 -0700 (PDT)
X-Received: by 2002:a5d:815a:: with SMTP id f26mr210985ioo.111.1603903671695;
        Wed, 28 Oct 2020 09:47:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603903671; cv=none;
        d=google.com; s=arc-20160816;
        b=uKvr+rswB3UKUiemM/MIcqnFJKG0IKFwr+y0xfSys1QXSLAW1DK7eQmf3fPXyOfUN5
         UhrUAUF4maZnF13jiGQ0DL1uDjYCAOo2MJHXXxQC8l0ZxSNiJTcrjh8ID39vq1Q/KUWq
         U3cLhMMlDDjJZSmeTVKXjYHdt+x8yxCmmFYfc07yXaQPTu77j5x8RF31Ft0+m8PS8iR7
         S7jBmkpI3dLYtgkd1kmjV/NA3n7EcCVnuC+M7HS+lOvDqx1qu/GtTxFeSC8EBsRk5xog
         6vqaT3JoT7XaDdeyHsiCnG4dosC0JdO4K4eQY5GhLDVcVdeR8kiGRQ9HKc8O4SJL9dJM
         FaoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3/dbD6k4zYkgkO9i/jaBjHmJBv6HsgR1Y1s5z72VaeM=;
        b=jnuAeNZHSKA/NonofBExTaMfHsIr1mK523iPDscLKaE47nsTHBImwKgUyfWCP6NYw5
         rwSrUfNzKNVZwp7tZWZpPjDzwHuz24VOnBfcCzAf8mfqYbBgOF4ZRlSrfyEUU9gPL7Jx
         gqEpAle0Fr06BJZKu4ES8bsS72So/M1tWZjF3qwm2pI/X+y1Ry1ZvHo/j8jSHI90RMQZ
         fu4R2wsus2ETLu9s34JEBPoul5WfIDs8vhHpQWertCEZYwowWSu/9pbU1IpncBdGIV97
         rOBo1yTruQQOCwb4dZ95aligAFBj0sKWdQee+QMHyo9+nbhGjhs6imcLVSKuIL19/3mN
         U72g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jzDu0zGY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id p5si6110ilg.3.2020.10.28.09.47.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 09:47:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id h12so4006409qtc.9
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 09:47:51 -0700 (PDT)
X-Received: by 2002:ac8:44ae:: with SMTP id a14mr8151829qto.67.1603903670610;
 Wed, 28 Oct 2020 09:47:50 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <21fa5f4eb6ee132a57b716ff6245f2c98de2d204.1603372719.git.andreyknvl@google.com>
In-Reply-To: <21fa5f4eb6ee132a57b716ff6245f2c98de2d204.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 17:47:39 +0100
Message-ID: <CACT4Y+Z-BVAVy-WLLT7x8iFAzk+VoPSaiHK3xh9ya_2xJ-7hZA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 15/21] kasan: check kasan_enabled in annotations
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jzDu0zGY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Declare the kasan_enabled static key in include/linux/kasan.h and in
> include/linux/mm.h and check it in all kasan annotations. This allows to
> avoid any slowdown caused by function calls when kasan_enabled is
> disabled.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
> ---
>  include/linux/kasan.h | 210 ++++++++++++++++++++++++++++++++----------
>  include/linux/mm.h    |  27 ++++--
>  mm/kasan/common.c     |  60 ++++++------
>  3 files changed, 211 insertions(+), 86 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 2b9023224474..8654275aa62e 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -2,6 +2,7 @@
>  #ifndef _LINUX_KASAN_H
>  #define _LINUX_KASAN_H
>
> +#include <linux/jump_label.h>
>  #include <linux/types.h>
>
>  struct kmem_cache;
> @@ -66,40 +67,154 @@ static inline void kasan_disable_current(void) {}
>
>  #ifdef CONFIG_KASAN
>
> -void kasan_alloc_pages(struct page *page, unsigned int order);
> -void kasan_free_pages(struct page *page, unsigned int order);
> +struct kasan_cache {
> +       int alloc_meta_offset;
> +       int free_meta_offset;
> +};
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +DECLARE_STATIC_KEY_FALSE(kasan_enabled);
> +#else
> +DECLARE_STATIC_KEY_TRUE(kasan_enabled);
> +#endif
>
> -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> -                       slab_flags_t *flags);
> +void __kasan_alloc_pages(struct page *page, unsigned int order);
> +static inline void kasan_alloc_pages(struct page *page, unsigned int order)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_alloc_pages(page, order);

The patch looks fine per se, but I think with the suggestion in the
previous patch, this should be:

      if (kasan_is_enabled())
             __kasan_alloc_pages(page, order);

No overhead for other modes and less logic duplication.

> +}
>
> -void kasan_unpoison_data(const void *address, size_t size);
> -void kasan_unpoison_slab(const void *ptr);
> +void __kasan_free_pages(struct page *page, unsigned int order);
> +static inline void kasan_free_pages(struct page *page, unsigned int order)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_free_pages(page, order);
> +}
>
> -void kasan_poison_slab(struct page *page);
> -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> -void kasan_poison_object_data(struct kmem_cache *cache, void *object);
> -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> -                                       const void *object);
> +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> +                               slab_flags_t *flags);
> +static inline void kasan_cache_create(struct kmem_cache *cache,
> +                       unsigned int *size, slab_flags_t *flags)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_cache_create(cache, size, flags);
> +}
>
> -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> -                                               gfp_t flags);
> -void kasan_kfree_large(void *ptr, unsigned long ip);
> -void kasan_poison_kfree(void *ptr, unsigned long ip);
> -void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> -                                       size_t size, gfp_t flags);
> -void * __must_check kasan_krealloc(const void *object, size_t new_size,
> -                                       gfp_t flags);
> +size_t __kasan_metadata_size(struct kmem_cache *cache);
> +static inline size_t kasan_metadata_size(struct kmem_cache *cache)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_metadata_size(cache);
> +       return 0;
> +}
>
> -void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
> -                                       gfp_t flags);
> -bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> +void __kasan_unpoison_data(const void *addr, size_t size);
> +static inline void kasan_unpoison_data(const void *addr, size_t size)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_unpoison_data(addr, size);
> +}
>
> -struct kasan_cache {
> -       int alloc_meta_offset;
> -       int free_meta_offset;
> -};
> +void __kasan_unpoison_slab(const void *ptr);
> +static inline void kasan_unpoison_slab(const void *ptr)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_unpoison_slab(ptr);
> +}
> +
> +void __kasan_poison_slab(struct page *page);
> +static inline void kasan_poison_slab(struct page *page)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_poison_slab(page);
> +}
> +
> +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> +static inline void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_unpoison_object_data(cache, object);
> +}
> +
> +void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
> +static inline void kasan_poison_object_data(struct kmem_cache *cache, void *object)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_poison_object_data(cache, object);
> +}
> +
> +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> +                                         const void *object);
> +static inline void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> +                                                     const void *object)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_init_slab_obj(cache, object);
> +       return (void *)object;
> +}
> +
> +bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_slab_free(s, object, ip);
> +       return false;
> +}
>
> -size_t kasan_metadata_size(struct kmem_cache *cache);
> +void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> +                                      void *object, gfp_t flags);
> +static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
> +                                                  void *object, gfp_t flags)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_slab_alloc(s, object, flags);
> +       return object;
> +}
> +
> +void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
> +                                   size_t size, gfp_t flags);
> +static inline void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> +                                               size_t size, gfp_t flags)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_kmalloc(s, object, size, flags);
> +       return (void *)object;
> +}
> +
> +void * __must_check __kasan_kmalloc_large(const void *ptr,
> +                                         size_t size, gfp_t flags);
> +static inline void * __must_check kasan_kmalloc_large(const void *ptr,
> +                                                     size_t size, gfp_t flags)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_kmalloc_large(ptr, size, flags);
> +       return (void *)ptr;
> +}
> +
> +void * __must_check __kasan_krealloc(const void *object,
> +                                    size_t new_size, gfp_t flags);
> +static inline void * __must_check kasan_krealloc(const void *object,
> +                                                size_t new_size, gfp_t flags)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               return __kasan_krealloc(object, new_size, flags);
> +       return (void *)object;
> +}
> +
> +void __kasan_poison_kfree(void *ptr, unsigned long ip);
> +static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_poison_kfree(ptr, ip);
> +}
> +
> +void __kasan_kfree_large(void *ptr, unsigned long ip);
> +static inline void kasan_kfree_large(void *ptr, unsigned long ip)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_kfree_large(ptr, ip);
> +}
>
>  bool kasan_save_enable_multi_shot(void);
>  void kasan_restore_multi_shot(bool enabled);
> @@ -108,14 +223,12 @@ void kasan_restore_multi_shot(bool enabled);
>
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> -
>  static inline void kasan_cache_create(struct kmem_cache *cache,
>                                       unsigned int *size,
>                                       slab_flags_t *flags) {}
> -
> -static inline void kasan_unpoison_data(const void *address, size_t size) { }
> -static inline void kasan_unpoison_slab(const void *ptr) { }
> -
> +static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> +static inline void kasan_unpoison_data(const void *address, size_t size) {}
> +static inline void kasan_unpoison_slab(const void *ptr) {}
>  static inline void kasan_poison_slab(struct page *page) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>                                         void *object) {}
> @@ -126,36 +239,33 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>  {
>         return (void *)object;
>  }
> -
> -static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> +                                  unsigned long ip)
>  {
> -       return ptr;
> +       return false;
>  }
> -static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> -static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
> -                               size_t size, gfp_t flags)
> +static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> +                                  gfp_t flags)
>  {
> -       return (void *)object;
> +       return object;
>  }
> -static inline void *kasan_krealloc(const void *object, size_t new_size,
> -                                gfp_t flags)
> +static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
> +                               size_t size, gfp_t flags)
>  {
>         return (void *)object;
>  }
>
> -static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> -                                  gfp_t flags)
> +static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
>  {
> -       return object;
> +       return (void *)ptr;
>  }
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> -                                  unsigned long ip)
> +static inline void *kasan_krealloc(const void *object, size_t new_size,
> +                                gfp_t flags)
>  {
> -       return false;
> +       return (void *)object;
>  }
> -
> -static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> +static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> +static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
>
>  #endif /* CONFIG_KASAN */
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index a3cac68c737c..701e9d7666d6 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1412,22 +1412,36 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
>  #endif /* CONFIG_NUMA_BALANCING */
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +DECLARE_STATIC_KEY_FALSE(kasan_enabled);
> +#else
> +DECLARE_STATIC_KEY_TRUE(kasan_enabled);
> +#endif
> +
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
> -       return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> +       if (static_branch_likely(&kasan_enabled))
> +               return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> +       return 0xff;
>  }
>
>  static inline void page_kasan_tag_set(struct page *page, u8 tag)
>  {
> -       page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> -       page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> +       if (static_branch_likely(&kasan_enabled)) {
> +               page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> +               page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> +       }
>  }
>
>  static inline void page_kasan_tag_reset(struct page *page)
>  {
> -       page_kasan_tag_set(page, 0xff);
> +       if (static_branch_likely(&kasan_enabled))
> +               page_kasan_tag_set(page, 0xff);
>  }
> -#else
> +
> +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> +
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
>         return 0xff;
> @@ -1435,7 +1449,8 @@ static inline u8 page_kasan_tag(const struct page *page)
>
>  static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
>  static inline void page_kasan_tag_reset(struct page *page) { }
> -#endif
> +
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline struct zone *page_zone(const struct page *page)
>  {
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index cc129ef62ab1..c5ec60e1a4d2 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -81,7 +81,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  }
>  #endif /* CONFIG_KASAN_STACK */
>
> -void kasan_alloc_pages(struct page *page, unsigned int order)
> +void __kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>         u8 tag;
>         unsigned long i;
> @@ -95,7 +95,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
>         kasan_unpoison_memory(page_address(page), PAGE_SIZE << order);
>  }
>
> -void kasan_free_pages(struct page *page, unsigned int order)
> +void __kasan_free_pages(struct page *page, unsigned int order)
>  {
>         if (likely(!PageHighMem(page)))
>                 kasan_poison_memory(page_address(page),
> @@ -122,8 +122,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
>                 object_size <= (1 << 16) - 1024 ? 1024 : 2048;
>  }
>
> -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> -                       slab_flags_t *flags)
> +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> +                         slab_flags_t *flags)
>  {
>         unsigned int orig_size = *size;
>         unsigned int redzone_size;
> @@ -165,7 +165,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>         *flags |= SLAB_KASAN;
>  }
>
> -size_t kasan_metadata_size(struct kmem_cache *cache)
> +size_t __kasan_metadata_size(struct kmem_cache *cache)
>  {
>         if (static_branch_unlikely(&kasan_stack))
>                 return (cache->kasan_info.alloc_meta_offset ?
> @@ -188,17 +188,17 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>         return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>
> -void kasan_unpoison_data(const void *address, size_t size)
> +void __kasan_unpoison_data(const void *addr, size_t size)
>  {
> -       kasan_unpoison_memory(address, size);
> +       kasan_unpoison_memory(addr, size);
>  }
>
> -void kasan_unpoison_slab(const void *ptr)
> +void __kasan_unpoison_slab(const void *ptr)
>  {
>         kasan_unpoison_memory(ptr, __ksize(ptr));
>  }
>
> -void kasan_poison_slab(struct page *page)
> +void __kasan_poison_slab(struct page *page)
>  {
>         unsigned long i;
>
> @@ -208,12 +208,12 @@ void kasan_poison_slab(struct page *page)
>                         KASAN_KMALLOC_REDZONE);
>  }
>
> -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  {
>         kasan_unpoison_memory(object, cache->object_size);
>  }
>
> -void kasan_poison_object_data(struct kmem_cache *cache, void *object)
> +void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
>         kasan_poison_memory(object,
>                         round_up(cache->object_size, KASAN_GRANULE_SIZE),
> @@ -266,7 +266,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
>  #endif
>  }
>
> -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>                                                 const void *object)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> @@ -285,7 +285,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>         return (void *)object;
>  }
>
> -static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> +static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>                               unsigned long ip, bool quarantine)
>  {
>         u8 tag;
> @@ -329,9 +329,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>         return false;
>  }
>
> -bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> +bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  {
> -       return __kasan_slab_free(cache, object, ip, true);
> +       return ____kasan_slab_free(cache, object, ip, true);
>  }
>
>  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> @@ -339,7 +339,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>         kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
>  }
>
> -static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> +static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                                 size_t size, gfp_t flags, bool keep_tag)
>  {
>         unsigned long redzone_start;
> @@ -371,20 +371,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         return set_tag(object, tag);
>  }
>
> -void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
> -                                       gfp_t flags)
> +void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
> +                                       void *object, gfp_t flags)
>  {
> -       return __kasan_kmalloc(cache, object, cache->object_size, flags, false);
> +       return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
>  }
>
> -void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
> -                               size_t size, gfp_t flags)
> +void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
> +                                       size_t size, gfp_t flags)
>  {
> -       return __kasan_kmalloc(cache, object, size, flags, true);
> +       return ____kasan_kmalloc(cache, object, size, flags, true);
>  }
> -EXPORT_SYMBOL(kasan_kmalloc);
> +EXPORT_SYMBOL(__kasan_kmalloc);
>
> -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> +void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>                                                 gfp_t flags)
>  {
>         struct page *page;
> @@ -409,7 +409,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
>         return (void *)ptr;
>  }
>
> -void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
> +void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
>  {
>         struct page *page;
>
> @@ -419,13 +419,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
>         page = virt_to_head_page(object);
>
>         if (unlikely(!PageSlab(page)))
> -               return kasan_kmalloc_large(object, size, flags);
> +               return __kasan_kmalloc_large(object, size, flags);
>         else
> -               return __kasan_kmalloc(page->slab_cache, object, size,
> +               return ____kasan_kmalloc(page->slab_cache, object, size,
>                                                 flags, true);
>  }
>
> -void kasan_poison_kfree(void *ptr, unsigned long ip)
> +void __kasan_poison_kfree(void *ptr, unsigned long ip)
>  {
>         struct page *page;
>
> @@ -438,11 +438,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
>                 }
>                 kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
>         } else {
> -               __kasan_slab_free(page->slab_cache, ptr, ip, false);
> +               ____kasan_slab_free(page->slab_cache, ptr, ip, false);
>         }
>  }
>
> -void kasan_kfree_large(void *ptr, unsigned long ip)
> +void __kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>         if (ptr != page_address(virt_to_head_page(ptr)))
>                 kasan_report_invalid_free(ptr, ip);
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ-BVAVy-WLLT7x8iFAzk%2BVoPSaiHK3xh9ya_2xJ-7hZA%40mail.gmail.com.
