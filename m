Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2636H6AKGQEJX7WPWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5372F2A0ED9
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 20:47:57 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id j10sf5350069pgc.6
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 12:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604087276; cv=pass;
        d=google.com; s=arc-20160816;
        b=SVIdesshxwom+A3QCX7IMexjC6bz39ChnilGt+t66acR4CpEBVHE0MYLw/uKyB7NI3
         BZGLLSFlwclvFsl05bVOnOA+QZCIkH4N5peAXmgNI00FhitNyAmwvuGMVS3xcYCoPsra
         KZ5n+EB+shHCIvtRtWMUhtHzlzRokkmDrDN2yqN5PGavxAnS42ebhIgQL2wf+3vqHFO+
         MPM5EwLqRdfb/OQCnJrFi5u6C7AkmvZT6V+v66WKTuQwBz8rM+1nQAaGPBUDF5lXC/6U
         imnJGkdhplC//u3r7fMMZmrpPlBjbXdG0JiIZ1QW+krQfe0cYsoOEAftyB2qUAX9mYlp
         o1Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mC0EnVUPmcPZn032bZEbdV9mtZict7wZkWnQPyj2NOM=;
        b=I/VWM0J1QUuxsheoGi7XdyNN2zqNoDisb1f22+bRtrE+UGLH3KQG3gJheiXyX7c4Y6
         Co9ayIomOZ2RAfezfzBVo10sRVwd/i26dGXJT3F4yWmEBbyOPNqRafG26nQEMvnmw0pz
         z3GwNtyWF/nDVpQeJIkXdpa7U3X/FD79EoadPTEQtkB3IezcxO/1vYDU+UeVY93xYPBF
         K6PHp3p6Z4LiiR/8M1hbmTFJVHHrqrasqenAdtDrd3WMpCojcHUR/PUaneGPbsPTvDwg
         cezftUvou1JJuBLQhOc/CfJATejXeqWwSjNyvZBZfVoqzevq0fghJ/83NjE+za8UQ6A+
         ZYqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=czVKKHgF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mC0EnVUPmcPZn032bZEbdV9mtZict7wZkWnQPyj2NOM=;
        b=CtcbxawI4UjAyU0DF/huZF4nL/EjKCvvEoZgwuUBKad2EqDPeCw3JGGsu3MGMSMhNe
         9x9MoY7BxfvEHrr0wSbA6GnHSp+fzTE3riArLr7Dgt5SPFXGZrm3EQIAznXyK9MH5uuv
         LjfpMjFnHDX9WeGTTE5rbiJa8fvmvoy1A0W6yD22EKfiX4tyD/AbtAy54ZsiRYUiTDZe
         W852BLQajBBqGF+6BD4ge1cwn5bxmojs0PyruWqEGtfIYk0favTzIJfbgufPz8MWCNOZ
         5RJtCjBMF/kX/Jo+9zduXAoBQ3NiUELksfhleFmsvBXa6X0nkAV88t3dxwt8DUay6URZ
         1Q3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mC0EnVUPmcPZn032bZEbdV9mtZict7wZkWnQPyj2NOM=;
        b=BAdDWvilTExJc3YoCtKH9q96ZzEhmKapUpqnKU9To8dmLTytI/aRAWjShAywvc/kEU
         Kv+j+4d7YpvIMzmgI9Odru4aMrlOl/gZwC5dtIE1d25uwyq2ETuRvAWzxZspE1nqEWzb
         IWWuW6kEYBR2TO1IYtXc9OVyog5J1FFRYfUXqPgQ3wbWT/kr90Gw9XgSrJxLPf6dg7TS
         M6OiuC1dm2us+HmCgbw3pb3qk7tqXhBJuVmbdm4IFieLCltyFU84nBprYU6ZiXOlc+rw
         c5+JnnjeJ3d1NiOfx5AU29C+6ZAVtEf9C++h8DPpuvwc8RlkCOlIYnSOK1eLtjPyqKRd
         RPOw==
X-Gm-Message-State: AOAM532e2xJ2Ib75myRhUFhzQNboKtenyhQ+OlnBFfobFxHT5P/KGr/r
	7O9RNvTyaqZHT7EpntgD+9g=
X-Google-Smtp-Source: ABdhPJzQutjPLuLoV/BbO5NtrT8tHTzJllfwHLApZSaxXfQu03JJNZgVnKoYsj99zCcbACYsvM8oOw==
X-Received: by 2002:a17:902:525:b029:d1:920c:c200 with SMTP id 34-20020a1709020525b02900d1920cc200mr10495662plf.25.1604087275935;
        Fri, 30 Oct 2020 12:47:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5112:: with SMTP id f18ls2637768pgb.0.gmail; Fri, 30 Oct
 2020 12:47:55 -0700 (PDT)
X-Received: by 2002:a62:2ce:0:b029:160:77b1:8d60 with SMTP id 197-20020a6202ce0000b029016077b18d60mr11090574pfc.9.1604087275378;
        Fri, 30 Oct 2020 12:47:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604087275; cv=none;
        d=google.com; s=arc-20160816;
        b=AX9kLCJo6hqTbTEZCrtnnqn7F10szqkKd17nFUrBuBY4hu+qW8mVkrXu/B8vACVAAG
         Jsvnf4yqMKIuXjAO9QIgAxZ18rqxJ8iSiGrt5AqIlmbDThlZ1dJ8nEpwzvWn73g8BVwZ
         C1BrnHnfXo70KFnlNtAENDu5czOK9TPuI4izJRugDNBClC5/vrkVEm2s7UPX2hOvoaVZ
         LPVQT927koB3MuPEGumB1uuO1r7+XOLmix8OjukxzRjHTACkvaeCST5a/D0Y7geX8oZR
         650vHZ07IMH8vxFszMIUg3d+zqKVjDYC1lLqcIJ0b+wZwIPgysnYsgEYZA/SaMQlC9hi
         /fsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EMJ760ZgrDfMEmFTsZlozgQI07semX5vBiLWp/Ht+2o=;
        b=HrtWlVQI6HKMNrEohMaYU3VdzmCDyVeWhQCNGPdnOMWYUBss3ApPpSbwCoY0u09YTi
         zouJyTEPKdlDCKNz+IzAFOhZeNVo0HlbGamRJ3V5n6QKGdlnt1wncDfhzLS2/TAoxAtz
         GeuRfgxBI8hYAEbGBEkry+xZjwuRmJmk7t0fUTViDoNeGVLGzTtyhNxxnN9SHHr8VRZ1
         Ttk1tEXwZ7XT3j4rZCz56/jpvBPmEz+E2H7iGmHTSTgXmiU4MQWCnKwzVkJ1pZ7Qpire
         FavQ/0Djk4YY1Z7/Gg5YOLkeueAxQeP4CFIYg3dDL0HDKDXt7G7HYjD8NpgQ5Ou7lYpC
         tpOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=czVKKHgF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id l11si550156pgt.3.2020.10.30.12.47.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 12:47:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x13so6198100pfa.9
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 12:47:55 -0700 (PDT)
X-Received: by 2002:a17:90a:f293:: with SMTP id fs19mr4720214pjb.41.1604087274686;
 Fri, 30 Oct 2020 12:47:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <21fa5f4eb6ee132a57b716ff6245f2c98de2d204.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Z-BVAVy-WLLT7x8iFAzk+VoPSaiHK3xh9ya_2xJ-7hZA@mail.gmail.com>
In-Reply-To: <CACT4Y+Z-BVAVy-WLLT7x8iFAzk+VoPSaiHK3xh9ya_2xJ-7hZA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 20:47:43 +0100
Message-ID: <CAAeHK+wjN9MuJ-H+1+ajSq2yAtbdAdHT9NTg5n+3hw9z7NH19Q@mail.gmail.com>
Subject: Re: [PATCH RFC v2 15/21] kasan: check kasan_enabled in annotations
To: Dmitry Vyukov <dvyukov@google.com>
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
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=czVKKHgF;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 28, 2020 at 5:47 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Declare the kasan_enabled static key in include/linux/kasan.h and in
> > include/linux/mm.h and check it in all kasan annotations. This allows to
> > avoid any slowdown caused by function calls when kasan_enabled is
> > disabled.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
> > ---
> >  include/linux/kasan.h | 210 ++++++++++++++++++++++++++++++++----------
> >  include/linux/mm.h    |  27 ++++--
> >  mm/kasan/common.c     |  60 ++++++------
> >  3 files changed, 211 insertions(+), 86 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 2b9023224474..8654275aa62e 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -2,6 +2,7 @@
> >  #ifndef _LINUX_KASAN_H
> >  #define _LINUX_KASAN_H
> >
> > +#include <linux/jump_label.h>
> >  #include <linux/types.h>
> >
> >  struct kmem_cache;
> > @@ -66,40 +67,154 @@ static inline void kasan_disable_current(void) {}
> >
> >  #ifdef CONFIG_KASAN
> >
> > -void kasan_alloc_pages(struct page *page, unsigned int order);
> > -void kasan_free_pages(struct page *page, unsigned int order);
> > +struct kasan_cache {
> > +       int alloc_meta_offset;
> > +       int free_meta_offset;
> > +};
> > +
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +DECLARE_STATIC_KEY_FALSE(kasan_enabled);
> > +#else
> > +DECLARE_STATIC_KEY_TRUE(kasan_enabled);
> > +#endif
> >
> > -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > -                       slab_flags_t *flags);
> > +void __kasan_alloc_pages(struct page *page, unsigned int order);
> > +static inline void kasan_alloc_pages(struct page *page, unsigned int order)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_alloc_pages(page, order);
>
> The patch looks fine per se, but I think with the suggestion in the
> previous patch, this should be:
>
>       if (kasan_is_enabled())
>              __kasan_alloc_pages(page, order);
>
> No overhead for other modes and less logic duplication.

Will do, thanks!

>
> > +}
> >
> > -void kasan_unpoison_data(const void *address, size_t size);
> > -void kasan_unpoison_slab(const void *ptr);
> > +void __kasan_free_pages(struct page *page, unsigned int order);
> > +static inline void kasan_free_pages(struct page *page, unsigned int order)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_free_pages(page, order);
> > +}
> >
> > -void kasan_poison_slab(struct page *page);
> > -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> > -void kasan_poison_object_data(struct kmem_cache *cache, void *object);
> > -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > -                                       const void *object);
> > +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > +                               slab_flags_t *flags);
> > +static inline void kasan_cache_create(struct kmem_cache *cache,
> > +                       unsigned int *size, slab_flags_t *flags)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_cache_create(cache, size, flags);
> > +}
> >
> > -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> > -                                               gfp_t flags);
> > -void kasan_kfree_large(void *ptr, unsigned long ip);
> > -void kasan_poison_kfree(void *ptr, unsigned long ip);
> > -void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> > -                                       size_t size, gfp_t flags);
> > -void * __must_check kasan_krealloc(const void *object, size_t new_size,
> > -                                       gfp_t flags);
> > +size_t __kasan_metadata_size(struct kmem_cache *cache);
> > +static inline size_t kasan_metadata_size(struct kmem_cache *cache)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_metadata_size(cache);
> > +       return 0;
> > +}
> >
> > -void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
> > -                                       gfp_t flags);
> > -bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> > +void __kasan_unpoison_data(const void *addr, size_t size);
> > +static inline void kasan_unpoison_data(const void *addr, size_t size)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_unpoison_data(addr, size);
> > +}
> >
> > -struct kasan_cache {
> > -       int alloc_meta_offset;
> > -       int free_meta_offset;
> > -};
> > +void __kasan_unpoison_slab(const void *ptr);
> > +static inline void kasan_unpoison_slab(const void *ptr)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_unpoison_slab(ptr);
> > +}
> > +
> > +void __kasan_poison_slab(struct page *page);
> > +static inline void kasan_poison_slab(struct page *page)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_poison_slab(page);
> > +}
> > +
> > +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> > +static inline void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_unpoison_object_data(cache, object);
> > +}
> > +
> > +void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
> > +static inline void kasan_poison_object_data(struct kmem_cache *cache, void *object)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_poison_object_data(cache, object);
> > +}
> > +
> > +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> > +                                         const void *object);
> > +static inline void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > +                                                     const void *object)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_init_slab_obj(cache, object);
> > +       return (void *)object;
> > +}
> > +
> > +bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> > +static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_slab_free(s, object, ip);
> > +       return false;
> > +}
> >
> > -size_t kasan_metadata_size(struct kmem_cache *cache);
> > +void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> > +                                      void *object, gfp_t flags);
> > +static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
> > +                                                  void *object, gfp_t flags)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_slab_alloc(s, object, flags);
> > +       return object;
> > +}
> > +
> > +void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
> > +                                   size_t size, gfp_t flags);
> > +static inline void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> > +                                               size_t size, gfp_t flags)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_kmalloc(s, object, size, flags);
> > +       return (void *)object;
> > +}
> > +
> > +void * __must_check __kasan_kmalloc_large(const void *ptr,
> > +                                         size_t size, gfp_t flags);
> > +static inline void * __must_check kasan_kmalloc_large(const void *ptr,
> > +                                                     size_t size, gfp_t flags)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_kmalloc_large(ptr, size, flags);
> > +       return (void *)ptr;
> > +}
> > +
> > +void * __must_check __kasan_krealloc(const void *object,
> > +                                    size_t new_size, gfp_t flags);
> > +static inline void * __must_check kasan_krealloc(const void *object,
> > +                                                size_t new_size, gfp_t flags)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return __kasan_krealloc(object, new_size, flags);
> > +       return (void *)object;
> > +}
> > +
> > +void __kasan_poison_kfree(void *ptr, unsigned long ip);
> > +static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_poison_kfree(ptr, ip);
> > +}
> > +
> > +void __kasan_kfree_large(void *ptr, unsigned long ip);
> > +static inline void kasan_kfree_large(void *ptr, unsigned long ip)
> > +{
> > +       if (static_branch_likely(&kasan_enabled))
> > +               __kasan_kfree_large(ptr, ip);
> > +}
> >
> >  bool kasan_save_enable_multi_shot(void);
> >  void kasan_restore_multi_shot(bool enabled);
> > @@ -108,14 +223,12 @@ void kasan_restore_multi_shot(bool enabled);
> >
> >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> > -
> >  static inline void kasan_cache_create(struct kmem_cache *cache,
> >                                       unsigned int *size,
> >                                       slab_flags_t *flags) {}
> > -
> > -static inline void kasan_unpoison_data(const void *address, size_t size) { }
> > -static inline void kasan_unpoison_slab(const void *ptr) { }
> > -
> > +static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > +static inline void kasan_unpoison_data(const void *address, size_t size) {}
> > +static inline void kasan_unpoison_slab(const void *ptr) {}
> >  static inline void kasan_poison_slab(struct page *page) {}
> >  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
> >                                         void *object) {}
> > @@ -126,36 +239,33 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
> >  {
> >         return (void *)object;
> >  }
> > -
> > -static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
> > +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> > +                                  unsigned long ip)
> >  {
> > -       return ptr;
> > +       return false;
> >  }
> > -static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> > -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> > -static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
> > -                               size_t size, gfp_t flags)
> > +static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> > +                                  gfp_t flags)
> >  {
> > -       return (void *)object;
> > +       return object;
> >  }
> > -static inline void *kasan_krealloc(const void *object, size_t new_size,
> > -                                gfp_t flags)
> > +static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
> > +                               size_t size, gfp_t flags)
> >  {
> >         return (void *)object;
> >  }
> >
> > -static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> > -                                  gfp_t flags)
> > +static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
> >  {
> > -       return object;
> > +       return (void *)ptr;
> >  }
> > -static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> > -                                  unsigned long ip)
> > +static inline void *kasan_krealloc(const void *object, size_t new_size,
> > +                                gfp_t flags)
> >  {
> > -       return false;
> > +       return (void *)object;
> >  }
> > -
> > -static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > +static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> > +static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> >
> >  #endif /* CONFIG_KASAN */
> >
> > diff --git a/include/linux/mm.h b/include/linux/mm.h
> > index a3cac68c737c..701e9d7666d6 100644
> > --- a/include/linux/mm.h
> > +++ b/include/linux/mm.h
> > @@ -1412,22 +1412,36 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
> >  #endif /* CONFIG_NUMA_BALANCING */
> >
> >  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > +
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +DECLARE_STATIC_KEY_FALSE(kasan_enabled);
> > +#else
> > +DECLARE_STATIC_KEY_TRUE(kasan_enabled);
> > +#endif
> > +
> >  static inline u8 page_kasan_tag(const struct page *page)
> >  {
> > -       return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> > +       if (static_branch_likely(&kasan_enabled))
> > +               return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> > +       return 0xff;
> >  }
> >
> >  static inline void page_kasan_tag_set(struct page *page, u8 tag)
> >  {
> > -       page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> > -       page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> > +       if (static_branch_likely(&kasan_enabled)) {
> > +               page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> > +               page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> > +       }
> >  }
> >
> >  static inline void page_kasan_tag_reset(struct page *page)
> >  {
> > -       page_kasan_tag_set(page, 0xff);
> > +       if (static_branch_likely(&kasan_enabled))
> > +               page_kasan_tag_set(page, 0xff);
> >  }
> > -#else
> > +
> > +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> > +
> >  static inline u8 page_kasan_tag(const struct page *page)
> >  {
> >         return 0xff;
> > @@ -1435,7 +1449,8 @@ static inline u8 page_kasan_tag(const struct page *page)
> >
> >  static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
> >  static inline void page_kasan_tag_reset(struct page *page) { }
> > -#endif
> > +
> > +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> >
> >  static inline struct zone *page_zone(const struct page *page)
> >  {
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index cc129ef62ab1..c5ec60e1a4d2 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -81,7 +81,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
> >  }
> >  #endif /* CONFIG_KASAN_STACK */
> >
> > -void kasan_alloc_pages(struct page *page, unsigned int order)
> > +void __kasan_alloc_pages(struct page *page, unsigned int order)
> >  {
> >         u8 tag;
> >         unsigned long i;
> > @@ -95,7 +95,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
> >         kasan_unpoison_memory(page_address(page), PAGE_SIZE << order);
> >  }
> >
> > -void kasan_free_pages(struct page *page, unsigned int order)
> > +void __kasan_free_pages(struct page *page, unsigned int order)
> >  {
> >         if (likely(!PageHighMem(page)))
> >                 kasan_poison_memory(page_address(page),
> > @@ -122,8 +122,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
> >                 object_size <= (1 << 16) - 1024 ? 1024 : 2048;
> >  }
> >
> > -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > -                       slab_flags_t *flags)
> > +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > +                         slab_flags_t *flags)
> >  {
> >         unsigned int orig_size = *size;
> >         unsigned int redzone_size;
> > @@ -165,7 +165,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >         *flags |= SLAB_KASAN;
> >  }
> >
> > -size_t kasan_metadata_size(struct kmem_cache *cache)
> > +size_t __kasan_metadata_size(struct kmem_cache *cache)
> >  {
> >         if (static_branch_unlikely(&kasan_stack))
> >                 return (cache->kasan_info.alloc_meta_offset ?
> > @@ -188,17 +188,17 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> >         return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
> >  }
> >
> > -void kasan_unpoison_data(const void *address, size_t size)
> > +void __kasan_unpoison_data(const void *addr, size_t size)
> >  {
> > -       kasan_unpoison_memory(address, size);
> > +       kasan_unpoison_memory(addr, size);
> >  }
> >
> > -void kasan_unpoison_slab(const void *ptr)
> > +void __kasan_unpoison_slab(const void *ptr)
> >  {
> >         kasan_unpoison_memory(ptr, __ksize(ptr));
> >  }
> >
> > -void kasan_poison_slab(struct page *page)
> > +void __kasan_poison_slab(struct page *page)
> >  {
> >         unsigned long i;
> >
> > @@ -208,12 +208,12 @@ void kasan_poison_slab(struct page *page)
> >                         KASAN_KMALLOC_REDZONE);
> >  }
> >
> > -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> > +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> >  {
> >         kasan_unpoison_memory(object, cache->object_size);
> >  }
> >
> > -void kasan_poison_object_data(struct kmem_cache *cache, void *object)
> > +void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
> >  {
> >         kasan_poison_memory(object,
> >                         round_up(cache->object_size, KASAN_GRANULE_SIZE),
> > @@ -266,7 +266,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
> >  #endif
> >  }
> >
> > -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> >                                                 const void *object)
> >  {
> >         struct kasan_alloc_meta *alloc_meta;
> > @@ -285,7 +285,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >         return (void *)object;
> >  }
> >
> > -static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > +static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> >                               unsigned long ip, bool quarantine)
> >  {
> >         u8 tag;
> > @@ -329,9 +329,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >         return false;
> >  }
> >
> > -bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> > +bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> >  {
> > -       return __kasan_slab_free(cache, object, ip, true);
> > +       return ____kasan_slab_free(cache, object, ip, true);
> >  }
> >
> >  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> > @@ -339,7 +339,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> >         kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> >  }
> >
> > -static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > +static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >                                 size_t size, gfp_t flags, bool keep_tag)
> >  {
> >         unsigned long redzone_start;
> > @@ -371,20 +371,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >         return set_tag(object, tag);
> >  }
> >
> > -void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
> > -                                       gfp_t flags)
> > +void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
> > +                                       void *object, gfp_t flags)
> >  {
> > -       return __kasan_kmalloc(cache, object, cache->object_size, flags, false);
> > +       return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
> >  }
> >
> > -void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > -                               size_t size, gfp_t flags)
> > +void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > +                                       size_t size, gfp_t flags)
> >  {
> > -       return __kasan_kmalloc(cache, object, size, flags, true);
> > +       return ____kasan_kmalloc(cache, object, size, flags, true);
> >  }
> > -EXPORT_SYMBOL(kasan_kmalloc);
> > +EXPORT_SYMBOL(__kasan_kmalloc);
> >
> > -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> > +void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> >                                                 gfp_t flags)
> >  {
> >         struct page *page;
> > @@ -409,7 +409,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> >         return (void *)ptr;
> >  }
> >
> > -void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
> > +void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
> >  {
> >         struct page *page;
> >
> > @@ -419,13 +419,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
> >         page = virt_to_head_page(object);
> >
> >         if (unlikely(!PageSlab(page)))
> > -               return kasan_kmalloc_large(object, size, flags);
> > +               return __kasan_kmalloc_large(object, size, flags);
> >         else
> > -               return __kasan_kmalloc(page->slab_cache, object, size,
> > +               return ____kasan_kmalloc(page->slab_cache, object, size,
> >                                                 flags, true);
> >  }
> >
> > -void kasan_poison_kfree(void *ptr, unsigned long ip)
> > +void __kasan_poison_kfree(void *ptr, unsigned long ip)
> >  {
> >         struct page *page;
> >
> > @@ -438,11 +438,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
> >                 }
> >                 kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
> >         } else {
> > -               __kasan_slab_free(page->slab_cache, ptr, ip, false);
> > +               ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> >         }
> >  }
> >
> > -void kasan_kfree_large(void *ptr, unsigned long ip)
> > +void __kasan_kfree_large(void *ptr, unsigned long ip)
> >  {
> >         if (ptr != page_address(virt_to_head_page(ptr)))
> >                 kasan_report_invalid_free(ptr, ip);
> > --
> > 2.29.0.rc1.297.gfa9743e501-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwjN9MuJ-H%2B1%2BajSq2yAtbdAdHT9NTg5n%2B3hw9z7NH19Q%40mail.gmail.com.
