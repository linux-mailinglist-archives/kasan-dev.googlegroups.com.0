Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB4HWL6QKGQEWX3R2FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F3D882AFBC9
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:36:24 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id 190sf2507671pfz.16
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605141383; cv=pass;
        d=google.com; s=arc-20160816;
        b=cSmoNT1PBprY9QGyQX5+L82adzWu3fGLveqkVak56pjqQKdB6P9wbzmqsmAOON4cou
         FIhSZGuVjH37Tj3Qzs2FZ8vXeje/Q3vFSdEGo3T+hNiUTcJHYtuw7yZwXXbRZCT646QS
         7o2UHbr40V7Rmq9x5m3RXb9f37NXw30HruwS68aQWiHSVzoDGi0+YMw7wHTrzyslk1E/
         iZNYBk2aB4OMM1o/AxJKxldppCIGXcrDr8juB16jUA7Fup3YyKGnM7Nk6TDP6qWIkHxK
         KDEaYibGCw3aGFQBnfNPFicPxZzy6iJOFHUfVyUbWNE45yqK2nKqktypUah97GccK5et
         dhNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FNZdcjS7qb4li2cTCUqoJF99/vbRt5i9MGNegDou2DY=;
        b=Osu97RwvCFQUfU92FishAj52A1vnP2MLpQn2o8BmxecPplLpiKCN1Q0WlbYHQHdzII
         n7M/rno2sJ1F5bozwSowWqjrYMwKSivI0AruQMRTxf5VmeVblPcdtGHNpJDoPUzEcw5B
         /aU8xq3aZ28tTHhuYNTk4JjjCW07ODUfnHXNTO196ktMi4QnEN54/P36fugA9WytT3Yi
         ELuuSTkTGcvM/wax24Q0TPzeh2+n7hfIRL3uBDJu9jYqSLv1WhMVQtrUCTAhroZ8YlNo
         0flz7sNK23GfIwanervgJomWF9q1+JgRNCRTHstbtYL+cF27aS1XvhF7l96PgNrJSCMJ
         1cLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SRSP4bgw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FNZdcjS7qb4li2cTCUqoJF99/vbRt5i9MGNegDou2DY=;
        b=oAs8m5QGCN/1qMlrpC64AOysYIyMPGwgvslFNUSwcEfGjdLrhffXYUWw7osnlw3sMO
         LNL10Z+auPIzHtiSeRRQfh3S1vuxhdX7WJ+h49BbMupSp0/d6y9bgQ95CeK3UfV5jkkt
         LY0DFp2K20/D1HvCeccNQE04/mRkub79fvNPEpOsT4IxHsQIo4fOOQzZyBPWx9qDBhWH
         mwY6cmlBFVtDRVsZPUnUXfKiNTv13tbnx23OrliFHXm7pRajA7BCSkpBhHy0vVZj0d0M
         8Bi91vzQ0dE/jTMXvAgckWgjabtQQ/X8TexwASXHk8cXZym5zkVHq7u+axujJkv/i5lK
         RLJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FNZdcjS7qb4li2cTCUqoJF99/vbRt5i9MGNegDou2DY=;
        b=qQ/l4ntYqVstoXmIFstN6Q9QZb7Rc9liQ4e5GyX3DJQwynLQNsLcSye8MqcCHs0lcM
         OSITN4nHXfisIEpVfG5k6lB8puRF86tyf2AESqXw1bPBdUrO5T8fUKXY14eGLLHTZw2C
         PRBEbkA+/aduE0nAg2AXpVy7yoyqJLHrPzu7OtPxLvDjIJHXsyH1anrJTsPdg1zlSzOs
         PNEozqQ7Mf47wba91Mtynk76Lch0huK1KdWZZXNv+QjVEtSODzNgfUCUsivPPiMJ+JQT
         ZF5HqZ3khA1vBSIPlYy2wKYLeunQsuw5hI1GLOudKV8V9XoKiy7S4Y7STJKDIFBalqXD
         pnUw==
X-Gm-Message-State: AOAM532LFApj1C3/TOdMyvpi1DfCiTpewZN4TPXdqiQdXDHLcngQZLKa
	RS8cubDEVlh7Q5Ma8bEyJ5w=
X-Google-Smtp-Source: ABdhPJxd9z9+1YJhl1cwc6LxUiVztX+T9wSlUhoNjGW594qEqdvnD4rhyWnXNnUW+wOZu1IwPRysLA==
X-Received: by 2002:a62:52d7:0:b029:18b:7093:fb88 with SMTP id g206-20020a6252d70000b029018b7093fb88mr25606457pfb.76.1605141383666;
        Wed, 11 Nov 2020 16:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls432877pga.5.gmail; Wed, 11 Nov
 2020 16:36:23 -0800 (PST)
X-Received: by 2002:a63:4a02:: with SMTP id x2mr20439521pga.313.1605141382986;
        Wed, 11 Nov 2020 16:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605141382; cv=none;
        d=google.com; s=arc-20160816;
        b=ScIfFJGffu8+FP9CDfdIU1ygT6Y7VCDIIw1oE6jq6cSqEN2NquK2/2NCesMntWEaM8
         zy0c6xgkQtZ6JmqJ4MO6siW0zJtfzEfONamsSODnb4nTqFO8PezzxO1ZHvrpK/rQUpqs
         5mqtdv3a3Rw5+5bs4/X/cIF37IQpwlRtC9U5hVt7FkzfKy9mxR4jA+MMbel3kNGmL8N9
         GkT/LZ1pSz4ZIQXU1y86egMKNkl0ds1GeoxQhCMbc32XJImKNQOIJQ4xXw1/hbTXbEje
         /HQwCYSxkUOrs+JMZDQva3XJHGF8McrGZ2ijwUp/nUHTBvhoa0t/Vu3Ntco3z1YAugql
         bPDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CFTbS3XruYMJdExCb+c4iy5kJR85txQxN5EUwdeSKjw=;
        b=f+cCnl42xOmJOYwXpPmbsz5sOVX6RSsrH9eafh/7bYMiWm6ojd7cuMz8ACWdw23FTs
         lESWqNrz2v2tuhU0QRufcAQ1kwxwfG/eyiM6epKb02Bo+W8BIBUXX2ksGbaNiH7nh2YZ
         +lsBGxiaHBuqUa0or+5VdX4kiU4una49HuN66YPRFZY7wHSnBXy2ynhXF0MN5PAbGfJa
         WC+yhPy6Z5nMDiTczylcjxSQ29w+KuNnDo3vFjycJBBwZ6ca/CAkBAkdAEnhLqVDWT+t
         y3j5YYM9g2X0WGkAk/xnZzZHb/kZ1WYanQZ2S+DvOrstEdf7HMVkHwruTqlXdVt+jFJI
         KV5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SRSP4bgw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id e2si120815pjm.2.2020.11.11.16.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 16:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id c20so2872574pfr.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 16:36:22 -0800 (PST)
X-Received: by 2002:a63:1f53:: with SMTP id q19mr24327268pgm.286.1605141382317;
 Wed, 11 Nov 2020 16:36:22 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <22c1a837d4d0c0b241a700c88f180f5e831a1953.1605046662.git.andreyknvl@google.com>
 <CANpmjNOLQm3Em4uNKyrFsxD4umr0M22XYzah7TOGaJaSYCZe1Q@mail.gmail.com>
In-Reply-To: <CANpmjNOLQm3Em4uNKyrFsxD4umr0M22XYzah7TOGaJaSYCZe1Q@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 01:36:11 +0100
Message-ID: <CAAeHK+y+cS8SAeo+iSedd79eudrh4DWa=y4NGMbi4AVd+ZnOxQ@mail.gmail.com>
Subject: Re: [PATCH v2 12/20] kasan, mm: check kasan_enabled in annotations
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SRSP4bgw;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
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

On Wed, Nov 11, 2020 at 3:48 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 10 Nov 2020 at 23:20, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Declare the kasan_enabled static key in include/linux/kasan.h and in
> > include/linux/mm.h and check it in all kasan annotations. This allows to
> > avoid any slowdown caused by function calls when kasan_enabled is
> > disabled.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
> > ---
> >  include/linux/kasan.h | 220 ++++++++++++++++++++++++++++++++----------
> >  include/linux/mm.h    |  22 +++--
> >  mm/kasan/common.c     |  60 ++++++------
> >  3 files changed, 216 insertions(+), 86 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index f1a5042ae4fc..779f8e703982 100644
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
> > @@ -74,56 +75,179 @@ static inline void kasan_disable_current(void) {}
> >
> >  #ifdef CONFIG_KASAN
> >
> > -void kasan_alloc_pages(struct page *page, unsigned int order);
> > -void kasan_free_pages(struct page *page, unsigned int order);
> > +struct kasan_cache {
> > +       int alloc_meta_offset;
> > +       int free_meta_offset;
> > +};
> >
> > -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > -                       slab_flags_t *flags);
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > +static inline kasan_enabled(void)
>
> These are missing types, as noticed by Andrew:
> https://marc.info/?l=linux-mm-commits&m=160505097028591&w=2
>
> > +{
> > +       return static_branch_likely(&kasan_flag_enabled);
> > +}
>
> I think this should be __always_inline, as not inlining is a bug.
>
> Also, I believe that all the below wrappers need to become
> __always_inline, as we really cannot tolerate them not being inlined.

Will do in v3, thanks!

>
> > +#else
> > +static inline kasan_enabled(void)
> > +{
> > +       return true;
> > +}
>
> (Some of these could be on 1 line, but I don't mind.)
>
> > +#endif
>
> > -void kasan_unpoison_data(const void *address, size_t size);
> > -void kasan_unpoison_slab(const void *ptr);
> > +void __kasan_alloc_pages(struct page *page, unsigned int order);
> > +static inline void kasan_alloc_pages(struct page *page, unsigned int order)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_alloc_pages(page, order);
> > +}
> >
> > -void kasan_poison_slab(struct page *page);
> > -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> > -void kasan_poison_object_data(struct kmem_cache *cache, void *object);
> > -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > -                                       const void *object);
> > +void __kasan_free_pages(struct page *page, unsigned int order);
> > +static inline void kasan_free_pages(struct page *page, unsigned int order)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_free_pages(page, order);
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
> > +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > +                               slab_flags_t *flags);
> > +static inline void kasan_cache_create(struct kmem_cache *cache,
> > +                       unsigned int *size, slab_flags_t *flags)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_cache_create(cache, size, flags);
> > +}
> >
> > -void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
> > -                                       gfp_t flags);
> > -bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> > +size_t __kasan_metadata_size(struct kmem_cache *cache);
> > +static inline size_t kasan_metadata_size(struct kmem_cache *cache)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_metadata_size(cache);
> > +       return 0;
> > +}
> >
> > -struct kasan_cache {
> > -       int alloc_meta_offset;
> > -       int free_meta_offset;
> > -};
> > +void __kasan_unpoison_data(const void *addr, size_t size);
> > +static inline void kasan_unpoison_data(const void *addr, size_t size)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_unpoison_data(addr, size);
> > +}
> > +
> > +void __kasan_unpoison_slab(const void *ptr);
> > +static inline void kasan_unpoison_slab(const void *ptr)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_unpoison_slab(ptr);
> > +}
> > +
> > +void __kasan_poison_slab(struct page *page);
> > +static inline void kasan_poison_slab(struct page *page)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_poison_slab(page);
> > +}
> > +
> > +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> > +static inline void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_unpoison_object_data(cache, object);
> > +}
> > +
> > +void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
> > +static inline void kasan_poison_object_data(struct kmem_cache *cache, void *object)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_poison_object_data(cache, object);
> > +}
> > +
> > +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> > +                                         const void *object);
> > +static inline void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > +                                                     const void *object)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_init_slab_obj(cache, object);
> > +       return (void *)object;
> > +}
> > +
> > +bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> > +static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_slab_free(s, object, ip);
> > +       return false;
> > +}
> > +
> > +void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> > +                                      void *object, gfp_t flags);
> > +static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
> > +                                                  void *object, gfp_t flags)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_slab_alloc(s, object, flags);
> > +       return object;
> > +}
> >
> > -size_t kasan_metadata_size(struct kmem_cache *cache);
> > +void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
> > +                                   size_t size, gfp_t flags);
> > +static inline void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> > +                                               size_t size, gfp_t flags)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_kmalloc(s, object, size, flags);
> > +       return (void *)object;
> > +}
> > +
> > +void * __must_check __kasan_kmalloc_large(const void *ptr,
> > +                                         size_t size, gfp_t flags);
> > +static inline void * __must_check kasan_kmalloc_large(const void *ptr,
> > +                                                     size_t size, gfp_t flags)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_kmalloc_large(ptr, size, flags);
> > +       return (void *)ptr;
> > +}
> > +
> > +void * __must_check __kasan_krealloc(const void *object,
> > +                                    size_t new_size, gfp_t flags);
> > +static inline void * __must_check kasan_krealloc(const void *object,
> > +                                                size_t new_size, gfp_t flags)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_krealloc(object, new_size, flags);
> > +       return (void *)object;
> > +}
> > +
> > +void __kasan_poison_kfree(void *ptr, unsigned long ip);
> > +static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_poison_kfree(ptr, ip);
> > +}
> > +
> > +void __kasan_kfree_large(void *ptr, unsigned long ip);
> > +static inline void kasan_kfree_large(void *ptr, unsigned long ip)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_kfree_large(ptr, ip);
> > +}
> >
> >  bool kasan_save_enable_multi_shot(void);
> >  void kasan_restore_multi_shot(bool enabled);
> >
> >  #else /* CONFIG_KASAN */
> >
> > +static inline kasan_enabled(void)
> > +{
> > +       return false;
> > +}
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
> > @@ -134,36 +258,32 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
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
> > +}
> > +static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> > +                                  gfp_t flags)
> > +{
> > +       return object;
> >  }
> > -static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> > -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> >  static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
> >                                 size_t size, gfp_t flags)
> >  {
> >         return (void *)object;
> >  }
> > +static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
> > +{
> > +       return (void *)ptr;
> > +}
> >  static inline void *kasan_krealloc(const void *object, size_t new_size,
> >                                  gfp_t flags)
> >  {
> >         return (void *)object;
> >  }
> > -
> > -static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> > -                                  gfp_t flags)
> > -{
> > -       return object;
> > -}
> > -static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> > -                                  unsigned long ip)
> > -{
> > -       return false;
> > -}
> > -
> > -static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > +static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> > +static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> >
> >  #endif /* CONFIG_KASAN */
> >
> > diff --git a/include/linux/mm.h b/include/linux/mm.h
> > index 0793d03a4183..8d84a6b2fa3c 100644
> > --- a/include/linux/mm.h
> > +++ b/include/linux/mm.h
> > @@ -31,6 +31,7 @@
> >  #include <linux/sizes.h>
> >  #include <linux/sched.h>
> >  #include <linux/pgtable.h>
> > +#include <linux/kasan.h>
> >
> >  struct mempolicy;
> >  struct anon_vma;
> > @@ -1414,22 +1415,30 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
> >  #endif /* CONFIG_NUMA_BALANCING */
> >
> >  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > +
> >  static inline u8 page_kasan_tag(const struct page *page)
> >  {
> > -       return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> > +       if (kasan_enabled())
> > +               return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> > +       return 0xff;
> >  }
> >
> >  static inline void page_kasan_tag_set(struct page *page, u8 tag)
> >  {
> > -       page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> > -       page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> > +       if (kasan_enabled()) {
> > +               page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> > +               page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> > +       }
> >  }
> >
> >  static inline void page_kasan_tag_reset(struct page *page)
> >  {
> > -       page_kasan_tag_set(page, 0xff);
> > +       if (kasan_enabled())
> > +               page_kasan_tag_set(page, 0xff);
> >  }
> > -#else
> > +
> > +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> > +
> >  static inline u8 page_kasan_tag(const struct page *page)
> >  {
> >         return 0xff;
> > @@ -1437,7 +1446,8 @@ static inline u8 page_kasan_tag(const struct page *page)
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
> > index efad5ed6a3bd..385863eaec2c 100644
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
> > @@ -168,7 +168,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >         *flags |= SLAB_KASAN;
> >  }
> >
> > -size_t kasan_metadata_size(struct kmem_cache *cache)
> > +size_t __kasan_metadata_size(struct kmem_cache *cache)
> >  {
> >         if (!kasan_stack_collection_enabled())
> >                 return 0;
> > @@ -191,17 +191,17 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> >         return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
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
> > @@ -211,12 +211,12 @@ void kasan_poison_slab(struct page *page)
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
> > @@ -269,7 +269,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
> >  #endif
> >  }
> >
> > -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> >                                                 const void *object)
> >  {
> >         struct kasan_alloc_meta *alloc_meta;
> > @@ -288,7 +288,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >         return (void *)object;
> >  }
> >
> > -static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > +static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> >                               unsigned long ip, bool quarantine)
> >  {
> >         u8 tag;
> > @@ -331,9 +331,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >         return IS_ENABLED(CONFIG_KASAN_GENERIC);
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
> > @@ -341,7 +341,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> >         kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> >  }
> >
> > -static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > +static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >                                 size_t size, gfp_t flags, bool keep_tag)
> >  {
> >         unsigned long redzone_start;
> > @@ -373,20 +373,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
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
> > @@ -411,7 +411,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> >         return (void *)ptr;
> >  }
> >
> > -void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
> > +void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
> >  {
> >         struct page *page;
> >
> > @@ -421,13 +421,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
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
> > @@ -440,11 +440,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
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
> > 2.29.2.222.g5d2a92d10f8-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By%2BcS8SAeo%2BiSedd79eudrh4DWa%3Dy4NGMbi4AVd%2BZnOxQ%40mail.gmail.com.
