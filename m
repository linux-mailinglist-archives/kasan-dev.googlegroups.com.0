Return-Path: <kasan-dev+bncBCMIZB7QWENRBEPAZ36QKGQERMKVUJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 78DDE2B5E0C
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 12:12:18 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id u129sf14335438ilc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 03:12:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605611537; cv=pass;
        d=google.com; s=arc-20160816;
        b=KynfH1DYc2ApbufStgzr2PVOL0l8/vCV/sacEo7toaUEnabpn0VLMSyMmTzBFxyq5W
         7NZjXJR9zxJdW+McHqvSQiu3KDyqm5bFrbCqt78z0w5HZAyx447rSiYLOqqRSh5diI6J
         V2pSMepDT4+mqis/ipz7ZaCPIFDmdWPlOtgi1dZNJJW1BMdMbEjSEvy/1DksGZ/gZZdO
         oF2jtwEmbhIMDAsGpa4L6msybUO9p0jAvc9Y0d/hd88bVA689R2V3RrhjvvfYA54t8LV
         0uvZIEkbFeFJtEGgfvibtNZkUQQ92IyxUCCXy8ZL9CE8Y4gfOwHaK2NbfyEtAvIRisoe
         myOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=biv+3qu31rs+WoFOLcVOolN4IDLZCp7U16Awyz6O2uA=;
        b=vJkXV7F34M6+zo+hW/RbHAT5TIbBj6sbPABCv+AwmFqiD6d+X1JvqfZeG1h3/lKnj4
         eDj188EoAfkEY3dIbK4SeBYWeodDmbG0UGHqfqwZgFsrfkO5geZDvwmzHx+mGN5rfN0F
         ZbAA1H+ib51erEhnmnRaFN4kdPjAmn7miPga0fU2aTK3mpOCHAd3f4yZv9An8+26dr5e
         8DFJZS+RLY1m72BFXZZyY0fG2jSJuvW81kW35f3DpiYGZjtxV3BS+jSbYMJ83nc3A86Z
         oCEHqlITK0+0+vsL3Ej3KnKkTCmxo8uQ0OXhbnMu16nMgVWF2NGWkx+Nwc9CII9ayyr8
         YJPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mU76moTE;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=biv+3qu31rs+WoFOLcVOolN4IDLZCp7U16Awyz6O2uA=;
        b=PrOSiow18sPqg8TI4IWut0eNh1Wclckq6URW7Vs6IOUg+NVWjrTb6fyDY8XbdWwZNW
         G2eNqUuUsfo70E1kJteQgpzI5fPbmR3FQd48Emgp6OrL5K3/GjgSTLG8Kr2clebIo5So
         pzAUpJC9XXQPpMdEhMmjnE1ygPNTaRgwJFqEDhAo8iK1YLZZv9WZKkfJP63WnXNpJl3F
         MN3mtHAlG14++TdraovZuAaucuB2FEwkZg7JPBa0IUu7qrxsi/9dMg+1dnMGc8nwQJ+2
         fN57IntQm7+yAXtsBAR9BFIyKAVzNiQXN/dwOt3F3wr6EAIRcT+aAZJslrurx9crk4M+
         OGIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=biv+3qu31rs+WoFOLcVOolN4IDLZCp7U16Awyz6O2uA=;
        b=mZ47OmFEqHDP6cV44fZRJHRWM/49/7tZfqRp6SiFTHege5b8txBinb/chLWb5GWuRj
         c3qGk3uordmHr9rq5N8rk/ZgGv2Oocdgm8gAEIDRN6Tf6pUVOhgOD59QxpuhfEnvJCT2
         GNt2gqqS6zfbCY8zuQ2YDZ89BNfQn+wEaWxKHuDg6aKMrnQV/VIKr/VbHh0wGRxRRIAc
         dqlBYY03Wiv+dVhMESo16ZcqdQK0+XTTLkZOCiMytbS2trvTme7iLDo6c4Sfg4XHHj13
         2RHrGfc59GkOA9Ase+vKaG76HnF+D5HSFDl7+60UWRhdvL50jAFKVpxSW3EfL6iwcQQI
         9eGQ==
X-Gm-Message-State: AOAM531ofmKzru2SwQ0YnG7iuzg7N+JKItIg51T7zStJ5Or+N1EkttaA
	l5ELISwL70SUZAdBdGmD1AY=
X-Google-Smtp-Source: ABdhPJxENwRvdEO6/HXJddtGcDMbPNIO2F0PWcm/qeInKhEI+PzkH4xQnZROozouUQSWTAQL3Zen4g==
X-Received: by 2002:a92:d03:: with SMTP id 3mr752734iln.197.1605611537469;
        Tue, 17 Nov 2020 03:12:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a41:: with SMTP id 62ls1914216jaw.1.gmail; Tue, 17 Nov
 2020 03:12:17 -0800 (PST)
X-Received: by 2002:a05:6638:159:: with SMTP id y25mr3231014jao.4.1605611537055;
        Tue, 17 Nov 2020 03:12:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605611537; cv=none;
        d=google.com; s=arc-20160816;
        b=sDFh0Lw6g9Y5BfXwagCdP5BEDep36xtrVq2/uc3qC7Z4k4lstp2y0HJVvvXK8bM/8r
         hBCaawmlTVoL7mwmapwcvbmXqaasUYKwDckFzW3moJyMaZoipalmM7+3KAPmYZ2MRTkt
         fcLUGm+DggyBZXpRFHyKud87M+e0zXHUq1ZtPovz0rylZUoCQDOzTQEKsEkbWgCr14om
         JZlg+vVd3m39aKEXrGNJrDaqKEEEM07eHIl+2OFGX7U6leKT30r0SZsFkcH4FZyaq/Z6
         9K0JJ8iSosnAFZmwLWTxWHeu/hbl9vn7fzKO2J2MaSExRAnPAq/gkOgLVkoca0uJOTRl
         wV7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SWCyNDrYaNVDsvMRvzDZ8b9wPrMc5eTPA+QwYkR7Xz4=;
        b=HMn0GZcLeLHvGPq0RODB5Yw9S4PBmStxS3KKC+o+u+3OTarqrjzq+fhnfnY8/NLU9b
         rhW10YnF+uUtmwoKw8WK2+DCmG98xe6aTrJySBX6b+DA5ab+Gl6WsFL1wrioQlKf3IJl
         v6BTRvMbIDQk3tLbICtPihs4mTqVtHCFyCzvFd5FNDPMV4X4iuc6XaAGCcf45unL44VN
         cy9Qx34XHvtfr02dOOx8rzvcGXYLTcgMSU565n+H0upSr5nuz6yBGi1NaqIen532YpQP
         Q3WEysRX86nVlH7kWmFFVJvIeyI3Rgw0C4O8Ls54lBWvE07dY/Twk8QmgLGk+danEO2y
         u5xQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mU76moTE;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id y11si646622ily.1.2020.11.17.03.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 03:12:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id a15so8198818qvk.5
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 03:12:17 -0800 (PST)
X-Received: by 2002:a05:6214:9c4:: with SMTP id dp4mr19039666qvb.44.1605611536141;
 Tue, 17 Nov 2020 03:12:16 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <68b9e818c971a28c4b8082d6dbac52967553bd73.1605305978.git.andreyknvl@google.com>
 <20201116152624.GD1357314@elver.google.com>
In-Reply-To: <20201116152624.GD1357314@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 12:12:05 +0100
Message-ID: <CACT4Y+btgvMM78Bhnmz7S2c8u+hgNMzPGXxE-rWsypGCRMCptA@mail.gmail.com>
Subject: Re: [PATCH mm v3 12/19] kasan, mm: check kasan_enabled in annotations
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mU76moTE;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Mon, Nov 16, 2020 at 4:26 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Nov 13, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > Declare the kasan_enabled static key in include/linux/kasan.h and in
> > include/linux/mm.h and check it in all kasan annotations. This allows to
> > avoid any slowdown caused by function calls when kasan_enabled is
> > disabled.
> >
> > Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> > Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
>
> Reviewed-by: Marco Elver <elver@google.com>

Also much nicer with kasan_enabled() now.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> > ---
> >  include/linux/kasan.h | 213 ++++++++++++++++++++++++++++++++----------
> >  include/linux/mm.h    |  22 +++--
> >  mm/kasan/common.c     |  56 +++++------
> >  3 files changed, 210 insertions(+), 81 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 872bf145ddde..6bd95243a583 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -2,6 +2,7 @@
> >  #ifndef _LINUX_KASAN_H
> >  #define _LINUX_KASAN_H
> >
> > +#include <linux/static_key.h>
> >  #include <linux/types.h>
> >
> >  struct kmem_cache;
> > @@ -74,54 +75,176 @@ static inline void kasan_disable_current(void) {}
> >
> >  #ifdef CONFIG_KASAN
> >
> > -void kasan_unpoison_range(const void *address, size_t size);
> > +struct kasan_cache {
> > +     int alloc_meta_offset;
> > +     int free_meta_offset;
> > +};
> >
> > -void kasan_alloc_pages(struct page *page, unsigned int order);
> > -void kasan_free_pages(struct page *page, unsigned int order);
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > +static __always_inline bool kasan_enabled(void)
> > +{
> > +     return static_branch_likely(&kasan_flag_enabled);
> > +}
> > +#else
> > +static inline bool kasan_enabled(void)
> > +{
> > +     return true;
> > +}
> > +#endif
> >
> > -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > -                     slab_flags_t *flags);
> > +void __kasan_unpoison_range(const void *addr, size_t size);
> > +static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_unpoison_range(addr, size);
> > +}
> >
> > -void kasan_poison_slab(struct page *page);
> > -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> > -void kasan_poison_object_data(struct kmem_cache *cache, void *object);
> > -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > -                                     const void *object);
> > +void __kasan_alloc_pages(struct page *page, unsigned int order);
> > +static __always_inline void kasan_alloc_pages(struct page *page,
> > +                                             unsigned int order)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_alloc_pages(page, order);
> > +}
> >
> > -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> > -                                             gfp_t flags);
> > -void kasan_kfree_large(void *ptr, unsigned long ip);
> > -void kasan_poison_kfree(void *ptr, unsigned long ip);
> > -void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> > -                                     size_t size, gfp_t flags);
> > -void * __must_check kasan_krealloc(const void *object, size_t new_size,
> > -                                     gfp_t flags);
> > +void __kasan_free_pages(struct page *page, unsigned int order);
> > +static __always_inline void kasan_free_pages(struct page *page,
> > +                                             unsigned int order)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_free_pages(page, order);
> > +}
> >
> > -void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
> > -                                     gfp_t flags);
> > -bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> > +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > +                             slab_flags_t *flags);
> > +static __always_inline void kasan_cache_create(struct kmem_cache *cache,
> > +                             unsigned int *size, slab_flags_t *flags)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_cache_create(cache, size, flags);
> > +}
> >
> > -struct kasan_cache {
> > -     int alloc_meta_offset;
> > -     int free_meta_offset;
> > -};
> > +size_t __kasan_metadata_size(struct kmem_cache *cache);
> > +static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_metadata_size(cache);
> > +     return 0;
> > +}
> > +
> > +void __kasan_poison_slab(struct page *page);
> > +static __always_inline void kasan_poison_slab(struct page *page)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_poison_slab(page);
> > +}
> > +
> > +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
> > +static __always_inline void kasan_unpoison_object_data(struct kmem_cache *cache,
> > +                                                     void *object)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_unpoison_object_data(cache, object);
> > +}
> > +
> > +void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
> > +static __always_inline void kasan_poison_object_data(struct kmem_cache *cache,
> > +                                                     void *object)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_poison_object_data(cache, object);
> > +}
> > +
> > +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> > +                                       const void *object);
> > +static __always_inline void * __must_check kasan_init_slab_obj(
> > +                             struct kmem_cache *cache, const void *object)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_init_slab_obj(cache, object);
> > +     return (void *)object;
> > +}
> > +
> > +bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> > +static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> > +                                             unsigned long ip)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_slab_free(s, object, ip);
> > +     return false;
> > +}
> > +
> > +void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> > +                                    void *object, gfp_t flags);
> > +static __always_inline void * __must_check kasan_slab_alloc(
> > +                             struct kmem_cache *s, void *object, gfp_t flags)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_slab_alloc(s, object, flags);
> > +     return object;
> > +}
> > +
> > +void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
> > +                                 size_t size, gfp_t flags);
> > +static __always_inline void * __must_check kasan_kmalloc(struct kmem_cache *s,
> > +                             const void *object, size_t size, gfp_t flags)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_kmalloc(s, object, size, flags);
> > +     return (void *)object;
> > +}
> >
> > -size_t kasan_metadata_size(struct kmem_cache *cache);
> > +void * __must_check __kasan_kmalloc_large(const void *ptr,
> > +                                       size_t size, gfp_t flags);
> > +static __always_inline void * __must_check kasan_kmalloc_large(const void *ptr,
> > +                                                   size_t size, gfp_t flags)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_kmalloc_large(ptr, size, flags);
> > +     return (void *)ptr;
> > +}
> > +
> > +void * __must_check __kasan_krealloc(const void *object,
> > +                                  size_t new_size, gfp_t flags);
> > +static __always_inline void * __must_check kasan_krealloc(const void *object,
> > +                                              size_t new_size, gfp_t flags)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_krealloc(object, new_size, flags);
> > +     return (void *)object;
> > +}
> > +
> > +void __kasan_poison_kfree(void *ptr, unsigned long ip);
> > +static __always_inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_poison_kfree(ptr, ip);
> > +}
> > +
> > +void __kasan_kfree_large(void *ptr, unsigned long ip);
> > +static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_kfree_large(ptr, ip);
> > +}
> >
> >  bool kasan_save_enable_multi_shot(void);
> >  void kasan_restore_multi_shot(bool enabled);
> >
> >  #else /* CONFIG_KASAN */
> >
> > +static inline bool kasan_enabled(void)
> > +{
> > +     return false;
> > +}
> >  static inline void kasan_unpoison_range(const void *address, size_t size) {}
> > -
> >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> > -
> >  static inline void kasan_cache_create(struct kmem_cache *cache,
> >                                     unsigned int *size,
> >                                     slab_flags_t *flags) {}
> > -
> > +static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> >  static inline void kasan_poison_slab(struct page *page) {}
> >  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
> >                                       void *object) {}
> > @@ -132,36 +255,32 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
> >  {
> >       return (void *)object;
> >  }
> > -
> > -static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
> > +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> > +                                unsigned long ip)
> >  {
> > -     return ptr;
> > +     return false;
> > +}
> > +static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> > +                                gfp_t flags)
> > +{
> > +     return object;
> >  }
> > -static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> > -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> >  static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
> >                               size_t size, gfp_t flags)
> >  {
> >       return (void *)object;
> >  }
> > +static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
> > +{
> > +     return (void *)ptr;
> > +}
> >  static inline void *kasan_krealloc(const void *object, size_t new_size,
> >                                gfp_t flags)
> >  {
> >       return (void *)object;
> >  }
> > -
> > -static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> > -                                gfp_t flags)
> > -{
> > -     return object;
> > -}
> > -static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> > -                                unsigned long ip)
> > -{
> > -     return false;
> > -}
> > -
> > -static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > +static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> > +static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> >
> >  #endif /* CONFIG_KASAN */
> >
> > diff --git a/include/linux/mm.h b/include/linux/mm.h
> > index 947f4f1a6536..24f47e140a4c 100644
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
> > @@ -1415,22 +1416,30 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
> >  #endif /* CONFIG_NUMA_BALANCING */
> >
> >  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > +
> >  static inline u8 page_kasan_tag(const struct page *page)
> >  {
> > -     return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> > +     if (kasan_enabled())
> > +             return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> > +     return 0xff;
> >  }
> >
> >  static inline void page_kasan_tag_set(struct page *page, u8 tag)
> >  {
> > -     page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> > -     page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> > +     if (kasan_enabled()) {
> > +             page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
> > +             page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
> > +     }
> >  }
> >
> >  static inline void page_kasan_tag_reset(struct page *page)
> >  {
> > -     page_kasan_tag_set(page, 0xff);
> > +     if (kasan_enabled())
> > +             page_kasan_tag_set(page, 0xff);
> >  }
> > -#else
> > +
> > +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> > +
> >  static inline u8 page_kasan_tag(const struct page *page)
> >  {
> >       return 0xff;
> > @@ -1438,7 +1447,8 @@ static inline u8 page_kasan_tag(const struct page *page)
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
> > index a11e3e75eb08..17918bd20ed9 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -59,7 +59,7 @@ void kasan_disable_current(void)
> >  }
> >  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> >
> > -void kasan_unpoison_range(const void *address, size_t size)
> > +void __kasan_unpoison_range(const void *address, size_t size)
> >  {
> >       unpoison_range(address, size);
> >  }
> > @@ -87,7 +87,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
> >  }
> >  #endif /* CONFIG_KASAN_STACK */
> >
> > -void kasan_alloc_pages(struct page *page, unsigned int order)
> > +void __kasan_alloc_pages(struct page *page, unsigned int order)
> >  {
> >       u8 tag;
> >       unsigned long i;
> > @@ -101,7 +101,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
> >       unpoison_range(page_address(page), PAGE_SIZE << order);
> >  }
> >
> > -void kasan_free_pages(struct page *page, unsigned int order)
> > +void __kasan_free_pages(struct page *page, unsigned int order)
> >  {
> >       if (likely(!PageHighMem(page)))
> >               poison_range(page_address(page),
> > @@ -128,8 +128,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
> >               object_size <= (1 << 16) - 1024 ? 1024 : 2048;
> >  }
> >
> > -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > -                     slab_flags_t *flags)
> > +void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > +                       slab_flags_t *flags)
> >  {
> >       unsigned int orig_size = *size;
> >       unsigned int redzone_size;
> > @@ -174,7 +174,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >       *flags |= SLAB_KASAN;
> >  }
> >
> > -size_t kasan_metadata_size(struct kmem_cache *cache)
> > +size_t __kasan_metadata_size(struct kmem_cache *cache)
> >  {
> >       if (!kasan_stack_collection_enabled())
> >               return 0;
> > @@ -197,7 +197,7 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> >       return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
> >  }
> >
> > -void kasan_poison_slab(struct page *page)
> > +void __kasan_poison_slab(struct page *page)
> >  {
> >       unsigned long i;
> >
> > @@ -207,12 +207,12 @@ void kasan_poison_slab(struct page *page)
> >                    KASAN_KMALLOC_REDZONE);
> >  }
> >
> > -void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> > +void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
> >  {
> >       unpoison_range(object, cache->object_size);
> >  }
> >
> > -void kasan_poison_object_data(struct kmem_cache *cache, void *object)
> > +void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
> >  {
> >       poison_range(object,
> >                       round_up(cache->object_size, KASAN_GRANULE_SIZE),
> > @@ -265,7 +265,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
> >  #endif
> >  }
> >
> > -void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > +void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> >                                               const void *object)
> >  {
> >       struct kasan_alloc_meta *alloc_meta;
> > @@ -284,7 +284,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >       return (void *)object;
> >  }
> >
> > -static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > +static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> >                             unsigned long ip, bool quarantine)
> >  {
> >       u8 tag;
> > @@ -330,9 +330,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >       return IS_ENABLED(CONFIG_KASAN_GENERIC);
> >  }
> >
> > -bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> > +bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> >  {
> > -     return __kasan_slab_free(cache, object, ip, true);
> > +     return ____kasan_slab_free(cache, object, ip, true);
> >  }
> >
> >  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> > @@ -340,7 +340,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> >       kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> >  }
> >
> > -static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > +static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >                               size_t size, gfp_t flags, bool keep_tag)
> >  {
> >       unsigned long redzone_start;
> > @@ -375,20 +375,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >       return set_tag(object, tag);
> >  }
> >
> > -void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
> > -                                     gfp_t flags)
> > +void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
> > +                                     void *object, gfp_t flags)
> >  {
> > -     return __kasan_kmalloc(cache, object, cache->object_size, flags, false);
> > +     return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
> >  }
> >
> > -void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > -                             size_t size, gfp_t flags)
> > +void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > +                                     size_t size, gfp_t flags)
> >  {
> > -     return __kasan_kmalloc(cache, object, size, flags, true);
> > +     return ____kasan_kmalloc(cache, object, size, flags, true);
> >  }
> > -EXPORT_SYMBOL(kasan_kmalloc);
> > +EXPORT_SYMBOL(__kasan_kmalloc);
> >
> > -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> > +void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> >                                               gfp_t flags)
> >  {
> >       struct page *page;
> > @@ -413,7 +413,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> >       return (void *)ptr;
> >  }
> >
> > -void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
> > +void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
> >  {
> >       struct page *page;
> >
> > @@ -423,13 +423,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
> >       page = virt_to_head_page(object);
> >
> >       if (unlikely(!PageSlab(page)))
> > -             return kasan_kmalloc_large(object, size, flags);
> > +             return __kasan_kmalloc_large(object, size, flags);
> >       else
> > -             return __kasan_kmalloc(page->slab_cache, object, size,
> > +             return ____kasan_kmalloc(page->slab_cache, object, size,
> >                                               flags, true);
> >  }
> >
> > -void kasan_poison_kfree(void *ptr, unsigned long ip)
> > +void __kasan_poison_kfree(void *ptr, unsigned long ip)
> >  {
> >       struct page *page;
> >
> > @@ -442,11 +442,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
> >               }
> >               poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
> >       } else {
> > -             __kasan_slab_free(page->slab_cache, ptr, ip, false);
> > +             ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> >       }
> >  }
> >
> > -void kasan_kfree_large(void *ptr, unsigned long ip)
> > +void __kasan_kfree_large(void *ptr, unsigned long ip)
> >  {
> >       if (ptr != page_address(virt_to_head_page(ptr)))
> >               kasan_report_invalid_free(ptr, ip);
> > --
> > 2.29.2.299.gdc1121823c-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbtgvMM78Bhnmz7S2c8u%2BhgNMzPGXxE-rWsypGCRMCptA%40mail.gmail.com.
