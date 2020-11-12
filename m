Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYMUWL6QKGQELB4VRQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 302FB2AFBDE
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 02:05:38 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id o16sf2397247qtr.14
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:05:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605143137; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJ9SVQDXmZZ99awDrtifpf0YjijlVvyj4HRoyKKL7SpB4rjp9460i5MBVNcEboLcsr
         iR1a1//5Us3cB4qJjHELdpFKf2tPG+ep386Nh0MDIkbdvqd5vC/+/dSiByzIzVmjrUF9
         d8LFbiiTzCVMaBAy5CxCqlkCOWSzeKfvbIT/ERL7jjpUV8Z8hD4ocPe2ZCDB8ODgXlPH
         FsMfnV+zx5tEhrOykAgLYVeF6zHaL4BJv9ZMsAywi7vyM/XBYSpJsYSZr5MlF0S6OPMM
         bq9NVJD43pcUUNgPl7qd5wdJoC7jYZg9cU48kZWQiaxA3FCjEui+MZwuXElvPhy3iFpO
         MdaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sGk85ICtQeJ4RiKT0Z/6ezuKDZZ2rGdi6h/T1fLIOsI=;
        b=ygtG22X2+IsWa3a9xQ2xTiR4etQKqLSbY8bJINaIbqqO1/9jaYkoWz/+ocxG2XTHfb
         p2PvyJ7VIwV3Bgd1lnGcoSdT+pc19FAFyNjbaIUQhY2ACYsgNEuuaAIEX3UoqDJXTpEw
         riW7d4gULBWl2e9xN/7rjYrmEMP8Ijq16ShwrDM+p1SV/68ZiCcZGyb7zAX0K/LBaEZ6
         bQMcppEoq4zQZG/n+utLrWYhsAx0/v6ooh9w3zbmQLBH5hXIXsS/NdG2BUbd1ZcWTf+u
         BMArjje2wxMDnK+bLpmUJLcurD48m3Sgm1Xe6TQyvpBGIvQ46SXnhd5+HL09/K7JMNcv
         m54Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n0qYkfxG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sGk85ICtQeJ4RiKT0Z/6ezuKDZZ2rGdi6h/T1fLIOsI=;
        b=QY9hEZeEPRK5j/MxL6ilZZfS95z0m1SWGoWAm0rurTsx7sAGS6Fq73eo1OUwlzh1Yj
         7LUML0hAPQp6gn32CvNWNeAPYSK4uTdTr3Z3Al6Vhdo/+emiqfXjxK4zWJLv3jWHbaew
         +UVyrVO63TtYSAgRonSQh4kPvCqv6+cYB2xH3PP+NF5rHuFFs83wuMdcLH/0GORsz2Wd
         O+st+Wr13lhlrYm9OGZwXPI5QfDpPzyz/2JMlLJJYBxinkvwB48f1Z4w58NOo0NktugW
         dpD4w/sfWH7c/4Kt+O1pc4TpK6e8JdwQbtwJkWQOEfY/HkGu68VeYzTgMJsxBdMsoQ5I
         bsPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sGk85ICtQeJ4RiKT0Z/6ezuKDZZ2rGdi6h/T1fLIOsI=;
        b=LM1KFyPdkDYVbRNB/itr4GjborJi9/pOMXWC34U6hHIRfqfvwFVed3zC76JmMtFyVf
         ef85itJL3P3R9xjFlWKugRy0nLoXenhJMXU7wWLzcSflrZBT3aqHLGXiKuqGUdUq6RO+
         mppJAn2LzZXQcFPxCHdLKvQQf7+I87yHDAPUsyyvjFZIgkv8zYTZwV2HldY7QzfvTOu1
         baVWQsfNzY4ONKLx9TiZKSIc15nt7dJgvBSOg0dm9UKkovx0/9baNXj9JZAh7udJ1WsL
         +6NAM+1jg+oj26W3p4gd97ZJ0Gav0g75Idd+CVCVVt0ww5MMPEwTouTDGkPt5dnYlrWt
         y2kw==
X-Gm-Message-State: AOAM5320bWnhKAzauDt1hHl59tWjc3X8oatMI5H6EStT7hZEx2DGXtMT
	QSPjGrPuawwHYacUsw2b9w4=
X-Google-Smtp-Source: ABdhPJyChWR2XjhBQuu1GOqfejVn2LdAZOQ3A0BfZOAoDtihsLOcUTdziORQbfHlxtSEKadvZSoypg==
X-Received: by 2002:a0c:d6cb:: with SMTP id l11mr27685069qvi.9.1605143137107;
        Wed, 11 Nov 2020 17:05:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b6c4:: with SMTP id g187ls93687qkf.7.gmail; Wed, 11 Nov
 2020 17:05:36 -0800 (PST)
X-Received: by 2002:a37:8906:: with SMTP id l6mr18359293qkd.356.1605143136506;
        Wed, 11 Nov 2020 17:05:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605143136; cv=none;
        d=google.com; s=arc-20160816;
        b=c6KTQ0m/VEvKyt+tQ5gc4kuc8obNX3gz1JDYyCrNB0lYce3a7PSPmvy2Vo8SFz9cIm
         t61dhMQxo44ZP8mi5YZHOVtX25++UcsvEXA0nlW/qfgWzOtCNy6x0q/MYVmmlKucJpVy
         Y8tXUEpXIQFu3cg14Uv6rwuTdgfRejS9u1wAzHK9PbWXspKl6uYEfOi4buKJsDOca2u2
         EWYuMlEfWHLYrqmngS2qt0sRD945lZJw54L/Dl4zYMK5knX+FjlnI3BfMwn9+fFhe8Sh
         79cuB1kGNsmBTr1RGkxbo38RKyeEMrY//otnqNBqZ+Xhcf6MAz3kus3bbj4WRsbmuS7a
         OUmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l+cNXIP3GmliSWhOXa8yhQOrloSbuarLwUXvnWs+zAI=;
        b=RxmfEggVLYo5jj8VQ2zU8FloWx+722L10o25GrkJYUIU28G7UrRLzLwixDxFrJwOAT
         sCfcRmT5bQfsOUuDJ6vZ271K15DViB1hfOKUlGxLhstrCTNCTQ8MKZx81ymzUSVvxCk8
         eB5A5nIVaPlEQpxcIaJ4ecDOpCpqIUS75guOQcGolqY54525XX2H7vqfdm8oW/+wCGLN
         oBdVX1GfMBZKulFtOhGZUquYVU6+iF9uDHPZ80qTT3LAkq07ZKxix+nrwzKSovvWaP5l
         VaJnLnDav5uxQUtgQf7e7bra4gogio6em00kl9OSlmzdFZGFV/liecSY4bgbyqGofl2G
         /1VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n0qYkfxG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id r3si236894qtn.0.2020.11.11.17.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 17:05:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id u2so1898058pls.10
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 17:05:36 -0800 (PST)
X-Received: by 2002:a17:902:bb95:b029:d7:db34:2ddb with SMTP id
 m21-20020a170902bb95b02900d7db342ddbmr9884528pls.85.1605143135417; Wed, 11
 Nov 2020 17:05:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <ee33aa1d9c57c3f2b2c700e8f2c6c24db8703612.1605046662.git.andreyknvl@google.com>
 <20201111185326.GP517454@elver.google.com>
In-Reply-To: <20201111185326.GP517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 02:05:24 +0100
Message-ID: <CAAeHK+zZu60aYGkzj34vqQ8pM=afLXGNqVECt68f5oDjHhQwqA@mail.gmail.com>
Subject: Re: [PATCH v2 14/20] kasan, mm: rename kasan_poison_kfree
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
 header.i=@google.com header.s=20161025 header.b=n0qYkfxG;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
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

On Wed, Nov 11, 2020 at 7:53 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > Rename kasan_poison_kfree() to kasan_slab_free_mempool() as it better
> > reflects what this annotation does.
>
> This function is again so simple, and now it seems it's mempool
> specific, can't we just remove it and open-code it in mempool.c?

The simplification introduced in the previous patch is based on a
false assumption and will be reverted. Thus will keep this as a
separate function.

>
> > No functional changes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
> > ---
> >  include/linux/kasan.h | 16 ++++++++--------
> >  mm/kasan/common.c     | 16 ++++++++--------
> >  mm/mempool.c          |  2 +-
> >  3 files changed, 17 insertions(+), 17 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 779f8e703982..534ab3e2935a 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -177,6 +177,13 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned
> >       return false;
> >  }
> >
> > +void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
> > +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_slab_free_mempool(ptr, ip);
> > +}
> > +
> >  void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> >                                      void *object, gfp_t flags);
> >  static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
> > @@ -217,13 +224,6 @@ static inline void * __must_check kasan_krealloc(const void *object,
> >       return (void *)object;
> >  }
> >
> > -void __kasan_poison_kfree(void *ptr, unsigned long ip);
> > -static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> > -{
> > -     if (kasan_enabled())
> > -             __kasan_poison_kfree(ptr, ip);
> > -}
> > -
> >  void __kasan_kfree_large(void *ptr, unsigned long ip);
> >  static inline void kasan_kfree_large(void *ptr, unsigned long ip)
> >  {
> > @@ -263,6 +263,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> >  {
> >       return false;
> >  }
> > +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
> >  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> >                                  gfp_t flags)
> >  {
> > @@ -282,7 +283,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
> >  {
> >       return (void *)object;
> >  }
> > -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> >  static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> >
> >  #endif /* CONFIG_KASAN */
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 819403548f2e..60793f8695a8 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -336,6 +336,14 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> >       return ____kasan_slab_free(cache, object, ip, true);
> >  }
> >
> > +void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
> > +{
> > +     struct page *page;
> > +
> > +     page = virt_to_head_page(ptr);
> > +     ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> > +}
> > +
> >  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> >  {
> >       kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> > @@ -427,14 +435,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
> >                                               flags, true);
> >  }
> >
> > -void __kasan_poison_kfree(void *ptr, unsigned long ip)
> > -{
> > -     struct page *page;
> > -
> > -     page = virt_to_head_page(ptr);
> > -     ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> > -}
> > -
> >  void __kasan_kfree_large(void *ptr, unsigned long ip)
> >  {
> >       if (ptr != page_address(virt_to_head_page(ptr)))
> > diff --git a/mm/mempool.c b/mm/mempool.c
> > index f473cdddaff0..b1f39fa75ade 100644
> > --- a/mm/mempool.c
> > +++ b/mm/mempool.c
> > @@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
> >  static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
> >  {
> >       if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
> > -             kasan_poison_kfree(element, _RET_IP_);
> > +             kasan_slab_free_mempool(element, _RET_IP_);
>
> This is already a kasan-prefixed function, so if
> kasan_slab_free_mempool() is only ever called in this function, we
> should just call kasan_slab_free() here directly with the 2 extra args
> it requires open-coded.
>
> >       else if (pool->alloc == mempool_alloc_pages)
> >               kasan_free_pages(element, (unsigned long)pool->pool_data);
> >  }
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzZu60aYGkzj34vqQ8pM%3DafLXGNqVECt68f5oDjHhQwqA%40mail.gmail.com.
