Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4VG42AAMGQE2G7G66Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C20B30C8C2
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 19:01:23 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id f5sf14896661qtf.15
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 10:01:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612288882; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/lBy8GwYzqI+XXMNckBWCbwWsDVzDscEx7FWZLcA3bLo1KNnoh2zPqOPvI8jUtUtJ
         9RGlemOcleRLe598bNXgQ5oRcnREezlXOW9Aqfx+PRDuTQNsqTmUryXU+pHqw92J+yxH
         c5aZl2l/T/0JE568zsdgFH9zLTKNGUhHLYejD2hvWG8w0QIkxhgeAXjKOodQ+bPcD3+c
         TXlzxEg4LWOVABp9foU6BkYz6aeh+zBJZaYy94uGVpwyKf6/NxOnsbMfdl+iqrCuk0QS
         R6S/Op6Eh6J6T0hKOVKKOX0rUdMLAdJARn0L5XPHHIzYHMoJIMXja5iqYYcOMgGWkici
         GNvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gF9hBjDq/Wl7qcw0W160u0sfqOwI7C1bfomRUjHT1/8=;
        b=pifSjXeINbP2CG2UCfZmo+ZAPdtJTvuMJZv2UxG40q3+TR3yDaDSY11x17h88jr6JK
         N6gfaGRpp3+6KfI3izMwUzTPIRnre+CdzOggK1OK2boNlIwxS7XjEJcJjMsKIHDTG8r9
         02wjXPIL2bpoat8+CF0E0KG9bEXXs9Hz8qbpL2dzbs/z0jLwnYNwv7eMxpcpP4LEv7cR
         vuTt64guIuG8LD7zdWigicHGCQ+fVf7WMCE46Gb5FlmvEJPs5Z6s3fS/VwA7TC9e0yvI
         jive+l3/lML4U5FC+0w+9OTsu3awh1PXgbvk4UHthefZ5HnlvzYM1poAEpfWtMTZOCGe
         xX1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jNc6EBwz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gF9hBjDq/Wl7qcw0W160u0sfqOwI7C1bfomRUjHT1/8=;
        b=eRARKnhzkRzOOypMckFBicn4nMBS8RtQjuk+7oqYUeeV/eKJZfaODWYVs7Naa1sL5d
         b7nK3Bb6FKwv31TwNPixb0xCb+vPeqqraunHq2kYA1VXu6jbJotwpL1a5pPKD0dxrW4r
         97N0dSDhkgamSkGysT2wavixT/20VuGH4aVSoG2Ae2sMSrmdMafhqY127R+mobnzaSh+
         15Ed8NhvPAUaMpVVrW2j2rUBdqtrr0yXjynzCZoIE+z+nbmhfGkh+FpXqQG+ARZpWAWD
         SdPqPRcclQGwqYgCgHywqZoi9gY8LJ+OJUsyGxUPqZA+q6ZHCViSKzS3y9uiJp1+AH85
         vOFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gF9hBjDq/Wl7qcw0W160u0sfqOwI7C1bfomRUjHT1/8=;
        b=ZZiRYLv11eeo8KKVV74DnuiEOOebs/1HpeApan1ADZUIBY/ZOU4k29+5khPZZSxXmi
         ynqNXLJhuWgi4qLPUB5zGxlwpslIDJYftE2+D4trsNRWE6hLmlzmkrGQYYLAR8q03T4l
         aJBUs41inB+AoQsMrNo3L3yCDPSz9vtkCnIItwcV5y/kaVsVeMx17QC6gp1CnDAQ4d1H
         sGi1HfKzOtul08RQaV/LV9X7WdWTYEyAXqnlSS93+h1DS77AxAdBAyyiCwHrsPFY9TYG
         nLiCAYaFu7SzHnfq5SlERPKXGMHDPmZrgo4HP59XwAnfc0w2sAz07wcOK2wOtphJe4OC
         92Tw==
X-Gm-Message-State: AOAM533PW0AzK84XZHoYoJXK725oMCHFZAFJ/7mHQDwj+wEilt/YsTzE
	o9Dc/4HyFrAQpE8Gt6xZ6zY=
X-Google-Smtp-Source: ABdhPJxRDl3nJnPYnJ764xN/dXRWfZ7aTeSca4IdGhdFBVIYAQPWkdYnuYwWxLQwPooEdPzxJa251A==
X-Received: by 2002:ac8:1c61:: with SMTP id j30mr18676630qtk.297.1612288882452;
        Tue, 02 Feb 2021 10:01:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a404:: with SMTP id n4ls5427510qke.7.gmail; Tue, 02 Feb
 2021 10:01:22 -0800 (PST)
X-Received: by 2002:a37:a3cc:: with SMTP id m195mr21332929qke.400.1612288882128;
        Tue, 02 Feb 2021 10:01:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612288882; cv=none;
        d=google.com; s=arc-20160816;
        b=hj0x6cqcqlDHnKA+kPdfA5AhgAg9wfLBY3GVmup7k6Isc6NwlSI9vqbNrIbUJZrbe4
         aNcBbmHBBRf7xOJJXhMivYjSXTPzD3KFnW3WPv//Kismr8Ze9H5AKkuvHOEWM+lKYE53
         H3kPFjuQ6YBfn8ODsanLiZRYguvXnEu+M0/T04xQ+WT69qj/4UhGMplj2VtF4L3YyZM0
         CoShnD9BiEbjDur7M/Mg2yEpW9KI8yGll5YW/6LWCD+YL3kfIgkVK5+sbgynCZDIc1Q0
         047OcXAArIoCHAVhOGk1UzaHhq1NYjxJ74bC1YG2SBXnQsb4oJ28BcBcTX5+6q8I+gJD
         PYEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L1MZ9fF4ca6SaeZxY2832DoPpHMX3bUKUCoXNkXBzTg=;
        b=PH5Wln3OE5D5aTF/+DSqFymzuAsJEGmE8gQbxxPSK7CQMRytLqlN39jzQwIXiunzVc
         Jsl9DV2SzknpMUQLRyUwSVEWozydnqw9zCgEoo1/Z2ZXQJ9+N9k6nb3Eb+bKtQMN955P
         LIUM18ufqQSjMEhcMRVRwFJUDiQ+TcDIuH6YbhYIG4Exoiaswzr98D5CEYGA3p9V9KPn
         2froYBggFf/sr8Q3HnmlqbO1R3bZvBRuKybfjNzojhVqCaNxrJRAFIhT32Mnqwj9JirT
         BAd5FOT95+m8nz4w/F7DFt5gql/yp1CN4eLhAEJzVKAfNYijc32KiiGkMUfDvJQG/lWS
         WxZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jNc6EBwz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id c3si1293714qkc.2.2021.02.02.10.01.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 10:01:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id b8so12911243plh.12
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 10:01:22 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr5531989pjb.166.1612288881120;
 Tue, 02 Feb 2021 10:01:21 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com> <c153f78b173df7537c9be6f2f3a888ddf0b42a3b.1612208222.git.andreyknvl@google.com>
 <YBl4fY54BN4PaLVG@elver.google.com>
In-Reply-To: <YBl4fY54BN4PaLVG@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 19:01:09 +0100
Message-ID: <CAAeHK+wnufE=jOAOsG6LTA5Objcj=OyakEDr4zPKVW+Qq+y28g@mail.gmail.com>
Subject: Re: [PATCH 01/12] kasan, mm: don't save alloc stacks twice
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jNc6EBwz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b
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

On Tue, Feb 2, 2021 at 5:06 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> > Currently KASAN saves allocation stacks in both kasan_slab_alloc() and
> > kasan_kmalloc() annotations. This patch changes KASAN to save allocation
> > stacks for slab objects from kmalloc caches in kasan_kmalloc() only,
> > and stacks for other slab objects in kasan_slab_alloc() only.
> >
> > This change requires ____kasan_kmalloc() knowing whether the object
> > belongs to a kmalloc cache. This is implemented by adding a flag field
> > to the kasan_info structure. That flag is only set for kmalloc caches
> > via a new kasan_cache_create_kmalloc() annotation.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> > ---
> >  include/linux/kasan.h |  9 +++++++++
> >  mm/kasan/common.c     | 18 ++++++++++++++----
> >  mm/slab_common.c      |  1 +
> >  3 files changed, 24 insertions(+), 4 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 6d8f3227c264..2d5de4092185 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -83,6 +83,7 @@ static inline void kasan_disable_current(void) {}
> >  struct kasan_cache {
> >       int alloc_meta_offset;
> >       int free_meta_offset;
> > +     bool is_kmalloc;
> >  };
> >
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > @@ -143,6 +144,13 @@ static __always_inline void kasan_cache_create(struct kmem_cache *cache,
> >               __kasan_cache_create(cache, size, flags);
> >  }
> >
> > +void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
> > +static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
> > +{
> > +     if (kasan_enabled())
> > +             __kasan_cache_create_kmalloc(cache);
> > +}
> > +
> >  size_t __kasan_metadata_size(struct kmem_cache *cache);
> >  static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
> >  {
> > @@ -278,6 +286,7 @@ static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> >  static inline void kasan_cache_create(struct kmem_cache *cache,
> >                                     unsigned int *size,
> >                                     slab_flags_t *flags) {}
> > +static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
> >  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> >  static inline void kasan_poison_slab(struct page *page) {}
> >  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index fe852f3cfa42..374049564ea3 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -210,6 +210,11 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >               *size = optimal_size;
> >  }
> >
> > +void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
> > +{
> > +     cache->kasan_info.is_kmalloc = true;
> > +}
> > +
> >  size_t __kasan_metadata_size(struct kmem_cache *cache)
> >  {
> >       if (!kasan_stack_collection_enabled())
> > @@ -394,17 +399,22 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
> >       }
> >  }
> >
> > -static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> > +static void set_alloc_info(struct kmem_cache *cache, void *object,
> > +                             gfp_t flags, bool kmalloc)
> >  {
> >       struct kasan_alloc_meta *alloc_meta;
> >
> > +     /* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
> > +     if (cache->kasan_info.is_kmalloc && !kmalloc)
> > +             return;
> > +
> >       alloc_meta = kasan_get_alloc_meta(cache, object);
> >       if (alloc_meta)
> >               kasan_set_track(&alloc_meta->alloc_track, flags);
> >  }
> >
> >  static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > -                             size_t size, gfp_t flags, bool keep_tag)
> > +                             size_t size, gfp_t flags, bool kmalloc)
> >  {
> >       unsigned long redzone_start;
> >       unsigned long redzone_end;
> > @@ -423,7 +433,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >                               KASAN_GRANULE_SIZE);
> >       redzone_end = round_up((unsigned long)object + cache->object_size,
> >                               KASAN_GRANULE_SIZE);
> > -     tag = assign_tag(cache, object, false, keep_tag);
> > +     tag = assign_tag(cache, object, false, kmalloc);
> >
> >       /* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
> >       kasan_unpoison(set_tag(object, tag), size);
> > @@ -431,7 +441,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >                          KASAN_KMALLOC_REDZONE);
> >
> >       if (kasan_stack_collection_enabled())
> > -             set_alloc_info(cache, (void *)object, flags);
> > +             set_alloc_info(cache, (void *)object, flags, kmalloc);
>
> It doesn't bother me too much, but: 'bool kmalloc' shadows function
> 'kmalloc' so this is technically fine, but using 'kmalloc' as the
> variable name here might be confusing and there is a small chance it
> might cause problems in a future refactor.

Good point. Does "is_kmalloc" sound good?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwnufE%3DjOAOsG6LTA5Objcj%3DOyakEDr4zPKVW%2BQq%2By28g%40mail.gmail.com.
