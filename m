Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7GFQD6QKGQEJMXA3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id ADA5E2A2DEC
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 16:17:17 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id p17sf10558324ilb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 07:17:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604330236; cv=pass;
        d=google.com; s=arc-20160816;
        b=NX7XzDcB1FVI+/1QwD3384YpaNR0DJA4sRyXC6T3Lwc+XAUcr4SMpANGu360+IyBsb
         yT2AN/QZHaadg+B4F+KPN83LgzwEXVi+K9pfaewwMtO96ZGoeLy+CGsY88t/efcKgcXT
         BwE2AnNLaHykTunob2HbreaibXfB4IBzpPKy31yDfSNLn72REJ7rAsCFJ514GhvIe83i
         k6Dn/f46c7f3Ke5py9e9mZ3iUoKU7V3B27hZ7Vn/EJrXU7s4unU2kkPXqvm+BfShtjxj
         1aYwMGXUUUE+bSXaeNHI/i8BUjujMBWf3BtbN7kYnfalCkMW8lwcKO4EUrKrXfl5jK4W
         E3Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tv6j/MGtPPVrUdXVQcLbZJ5dkQsTYZ/dpFTLlFzccWA=;
        b=CcmiX8ipAN8uDybrF007tr9hN8zhko0GxwArWximBDi5+NFCjWQ+0xu0ciO+aObJpn
         6gGQnBpz2mOo6Tu7Vv1pcPX0vz4cor/edIPCPdhYtBy+Htjgx+gU0ynEYDy4LuviUelU
         u+kTHcS7gKDW+JRzX5nGljuHKBvTepP3nJdOBFouLe/S+PGWnVysUaXUL2Xk2HQF2Exx
         zE66DEwQ9oB26sXlLvMvF7LNt+k5cdgsz1pwZJps+0bnBNJsnBh4W8EY91m3PvTJ35x3
         oo6b9ArUQut+qsfz/4q7J0CVONPU3Pkirg++MIRsxHKWL5sDr/gbcj0SSThd+9zeBwh1
         jNgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="DkhU/qMV";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tv6j/MGtPPVrUdXVQcLbZJ5dkQsTYZ/dpFTLlFzccWA=;
        b=KKJEgTo2O8tLQtbyzZKT9Xsw5d+MYAtgdUlJ2JYAPD0U/mELsylx/47e+5qcZNK1kZ
         10G7ZajtiIFuInurUw2Qe5Xykygr4VaLY7SY3nImMZ0CobVD3fuFVWum1zKncC6hUjPN
         quGWtUtGoUvzPxm1CYZn1m/BrOXiv9FOKryKAyJyHMhPL7M/vricYxh8cfg9gCQPanA/
         uIQCaVoqvxcLKlEB/1Zyjz+Sp52VU/Ac7dXX4t8TFFRX9xyTUdaEx7OgY9KbM9rcWpkH
         oFSftH+Z0cZ+5eiCqSu5HmlX7++VCkGlk/+Qx2VwIGTTG9PgV/4ZpvXQRKYgdxZsamNL
         ezpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tv6j/MGtPPVrUdXVQcLbZJ5dkQsTYZ/dpFTLlFzccWA=;
        b=VEg4+FXwazZ5ybKVyUlp5cL7yGPf/gde+NL6LMRKz11ulpPa4BFf+jGvuhtSmvEPw0
         N+ZFSf4vBVEeu4ntZXD6aWbf/w9frVODpQvO2PQeMZHbfujsSHaj7iDmenaKAwGQRWyV
         z+DNUNIR3tzYTWrQoilgQ8ayQ8A7l6T9MwYeehK4JE8IiBFQb+Cod7rbrb3rtUACliwu
         JCvgynNAU7qwecpK8whNTccmzIg4FU9WdJA3jC/JlfWQcUgEugZ+E+hAGlYz19WvKiH6
         IRlrmQg2zByMXQIz8ezPhNlr/cm0D34v8fs1nil1BWgTr1jIxLVHXpfmdjTYVs1nAtgQ
         mo1w==
X-Gm-Message-State: AOAM5335AHzzJMuXoMlI3C8H38eExezfyBVHSnciJeljiZgjOZsZJLOM
	ri/qmZqv6UQW0DyTjWiSUaI=
X-Google-Smtp-Source: ABdhPJzxuPYIhER7Xh2WLlRL2h+J+RTOEA9FDXzuR+GimIEq2tGFiL4BXMZtiN/waUQEyDMHtOENSA==
X-Received: by 2002:a05:6e02:2cc:: with SMTP id v12mr11450863ilr.115.1604330236469;
        Mon, 02 Nov 2020 07:17:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:140f:: with SMTP id n15ls3138183ilo.4.gmail; Mon,
 02 Nov 2020 07:17:16 -0800 (PST)
X-Received: by 2002:a92:6b08:: with SMTP id g8mr5606804ilc.32.1604330236035;
        Mon, 02 Nov 2020 07:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604330236; cv=none;
        d=google.com; s=arc-20160816;
        b=co7mlk1WrBZXJ+717/wOveQfPGFU8xfFeDHaCWCQ7n+1A39XYHq9GZzNi9PvyMuWCS
         NQh6LwjqOTEv2GdnN8ou9lG+nWrsiAHtrMZSM0XLMFmDEeQTCnCt2knS/FuWeISvjvCy
         aBXFsBkEcqPRpzhWYR9db4zzOceYxgTLvV1dTCehz/54652DjW3cnHdv5XX+cAq5WN93
         XwOxe0yQAaTyJzgwHDvo6Q8lTn/xj3V8LmQ0xK6u0EFI+JmknGEO3tOlrZGdQ+lKro2Q
         ytDa34n8WIY9sDpD9tcEpzrq/zSXAhijBi8204MFIUOL8+6HINRe1cesQcjdtDdh/RFy
         EieQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3SSjI8L6tAN7wnaresierGkcZcom6o46dDNzyiPHjlU=;
        b=qjJKJopsCC2DXIOUwQUMG2Dmb00tRPlKvNfW4iimrEarc2DFULBKD3BFUZaam8noFc
         q3mqUo1gPa1UinjYsr99u5XhT5KBgp6/E4/mK3RBBobD0xVjZa/EYT5sP660IVY2yzfF
         OUT/q3KuikzWhlisjRlufOKOdS5n+IqWY1coCHbc7Ye89PXoG1pyTib9BzV+2VS2FVfa
         VZlSDjM6bWiFd53foX4FbWG37JImQjOhRhx0NoTJhviq5RNNV5rpZ0Oem4KzY8OmFY3n
         sm3Zq3oF2R6X4mt/kGIbAK3kXTLZXZZyswbP0jsZNcSPAsAzcA1Iarl+ad7R3NduH1zt
         vPeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="DkhU/qMV";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id y16si756512ilk.4.2020.11.02.07.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 07:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id t14so11048437pgg.1
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 07:17:16 -0800 (PST)
X-Received: by 2002:a63:d456:: with SMTP id i22mr13760189pgj.440.1604330235200;
 Mon, 02 Nov 2020 07:17:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ce573435398f21d3e604f104c29ba65eca70d9e7.1603372719.git.andreyknvl@google.com>
 <CACT4Y+YF9bL8jRjVMfryr+LExYjH-rNdDEq2SvuQD+rGT4mVJQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YF9bL8jRjVMfryr+LExYjH-rNdDEq2SvuQD+rGT4mVJQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Nov 2020 16:17:04 +0100
Message-ID: <CAAeHK+zTPyX6h+8uJvjKwryA1U3L0ErufSoAmNvBu=QC5bomXw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 16/21] kasan: optimize poisoning in kmalloc and krealloc
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
 header.i=@google.com header.s=20161025 header.b="DkhU/qMV";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Wed, Oct 28, 2020 at 5:55 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Since kasan_kmalloc() always follows kasan_slab_alloc(), there's no need
> > to reunpoison the object data, only to poison the redzone.
> >
> > This requires changing kasan annotation for early SLUB cache to
> > kasan_slab_alloc(). Otherwise kasan_kmalloc() doesn't untag the object.
> > This doesn't do any functional changes, as kmem_cache_node->object_size
> > is equal to sizeof(struct kmem_cache_node).
> >
> > Similarly for kasan_krealloc(), as it's called after ksize(), which
> > already unpoisoned the object, there's no need to do it again.
>
> Have you considered doing this the other way around: make krealloc
> call __ksize and unpoison in kasan_krealloc?
> This has the advantage of more precise poisoning as ksize will
> unpoison the whole underlying object.
>
> But then maybe we will need to move first checks in ksize into __ksize
> as we may need them in krealloc as well.

This might be a good idea. I won't implement this for the next
version, but will look into this after that. Thanks!

>
>
>
>
>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I4083d3b55605f70fef79bca9b90843c4390296f2
> > ---
> >  mm/kasan/common.c | 31 +++++++++++++++++++++----------
> >  mm/slub.c         |  3 +--
> >  2 files changed, 22 insertions(+), 12 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index c5ec60e1a4d2..a581937c2a44 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -360,8 +360,14 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> >                 tag = assign_tag(cache, object, false, keep_tag);
> >
> > -       /* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
> > -       kasan_unpoison_memory(set_tag(object, tag), size);
> > +       /*
> > +        * Don't unpoison the object when keeping the tag. Tag is kept for:
> > +        * 1. krealloc(), and then the memory has already been unpoisoned via ksize();
> > +        * 2. kmalloc(), and then the memory has already been unpoisoned by kasan_kmalloc().
> > +        * Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS.
> > +        */
> > +       if (!keep_tag)
> > +               kasan_unpoison_memory(set_tag(object, tag), size);
> >         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
> >                 KASAN_KMALLOC_REDZONE);
> >
> > @@ -384,10 +390,9 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
> >  }
> >  EXPORT_SYMBOL(__kasan_kmalloc);
> >
> > -void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> > -                                               gfp_t flags)
> > +static void * __must_check ____kasan_kmalloc_large(struct page *page, const void *ptr,
> > +                                               size_t size, gfp_t flags, bool realloc)
> >  {
> > -       struct page *page;
> >         unsigned long redzone_start;
> >         unsigned long redzone_end;
> >
> > @@ -397,18 +402,24 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> >         if (unlikely(ptr == NULL))
> >                 return NULL;
> >
> > -       page = virt_to_page(ptr);
> > -       redzone_start = round_up((unsigned long)(ptr + size),
> > -                               KASAN_GRANULE_SIZE);
> > +       redzone_start = round_up((unsigned long)(ptr + size), KASAN_GRANULE_SIZE);
> >         redzone_end = (unsigned long)ptr + page_size(page);
> >
> > -       kasan_unpoison_memory(ptr, size);
> > +       /* ksize() in __do_krealloc() already unpoisoned the memory. */
> > +       if (!realloc)
> > +               kasan_unpoison_memory(ptr, size);
> >         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
> >                 KASAN_PAGE_REDZONE);
> >
> >         return (void *)ptr;
> >  }
> >
> > +void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> > +                                               gfp_t flags)
> > +{
> > +       return ____kasan_kmalloc_large(virt_to_page(ptr), ptr, size, flags, false);
> > +}
> > +
> >  void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
> >  {
> >         struct page *page;
> > @@ -419,7 +430,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
> >         page = virt_to_head_page(object);
> >
> >         if (unlikely(!PageSlab(page)))
> > -               return __kasan_kmalloc_large(object, size, flags);
> > +               return ____kasan_kmalloc_large(page, object, size, flags, true);
> >         else
> >                 return ____kasan_kmalloc(page->slab_cache, object, size,
> >                                                 flags, true);
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 1d3f2355df3b..afb035b0bf2d 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -3535,8 +3535,7 @@ static void early_kmem_cache_node_alloc(int node)
> >         init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
> >         init_tracking(kmem_cache_node, n);
> >  #endif
> > -       n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
> > -                     GFP_KERNEL);
> > +       n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
> >         page->freelist = get_freepointer(kmem_cache_node, n);
> >         page->inuse = 1;
> >         page->frozen = 0;
> > --
> > 2.29.0.rc1.297.gfa9743e501-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzTPyX6h%2B8uJvjKwryA1U3L0ErufSoAmNvBu%3DQC5bomXw%40mail.gmail.com.
