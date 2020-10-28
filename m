Return-Path: <kasan-dev+bncBCMIZB7QWENRBFWF436AKGQEJDGUC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8163729D125
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 17:55:51 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id s10sf3770047iot.21
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 09:55:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603904150; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fv2yI4aYtW1oEbYk0KFA0nAeoNxvuVD0G0oa3LbvlYYK15oAmUWlZ3Ebs+5e43spP2
         AwdCocbRr3pc/HRCZNjPKo7U8l3aOoqsTnb1QplMKjNNlMPIPMALNLgvEIm0vx08c8KJ
         Esy/bHVGByC70JHg1dzSdssUhd0V8aSiFdlv03lsAVnjckNM2FzczGduscpe/pCdIuQ/
         4K4+7FZouM90G6C9mCBgnv9SGfGXUAWGyl3x3NVJZTzZUDqVcQS2onbhA4tyFvg7WHYC
         IMI+SeBavYDshB1/4PRUFEFD8M1QOa5YvEnBZltOZ0iVY3U+6ny6JukzPWtoMKf6PEq+
         a7Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ySzTrykh658NhQICELUrW+U+jedPNAW0rgd956htEgo=;
        b=pKrAHWCky7BQgLnbdUotCgxJzZk8kaiG8+NAIRGV4Ji5xRU2Ys1yDph5UO1LpcDsOi
         RGDBGWFHcZJxmKK/PRuj7cpq1Ajyj66PjJ+bL4QuuWxH+tdVqx7r+UgHe63CNQaeD7WU
         EQ/ULk7o6wx9EQSMJOjwiWj0tMQjTHEDyrdGUJ0na0TA42vVlD2mNhh6m1HvqGLb4sgD
         OvcVxLDkEECCw+VmpC8gpz5BsO61b0Zm25CY5+VbHV+Mn13+Yu+t0kUi1h9p+kp1TMgQ
         vwDyqbOQF6eZ1ZqMGihb3s2sEffiI9JXDvYpYKb9TH23/f2QH4lqWp4iptdsmMbl7wMx
         bwKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uvnv6eHJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ySzTrykh658NhQICELUrW+U+jedPNAW0rgd956htEgo=;
        b=RhwQUfhTpNcvDkJm8tefaNUGKE1P5h3fytdKGsy98QIp16pEbVn60jL4LbZ056uI6V
         sSI/rLrVHFP1pkE2TKpkOSEwZtWOVvfj0Y2b2CZ05YlrGOggM0pd/NrtTby5WRWtywnV
         oXNJtXYLQFlMs0zU0NltFRwZ9ZmHabvQ/ABFe1+0QXx+lO0lZOkL3+IADMmrHrj0YtAs
         bX3jMJxXqxrf/mudYZFkW41ZvJcoh45ezhoGkkSfZ5xZ5iUWOgGX3tjtV43DqrOXncra
         mdbiLLBiz4b1NIQwwK0ACm2Aqdb8tjGP0CNmWNozphWmDK2pV4hVVieJqSj8CImePbAK
         TyhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ySzTrykh658NhQICELUrW+U+jedPNAW0rgd956htEgo=;
        b=KUF8tuyqIO4+YZC6r9F5BwA3p3XoHMvgvZiA4z20RAqwupE3Q4bP9v22mYdHeu44nN
         EV+feeITGj69SzOyCAGHLbylRuspOqyirXE1STfvyofh8OCFm0dWxCRL6KEFVzK8uxuf
         ssveGpD6VJ2CBUzIF/h0yvKHkdqsr16C2UHKfDaxP4exi4/vzuG0TkgK24nW4QPgHKJX
         ZmCoAHN52hxnoqG+PxhQB2yhkgn1F3Vxq7YxHC6JEneCPVwysH9MMB9B5QwMTVHc2C0w
         dS+yxqET3jTCAaCFSRiht9hVhuc1Axq7roObutnCZoKdtmF64KCnA2H3rklQt4DPykRC
         EoYw==
X-Gm-Message-State: AOAM531IVk6OE5zLmfio/Xe9h03tplsPYTULKweY9xmdC4HtCYAzZKYL
	yFKfTYuQ/vW+ztHcy1eOBig=
X-Google-Smtp-Source: ABdhPJz3IXO8INwkS0y1YOoD8q0pKLrpEDOJ9mHi3nhCsBTNJE3XHHJcKyNniaZ+So9wo60fD0TrhQ==
X-Received: by 2002:a92:9f0c:: with SMTP id u12mr6784986ili.113.1603904150201;
        Wed, 28 Oct 2020 09:55:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2a06:: with SMTP id r6ls39729ile.0.gmail; Wed, 28 Oct
 2020 09:55:49 -0700 (PDT)
X-Received: by 2002:a92:8b41:: with SMTP id i62mr6628148ild.9.1603904149687;
        Wed, 28 Oct 2020 09:55:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603904149; cv=none;
        d=google.com; s=arc-20160816;
        b=Kv3+F4mjXsaSNjM6tLeRvTkZpYusPJAI4VDrwhZPPgz9WMP3+gl5rN0xi7pRKu0i3H
         oHukZcPQSP3C5OANlh15YlmlP1LaDFiqB6bR7vrYcq5iojzaruBh3k+7hS+HvYF4Zou1
         U93eDj2rKSHFdtl/4WTooRddYSGqUanX7n+EX8JBcxhvMGq3p5bnt8laUhcg2YDc7Erd
         SidHW8zlRUiRs3AyNl0z2Wegih4dFm1JiW8dSM7UtL86WzsEqZB99JDBi5D+6MD7DqQ5
         xlId3phz0a0FbbfPSJUpMXJ3PLmy1smcQYGY/yhdmRHg9iWJQtGMSf+wAgWNUbUHBwEa
         xhLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Gj1Q53KOuMFzpLJ+wtLX5dUP0ORJzeWOcnEBSsd3zsg=;
        b=pttTLeyqIYjs41AJoZDCVyGw0VAblDfLjWk5fKyjEoT9pcGMGWXZo9r54my/u5DLby
         hMM25sW7VRwgOSzMPLZ/ojeOFM2Yu0y+CuY4cD1NrIUc/UqBiX+J9+9nhxG7Mt3iOK1N
         x9N3LuwJMt8IGsuMTKYPtNE51tlHXRG5399+E4aIHzuY4ZJHdNGAXOIpSk5RSTSKuS+d
         ikUG1ny1LNxK6c0YILDkph1yGkd6edNI3H7KmHkNCpnUZABn+rZ8GRTdK+Ys6iUWRY3P
         QSpTbAKN0e3T4wVxlTvjV2+G6iKI0OiX1TdcZTEAnpndIDkjyBaudPb6U1K5mo5lOMQw
         b2iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uvnv6eHJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id p5si7575ilg.3.2020.10.28.09.55.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 09:55:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id j62so60618qtd.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 09:55:49 -0700 (PDT)
X-Received: by 2002:ac8:6c54:: with SMTP id z20mr7606223qtu.337.1603904147897;
 Wed, 28 Oct 2020 09:55:47 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ce573435398f21d3e604f104c29ba65eca70d9e7.1603372719.git.andreyknvl@google.com>
In-Reply-To: <ce573435398f21d3e604f104c29ba65eca70d9e7.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 17:55:36 +0100
Message-ID: <CACT4Y+YF9bL8jRjVMfryr+LExYjH-rNdDEq2SvuQD+rGT4mVJQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2 16/21] kasan: optimize poisoning in kmalloc and krealloc
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
 header.i=@google.com header.s=20161025 header.b=uvnv6eHJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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
> Since kasan_kmalloc() always follows kasan_slab_alloc(), there's no need
> to reunpoison the object data, only to poison the redzone.
>
> This requires changing kasan annotation for early SLUB cache to
> kasan_slab_alloc(). Otherwise kasan_kmalloc() doesn't untag the object.
> This doesn't do any functional changes, as kmem_cache_node->object_size
> is equal to sizeof(struct kmem_cache_node).
>
> Similarly for kasan_krealloc(), as it's called after ksize(), which
> already unpoisoned the object, there's no need to do it again.

Have you considered doing this the other way around: make krealloc
call __ksize and unpoison in kasan_krealloc?
This has the advantage of more precise poisoning as ksize will
unpoison the whole underlying object.

But then maybe we will need to move first checks in ksize into __ksize
as we may need them in krealloc as well.





> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I4083d3b55605f70fef79bca9b90843c4390296f2
> ---
>  mm/kasan/common.c | 31 +++++++++++++++++++++----------
>  mm/slub.c         |  3 +--
>  2 files changed, 22 insertions(+), 12 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c5ec60e1a4d2..a581937c2a44 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -360,8 +360,14 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 tag = assign_tag(cache, object, false, keep_tag);
>
> -       /* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
> -       kasan_unpoison_memory(set_tag(object, tag), size);
> +       /*
> +        * Don't unpoison the object when keeping the tag. Tag is kept for:
> +        * 1. krealloc(), and then the memory has already been unpoisoned via ksize();
> +        * 2. kmalloc(), and then the memory has already been unpoisoned by kasan_kmalloc().
> +        * Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS.
> +        */
> +       if (!keep_tag)
> +               kasan_unpoison_memory(set_tag(object, tag), size);
>         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>                 KASAN_KMALLOC_REDZONE);
>
> @@ -384,10 +390,9 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
>  }
>  EXPORT_SYMBOL(__kasan_kmalloc);
>
> -void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> -                                               gfp_t flags)
> +static void * __must_check ____kasan_kmalloc_large(struct page *page, const void *ptr,
> +                                               size_t size, gfp_t flags, bool realloc)
>  {
> -       struct page *page;
>         unsigned long redzone_start;
>         unsigned long redzone_end;
>
> @@ -397,18 +402,24 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>         if (unlikely(ptr == NULL))
>                 return NULL;
>
> -       page = virt_to_page(ptr);
> -       redzone_start = round_up((unsigned long)(ptr + size),
> -                               KASAN_GRANULE_SIZE);
> +       redzone_start = round_up((unsigned long)(ptr + size), KASAN_GRANULE_SIZE);
>         redzone_end = (unsigned long)ptr + page_size(page);
>
> -       kasan_unpoison_memory(ptr, size);
> +       /* ksize() in __do_krealloc() already unpoisoned the memory. */
> +       if (!realloc)
> +               kasan_unpoison_memory(ptr, size);
>         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>                 KASAN_PAGE_REDZONE);
>
>         return (void *)ptr;
>  }
>
> +void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> +                                               gfp_t flags)
> +{
> +       return ____kasan_kmalloc_large(virt_to_page(ptr), ptr, size, flags, false);
> +}
> +
>  void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
>  {
>         struct page *page;
> @@ -419,7 +430,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>         page = virt_to_head_page(object);
>
>         if (unlikely(!PageSlab(page)))
> -               return __kasan_kmalloc_large(object, size, flags);
> +               return ____kasan_kmalloc_large(page, object, size, flags, true);
>         else
>                 return ____kasan_kmalloc(page->slab_cache, object, size,
>                                                 flags, true);
> diff --git a/mm/slub.c b/mm/slub.c
> index 1d3f2355df3b..afb035b0bf2d 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3535,8 +3535,7 @@ static void early_kmem_cache_node_alloc(int node)
>         init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
>         init_tracking(kmem_cache_node, n);
>  #endif
> -       n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
> -                     GFP_KERNEL);
> +       n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
>         page->freelist = get_freepointer(kmem_cache_node, n);
>         page->inuse = 1;
>         page->frozen = 0;
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYF9bL8jRjVMfryr%2BLExYjH-rNdDEq2SvuQD%2BrGT4mVJQ%40mail.gmail.com.
