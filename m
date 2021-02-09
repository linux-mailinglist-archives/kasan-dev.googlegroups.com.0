Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIU2RKAQMGQEPHR7LJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B6B92315019
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 14:24:51 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id h10sf9474967ooj.11
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 05:24:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612877090; cv=pass;
        d=google.com; s=arc-20160816;
        b=fFBqeOditHAX/ovSKb5CXyRsG2hUWw0jece++HTcoLjAyJeEMCgBYDQ+7QmJY4eRNq
         Vo9tOlL50HVSC1jYs5SDEbxTfvBibsyZBxiuOFce7ijqBcYdvegVxrz3pYcazSmF/D25
         cvMwnY3gmf1gDeqDP1QYDC/2Fp823VfcRgXtf+0rXyYLlZqY03UvUAvE4T3MaObkbpnk
         nk7vfKyophvsYGTnDz4Qab74RFfCnpNTkk3VjMDSNtwWPoXhB7/3UFa482SIvvAIDYlt
         FDm+KjFSs8PgRh6MRIFb0ea7cfGO42RNeheWAOWbOmnMO7727NevlN8bSJPKHZRyo7Pw
         am6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gCELPwYlYsAJKOwXGYCVUG8H/qc8jLX5buA2s0tXWTU=;
        b=jLGxutW57sMtulqaRid3pwMQfpl5EeqELNfwQnQ8wdBziSULvz0u9O+fB/9KrUzhsb
         UOJK4bhlciKYGkdBxDD/m3HHjYhpqyply9ihr+DL1lsHNPWFhH+CScWVLOxYpZzgHCuJ
         v76KtGRugUMUWKQVYSdnX06G1JPuij115YiUZKFA8PbjCMODnIntHBQt/BaEXZFR9e7z
         FuKVUe5GIUFEIn/neLl1T0uHmotX1PdWLw7D10kHJ7XVSnZaeCXF6iqdN8HSlhZhf0Mv
         LrPMald30ENN3xyV6kJBcGDIi/8QqueCRPZHKMJu1Hoij7fE3kBlZiYU3PTreVK7iwyB
         hPeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Aaono0oI;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCELPwYlYsAJKOwXGYCVUG8H/qc8jLX5buA2s0tXWTU=;
        b=hqUFSLa9zzdNlz6E0TisN+xiV+DLVJBWv+Dr/KT6tctFM5VDa+rY+Tw+wj9MflsYAV
         jG7Lb78Q+iIIdWcrAZ1nOfaydVChzWOPUlfjB7swebinDQQjWSH50VyF/5a/83XGX9BU
         HLyNHuNW2mZrrF4e8Hy04lfgqcTi+kisDziJyZnAKvHOSPsejllR8C0Wq9WUx3rWpeDp
         +uXWiJCB975sh/zqtB8P4vYqYJ1P8RyC43qLegxpO17Cp2htJByHh2krK7UDEb/tHVXO
         EPNq4vuuvTmn5OTOvz3PwyZCWUuqQhOKm8o3g27379y8dbsGditpjtW0xGcl8PncV8dX
         SRFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCELPwYlYsAJKOwXGYCVUG8H/qc8jLX5buA2s0tXWTU=;
        b=k4XugL6CmmDHtRqe7d7/xNVmCR/7W5bRDpzzh30N7wLJvIBbYe9m6N3j2zIGUhbvlm
         P6TKSWdUVQ0oeHjuueWs2ZyoKuJFP/LjEdEx18CZv3bJ9gBlWF9+fQ/WlaWZ/UNRmofo
         smwKSRBxJr0yAmnIenGwrly/2veNaIRJtUCUTrztN/KYqHBsjyzjvE0+ZzBp8RsJuMaB
         kmq7XB8GWObIXu02HCesnpmeUbTCXJmV0kMAs0GVQAWqTWGwWHLe5qeTUum1h6On0VFy
         gJBakeIIDX30C05YFE+dqcP9kShyBgRJGYiQoFJBepf6YCR+PQKDxgbDj4rd0Ho26KNf
         5bDA==
X-Gm-Message-State: AOAM531HC1RFCAHnCULXd/+OaVyNq+0ARyjMly4fVNGO3EZ7ZF7NvJQG
	wD5BME5NEk1wtMfYWgMkoTY=
X-Google-Smtp-Source: ABdhPJxxO/6Nh0dFmKXhA5+HMzTzu17CgtYTJfqc+oEDG9dLYYE7WZQtS3En7QjxHqtPFlHQbQP/dQ==
X-Received: by 2002:a9d:68c5:: with SMTP id i5mr15510525oto.262.1612877090727;
        Tue, 09 Feb 2021 05:24:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:19f8:: with SMTP id t24ls1697426ott.11.gmail; Tue,
 09 Feb 2021 05:24:50 -0800 (PST)
X-Received: by 2002:a05:6830:1c61:: with SMTP id s1mr6758200otg.149.1612877090301;
        Tue, 09 Feb 2021 05:24:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612877090; cv=none;
        d=google.com; s=arc-20160816;
        b=TCjg9GuoMt7HabWIl+U8GSqzC5sbwQXu7OpRWfyFGl8Fmm9E0xy3tGsLt95G1l5fXi
         eooar4f1F3iRpePxMbS2DBW+lbanoyoncxZ96NoGSwdpxkEFHnVsJsUKQqwzV8Prw1EE
         x/1NjO5L8eydWtrtJfp84ddaOgRyaBGoU3Eic/D2qvPMPh4t16MFQDRPvGsqZmUL47ko
         HuA9F3UNwENmfRQKx/MVzq1Qcsg2Znquck6o3MnNV618D7PnO9u2Sg9d7tdlQijnVxSv
         jtIXAexmwJLrJMgVOQz6GKw/pP7yGVrw1Ty8YCqaQ6CxVNiMQFdOiWrrFVrAtY34rzja
         78Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dLaBmb+gbvYqE7SFoBORWrnKQFbpMrwQooOmjDgpSmc=;
        b=nnZSa7ccJl8CY0XvCJzItK30NwFjYeizQFFjrbP7PlWx2mCdmQVfhfWMInb2L6N481
         S4IinDcYfLq639Sulr+cHZBvizDy84uO10YNnx7/4JCcdm676OklzlfnAmI8nfh+BtVo
         6czgWebHa2GQnaKhFvL/50EKXzBLQwUSCW9ciNhsSAjq+o/VZftGV/Bo6AYzJHqfGQnR
         /ecU/JTd87nMCrptDNRQ6r6Tzla9W75PLM5/MgOhAR7Np4zhpVTJdl8tb3zxozWHeq7u
         mFLKfksHXP9C2/ZCG3s7WSVrgRUR+yy/3/xI6tbeNBFsTHcIgH4UpR8BPa3PVYs2C+9b
         Ndyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Aaono0oI;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id b11si1012999otq.0.2021.02.09.05.24.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 05:24:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id u11so9724239plg.13
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 05:24:50 -0800 (PST)
X-Received: by 2002:a17:903:31d1:b029:de:8361:739b with SMTP id
 v17-20020a17090331d1b02900de8361739bmr21064623ple.85.1612877089414; Tue, 09
 Feb 2021 05:24:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com> <9bef90327c9cb109d736c40115684fd32f49e6b0.1612546384.git.andreyknvl@google.com>
 <YCEW4SNDDERCWd7f@elver.google.com>
In-Reply-To: <YCEW4SNDDERCWd7f@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Feb 2021 14:24:38 +0100
Message-ID: <CAAeHK+xHnAVbVOF_wuk3+K5Dy2K2i0NTi+_fZfGX-KHXubRW4A@mail.gmail.com>
Subject: Re: [PATCH v3 mm 08/13] kasan, mm: optimize krealloc poisoning
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Aaono0oI;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::629
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

On Mon, Feb 8, 2021 at 11:48 AM Marco Elver <elver@google.com> wrote:
>
> On Fri, Feb 05, 2021 at 06:34PM +0100, Andrey Konovalov wrote:
> > Currently, krealloc() always calls ksize(), which unpoisons the whole
> > object including the redzone. This is inefficient, as kasan_krealloc()
> > repoisons the redzone for objects that fit into the same buffer.
> >
> > This patch changes krealloc() instrumentation to use uninstrumented
> > __ksize() that doesn't unpoison the memory. Instead, kasan_kreallos()
> > is changed to unpoison the memory excluding the redzone.
> >
> > For objects that don't fit into the old allocation, this patch disables
> > KASAN accessibility checks when copying memory into a new object instead
> > of unpoisoning it.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Clarification below.
>
> > ---
> >  mm/kasan/common.c | 12 ++++++++++--
> >  mm/slab_common.c  | 20 ++++++++++++++------
> >  2 files changed, 24 insertions(+), 8 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 7ea643f7e69c..a8a67dca5e55 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -476,7 +476,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >
> >       /*
> >        * The object has already been unpoisoned by kasan_slab_alloc() for
> > -      * kmalloc() or by ksize() for krealloc().
> > +      * kmalloc() or by kasan_krealloc() for krealloc().
> >        */
> >
> >       /*
> > @@ -526,7 +526,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
> >
> >       /*
> >        * The object has already been unpoisoned by kasan_alloc_pages() for
> > -      * alloc_pages() or by ksize() for krealloc().
> > +      * alloc_pages() or by kasan_krealloc() for krealloc().
> >        */
> >
> >       /*
> > @@ -554,8 +554,16 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
> >       if (unlikely(object == ZERO_SIZE_PTR))
> >               return (void *)object;
> >
> > +     /*
> > +      * Unpoison the object's data.
> > +      * Part of it might already have been unpoisoned, but it's unknown
> > +      * how big that part is.
> > +      */
> > +     kasan_unpoison(object, size);
> > +
> >       page = virt_to_head_page(object);
> >
> > +     /* Piggy-back on kmalloc() instrumentation to poison the redzone. */
> >       if (unlikely(!PageSlab(page)))
> >               return __kasan_kmalloc_large(object, size, flags);
> >       else
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index dad70239b54c..60a2f49df6ce 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -1140,19 +1140,27 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
> >       void *ret;
> >       size_t ks;
> >
> > -     if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
> > -             return NULL;
> > -
> > -     ks = ksize(p);
> > +     /* Don't use instrumented ksize to allow precise KASAN poisoning. */
> > +     if (likely(!ZERO_OR_NULL_PTR(p))) {
> > +             if (!kasan_check_byte(p))
> > +                     return NULL;
>
> Just checking: Check byte returns true if the object is not tracked by KASAN, right? I.e. if it's a KFENCE object, kasan_check_byte() always returns true.

kasan_check_byte() still performs the check, but since KFENCE objects
are never poisoned, the check always passes.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxHnAVbVOF_wuk3%2BK5Dy2K2i0NTi%2B_fZfGX-KHXubRW4A%40mail.gmail.com.
