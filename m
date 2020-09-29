Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBXGZT5QKGQESRBJRDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 391E727CEBA
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:13:43 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id ce9sf1879061ejb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:13:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601385223; cv=pass;
        d=google.com; s=arc-20160816;
        b=FVpviLDKr2rLfcx1JUqrSe2QIQBPAC2rDQ8P4EcA/LI5E5Iz2iVLhS3SLUtLWMOW9C
         J0nw1VFTirGQLyrh77mx3mfnGHblloFqx+8dZqQ76Ao9lFceyIuDIquEZ2OpJEm492yP
         6nm3+pA4adMS05at8w0908SaQDX6DA8dgducNHZK+4rXGuoYYYKqkjmCY4XPSnuQDDNm
         6uBQ59xP5YY1pSUT58GJ/1jugofA8r9D9uoFW18Ai8A2MYETVs/SsQK3q5uYPMyLHTTQ
         9/uhopTYYv4qkjBD9HcgiTo3nsRB3MZszldtTuTpOCCcuS6l7xSbxsHWwoEVepSnjhdV
         3r9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R0c+bg9jKpeWqes9GrVtVgjFYIlTSUoRbws65uwYBMo=;
        b=yiePvZP7SzU5hvPlCseK0bdIm6J/RrpgDNIqvUo10vLnMiDp8L6emTu03LuckoyqYs
         qnQok0Ah1X19ptTPreplaEAvTbyivg4TaNM/Ov0imN1xgk93AIy+9G2oC+kgeo/G3y4s
         I3wmr8QV7AzZKhjOK55Ux3uleU4Qw4KOPb8DI14isgbve7WSM7IXu0qWOGcMfzokjMiF
         lpybFY/H4nvhCEqkcCnj6bAY1DJvfWhSYi3Rw4SF9dg0Eqhg8mTmbRfCzKJLofqY1O6s
         IdQwB8cW2u+dPO59ZSp1Xrs9msapNXpw4yIeiE8jc5/JigiJtHXT7e04yMeTFph+4DQN
         8aJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lq57cMFj;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0c+bg9jKpeWqes9GrVtVgjFYIlTSUoRbws65uwYBMo=;
        b=XyId6Jq8F4vqh2a+K+aWTOhCs2/TVRHXNuhnAm+2aOE6Xa43P/2JrX4GQo4XvOHog9
         NwaVZLbk4Dtix0Tf82geIDtp4QJRU0NTeJkIOC9AOcUQZuPEK+N69n2rGcdHzY3ElgzX
         82gGyrcXG+NsS7ZUzi54o0bk7T2UtPB5npBAsV/6Zx/7bgFvFG2cq7FioLIBs+Za/P3V
         5+vxmF0yLLOSmPBxIWUJs4o1Ew+jnd7reLgSOngWA2aMD2KRjmkqqSOBuM9jQTJ0g1rY
         Fmg0cLtm1pByDfdNFq5klK88BO6jlEI+Lf+kr8t/ll4Jq7AsHjiz5yqgUGtBSSHvgT8w
         PXOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0c+bg9jKpeWqes9GrVtVgjFYIlTSUoRbws65uwYBMo=;
        b=gDkMMn6Otq8xX9jBwm0pUe0n3JaFDNt4N5wX0V7QSNhuonhbUE7hbh6WgL5Fma0d1h
         3CHOPplH5vT/a7LHzvO2X/DtGNrMjNQG6MeaSTv84CM7X87/KfIKJXXd8hi9zF2b5hMC
         rWOz8G6jsMhL2ljU6mNL2XmwFN3oZ2Ya3gJRqfv/Hn70N3qMyXFPcD5cyShKKVWha8d0
         ibQY2AGIA8kzvKVNPSYyRR4shw2t70zoOI+/UI1vbwCWemYuUqM0s3h1o1EcOPjYxFzb
         thLA7cwaq27JZEXoLsIz9k8H9FykXlthqqELcVk3mco3r1KEm48RxFap/ISwGQPnfKoK
         zNvw==
X-Gm-Message-State: AOAM533Cu1jBN8qSlmE9nuArHPKRn8jEo3H5QivwdrhnEaQOZ7Etd+IT
	6Huo2fXwVet5YiGT6ndnTPQ=
X-Google-Smtp-Source: ABdhPJwHAvTgYcv8Z0hfg5NHOkbClp5poXPkBAYRDF8o7O7SI0ozaVZny/OoilQYZHMg2eS7Zaqh8Q==
X-Received: by 2002:a17:907:40c1:: with SMTP id nv1mr3985494ejb.318.1601385222949;
        Tue, 29 Sep 2020 06:13:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:924e:: with SMTP id c14ls1282835ejx.0.gmail; Tue, 29
 Sep 2020 06:13:42 -0700 (PDT)
X-Received: by 2002:a17:906:95cf:: with SMTP id n15mr4014857ejy.14.1601385222012;
        Tue, 29 Sep 2020 06:13:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601385222; cv=none;
        d=google.com; s=arc-20160816;
        b=htLFbKxXUk1sL460s02QBc2w19ecTCrUsyoOouzDT0CQwO6bNk1WhGMXk6NS0B6e0Y
         7/XLsRPAPI2g13roRNcc03bWX4/ezLT/c4X1r3SEopquo6rP56E2e0zSW5nD/UPJksRt
         CGmhvTijFS4XR49av8AZ72RFPZaoW1T2F6aUAuVd5ht49wGlEPUK2kmvbUBV2f2T76ej
         OJhDjMXIsbtB5jYpTp6/R0W3cy/nw81WpbQA5+iGbXCL3OkO7WYQHftnEDAcpLPrvFUz
         0IWVY+98ylaFMFchsW0r5YRnqm/KlVMc8xZ77RcUJKTW0bHoappk71s9CBJcm1NCciiK
         l8/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JTFDtrWAFNtSx+STL9ivxdzcSQCqNLxR2RvvS87FYs8=;
        b=Ekb1F6tUB6jzDGFJTZ8N9ezn33Uu5xYs1M5oUCnAQsE8DSHo+Szs2qdh961x40miPJ
         Qcao8PaBVMtsOJT6fb5rmhx1TPcG8tTzyCIcTa4zYtsncAFsxi12gWR5pANS/eOa9p62
         nqSbqpbRoUCNMAaJZ0RdIisLlkCZRIwZ2Cy2eHsGqdjT4bvWIZfgLJS5XRDLwueZeLj+
         gStnGpFDKRlX1u4awgOB1gT12hhm3D4yfmxSHInFOrWBK9wP+4al7DPzcE4McIHhysvd
         LLA+xG4KzC08jl5b7ZwKIYX35k/0NpNvhNsJmQWohs75W1/laiIDmVnPF5WRPwZsWEnp
         6ttA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lq57cMFj;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id n5si38990eja.0.2020.09.29.06.13.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:13:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id s13so4567145wmh.4
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:13:41 -0700 (PDT)
X-Received: by 2002:a7b:c749:: with SMTP id w9mr4247992wmk.29.1601385221422;
 Tue, 29 Sep 2020 06:13:41 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-7-elver@google.com>
 <CAAeHK+yMmGSTpwC1zPxaoBmXsfmmhuLJ3b2N3qUXUjO5U0tM3Q@mail.gmail.com>
In-Reply-To: <CAAeHK+yMmGSTpwC1zPxaoBmXsfmmhuLJ3b2N3qUXUjO5U0tM3Q@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 15:13:30 +0200
Message-ID: <CAG_fn=VkLKE5OBFatheWGNGy7jcw8iuFqjqCARGu-uWOte6HOw@mail.gmail.com>
Subject: Re: [PATCH v3 06/10] kfence, kasan: make KFENCE compatible with KASAN
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Lq57cMFj;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 29, 2020 at 2:21 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Mon, Sep 21, 2020 at 3:26 PM Marco Elver <elver@google.com> wrote:
> >
> > From: Alexander Potapenko <glider@google.com>
> >
> > We make KFENCE compatible with KASAN for testing KFENCE itself. In
> > particular, KASAN helps to catch any potential corruptions to KFENCE
> > state, or other corruptions that may be a result of freepointer
> > corruptions in the main allocators.
> >
> > To indicate that the combination of the two is generally discouraged,
> > CONFIG_EXPERT=y should be set. It also gives us the nice property that
> > KFENCE will be build-tested by allyesconfig builds.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  lib/Kconfig.kfence | 2 +-
> >  mm/kasan/common.c  | 7 +++++++
> >  2 files changed, 8 insertions(+), 1 deletion(-)
> >
> > diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> > index 4c2ea1c722de..6825c1c07a10 100644
> > --- a/lib/Kconfig.kfence
> > +++ b/lib/Kconfig.kfence
> > @@ -10,7 +10,7 @@ config HAVE_ARCH_KFENCE_STATIC_POOL
> >
> >  menuconfig KFENCE
> >         bool "KFENCE: low-overhead sampling-based memory safety error detector"
> > -       depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> > +       depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
> >         depends on JUMP_LABEL # To ensure performance, require jump labels
> >         select STACKTRACE
> >         help
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 950fd372a07e..f5c49f0fdeff 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/init.h>
> >  #include <linux/kasan.h>
> >  #include <linux/kernel.h>
> > +#include <linux/kfence.h>
> >  #include <linux/kmemleak.h>
> >  #include <linux/linkage.h>
> >  #include <linux/memblock.h>
> > @@ -396,6 +397,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >         tagged_object = object;
> >         object = reset_tag(object);
> >
> > +       if (is_kfence_address(object))
> > +               return false;
> > +
> >         if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
> >             object)) {
> >                 kasan_report_invalid_free(tagged_object, ip);
> > @@ -444,6 +448,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >         if (unlikely(object == NULL))
> >                 return NULL;
> >
> > +       if (is_kfence_address(object))
> > +               return (void *)object;
> > +
> >         redzone_start = round_up((unsigned long)(object + size),
> >                                 KASAN_SHADOW_SCALE_SIZE);
> >         redzone_end = round_up((unsigned long)object + cache->object_size,
> > --
> > 2.28.0.681.g6f77f65b4e-goog
> >
>
> With KFENCE + KASAN both enabled we need to bail out in all KASAN
> hooks that get called from the allocator, right? Do I understand
> correctly that these two are the only ones that are called for
> KFENCE-allocated objects due to the way KFENCE is integrated into the
> allocator?

Yes, these two places were sufficient; we've checked that KFENCE and
KASAN work together.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVkLKE5OBFatheWGNGy7jcw8iuFqjqCARGu-uWOte6HOw%40mail.gmail.com.
