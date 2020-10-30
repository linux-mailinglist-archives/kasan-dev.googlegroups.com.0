Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT6T6H6AKGQE27LHTBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CCBC2A0EAB
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 20:30:24 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id m3sf909566uao.6
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 12:30:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604086223; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uj4R4HnGrX1bbLlSoYFMvXkfus8pc77zfRP6NKCzxwWVF0exgB3gURcAMq9NLYPXNI
         USMFd2abRnxVmA+RGxwg6ao/fm7kd3O3BwiVf+2tiYsaeEzbLRTxHJlRygGXEvQGZJ4f
         aK1bQJMaLFFUgWNCKhtst9IH3RVYpcF/GcgeUL0xEjHF/H3g2o4Yv6lxfvsvcpIqwBey
         bxMs8zgNv85lKPM7Fo8bONQsM9f11h71LTxHxrvRviw9pnwy4D5vr6lBnj76dzZalqz7
         5n1IavMv6KkYu749qoAmR0IbPYu309PwAVWldWuUOEcgHKLmj43msOOWxBJEcTeSBwE2
         KOMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WAcp4TplJj+yAupgX799ptFzh6swizD7bY/e+lzFcC0=;
        b=eWAlZjRUIEyemaUe2YuXixVn4P3YkEH+GnRJNoQxcN/J8qqPvZhYNTXA+wLJsjd+2X
         X10l1ydRJ7gRKFsWUhN/gYr0DQ97D0DuN0oSVP63uKG5OP76rO5BGOf91z3yH6VlO8qL
         rKY5W2mjUOpL7vVqwAvg/Ql7LkuaMWp2OWxORmpS96Gd24o/vRS7g0SWKS+TxYaU27r5
         V9Ox90N4cX3R8TVW206/qoLOk6Uep6eT8M83BjntI8rLtD5trd3lwaO/MPHVLyVma0IO
         tn8icVI46uocE1el09tGvj5To2Xs/dQrfzRLaWlBFSORCaofOqHDcvrPQ1yQWj9j1Akr
         QDwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iaEVNbKj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WAcp4TplJj+yAupgX799ptFzh6swizD7bY/e+lzFcC0=;
        b=BHvGmWCF35SKaVQrfHC5YYrNPXARkUAeTYP+8WcN33s/wRvqScHlI61Ixi2SYhQoe1
         SNkc1+L8H/ySj7tUqnWaTg1+LcgmND4EZZ6cbXFE/NL4tWpYDuCG8/edFp9jqnFnTPd5
         nBLUYSR2vvGyarnEh46FucHMq6HIYtbCFcw17xCYSSB0t47dJzEGVXhyQfjFl6+2+RB2
         0N0fdL8kYOU1rf23dCA0ShI7vzqTh2rSYxDJcMj+2ppgIzHLrwIYLfJOPX7ilVcb4oUM
         ZIFOeUcm33kb+7GlllWAcAhhDIcqLvmz+QO0xjo/mSv7urG41zFgoUXwLPg7/OWJZRyi
         ZwYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WAcp4TplJj+yAupgX799ptFzh6swizD7bY/e+lzFcC0=;
        b=gYmUOByL5BqFJkUK5Q0nT3D1Kb8SBUKozgqxqWdXrKIbiftheyGOE0JAvEjuBR03fE
         68TveYzRdu6uO7aHgOlKfO8TqOZBqyg5senKLcI9s7yF9Z//m8XTM0ZuYhOhVbgYrX+J
         mq3UDwKC+keN65vaRhnfzvOqkBigl93Mb7o5VuBJ4fHGvNvbeOZ8eI3ZSbAZ3w70NAic
         eABvTlAFpplxV3maGecysAnNk1K+lGKNHrVKz7HlGpaE7BITTdEH8DYttcmqUlnsItxR
         zEFxrMKgFH1TuHwltnSFa6pTd1OtodUiXi9v9QI/QzDRcpGTqi/PpxHREpIwI+D8zLiG
         f8Pg==
X-Gm-Message-State: AOAM531ram8X9lzMfe/NVdzog1MULTg7v73TW3O9Fr2ihHe78+AJjwcW
	gSm+nerKTZalZat6HVIDsxM=
X-Google-Smtp-Source: ABdhPJwveFiYAFCOHEcd4iiHr35Orpw1kqhbzFW2t6Umgxf+YCE9hDm/FZT9dVzITZXr78A1gw+XPg==
X-Received: by 2002:ac5:c80e:: with SMTP id y14mr8500888vkl.3.1604086223629;
        Fri, 30 Oct 2020 12:30:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3037:: with SMTP id v23ls1107565vsa.11.gmail; Fri,
 30 Oct 2020 12:30:23 -0700 (PDT)
X-Received: by 2002:a05:6102:22da:: with SMTP id a26mr7096467vsh.13.1604086223135;
        Fri, 30 Oct 2020 12:30:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604086223; cv=none;
        d=google.com; s=arc-20160816;
        b=ZABFd2gDnkuNIWLir05V6HedEQD+EVJG0cQihPV4AjGlqcvecNql9wAOgh81gQmzU9
         8i/tdkULvMXet/pOBROfQ/QoB44NBHy3ysg+o8gEm9rXFeW1Dt2lURYIZ/QfHxl6+zXO
         T6vfPAnGfHDTs/tQY2IXcDrQJ0RXcXTppQQ6QL7uYQzBu/Z2I2U9uYLSTP4cAJ/UyEp7
         yzcHUO5Zn+iD99/2JIEvUR6HkCCblvVs95jR3DNQA1YcoD90fbYbd448W8vxt9tMaHcQ
         UK3unPcf0BTPSgz63Nebv1WAchSXzUC/+9e8Sc86gze9US8w1lXUTrhy07l9ax83o9qF
         CQ3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uCxbrB8kOGB154Lx7US6rz7YBkrXxfF/uMObBntK2wE=;
        b=lpQi5cHwrixQLvpmkQT1Hr0m+E/O1VLBuO4f9tY5OzdxYvzt6HODgOcB2ZAWXGv1Rw
         E6ndSK+/lB5gUtgoVdl5hYQANcth2b84WCWcdZk0n3Dg4HSwGoh5m9wB3mj0gbqZfl3X
         44sKNn22C5W896XxMQLGKMbPE9My3ndFyxXYsZrEjCJWDqCl0YoR6qjX5rkUSbq6hiM1
         wjJ6TKH4lSiOlaHMMHsCYMarkjVcyTb13iBhyPHzLFoID4qqRo84b9jZOGOIuMUX5vab
         uyOF8ilHuJNBT/3uSw0QS/+fZySNvJHtZ3Pmo0e7bI7X2QWIadUgBAXlnZZZZddgGp9a
         rE9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iaEVNbKj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id w123si358384vke.3.2020.10.30.12.30.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 12:30:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id k9so4363243pgt.9
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 12:30:23 -0700 (PDT)
X-Received: by 2002:a63:d456:: with SMTP id i22mr3465961pgj.440.1604086222271;
 Fri, 30 Oct 2020 12:30:22 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
 <CACT4Y+ZNenL3B91huwk=0oMJFj6FN8ShsrO9w_mnQg4wgmjSdw@mail.gmail.com>
In-Reply-To: <CACT4Y+ZNenL3B91huwk=0oMJFj6FN8ShsrO9w_mnQg4wgmjSdw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 20:30:11 +0100
Message-ID: <CAAeHK+z3ksBYxcoJMzqnOjaci2xdUSrbNTUheQJ6oZ2p9Y1XUw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 14/21] kasan: add and integrate kasan boot parameters
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
 header.i=@google.com header.s=20161025 header.b=iaEVNbKj;       spf=pass
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

On Wed, Oct 28, 2020 at 1:27 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > TODO: no meaningful description here yet, please see the cover letter
> >       for this RFC series.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
> > ---
> >  mm/kasan/common.c  |  92 +++++++++++++-----------
> >  mm/kasan/generic.c |   5 ++
> >  mm/kasan/hw_tags.c | 169 ++++++++++++++++++++++++++++++++++++++++++++-
> >  mm/kasan/kasan.h   |   9 +++
> >  mm/kasan/report.c  |  14 +++-
> >  mm/kasan/sw_tags.c |   5 ++
> >  6 files changed, 250 insertions(+), 44 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 1a5e6c279a72..cc129ef62ab1 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -129,35 +129,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >         unsigned int redzone_size;
> >         int redzone_adjust;
> >
> > -       /* Add alloc meta. */
> > -       cache->kasan_info.alloc_meta_offset = *size;
> > -       *size += sizeof(struct kasan_alloc_meta);
> > -
> > -       /* Add free meta. */
> > -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> > -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> > -            cache->object_size < sizeof(struct kasan_free_meta))) {
> > -               cache->kasan_info.free_meta_offset = *size;
> > -               *size += sizeof(struct kasan_free_meta);
> > -       }
> > -
> > -       redzone_size = optimal_redzone(cache->object_size);
> > -       redzone_adjust = redzone_size - (*size - cache->object_size);
> > -       if (redzone_adjust > 0)
> > -               *size += redzone_adjust;
> > -
> > -       *size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> > -                       max(*size, cache->object_size + redzone_size));
> > +       if (static_branch_unlikely(&kasan_stack)) {
>
> Initially I thought kasan_stack is related to stack instrumentation.
> And then wondered why we check it during slab creation.
> I suggest giving it a slightly longer and more descriptive name.

Will do.

> ... reading code further, it also disables quarantine, right?
> Something to mention somewhere.

Quarantine is not supported for anything but generic KASAN. Maybe it
makes sense to put this into documentation...

> > +               /* Add alloc meta. */
> > +               cache->kasan_info.alloc_meta_offset = *size;
> > +               *size += sizeof(struct kasan_alloc_meta);
> > +
> > +               /* Add free meta. */
> > +               if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> > +                   (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> > +                    cache->object_size < sizeof(struct kasan_free_meta))) {
> > +                       cache->kasan_info.free_meta_offset = *size;
> > +                       *size += sizeof(struct kasan_free_meta);
> > +               }
> >
> > -       /*
> > -        * If the metadata doesn't fit, don't enable KASAN at all.
> > -        */
> > -       if (*size <= cache->kasan_info.alloc_meta_offset ||
> > -                       *size <= cache->kasan_info.free_meta_offset) {
> > -               cache->kasan_info.alloc_meta_offset = 0;
> > -               cache->kasan_info.free_meta_offset = 0;
> > -               *size = orig_size;
> > -               return;
> > +               redzone_size = optimal_redzone(cache->object_size);
> > +               redzone_adjust = redzone_size - (*size - cache->object_size);
> > +               if (redzone_adjust > 0)
> > +                       *size += redzone_adjust;
> > +
> > +               *size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> > +                               max(*size, cache->object_size + redzone_size));
> > +
> > +               /*
> > +                * If the metadata doesn't fit, don't enable KASAN at all.
> > +                */
> > +               if (*size <= cache->kasan_info.alloc_meta_offset ||
> > +                               *size <= cache->kasan_info.free_meta_offset) {
> > +                       cache->kasan_info.alloc_meta_offset = 0;
> > +                       cache->kasan_info.free_meta_offset = 0;
> > +                       *size = orig_size;
> > +                       return;
> > +               }
> >         }
> >
> >         *flags |= SLAB_KASAN;
> > @@ -165,10 +167,12 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >
> >  size_t kasan_metadata_size(struct kmem_cache *cache)
> >  {
> > -       return (cache->kasan_info.alloc_meta_offset ?
> > -               sizeof(struct kasan_alloc_meta) : 0) +
> > -               (cache->kasan_info.free_meta_offset ?
> > -               sizeof(struct kasan_free_meta) : 0);
> > +       if (static_branch_unlikely(&kasan_stack))
> > +               return (cache->kasan_info.alloc_meta_offset ?
> > +                       sizeof(struct kasan_alloc_meta) : 0) +
> > +                       (cache->kasan_info.free_meta_offset ?
> > +                       sizeof(struct kasan_free_meta) : 0);
> > +       return 0;
> >  }
> >
> >  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> > @@ -270,8 +274,10 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >         if (!(cache->flags & SLAB_KASAN))
> >                 return (void *)object;
> >
> > -       alloc_meta = kasan_get_alloc_meta(cache, object);
> > -       __memset(alloc_meta, 0, sizeof(*alloc_meta));
> > +       if (static_branch_unlikely(&kasan_stack)) {
>
> Interestingly, now SLAB_KASAN is always set when kasan_stack is not
> enabled. So it seems to me we can move the SLAB_KASAN check into this
> unlikely branch now.

Yes, will fix. I'll also include a complete rework of SLAB_KASAN into
the next version.

>
> > +               alloc_meta = kasan_get_alloc_meta(cache, object);
> > +               __memset(alloc_meta, 0, sizeof(*alloc_meta));
> > +       }
> >
> >         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> >                 object = set_tag(object, assign_tag(cache, object, true, false));
> > @@ -308,15 +314,19 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >         rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
> >         kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
> >
> > -       if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> > -                       unlikely(!(cache->flags & SLAB_KASAN)))
> > -               return false;
> > +       if (static_branch_unlikely(&kasan_stack)) {
> > +               if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> > +                               unlikely(!(cache->flags & SLAB_KASAN)))
> > +                       return false;
> > +
> > +               kasan_set_free_info(cache, object, tag);
> >
> > -       kasan_set_free_info(cache, object, tag);
> > +               quarantine_put(cache, object);
> >
> > -       quarantine_put(cache, object);
> > +               return IS_ENABLED(CONFIG_KASAN_GENERIC);
> > +       }
> >
> > -       return IS_ENABLED(CONFIG_KASAN_GENERIC);
> > +       return false;
> >  }
> >
> >  bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> > @@ -355,7 +365,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
> >                 KASAN_KMALLOC_REDZONE);
> >
> > -       if (cache->flags & SLAB_KASAN)
> > +       if (static_branch_unlikely(&kasan_stack) && (cache->flags & SLAB_KASAN))
> >                 set_alloc_info(cache, (void *)object, flags);
> >
> >         return set_tag(object, tag);
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index d259e4c3aefd..20a1e753e0c5 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -33,6 +33,11 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > +/* See the comments in hw_tags.c */
> > +DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
> > +EXPORT_SYMBOL(kasan_enabled);
> > +DEFINE_STATIC_KEY_TRUE_RO(kasan_stack);
> > +
> >  /*
> >   * All functions below always inlined so compiler could
> >   * perform better optimizations in each of __asan_loadX/__assn_storeX
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 915142da6b57..bccd781011ad 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -8,6 +8,8 @@
> >
> >  #define pr_fmt(fmt) "kasan: " fmt
> >
> > +#include <linux/init.h>
> > +#include <linux/jump_label.h>
> >  #include <linux/kasan.h>
> >  #include <linux/kernel.h>
> >  #include <linux/memory.h>
> > @@ -17,10 +19,175 @@
> >
> >  #include "kasan.h"
> >
> > +enum kasan_arg_mode {
> > +       KASAN_ARG_MODE_OFF,
> > +       KASAN_ARG_MODE_PROD,
> > +       KASAN_ARG_MODE_FULL,
> > +};
> > +
> > +enum kasan_arg_stack {
> > +       KASAN_ARG_STACK_DEFAULT,
> > +       KASAN_ARG_STACK_OFF,
> > +       KASAN_ARG_STACK_ON,
> > +};
> > +
> > +enum kasan_arg_trap {
> > +       KASAN_ARG_TRAP_DEFAULT,
> > +       KASAN_ARG_TRAP_ASYNC,
> > +       KASAN_ARG_TRAP_SYNC,
> > +};
> > +
> > +enum kasan_arg_fault {
> > +       KASAN_ARG_FAULT_DEFAULT,
> > +       KASAN_ARG_FAULT_REPORT,
> > +       KASAN_ARG_FAULT_PANIC,
> > +};
> > +
> > +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> > +static enum kasan_arg_stack kasan_arg_stack __ro_after_init;
> > +static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> > +static enum kasan_arg_trap kasan_arg_trap __ro_after_init;
> > +
> > +/* Whether KASAN is enabled at all. */
> > +DEFINE_STATIC_KEY_FALSE_RO(kasan_enabled);
> > +EXPORT_SYMBOL(kasan_enabled);
> > +
> > +/* Whether to collect alloc/free stack traces. */
> > +DEFINE_STATIC_KEY_FALSE_RO(kasan_stack);
> > +
> > +/* Whether to use synchronous or asynchronous tag checking. */
> > +static bool kasan_sync __ro_after_init;
> > +
> > +/* Whether panic or disable tag checking on fault. */
> > +bool kasan_panic __ro_after_init;
> > +
> > +/* kasan.mode=off/prod/full */
> > +static int __init early_kasan_mode(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (!strcmp(arg, "off"))
> > +               kasan_arg_mode = KASAN_ARG_MODE_OFF;
> > +       else if (!strcmp(arg, "prod"))
> > +               kasan_arg_mode = KASAN_ARG_MODE_PROD;
> > +       else if (!strcmp(arg, "full"))
> > +               kasan_arg_mode = KASAN_ARG_MODE_FULL;
> > +       else
> > +               return -EINVAL;
> > +
> > +       return 0;
> > +}
> > +early_param("kasan.mode", early_kasan_mode);
> > +
> > +/* kasan.stack=off/on */
> > +static int __init early_kasan_stack(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (!strcmp(arg, "off"))
> > +               kasan_arg_stack = KASAN_ARG_STACK_OFF;
> > +       else if (!strcmp(arg, "on"))
> > +               kasan_arg_stack = KASAN_ARG_STACK_ON;
> > +       else
> > +               return -EINVAL;
> > +
> > +       return 0;
> > +}
> > +early_param("kasan.stack", early_kasan_stack);
> > +
> > +/* kasan.trap=sync/async */
> > +static int __init early_kasan_trap(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (!strcmp(arg, "ASYNC"))
> > +               kasan_arg_trap = KASAN_ARG_TRAP_ASYNC;
> > +       else if (!strcmp(arg, "sync"))
> > +               kasan_arg_trap = KASAN_ARG_TRAP_SYNC;
> > +       else
> > +               return -EINVAL;
> > +
> > +       return 0;
> > +}
> > +early_param("kasan.trap", early_kasan_trap);
> > +
> > +/* kasan.fault=report/panic */
> > +static int __init early_kasan_fault(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (!strcmp(arg, "report"))
> > +               kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> > +       else if (!strcmp(arg, "panic"))
> > +               kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> > +       else
> > +               return -EINVAL;
> > +
> > +       return 0;
> > +}
> > +early_param("kasan.fault", early_kasan_fault);
> > +
> >  void __init kasan_init_tags(void)
> >  {
> > -       init_tags(KASAN_TAG_MAX);
> > +       if (!cpu_supports_tags())
> > +               return;
> > +
> > +       /* First, preset values based on the mode. */
> > +
> > +       switch (kasan_arg_mode) {
> > +       case KASAN_ARG_MODE_OFF:
> > +               return;
> > +       case KASAN_ARG_MODE_PROD:
> > +               static_branch_enable(&kasan_enabled);
> > +               break;
> > +       case KASAN_ARG_MODE_FULL:
> > +               static_branch_enable(&kasan_enabled);
> > +               static_branch_enable(&kasan_stack);
> > +               kasan_sync = true;
> > +               break;
> > +       }
> > +
> > +       /* Now, optionally override the presets. */
> >
> > +       switch (kasan_arg_stack) {
> > +       case KASAN_ARG_STACK_OFF:
> > +               static_branch_disable(&kasan_stack);
> > +               break;
> > +       case KASAN_ARG_STACK_ON:
> > +               static_branch_enable(&kasan_stack);
> > +               break;
> > +       default:
> > +               break;
> > +       }
> > +
> > +       switch (kasan_arg_trap) {
> > +       case KASAN_ARG_TRAP_ASYNC:
> > +               kasan_sync = false;
> > +               break;
> > +       case KASAN_ARG_TRAP_SYNC:
> > +               kasan_sync = true;
> > +               break;
> > +       default:
> > +               break;
> > +       }
> > +
> > +       switch (kasan_arg_fault) {
> > +       case KASAN_ARG_FAULT_REPORT:
> > +               kasan_panic = false;
> > +               break;
> > +       case KASAN_ARG_FAULT_PANIC:
> > +               kasan_panic = true;
> > +               break;
> > +       default:
> > +               break;
> > +       }
> > +
> > +       /* TODO: choose between sync and async based on kasan_sync. */
> > +       init_tags(KASAN_TAG_MAX);
> >         pr_info("KernelAddressSanitizer initialized\n");
> >  }
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index f7ae0c23f023..00b47bc753aa 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -2,9 +2,18 @@
> >  #ifndef __MM_KASAN_KASAN_H
> >  #define __MM_KASAN_KASAN_H
> >
> > +#include <linux/jump_label.h>
> >  #include <linux/kasan.h>
> >  #include <linux/stackdepot.h>
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +DECLARE_STATIC_KEY_FALSE(kasan_stack);
> > +#else
> > +DECLARE_STATIC_KEY_TRUE(kasan_stack);
> > +#endif
>
> kasan_stack and kasan_enabled make sense and changed only in hw_tags mode.
> It would be cleaner (and faster for other modes) to abstract static keys as:
>
> #ifdef CONFIG_KASAN_HW_TAGS
> #include <linux/jump_label.h>
> DECLARE_STATIC_KEY_FALSE(kasan_stack);
> static inline bool kasan_stack_collection_enabled()
> {
>   return static_branch_unlikely(&kasan_stack);
> }
> #else
> static inline bool kasan_stack_collection_enabled() { return true; }
> #endif
>
> This way we don't need to include and define static keys for other modes.

Sounds good, will do.

>
> > +extern bool kasan_panic __ro_after_init;
> > +
> >  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> >  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
> >  #else
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index dee5350b459c..426dd1962d3c 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -97,6 +97,10 @@ static void end_report(unsigned long *flags)
> >                 panic_on_warn = 0;
> >                 panic("panic_on_warn set ...\n");
> >         }
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +       if (kasan_panic)
> > +               panic("kasan.fault=panic set ...\n");
> > +#endif
> >         kasan_enable_current();
> >  }
> >
> > @@ -159,8 +163,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> >                 (void *)(object_addr + cache->object_size));
> >  }
> >
> > -static void describe_object(struct kmem_cache *cache, void *object,
> > -                               const void *addr, u8 tag)
> > +static void describe_object_stacks(struct kmem_cache *cache, void *object,
> > +                                       const void *addr, u8 tag)
> >  {
> >         struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
> >
> > @@ -188,7 +192,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >                 }
> >  #endif
> >         }
> > +}
> >
> > +static void describe_object(struct kmem_cache *cache, void *object,
> > +                               const void *addr, u8 tag)
> > +{
> > +       if (static_branch_unlikely(&kasan_stack))
> > +               describe_object_stacks(cache, object, addr, tag);
> >         describe_object_addr(cache, object, addr);
> >  }
> >
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index 4db41f274702..b6d185adf2c5 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -33,6 +33,11 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > +/* See the comments in hw_tags.c */
> > +DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
> > +EXPORT_SYMBOL(kasan_enabled);
> > +DEFINE_STATIC_KEY_TRUE_RO(kasan_stack);
> > +
> >  static DEFINE_PER_CPU(u32, prng_state);
> >
> >  void __init kasan_init_tags(void)
> > --
> > 2.29.0.rc1.297.gfa9743e501-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz3ksBYxcoJMzqnOjaci2xdUSrbNTUheQJ6oZ2p9Y1XUw%40mail.gmail.com.
