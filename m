Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAUXSP5QKGQELZG6VMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EA7D27005C
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:00:19 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id z5sf1702726oto.9
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:00:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600441218; cv=pass;
        d=google.com; s=arc-20160816;
        b=qi/URx036m2MvOtBHy/VyrorGG/x8KrexLgIwy+9SUEH946YtaWAzK50r34mbZpxAq
         WW4K6GU94/z3v4XicGOhRnLoB+4QV/myMJjlUuGfq97C48Or6xfeBFIP6OUxIcQzvEZs
         yNYG505uv8Z1ZUEp6V6GePulDtsv+Cz46z1pHOjPnmUdMz1c0w4ug5mTDvizqZh9XS/i
         wrey5UFYPqxf2S3Wpng3W9GQYDWM0795pOJaIrqL+2o0QsI0vyphgtWTScmMkTcBa4HE
         hSgmlJ671cRCXEXuN8b6TQKvPizCLOej77sXsndlBmvWWgEplCTYFr2b9nRtPb6l2bYX
         IHKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FHKQCsbOgYJyIQkKXTUiExFtDNhD7lZ0ULCt0mzzwxM=;
        b=kHEHnCxqTL/7IGdDGDv/KwU+Wu85nL4nl9beU4hRH8urJCKKNDfUzDcL+Qg2Su1b4J
         dkagHknzJ9c3VrDVTxSNBhNzL51IV8BcVfrCQ9aU0D6VcNCXN+hlq0Z3nBxuxkfVLtgg
         J5c7JsNmTQKkZs0ZDHBTtJ3wcWDFpH6yUr6xH4i48O5RgJIrILtv2w1L7Oe9dfKLQRiz
         Bvy99zmFn2SD4nuIkmhDNQCRoqrWiSkacDZzj+9YtdjdiWORn759hGnhtnormW+FxE9X
         njtbqWiGZHCZJ9BFo9vjQW3QCVc2CFcjVk9ZHkWN5aeugt9iLBgsazo0ERN4ajZRX00p
         nIaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZwMp8rTY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FHKQCsbOgYJyIQkKXTUiExFtDNhD7lZ0ULCt0mzzwxM=;
        b=leX+9yzvqhlH/FXl+ihvT80/PZFZXfmzqVwKsWEN5+h+w4svsPisB4GlELOF1AgCGV
         QX6ac3GExrgg/kMoWKKYy7Bzz69vjLVNJvH4bPuaM3Uxq4oFbHMF2NEjRqWxoFdq1uhR
         XMoM1Bw6HuYBpPKiF9kMBLFSSxr0Bg2sOwsATS6lS8TYtrpKQAU8Vh6Yys8jWcHaZY1D
         ucyPaSdzmQxNaMCEmiToWDRSNFqjYxFbpEDT4VdzD5Kj9BCIzuIIGp2bkIYGgdvLGKc9
         pzdk/kYEpcpnpGaKYUBj3fkQEFI2UP8pDmYhnsZkvwUQUgKfv4hAtIJ8IwKdP9EQ61l7
         NPbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FHKQCsbOgYJyIQkKXTUiExFtDNhD7lZ0ULCt0mzzwxM=;
        b=pTGoNBPgGQepr+jMDxs46hCKtZJ14OIbFRvVO861nPhR+fiOoUHBRu7x8A8K452Ueh
         blIMc3/1sRdai/QyqpC8SJkQ1vgHxQn2m71fNDHrb+OHXQYSjDJv8A/kLvlVADEHUEUY
         QP3QcPx2o1NvrH3W37ecpn4Q6Sa3u1eVgrDwhE63wOJp3vZcvR3vVy6LStKr2izw8i0+
         w9TbTVgAsm+WACldE35vI916XPRemMq4ZhgUHQGziTYPbqwpZyxlM09ZFyRRAA3w7azA
         Z1ssdIj9jLr4jlUD/o0+axDn73KxTV5hvhZUhVN1sDwACdAyoKxL2Y8Ne+3WLR7Ai+vr
         4ppA==
X-Gm-Message-State: AOAM533Fp2VpNnM78ME3adEOY7w8dn5BycOuSUNAy8EQoe84NLn325w1
	rxB+FCa4wWOoemZZ8I8K5gU=
X-Google-Smtp-Source: ABdhPJx/b9taaFSJUftDrBqlSSjJDNaTAFwEELfe2K2dTxe1C7iEuDd7H3FgzHP5EDKqervnvGXr/g==
X-Received: by 2002:a9d:6d88:: with SMTP id x8mr21626403otp.252.1600441218496;
        Fri, 18 Sep 2020 08:00:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:459:: with SMTP id d25ls1322528otc.7.gmail; Fri, 18
 Sep 2020 08:00:17 -0700 (PDT)
X-Received: by 2002:a9d:3b76:: with SMTP id z109mr23695184otb.250.1600441217884;
        Fri, 18 Sep 2020 08:00:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600441217; cv=none;
        d=google.com; s=arc-20160816;
        b=UYfHTctJsH0w8g7rfIIPtSLDLR3kIOmpWZauRnPy1YVhJlV1LMsp1uOi38XbwQXz2i
         cwDyU0bQHh+YO9yteF1B4TXwJv7oDgmC0gna9ULlxgN/HprUkvbabeYvy9KN8bwQtqDy
         Dd73i243FFgUeaPrUhiDu13bzhvWCcUZN2CG24TB7AhhqQZreqME+T3gYQOLSACU93bO
         RoWLc2Gtah9WWVjaBqYl68epQly9/dky9dN6+qlhHJfAgamLh5zsQsRuWze8Gnd0ePTu
         4gsSKiBjt4P8W7WcjlEULZR9USPIYWnpPpOentMe/Y5rxY5tuEqV+mH9Ix4nk6Ue1sJi
         tOww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=43HOBOFmwhtePq8PeIBCEBCa6ILf8VtzLC2fB6iIXLI=;
        b=D4nIqTFZoDbiHU/QmCOHOIp+0/v0a72HsOlHsCKrvnUdWxEpu3a/pa3QvehWWkMt34
         K/P9bkwMfpIPM4MuVDKuO1ktIhymtAvoiS1q1WyvGvlFD0ujFkO687+UHDwpdIwZu/zL
         6EnZJ1S1dmS+LCvrYSelmA3OXdgfrrhc0dM/AnHX5BgZOAPCvSHUBb57vJ8smp5jWis9
         LwGQxffzlcB7nR17DSQXg6DJu7vB/5/7yfcx+MQmN1B58rIB+h4dx0XrMQhhPgEUBmxN
         F20jU/3ueom64lHYh3Szq+6v2zxJzZ8exNhbQItvFZI9B6Bqjty4az4UIYnEJMttdNbu
         iiGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZwMp8rTY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id i15si255179oig.1.2020.09.18.08.00.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:00:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id f1so3101213plo.13
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:00:17 -0700 (PDT)
X-Received: by 2002:a17:902:b117:b029:d1:e5e7:bdf5 with SMTP id
 q23-20020a170902b117b02900d1e5e7bdf5mr15071472plr.85.1600441216910; Fri, 18
 Sep 2020 08:00:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
 <20200918125216.GD2384246@elver.google.com>
In-Reply-To: <20200918125216.GD2384246@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 17:00:06 +0200
Message-ID: <CAAeHK+z40FP0xJo+uc-Y49LEBTb-G54nNWqePJm9J-2SJ8v5sQ@mail.gmail.com>
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZwMp8rTY;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Fri, Sep 18, 2020 at 2:52 PM Marco Elver <elver@google.com> wrote:
>
> [ Sorry for the additional email on this patch; trying to consolidate
>   comments now. ]
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> > Provide implementation of KASAN functions required for the hardware
> > tag-based mode. Those include core functions for memory and pointer
> > tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
> > common KASAN code to support the new mode.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> > Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
> > ---
> >  arch/arm64/include/asm/memory.h   |  4 +-
> >  arch/arm64/kernel/setup.c         |  1 -
> >  include/linux/kasan.h             |  6 +--
> >  include/linux/mm.h                |  2 +-
> >  include/linux/page-flags-layout.h |  2 +-
> >  mm/kasan/Makefile                 |  5 ++
> >  mm/kasan/common.c                 | 14 +++---
> >  mm/kasan/kasan.h                  | 17 +++++--
> >  mm/kasan/report_tags_hw.c         | 47 +++++++++++++++++++
> >  mm/kasan/report_tags_sw.c         |  2 +-
> >  mm/kasan/shadow.c                 |  2 +-
> >  mm/kasan/tags_hw.c                | 78 +++++++++++++++++++++++++++++++
> >  mm/kasan/tags_sw.c                |  2 +-
> >  13 files changed, 162 insertions(+), 20 deletions(-)
> >  create mode 100644 mm/kasan/report_tags_hw.c
> >  create mode 100644 mm/kasan/tags_hw.c
> [...]
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 41c7f1105eaa..412a23d1546b 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -118,7 +118,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
> >   */
> >  static inline unsigned int optimal_redzone(unsigned int object_size)
> >  {
> > -     if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +     if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
> >               return 0;
> >
> >       return
> > @@ -183,14 +183,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
> >  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> >                                       const void *object)
> >  {
> > -     return (void *)object + cache->kasan_info.alloc_meta_offset;
> > +     return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
> >  }
> >
> >  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> >                                     const void *object)
> >  {
> >       BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> > -     return (void *)object + cache->kasan_info.free_meta_offset;
> > +     return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
> >  }
> >
> >  void kasan_poison_slab(struct page *page)
> > @@ -272,7 +272,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >       alloc_info = get_alloc_info(cache, object);
> >       __memset(alloc_info, 0, sizeof(*alloc_info));
>
> Suggested edit below (assuming the line-break wasn't intentional; this
> should still be within checkpatch.pl's 100 col limit):
> ------
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
> -                       IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 object = set_tag(object,
>                                 assign_tag(cache, object, true, false));
>
> @@ -343,8 +342,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         redzone_end = round_up((unsigned long)object + cache->object_size,
>                                 KASAN_GRANULE_SIZE);
>
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
> -                       IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 tag = assign_tag(cache, object, false, keep_tag);
> ------
>
> > -     if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +     if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
> > +                     IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> >               object = set_tag(object,
> >                               assign_tag(cache, object, true, false));
> >
> > @@ -342,10 +343,11 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >       redzone_end = round_up((unsigned long)object + cache->object_size,
> >                               KASAN_GRANULE_SIZE);
> >
> > -     if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +     if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
> > +                     IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> >               tag = assign_tag(cache, object, false, keep_tag);
> >
> > -     /* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> > +     /* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
> >       kasan_unpoison_memory(set_tag(object, tag), size);
> >       kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
> >               KASAN_KMALLOC_REDZONE);
> [...]
> > diff --git a/mm/kasan/report_tags_hw.c b/mm/kasan/report_tags_hw.c
> > new file mode 100644
> > index 000000000000..c2f73c46279a
> > --- /dev/null
> > +++ b/mm/kasan/report_tags_hw.c
> > @@ -0,0 +1,47 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * This file contains hardware tag-based KASAN specific error reporting code.
> > + *
> > + * Copyright (c) 2020 Google, Inc.
> > + * Author: Andrey Konovalov <andreyknvl@google.com>
> > + *
> > + * This program is free software; you can redistribute it and/or modify
> > + * it under the terms of the GNU General Public License version 2 as
> > + * published by the Free Software Foundation.
> > + *
>
> I do not think we put the "This program is ..." preamble in new files
> anymore. It should be covered by SPDX tag above.
>
> > + */
> > +
> > +#include <linux/kasan.h>
> > +#include <linux/kernel.h>
> > +#include <linux/memory.h>
> > +#include <linux/mm.h>
> > +#include <linux/string.h>
> > +#include <linux/types.h>
> [...]
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index 4888084ecdfc..ca69726adf8f 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -111,7 +111,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
> >
> >               if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> >                       *shadow = tag;
> > -             else
> > +             else /* CONFIG_KASAN_GENERIC */
> >                       *shadow = size & KASAN_GRANULE_MASK;
> >       }
> >  }
> > diff --git a/mm/kasan/tags_hw.c b/mm/kasan/tags_hw.c
> > new file mode 100644
> > index 000000000000..c93d43379e39
> > --- /dev/null
> > +++ b/mm/kasan/tags_hw.c
> > @@ -0,0 +1,78 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * This file contains core hardware tag-based KASAN code.
> > + *
> > + * Copyright (c) 2020 Google, Inc.
> > + * Author: Andrey Konovalov <andreyknvl@google.com>
> > + *
> > + * This program is free software; you can redistribute it and/or modify
> > + * it under the terms of the GNU General Public License version 2 as
> > + * published by the Free Software Foundation.
> > + *
>
> I do not think we put the "This program is ..." preamble in new files
> anymore. It should be covered by SPDX tag above.
>
> > + */
> > +
> > +#include <linux/kasan.h>
> > +#include <linux/kernel.h>
> > +#include <linux/memory.h>
> > +#include <linux/mm.h>
> > +#include <linux/string.h>
> > +#include <linux/types.h>
> > +
> > +#include "kasan.h"
> > +
> > +void kasan_init_tags(void)
> > +{
> > +     init_tags(KASAN_TAG_MAX);
> > +}
> > +
> > +void *kasan_reset_tag(const void *addr)
> > +{
> > +     return reset_tag(addr);
> > +}
> > +
>
> To help readability, would this edit be ok?
> ------
>  void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
> -       set_mem_tag_range(reset_tag(address),
> -               round_up(size, KASAN_GRANULE_SIZE), value);
> +       set_mem_tag_range(reset_tag(address), round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>
>  void kasan_unpoison_memory(const void *address, size_t size)
>  {
> -       set_mem_tag_range(reset_tag(address),
> -               round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +       set_mem_tag_range(reset_tag(address), round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
> ------
>
> > +void kasan_poison_memory(const void *address, size_t size, u8 value)
> > +{
> > +     set_mem_tag_range(reset_tag(address),
> > +             round_up(size, KASAN_GRANULE_SIZE), value);
> > +}
> > +
> > +void kasan_unpoison_memory(const void *address, size_t size)
> > +{
> > +     set_mem_tag_range(reset_tag(address),
> > +             round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> > +}
> > +
> > +u8 random_tag(void)
> > +{
> > +     return get_random_tag();
> > +}
> > +
> > +bool check_invalid_free(void *addr)
> > +{
> > +     u8 ptr_tag = get_tag(addr);
> > +     u8 mem_tag = get_mem_tag(addr);
> > +
>
>
> Why not just:
> ------
> -       if (shadow_byte == KASAN_TAG_INVALID)
> -               return true;
> -       if (tag != KASAN_TAG_KERNEL && tag != shadow_byte)
> -               return true;
> -       return false;
> +       return shadow_byte == KASAN_TAG_INVALID ||
> +              (tag != KASAN_TAG_KERNEL && tag != shadow_byte);
>  }
> ------
>
> > +     if (mem_tag == KASAN_TAG_INVALID)
> > +             return true;
> > +     if (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag)
> > +             return true;
> > +     return false;
> > +}
> > +

Will fix all these in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz40FP0xJo%2Buc-Y49LEBTb-G54nNWqePJm9J-2SJ8v5sQ%40mail.gmail.com.
