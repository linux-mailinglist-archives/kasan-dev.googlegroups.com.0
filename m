Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5WK4WDAMGQEU6FG3LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 88FF93B58E1
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 08:00:23 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id z64-20020a257e430000b0290550b1931c8dsf14694730ybc.4
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Jun 2021 23:00:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624860022; cv=pass;
        d=google.com; s=arc-20160816;
        b=P4cOziOcRHfuPZXkNb4sm6ZbNRAopEahd0/TxlqmSYdZpylL3Gs4qJdpJZWCX/wyAv
         E1GdJevC0XXQeZOvxUNPKFCVWUoUL3kFEQieKIv41D0Qd1PfSfM1YaO1a4v8yYntijYk
         8Au8aoEXt7WTRQ22cDVZ0XJxcc9Dxw/CCF/vLWd46uXGHOtiv3joLE0MsQStzJu3furr
         HiylcuxC4l6mqbueVWXGV0LdfRgN9g5JGlJgKI9UxuvdY/J/s2vTZtK4TzgfWSy4DZ3v
         T47PTCKfN+386waQfkORfL7/SLN5JAQPXcpxbhSAvE5ORnDoVOyovw1rH+sMDAfMAF7+
         LOqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ITXfIYSrqEcwaPmkwNQeRn6e4Mk4tbpCk9hgcZWC13A=;
        b=sX3bUoOux33ktbd8BZs1tlWBWcj/7pFIafNv5Mjdui9PHalosETH4O0kTpISsUFm0D
         stdgZoH1JrhkWvV2oQbCivnIpNSV6MMwMPZDOQLYoaA+NhkXBa+0qR76SDl44DQbh/iH
         80ZBLWk/grxHb7Im6aIqHt+0tXBFJkk0walXgKeGKv3SnYUmulN9T9VVC2Dbw9T3gxrH
         gPwdlK4K+zi03vw42APci2YTdnBbXN+uck9a3fcjOucmxIzTmmZ3pdUY/Ae2UrLfVyjH
         YChKiQynSXwpUI/wk2EERM677Js02/UCBUlJ6q9YlmhwREZEaNIZ/vUXh/7paUGoJK3w
         c9+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wOYvQpib;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ITXfIYSrqEcwaPmkwNQeRn6e4Mk4tbpCk9hgcZWC13A=;
        b=JoJ6+dUWyPOAhQCGClBbNYCFpouZVDr+Ay0ZE++xVH2KwNHTgzQXQ3cNxD/+2JY7qe
         f72wHbGtN1LUZN3IY5940lDuLkzQfs30yBkcBAj9w1iDh+Mwdv9D3zDLWZW7I0kTzFYH
         ZURtKIkzDVYsWLI5vrdsSDwAOEIUZWLBUSmOGWd43LIiZTBHZVFJeoPHUReWCLM7Srel
         RwV2pLCOS3ViZGXSgtHGberCukNnDZrHocNq39LwTVeHuJ4Rv21NHW6XJzgYYznaabCf
         IocPcanLYD0wnnexJ7hDkrzp9VkiS9HuDJiBgtRHMBrSUwwHPoH0nk+n6yyUH8Bt2dRA
         jIeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ITXfIYSrqEcwaPmkwNQeRn6e4Mk4tbpCk9hgcZWC13A=;
        b=N4ArKsDzMXJM9NBWxPBi4Bc5Bx9NnQaIeRTuEjnP6LuPN0qm5GFbQ+UFXYpqUWF98A
         fv+nYe6hyiHUynDah6gdq5JHOTdP00VlNmz49zTPahFOXrIS+xtqPG9Xq0NJ8lyuZrEY
         VrXPUXDW2iUk6rxXDsNCXT8lR7uSqoWIoYY4VkY4vXFnrfelhI0O9cKuYWgvqcq/Hjey
         wU3Zqkh3iUXbZnvxiop8YsNXiZD59yiTOH4ETw4delITo9AMfugpGIcyqDtdViuXuk7E
         sOzklniCoJtVie9LMqXsuL7Cwrbgl+l4yVPvU+bLoUr5+5L05nbqYBAqIjKE7vb6Bn2+
         7iHg==
X-Gm-Message-State: AOAM530I7S1pR2qhBYdbg/ywza8/UBtm+08frLkcLMkeMZaCrmGTsM9A
	WcE3GLaL4qkrD2giZLEtnJs=
X-Google-Smtp-Source: ABdhPJyAEwCvfPCRcj1STGlOMNoIOZr7G3ZA79Cep8Dp8LalFPZvh6PrpetpUIcjJxK82h3FOnpAYQ==
X-Received: by 2002:a25:7089:: with SMTP id l131mr29326171ybc.1.1624860022334;
        Sun, 27 Jun 2021 23:00:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:874d:: with SMTP id e13ls592751ybn.0.gmail; Sun, 27 Jun
 2021 23:00:21 -0700 (PDT)
X-Received: by 2002:a25:bbd0:: with SMTP id c16mr28144030ybk.7.1624860021666;
        Sun, 27 Jun 2021 23:00:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624860021; cv=none;
        d=google.com; s=arc-20160816;
        b=xWMpswmP2E5nd1HtOk64U/MglU7EWEyPEz7lDjoA8enx2rOYgmjWjlw7sQHhjxygh9
         cwfJIqtsKyfVeiaNQUT3dLpR+T4k8DnG6Xd3UyDWfPHzHjQETzjn6htFCpZrbGiH+dIp
         r3pqSMdnUKTbHTh8Xh0fDKRZBtC0cT1Hmyh7drNPrckzdWiv9NG7LLZbg63N/QDe2gDP
         t+gXuOIvGVJqqx09LofOUqW81zI0LTMFYGCyf9Ei4KE7w27OQQi79DIFIq6TNFlcs02c
         5aBBP9/Q6RfdMsVEFi6Dq4GSX+XjNtuIePTM5o0Lw72HjIg33oCqDBbjljlQ+eoe8PKp
         ffWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pKd6dJBV4N8YLl9Ne/rLrhUWGWga9X9929E81Ir9VwE=;
        b=txUseh975w/C70tN5ySeoQXA9atu4Bd4enLpII9tQUIScHm+is9FRb3B1cAJNolJ0b
         iSJBqnqPkPWV8HHO/Ao2J6Nk48SKyRf/2FR0yIQzuHw7bo9FLM9gHgEqPd7o06q90C+n
         h7s52kDdSUsCsNL4aL2heQB+GTxgfNkUXmjtta4osPomTkyEEqQ3Km5Xf+qL0eIQed78
         GqWFQm6jrBlqGaK3jIJFgo6tkuVmcY6h5soF16HxwM/kkWpPjBm6xQl2D7dlw6EK8/5I
         keol5Cwzgc+n3aOSz21odf7eHsT+mTjFkx/zlikIt5akiR/0OaDczsB22wJG5qtQdQD4
         JwAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wOYvQpib;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id c13si272435ybr.5.2021.06.27.23.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Jun 2021 23:00:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id a5-20020a05683012c5b029046700014863so792560otq.5
        for <kasan-dev@googlegroups.com>; Sun, 27 Jun 2021 23:00:21 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr19965428oto.17.1624860021048;
 Sun, 27 Jun 2021 23:00:21 -0700 (PDT)
MIME-Version: 1.0
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com> <20210626100931.22794-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210626100931.22794-3-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jun 2021 08:00:00 +0200
Message-ID: <CANpmjNO6odUDsERDtw2Qrt9VOTXXfswtcFw06fiRoAUvqKaK2w@mail.gmail.com>
Subject: Re: [PATCH v4 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org, 
	wsd_upstream@mediatek.com, chinwen.chang@mediatek.com, 
	nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wOYvQpib;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sat, 26 Jun 2021 at 12:09, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> 1. Move kasan_get_free_track() and kasan_set_free_info()
>    into tags.c and combine these two functions for
>    SW_TAGS and HW_TAGS kasan mode.
> 2. Move kasan_get_bug_type() to report_tags.c and
>    make this function compatible for SW_TAGS and
>    HW_TAGS kasan mode.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Suggested-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/Makefile         |  4 +--
>  mm/kasan/hw_tags.c        | 22 ---------------
>  mm/kasan/report_hw_tags.c |  5 ----
>  mm/kasan/report_sw_tags.c | 43 ----------------------------
>  mm/kasan/report_tags.c    | 51 +++++++++++++++++++++++++++++++++
>  mm/kasan/sw_tags.c        | 41 ---------------------------
>  mm/kasan/tags.c           | 59 +++++++++++++++++++++++++++++++++++++++
>  7 files changed, 112 insertions(+), 113 deletions(-)
>  create mode 100644 mm/kasan/report_tags.c
>  create mode 100644 mm/kasan/tags.c
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 9fe39a66388a..adcd9acaef61 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -37,5 +37,5 @@ CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>
>  obj-$(CONFIG_KASAN) := common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
> -obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
> -obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
> +obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
> +obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index ed5e5b833d61..4ea8c368b5b8 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -216,28 +216,6 @@ void __init kasan_init_hw_tags(void)
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> -void kasan_set_free_info(struct kmem_cache *cache,
> -                               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> -               kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> -}
> -
> -struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -                               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (!alloc_meta)
> -               return NULL;
> -
> -       return &alloc_meta->free_track[0];
> -}
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
>  {
>         /*
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index 42b2168755d6..5dbbbb930e7a 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -15,11 +15,6 @@
>
>  #include "kasan.h"
>
> -const char *kasan_get_bug_type(struct kasan_access_info *info)
> -{
> -       return "invalid-access";
> -}
> -
>  void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
>         return kasan_reset_tag(addr);
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 821a14a19a92..d2298c357834 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -29,49 +29,6 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -const char *kasan_get_bug_type(struct kasan_access_info *info)
> -{
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> -       struct kasan_alloc_meta *alloc_meta;
> -       struct kmem_cache *cache;
> -       struct page *page;
> -       const void *addr;
> -       void *object;
> -       u8 tag;
> -       int i;
> -
> -       tag = get_tag(info->access_addr);
> -       addr = kasan_reset_tag(info->access_addr);
> -       page = kasan_addr_to_page(addr);
> -       if (page && PageSlab(page)) {
> -               cache = page->slab_cache;
> -               object = nearest_obj(cache, page, (void *)addr);
> -               alloc_meta = kasan_get_alloc_meta(cache, object);
> -
> -               if (alloc_meta) {
> -                       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> -                               if (alloc_meta->free_pointer_tag[i] == tag)
> -                                       return "use-after-free";
> -                       }
> -               }
> -               return "out-of-bounds";
> -       }
> -
> -#endif
> -       /*
> -        * If access_size is a negative number, then it has reason to be
> -        * defined as out-of-bounds bug type.
> -        *
> -        * Casting negative numbers to size_t would indeed turn up as
> -        * a large size_t and its value will be larger than ULONG_MAX/2,
> -        * so that this can qualify as out-of-bounds.
> -        */
> -       if (info->access_addr + info->access_size < info->access_addr)
> -               return "out-of-bounds";
> -
> -       return "invalid-access";
> -}
> -
>  void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
>         u8 tag = get_tag(addr);
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> new file mode 100644
> index 000000000000..8a319fc16dab
> --- /dev/null
> +++ b/mm/kasan/report_tags.c
> @@ -0,0 +1,51 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> + * Copyright (c) 2020 Google, Inc.
> + */
> +
> +#include "kasan.h"
> +#include "../slab.h"
> +
> +const char *kasan_get_bug_type(struct kasan_access_info *info)
> +{
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +       struct kasan_alloc_meta *alloc_meta;
> +       struct kmem_cache *cache;
> +       struct page *page;
> +       const void *addr;
> +       void *object;
> +       u8 tag;
> +       int i;
> +
> +       tag = get_tag(info->access_addr);
> +       addr = kasan_reset_tag(info->access_addr);
> +       page = kasan_addr_to_page(addr);
> +       if (page && PageSlab(page)) {
> +               cache = page->slab_cache;
> +               object = nearest_obj(cache, page, (void *)addr);
> +               alloc_meta = kasan_get_alloc_meta(cache, object);
> +
> +               if (alloc_meta) {
> +                       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +                               if (alloc_meta->free_pointer_tag[i] == tag)
> +                                       return "use-after-free";
> +                       }
> +               }
> +               return "out-of-bounds";
> +       }
> +#endif
> +
> +       /*
> +        * If access_size is a negative number, then it has reason to be
> +        * defined as out-of-bounds bug type.
> +        *
> +        * Casting negative numbers to size_t would indeed turn up as
> +        * a large size_t and its value will be larger than ULONG_MAX/2,
> +        * so that this can qualify as out-of-bounds.
> +        */
> +       if (info->access_addr + info->access_size < info->access_addr)
> +               return "out-of-bounds";
> +
> +       return "invalid-access";
> +}
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index dd05e6c801fa..bd3f540feb47 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -167,47 +167,6 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
>
> -void kasan_set_free_info(struct kmem_cache *cache,
> -                               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       u8 idx = 0;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (!alloc_meta)
> -               return;
> -
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> -       idx = alloc_meta->free_track_idx;
> -       alloc_meta->free_pointer_tag[idx] = tag;
> -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> -#endif
> -
> -       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> -}
> -
> -struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -                               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       int i = 0;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (!alloc_meta)
> -               return NULL;
> -
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> -               if (alloc_meta->free_pointer_tag[i] == tag)
> -                       break;
> -       }
> -       if (i == KASAN_NR_FREE_STACKS)
> -               i = alloc_meta->free_track_idx;
> -#endif
> -
> -       return &alloc_meta->free_track[i];
> -}
> -
>  void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
>                         unsigned long ret_ip)
>  {
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> new file mode 100644
> index 000000000000..8f48b9502a17
> --- /dev/null
> +++ b/mm/kasan/tags.c
> @@ -0,0 +1,59 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains common tag-based KASAN code.
> + *
> + * Copyright (c) 2018 Google, Inc.
> + * Copyright (c) 2020 Google, Inc.
> + */
> +
> +#include <linux/init.h>
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/static_key.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +
> +#include "kasan.h"
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       u8 idx = 0;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (!alloc_meta)
> +               return;
> +
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +       idx = alloc_meta->free_track_idx;
> +       alloc_meta->free_pointer_tag[idx] = tag;
> +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> +#endif
> +
> +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       int i = 0;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (!alloc_meta)
> +               return NULL;
> +
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +               if (alloc_meta->free_pointer_tag[i] == tag)
> +                       break;
> +       }
> +       if (i == KASAN_NR_FREE_STACKS)
> +               i = alloc_meta->free_track_idx;
> +#endif
> +
> +       return &alloc_meta->free_track[i];
> +}
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210626100931.22794-3-Kuan-Ying.Lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO6odUDsERDtw2Qrt9VOTXXfswtcFw06fiRoAUvqKaK2w%40mail.gmail.com.
