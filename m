Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4MPSODAMGQEVTEGNJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 024B93A4F57
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 16:42:58 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id 45-20020a9f23300000b029025645a7d138sf3632542uae.11
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 07:42:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623508978; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZE1ZFdqbk25bkDWV3nKW9xouvTvr0jizLU1QxTYoBReKdgmmoa1FToFyxIAYrCoVvB
         e6DANEb3c2/CXj6Qwfml2CeSCeTExUg24L7Rz2kha/qaWyh+knkTjJ9tMTSshLPKOlPB
         iwnLmnoYYhxM8OqWU6yfI9wlUqENyjbKb15ovWqpjdKmXqtVDeUchAh3hqwO9YYdOPTg
         JOOyRda9CjEWstrl0g2VpVix7fKVAu0g4dwzXOAxnEu0gtxwZW9dWpNG0YWealq2ORFU
         Tufj7tD6S314KWo59aGqaDjnKq2ZrG+mNjFcVuoCw2jFw4pPrsOCgvViybEEmw713A0M
         ZQ7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WJmp/QRSN5CRnJp7NJIAf0xfEf2x2BOhl8g1+L0ISNA=;
        b=0NGWsGb3HQWfF1+GxQG7Ji1y/j85T1pAgGdBWYUAlWtMtbUr9E2QPJHUbXj3uFhVmc
         a6/PcUFmymv/AlvjL4YJf8tfACRd1aTwOQA2f2L6F4WOysY8ooRWUCyUXo5ZfVlXt6bP
         o0l5hBTGa3NiOssGgKWZGwH/J+ZSkfxvd8w7A7/tjWm7pe3U6aRnV2q5InCf67hHqiy5
         eJOG/sfjmRBLY4X803wr4vMwQ7SNN2TPejAE36r/I9jurzcAWmDM2necaIS4A1sjkj6E
         s4jybEcmj1jQMCGO4A7erlfu62BzQH8hgrX0sVZA7tqrutr5vdy2dhDp+U3s75DNyiBg
         y12g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="wNxXyE/0";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJmp/QRSN5CRnJp7NJIAf0xfEf2x2BOhl8g1+L0ISNA=;
        b=PTuTUCbUQQl7WDUgjH+NUCKnzLs45OXRBEEH8BwCGJLSFbxr+B0IQMejXRWAcsTRVj
         PgbM9I3qNa6PnuwIsXlKMNV/Z7lWNxqXvSdjc7GYpnRgAyB062M3eu9CpSNWKBegGHls
         zNAiYD6/4u+H0unHHNdIO/YLTik72nnYPydfc5zLd+hPnvQzN1AzyV9lKDZ51DS8n7ZQ
         X9joqa604tS3nNhjzPcZoE6hvboEyGcJP7QIeYZ0eMU5Grfw50tJ+kt/pjQsAqFeikJU
         CjEzzh/7cz2w5a0LKNz78gV7v7PA251Li/vRwtQs1mx9J4Nut7k7CJCoXhkT4ezceTzI
         IrQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJmp/QRSN5CRnJp7NJIAf0xfEf2x2BOhl8g1+L0ISNA=;
        b=ihshRTM1E9VlPt24ay5knrVN02if0hVP/w09FCzjKFuU+9d4PziP110CThawexR1fH
         EnCJyxaeQLCrdv6RcSdFk6c2f0cT3Tse0XpS3IGobeYPaF8Gg2uBCC4Q8KN8Kp0yGbEH
         QDwPAtwBfUTM3sL30ejb182pxWfLTzNDgigzfjrJq36gsYHKOlQsejfarKxfbF4BuvP+
         CwOXBnv1v2IwONCauUcChGtG67NvTa9PFfoGLAtF9aKytCmG7kRNnI0nXiWXW7gbFDzG
         yg715rWK6xjKKO4aQ+55DnhnthEvJmUh4ADepAZvIzs1N9PUxCgg1aXN68rtzJf+8IFx
         m5/Q==
X-Gm-Message-State: AOAM532W/+WVkXY0P3BvqqKk7NILHn5ql9nRwjxPuWt+17tNhevIc+m6
	XJro58hhH0kWX8kDz3T6DTY=
X-Google-Smtp-Source: ABdhPJycDP149OrRNIdm+tAgD1lr0jlm394MOlGilFhrgi+Xtw4SHBw7v7vrqsi0HrWFene+nHzrUA==
X-Received: by 2002:ab0:35eb:: with SMTP id w11mr7491549uau.142.1623508977880;
        Sat, 12 Jun 2021 07:42:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc4f:: with SMTP id p15ls320751vsq.2.gmail; Sat, 12 Jun
 2021 07:42:57 -0700 (PDT)
X-Received: by 2002:a67:443:: with SMTP id 64mr2062754vse.17.1623508977343;
        Sat, 12 Jun 2021 07:42:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623508977; cv=none;
        d=google.com; s=arc-20160816;
        b=hY/+LAe1JbEjY1YTi4KkL2qrbBsH7259dZLz6gmU4K3Zged8cqSqpbj6mRsY4zTFvF
         8TSR5IwAjFAL+BivJzvfO3WI2DKSlnsNm/uWhkeetOFzbAm/Gbn4RaxDZdcxTBaPXivM
         rr72hV91Ob/WAZiAqDMSBDycgIroskiQv0NwtXC4rlUwfB8jnoW1vrunqHIrrWwqp4i7
         6mv7DrfTzvSTw5oEVXcYo1UBAHAmmr6KgIAyKE5Dbaa3xfuBTOV8ObOGdwAL68aF0GBK
         zORQ6uNLIxRWMdAJLCjwr+gzSTMd0bvPo7QFcw71sRCV+P25qNaAB+lbMVl0Mt4TpzvP
         qs3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iH7EgL9X46ZYFZJtSIwwFSnS3uKaFXLbIujUQXunbi0=;
        b=jHgHLFX7vVvcLdiQ6+S1bGJHqV8ErABVW4OSc07JGWB479hYyNSp2UmLxPX17U9wvO
         z+Lprn6NiSE5n6SkV9ndb3nX2lIuPSkim19SQeqYMkdCE1skJy2Z6n5WcmaL7/QzVqRZ
         2n5G0ZtEp7QjGioLaVux6FRXFj69GgegtRRjov+JfqD9yZbiTvxXa6N5pUBaeuohz9TS
         vJsnDNINUuT+ytaIJFXjzHHXAwEF13WH/PHnUpC2hJdHUwZZ7RUDM6G2u/RTvkLEQlAJ
         Jkolyhv9QRi+e/zhtvGRJ32A4LOn8AY3T/nRLYoPUFWdDJuwVvkoa7QgpHjMM3FDBEv1
         SgXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="wNxXyE/0";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id a1si818937uaq.0.2021.06.12.07.42.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Jun 2021 07:42:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id 5-20020a9d01050000b02903c700c45721so6199782otu.6
        for <kasan-dev@googlegroups.com>; Sat, 12 Jun 2021 07:42:57 -0700 (PDT)
X-Received: by 2002:a05:6830:1c7b:: with SMTP id s27mr7290621otg.233.1623508976605;
 Sat, 12 Jun 2021 07:42:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210612045156.44763-1-kylee0686026@gmail.com> <20210612045156.44763-3-kylee0686026@gmail.com>
In-Reply-To: <20210612045156.44763-3-kylee0686026@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 12 Jun 2021 16:42:44 +0200
Message-ID: <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Kuan-Ying Lee <kylee0686026@gmail.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="wNxXyE/0";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Sat, 12 Jun 2021 at 06:52, Kuan-Ying Lee <kylee0686026@gmail.com> wrote:
> 1. Move kasan_get_free_track() and kasan_set_free_info()
>    into tags.c
> 2. Move kasan_get_bug_type() to header file
>
> Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>  mm/kasan/Makefile         |  4 +--
>  mm/kasan/hw_tags.c        | 22 ---------------
>  mm/kasan/report_hw_tags.c |  6 +---
>  mm/kasan/report_sw_tags.c | 46 +------------------------------
>  mm/kasan/report_tags.h    | 56 +++++++++++++++++++++++++++++++++++++
>  mm/kasan/sw_tags.c        | 41 ---------------------------
>  mm/kasan/tags.c           | 58 +++++++++++++++++++++++++++++++++++++++
>  7 files changed, 118 insertions(+), 115 deletions(-)
>  create mode 100644 mm/kasan/report_tags.h
>  create mode 100644 mm/kasan/tags.c
[...]
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
> index 42b2168755d6..ef5e7378f3aa 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -14,11 +14,7 @@
>  #include <linux/types.h>
>
>  #include "kasan.h"
> -
> -const char *kasan_get_bug_type(struct kasan_access_info *info)
> -{
> -       return "invalid-access";
> -}
> +#include "report_tags.h"
>
>  void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 821a14a19a92..d965a170083e 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -26,51 +26,7 @@
>
>  #include <asm/sections.h>
>
> -#include "kasan.h"
> -#include "../slab.h"
> -
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
> +#include "report_tags.h"
>
>  void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
> diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
> new file mode 100644
> index 000000000000..4f740d4d99ee
> --- /dev/null
> +++ b/mm/kasan/report_tags.h
> @@ -0,0 +1,56 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __MM_KASAN_REPORT_TAGS_H
> +#define __MM_KASAN_REPORT_TAGS_H
> +
> +#include "kasan.h"
> +#include "../slab.h"
> +
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +const char *kasan_get_bug_type(struct kasan_access_info *info)
> +{
[...]
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

This seems to change behaviour for SW_TAGS because it was there even
if !CONFIG_KASAN_TAGS_IDENTIFY. Does it still work as before?

> +
> +       return "invalid-access";
> +}
> +#else
> +const char *kasan_get_bug_type(struct kasan_access_info *info)
> +{
> +       return "invalid-access";
> +}
> +#endif
> +
> +#endif
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
> index 000000000000..9c33c0ebe1d1
> --- /dev/null
> +++ b/mm/kasan/tags.c
> @@ -0,0 +1,58 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains common tag-based KASAN code.
> + *
> + * Author: Kuan-Ying Lee <kylee0686026@gmail.com>

We appreciate your work on this, but this is misleading. Because you
merely copied/moved the code, have a look what sw_tags.c says -- that
should either be preserved, or we add nothing here.

I prefer to add nothing or the bare minimum (e.g. if the company
requires a Copyright line) for non-substantial additions because this
stuff becomes out-of-date fast and just isn't useful at all. 'git log'
is the source of truth.

Cc'ing Greg for process advice. For moved code, does it have to
preserve the original Copyright line if there was one?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH%3D-MKKgDb1-dQaA%40mail.gmail.com.
