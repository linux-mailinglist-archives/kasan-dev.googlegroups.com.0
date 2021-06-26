Return-Path: <kasan-dev+bncBDW2JDUY5AORBUUH3WDAMGQECMKPQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id BE6523B4F25
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 17:12:18 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id i7-20020a05600c3547b02901eaa4d778adsf430043wmq.7
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 08:12:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624720338; cv=pass;
        d=google.com; s=arc-20160816;
        b=eepu/32+fVpJEYpIUKkvEDePDKhCqp5zCRypB7vaYmxyH/4mVQWahqLQDZ1CXpsduY
         lHHfLsbHCLR1qYJfwYyfNk+SdmmxdHOrYUFl8Jl9kkkjGq2VE6AwifbRkAe+RFcRYpsc
         VzNy7rtoiVgGApm6ibfuks+0ucAXR+vQo4UtR9gu5w5EcKEM4zylQsbO0T+RfQqLAJND
         UmkSAwYl6DkazTMvfAoa3VGwn8MrDBWSc8E9vmeqMNjl+2DeRTygmkranGMPO6zfU7jN
         8vtQb+bvQjIgF7Y/xbxGL4PG1oBRkfNERR4j0l/hlT8i31YgEtarbLGV1sJ3TUtIf8qe
         QcfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=JbFpBYqUtKPR0hFBfolm8ZvFWZSuPRi6DsO90ZtJlq4=;
        b=QRF/ZDFUdIr3B7JpOUtG9mz9+/eFNGh2efeCveXYnu6OEhp7qtNtEAtE54PaGN+xjF
         MtKq3rfEkLRJVw0VOKcdMri0N4dy1houO166yRRzMZ1HTQ4bx1UCjpz7gFPRqqG8SfGu
         ab1/1u1lwtjIIZQnW5QfWQpWpblOpiIRGj85YedA4Y2eb0jTRSOjZ686MJ2Z84TGb84B
         iP8Cs+1RGJB1H3B/1+Bf5CBmSBdOJkRYV7EcibD+POCz7/VEfAD796IlXXOcecHlDVuJ
         UvLUnWHlpR3FtMVld2ehEAPbPWimLCVygoGEmlwyUkJww8F1tKjLmPrLhtFVaIA5ujjW
         MCdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sM5nFsqf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JbFpBYqUtKPR0hFBfolm8ZvFWZSuPRi6DsO90ZtJlq4=;
        b=Yn8p6qxgKP9sFwMEiu2eoo+9yrQn7BcjQlp3+pPLA6WjeQAiJHnNyOlFRu+8ej6T0O
         8LhHfZbD4tBHpPMw0O8fBFbxyO/9f1W6JwvkkcLHCh3NKjcmtFQqhtZmodxusKsHKMZL
         qruoX1B5vAKHO3i7pxNPJUBN+KK3Kz/f4ZplovV7EWh9QYT+KoZfsrRSC6dPXxHttcdd
         yoTw+zkgoRnp/rCAHdJVXJDz8GPna0drdCpKU6RAfxIPJ3Gs+4XCLSaUgOCInqXpXDbI
         FhiVKDrCqzCQJ/zTmyTorRceRI7wT+1IHSIty0dcGVHII/FyWHfxppLxaeKNhfl4tsQK
         WgSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JbFpBYqUtKPR0hFBfolm8ZvFWZSuPRi6DsO90ZtJlq4=;
        b=ucebPyvRy1rIqaOXSNgxdRRw+Z97lSCw+frjFWVwv1hgXrZawRAmzl/qKDwxlFHFGg
         n1vR3dT/iAGf8hJo/dU70kr74dfyJCM+gn/gmDH0UGiQTs3Si5evX81YxgCAuqlG2hCw
         7pGQDoMNjVllQU33psQBVteqq7wbZBOJFm1KlCqrFtq3Ppec7aUBDh9OoddGtwdYeWL0
         7Q9Dz0IFiCXbwW4GMktDnYhcopd+cWhuylRWQFYxkRBdsvWPYXrZAeXtz12EFqWmeIm9
         RqIgoDgswVp/8NFxKn2sCdX3i2fvs1eLm9s6b2MfzD1kYJz+J31cws1ft6Scdd47zSOj
         bfQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JbFpBYqUtKPR0hFBfolm8ZvFWZSuPRi6DsO90ZtJlq4=;
        b=fkWmYqWucoCxDR8Hd9kBO8SONjXb0UQgBx0/IKaQCJNs2rjm8zc0bF2G3x1ZJhFqEb
         zLCqy+rP75fwLs3pCtsbIZx2VG04DJLiHZanFFKGLfmmYl+JKFp1hutn9MmGyMIAdO4e
         UQR/+lw2D8w9H5rQBD9oKSYKOTvI4R6YR62MSmXLQEsYXtY4uQBIE4u3APt0XT7cEvl0
         0CZITaZCwEiDLh35nM2djcXA8hN7lSRoSQ1bWtHP9aAhZjUN6Cub/7xKhmlrEh3ZdUGF
         4wDFFNBfW37YSI/AQGkTdYbsruR2wtCBRJRlUSFVQelyFGL1kBDNFFbYRFBuNMTGnXiq
         bxHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TQ1jUiph72P4+weB5ABR6iYcz9NMMCE60jwBaL7yHAyfmpLKv
	Hi9tqZ0cGI6GOTw8SjZHVOc=
X-Google-Smtp-Source: ABdhPJwCct78/0OQYUyYscbU2nZWLSObqP+53k3GZPw6U0EXt1CRcpdF1Moyn/6HfpPt6LVr6VP/yQ==
X-Received: by 2002:a05:600c:3ba6:: with SMTP id n38mr16092148wms.9.1624720338513;
        Sat, 26 Jun 2021 08:12:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:: with SMTP id i4ls6215101wmq.1.canary-gmail;
 Sat, 26 Jun 2021 08:12:17 -0700 (PDT)
X-Received: by 2002:a05:600c:a45:: with SMTP id c5mr17587745wmq.153.1624720337657;
        Sat, 26 Jun 2021 08:12:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624720337; cv=none;
        d=google.com; s=arc-20160816;
        b=fcH44hfYvZhwWOZmS3OBQXVswmm0MFfXhv01EENwjvUfN/TXTVQw+C5qlczbr8EXVO
         4EGkFAaqIsBF4YtpaBsvr3sjPIpOwORk8g2V7xUr64GB9p8eLYp62SXM1R5iIsgXNh1S
         IumI8Picif1rryAQuf9kJ1d4BHL9Ch8iI8CLkzv6Cocb4gz8NNxT2qoPANjhFk0gPo3g
         AaypsGnauswWm3+gRPolEuT/tXv3Ov1/p4r9WcGD4zJeZAcnUr4QLt4HcrW+vZBSOrFe
         U8vqzUaA1ZjX4sbRcv82Odgb4Ec43MMzoT69VdKHwGHEw2tJriGTsLzOAkcsJ8dJ0Fuq
         kDOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d/h1uJ7qFN4vR9+WQkLvQTgqKrkSpgOks6V+odHZLsI=;
        b=OsFJhLe55iyaTaFfJ/f9xe5tHLkl6Gf1ZZog+tbEFXKdM3eFNJR1AnwrIMtpoSKtPQ
         ETEd6dsZUbO215OpS7ufdxKW7APRXIzcX4ldo+WQRlmwurXYRT5F9qc31g5erjFE8Y0f
         M4DqhS7XqGShRxKaNzfH7iqkJeqLTjN6tiI5Qwugvw0zBDlxyBAqcssi+jzxEffyf4N+
         oeOL8AKRFa/uGRtrcOJw/ed9umPIxwsUAu17eLVSKtkpT2e4iAXH/uCSGunu1ct3XF3R
         OAiGnjcsMH1Oiz4GTCID5vH5bGo49CWln4w2jYyosi9m9XEpc57HnBsoDpmeJOxCQnEp
         EyRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sM5nFsqf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id t7si569420wrp.5.2021.06.26.08.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Jun 2021 08:12:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id he7so20126525ejc.13
        for <kasan-dev@googlegroups.com>; Sat, 26 Jun 2021 08:12:17 -0700 (PDT)
X-Received: by 2002:a17:906:9452:: with SMTP id z18mr16652221ejx.227.1624720337395;
 Sat, 26 Jun 2021 08:12:17 -0700 (PDT)
MIME-Version: 1.0
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com> <20210626100931.22794-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210626100931.22794-3-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 26 Jun 2021 18:12:06 +0300
Message-ID: <CA+fCnZfy-C+J_wdMm7Wao+4iUcN1YUAmxX9wjNKDGRq=4YgAng@mail.gmail.com>
Subject: Re: [PATCH v4 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>, wsd_upstream@mediatek.com, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=sM5nFsqf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::630
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Jun 26, 2021 at 1:09 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfy-C%2BJ_wdMm7Wao%2B4iUcN1YUAmxX9wjNKDGRq%3D4YgAng%40mail.gmail.com.
