Return-Path: <kasan-dev+bncBCMIZB7QWENRBMWH4X6AKGQERWSGU7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8095329CFE9
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 13:27:31 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id n14sf892816vso.10
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 05:27:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603888050; cv=pass;
        d=google.com; s=arc-20160816;
        b=IqoG64w8l0Jydruew4XNOcMELLCRFSgWmNyIwPuiZQivGSX3rpdVhr8VprqorZiBlU
         QOOm9HniPCvRni+yw8SEfi9fychvpdBI4gkyfo/10YniH9wnDf8WeoDh86tJFUb1OfMz
         bZ2ftlbr6Cq6QASbfxlxXvYGLtxRqmvOx9K1JAHiSWN8aSqXI8D2EDvveKdEAfsZamkg
         5Bw0hDk+Fh4CxG3KlAMvhljM53hYxSQkiW/V9WeyJwSDlaVy+vrY+4hTvGMmUdWO6kR+
         zMPxb/96KuUsLO4bTmYJQ9acOSvkkRGHUHAZQMPeQ5N6vUc/8b8eDQv0pqQ8DNhidH9B
         xWoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rfauWy46TRMzkayLY42fXFrp8Q8zslb6mPjnuBq08Wg=;
        b=zd6XEgOgb8pvLa3IyLcHnSc1T3mrxNDqbujQTdtXPJHVBh3KBeBp1u9wBuBZYEYEwm
         Bb1aF8hLKOP5GmmiCVbvIFoB3+RFgFQApOpQ4oWyRU4rrIy65mtDx1kZ4uqTL92eGSID
         Az0KJZQzwKNDIGbi+TVp2r8+4c2ugVAhGgYDWIB3CjIV9WgtFFYS0E/pZCucwg5Q5gHd
         Rd8RG7f+ltrTvopLlw0DbVQX6J+BQXzjru28QGV64hm3V+AiX2TscwG4FZhVFiqPutXC
         sjOl2K1ZJb8hODZNT66qnysCjPRPjPFbf8zdLpRoVKUB9CJrbra71HAsz3J7d0Og6ZE8
         LLjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QbVXD6TT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rfauWy46TRMzkayLY42fXFrp8Q8zslb6mPjnuBq08Wg=;
        b=RFBlXlJ/BiAezy6AgT/huMnkpOAhLG41pC4uFje0lb8IHaLFGBGiEbgl2SaHK7/QDS
         Ax2eBqj5rqzf+PcwDXcx2o+aMgEqtS1t/OfkcCled/ObStdZXm+IFfuN+WqOveQfZjDD
         pnDwkSQqN9gYOF+1faqQ49LOSvXEgp6HbLbabLbAgG97moHuebW5uLkp12oocu1hht05
         QVKoRSh5OREDUUpLjLRvgWHHScR8tSQFa3CkfYYo5SFjQM+WMXe3Zs7z3vINtucHg2fw
         NJuP84pKe2rYUAopSdERALfjWVzpdLrbbTEhRVw1ut0pqXixyfa8NDX35DDd3IHSqCm3
         kPPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rfauWy46TRMzkayLY42fXFrp8Q8zslb6mPjnuBq08Wg=;
        b=TqR7PekMKDQoi6xk5l0GylRASuZvmmB7+p7cffnYx+zBAeA187umx1SsCq3gbo6gRh
         7pB+cjMntv/lU5KjTQiUH4IlU9PPzLCLqS701y0dz9QimNtfAQfbK3qxXXEYID5NHXT2
         slkCXOG6Ldxnt1B3tszt5Y6X31RGM8plA6Hlz/FaN8L0FAk9YJXFrvEwSgMEfQdFm3kn
         in11R7MyeutEvNPfCy9z1yiW63Tjd1LFkHksvFW2DQSq/FKtRzCKz3gWx0Q4sixWJORB
         GzysG9waogtWVrCk0wiRPAl+MopdeHxw0Rhz32fEGWJhQFBrY9HwKXb9Oy1vL0XpEmeT
         jtlQ==
X-Gm-Message-State: AOAM530SrERjnYpc5L33jrTOVxp8mdbQrZZZFjHPxSfPGoE/kIwL2TmD
	EY6iiN6+yVOEYhWIT3QQ+bU=
X-Google-Smtp-Source: ABdhPJyZZRfs4afN+eoqe169k9GOjViQtKtiquWtUsHgVxCYnakXEnU1rdwlLEq+vd6my9aHSfHbAg==
X-Received: by 2002:a67:42c5:: with SMTP id p188mr5000448vsa.46.1603888050554;
        Wed, 28 Oct 2020 05:27:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2f8c:: with SMTP id v134ls258770vkv.4.gmail; Wed, 28 Oct
 2020 05:27:30 -0700 (PDT)
X-Received: by 2002:a1f:2c4b:: with SMTP id s72mr4761406vks.16.1603888050053;
        Wed, 28 Oct 2020 05:27:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603888050; cv=none;
        d=google.com; s=arc-20160816;
        b=BhC1xYnUrehDD5dGuxg0dbGtptMNllndXcIIPDjCQo1UOB/SsWmk7UsWR5BAKboIL5
         v5jNU5WpN1jBcBnsSVdrTmmsZTej6gzA2kY9foFBahPzCVn8sucDBY/6UQu2tqnjoPiJ
         gS2mM1MQYn3rWA+beH7NEosLkoqwLQqqVwUMrnj6ktKgVf8or8mkWsrZ7pDPXGICDnBV
         eGdJh+zW9EnmUWJaZ+DOsW+5ottGEUtVUsJmH5VgyC4Mks2FIV+NimMehQoKbbTyN1rs
         Ezdj1tYOFHAGbvpDoT5UTzTS2x0ZK4mbnHP9Hk9WFRugAWDU3AWYzl8PrgzIpDx29AW4
         LsfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LpV8BNT61wGJwZlYcom8dCyYgF7yubMkbVCW0bXEnSU=;
        b=rhRHpjkPw/geJGWt07ZOZ1wAJrKfFQfuXEdioFOtvHmwAFil9LRlKAub5X5X0pfjjT
         +/iq68XQbg+9Tm/fRjlA904zVe4AAeSXtVpMH9a+Wn0mzOXPAn6Ef+Dm0UrunKkMMP0n
         zdUAdf9bQMlzQFv3hPt9E0yF4c9/MuRTqlCyFwOu7l61ofo0RCzUi05sPh6GgcAXWmK9
         e7Slg6eVHnIaQAhbnpsl4J5qlkISVgT7/7MrhXXMpniFP9Lw1F17Kk3gHzqYnUVmDrmB
         gHk+5P0hwPLesmNBSiPTSfH06rNoTLq4pRD/R/VnxNbvuqZHFyKv6RnyjafSEtmUlwB8
         WNzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QbVXD6TT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id b16si359398vkn.5.2020.10.28.05.27.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 05:27:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id r7so4272772qkf.3
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 05:27:30 -0700 (PDT)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr7174670qkc.350.1603888049269;
 Wed, 28 Oct 2020 05:27:29 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
In-Reply-To: <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 13:27:17 +0100
Message-ID: <CACT4Y+ZNenL3B91huwk=0oMJFj6FN8ShsrO9w_mnQg4wgmjSdw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 14/21] kasan: add and integrate kasan boot parameters
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
 header.i=@google.com header.s=20161025 header.b=QbVXD6TT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> TODO: no meaningful description here yet, please see the cover letter
>       for this RFC series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
> ---
>  mm/kasan/common.c  |  92 +++++++++++++-----------
>  mm/kasan/generic.c |   5 ++
>  mm/kasan/hw_tags.c | 169 ++++++++++++++++++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h   |   9 +++
>  mm/kasan/report.c  |  14 +++-
>  mm/kasan/sw_tags.c |   5 ++
>  6 files changed, 250 insertions(+), 44 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1a5e6c279a72..cc129ef62ab1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -129,35 +129,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>         unsigned int redzone_size;
>         int redzone_adjust;
>
> -       /* Add alloc meta. */
> -       cache->kasan_info.alloc_meta_offset = *size;
> -       *size += sizeof(struct kasan_alloc_meta);
> -
> -       /* Add free meta. */
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> -            cache->object_size < sizeof(struct kasan_free_meta))) {
> -               cache->kasan_info.free_meta_offset = *size;
> -               *size += sizeof(struct kasan_free_meta);
> -       }
> -
> -       redzone_size = optimal_redzone(cache->object_size);
> -       redzone_adjust = redzone_size - (*size - cache->object_size);
> -       if (redzone_adjust > 0)
> -               *size += redzone_adjust;
> -
> -       *size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> -                       max(*size, cache->object_size + redzone_size));
> +       if (static_branch_unlikely(&kasan_stack)) {

Initially I thought kasan_stack is related to stack instrumentation.
And then wondered why we check it during slab creation.
I suggest giving it a slightly longer and more descriptive name.

... reading code further, it also disables quarantine, right?
Something to mention somewhere.



> +               /* Add alloc meta. */
> +               cache->kasan_info.alloc_meta_offset = *size;
> +               *size += sizeof(struct kasan_alloc_meta);
> +
> +               /* Add free meta. */
> +               if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> +                   (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> +                    cache->object_size < sizeof(struct kasan_free_meta))) {
> +                       cache->kasan_info.free_meta_offset = *size;
> +                       *size += sizeof(struct kasan_free_meta);
> +               }
>
> -       /*
> -        * If the metadata doesn't fit, don't enable KASAN at all.
> -        */
> -       if (*size <= cache->kasan_info.alloc_meta_offset ||
> -                       *size <= cache->kasan_info.free_meta_offset) {
> -               cache->kasan_info.alloc_meta_offset = 0;
> -               cache->kasan_info.free_meta_offset = 0;
> -               *size = orig_size;
> -               return;
> +               redzone_size = optimal_redzone(cache->object_size);
> +               redzone_adjust = redzone_size - (*size - cache->object_size);
> +               if (redzone_adjust > 0)
> +                       *size += redzone_adjust;
> +
> +               *size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> +                               max(*size, cache->object_size + redzone_size));
> +
> +               /*
> +                * If the metadata doesn't fit, don't enable KASAN at all.
> +                */
> +               if (*size <= cache->kasan_info.alloc_meta_offset ||
> +                               *size <= cache->kasan_info.free_meta_offset) {
> +                       cache->kasan_info.alloc_meta_offset = 0;
> +                       cache->kasan_info.free_meta_offset = 0;
> +                       *size = orig_size;
> +                       return;
> +               }
>         }
>
>         *flags |= SLAB_KASAN;
> @@ -165,10 +167,12 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>
>  size_t kasan_metadata_size(struct kmem_cache *cache)
>  {
> -       return (cache->kasan_info.alloc_meta_offset ?
> -               sizeof(struct kasan_alloc_meta) : 0) +
> -               (cache->kasan_info.free_meta_offset ?
> -               sizeof(struct kasan_free_meta) : 0);
> +       if (static_branch_unlikely(&kasan_stack))
> +               return (cache->kasan_info.alloc_meta_offset ?
> +                       sizeof(struct kasan_alloc_meta) : 0) +
> +                       (cache->kasan_info.free_meta_offset ?
> +                       sizeof(struct kasan_free_meta) : 0);
> +       return 0;
>  }
>
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> @@ -270,8 +274,10 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>         if (!(cache->flags & SLAB_KASAN))
>                 return (void *)object;
>
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +       if (static_branch_unlikely(&kasan_stack)) {

Interestingly, now SLAB_KASAN is always set when kasan_stack is not
enabled. So it seems to me we can move the SLAB_KASAN check into this
unlikely branch now.

> +               alloc_meta = kasan_get_alloc_meta(cache, object);
> +               __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +       }
>
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 object = set_tag(object, assign_tag(cache, object, true, false));
> @@ -308,15 +314,19 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>         rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
>         kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
>
> -       if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> -                       unlikely(!(cache->flags & SLAB_KASAN)))
> -               return false;
> +       if (static_branch_unlikely(&kasan_stack)) {
> +               if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> +                               unlikely(!(cache->flags & SLAB_KASAN)))
> +                       return false;
> +
> +               kasan_set_free_info(cache, object, tag);
>
> -       kasan_set_free_info(cache, object, tag);
> +               quarantine_put(cache, object);
>
> -       quarantine_put(cache, object);
> +               return IS_ENABLED(CONFIG_KASAN_GENERIC);
> +       }
>
> -       return IS_ENABLED(CONFIG_KASAN_GENERIC);
> +       return false;
>  }
>
>  bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> @@ -355,7 +365,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>                 KASAN_KMALLOC_REDZONE);
>
> -       if (cache->flags & SLAB_KASAN)
> +       if (static_branch_unlikely(&kasan_stack) && (cache->flags & SLAB_KASAN))
>                 set_alloc_info(cache, (void *)object, flags);
>
>         return set_tag(object, tag);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d259e4c3aefd..20a1e753e0c5 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -33,6 +33,11 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +/* See the comments in hw_tags.c */
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
> +EXPORT_SYMBOL(kasan_enabled);
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_stack);
> +
>  /*
>   * All functions below always inlined so compiler could
>   * perform better optimizations in each of __asan_loadX/__assn_storeX
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 915142da6b57..bccd781011ad 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -8,6 +8,8 @@
>
>  #define pr_fmt(fmt) "kasan: " fmt
>
> +#include <linux/init.h>
> +#include <linux/jump_label.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
>  #include <linux/memory.h>
> @@ -17,10 +19,175 @@
>
>  #include "kasan.h"
>
> +enum kasan_arg_mode {
> +       KASAN_ARG_MODE_OFF,
> +       KASAN_ARG_MODE_PROD,
> +       KASAN_ARG_MODE_FULL,
> +};
> +
> +enum kasan_arg_stack {
> +       KASAN_ARG_STACK_DEFAULT,
> +       KASAN_ARG_STACK_OFF,
> +       KASAN_ARG_STACK_ON,
> +};
> +
> +enum kasan_arg_trap {
> +       KASAN_ARG_TRAP_DEFAULT,
> +       KASAN_ARG_TRAP_ASYNC,
> +       KASAN_ARG_TRAP_SYNC,
> +};
> +
> +enum kasan_arg_fault {
> +       KASAN_ARG_FAULT_DEFAULT,
> +       KASAN_ARG_FAULT_REPORT,
> +       KASAN_ARG_FAULT_PANIC,
> +};
> +
> +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> +static enum kasan_arg_stack kasan_arg_stack __ro_after_init;
> +static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> +static enum kasan_arg_trap kasan_arg_trap __ro_after_init;
> +
> +/* Whether KASAN is enabled at all. */
> +DEFINE_STATIC_KEY_FALSE_RO(kasan_enabled);
> +EXPORT_SYMBOL(kasan_enabled);
> +
> +/* Whether to collect alloc/free stack traces. */
> +DEFINE_STATIC_KEY_FALSE_RO(kasan_stack);
> +
> +/* Whether to use synchronous or asynchronous tag checking. */
> +static bool kasan_sync __ro_after_init;
> +
> +/* Whether panic or disable tag checking on fault. */
> +bool kasan_panic __ro_after_init;
> +
> +/* kasan.mode=off/prod/full */
> +static int __init early_kasan_mode(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_mode = KASAN_ARG_MODE_OFF;
> +       else if (!strcmp(arg, "prod"))
> +               kasan_arg_mode = KASAN_ARG_MODE_PROD;
> +       else if (!strcmp(arg, "full"))
> +               kasan_arg_mode = KASAN_ARG_MODE_FULL;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.mode", early_kasan_mode);
> +
> +/* kasan.stack=off/on */
> +static int __init early_kasan_stack(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_stack = KASAN_ARG_STACK_OFF;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_stack = KASAN_ARG_STACK_ON;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.stack", early_kasan_stack);
> +
> +/* kasan.trap=sync/async */
> +static int __init early_kasan_trap(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "ASYNC"))
> +               kasan_arg_trap = KASAN_ARG_TRAP_ASYNC;
> +       else if (!strcmp(arg, "sync"))
> +               kasan_arg_trap = KASAN_ARG_TRAP_SYNC;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.trap", early_kasan_trap);
> +
> +/* kasan.fault=report/panic */
> +static int __init early_kasan_fault(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "report"))
> +               kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> +       else if (!strcmp(arg, "panic"))
> +               kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.fault", early_kasan_fault);
> +
>  void __init kasan_init_tags(void)
>  {
> -       init_tags(KASAN_TAG_MAX);
> +       if (!cpu_supports_tags())
> +               return;
> +
> +       /* First, preset values based on the mode. */
> +
> +       switch (kasan_arg_mode) {
> +       case KASAN_ARG_MODE_OFF:
> +               return;
> +       case KASAN_ARG_MODE_PROD:
> +               static_branch_enable(&kasan_enabled);
> +               break;
> +       case KASAN_ARG_MODE_FULL:
> +               static_branch_enable(&kasan_enabled);
> +               static_branch_enable(&kasan_stack);
> +               kasan_sync = true;
> +               break;
> +       }
> +
> +       /* Now, optionally override the presets. */
>
> +       switch (kasan_arg_stack) {
> +       case KASAN_ARG_STACK_OFF:
> +               static_branch_disable(&kasan_stack);
> +               break;
> +       case KASAN_ARG_STACK_ON:
> +               static_branch_enable(&kasan_stack);
> +               break;
> +       default:
> +               break;
> +       }
> +
> +       switch (kasan_arg_trap) {
> +       case KASAN_ARG_TRAP_ASYNC:
> +               kasan_sync = false;
> +               break;
> +       case KASAN_ARG_TRAP_SYNC:
> +               kasan_sync = true;
> +               break;
> +       default:
> +               break;
> +       }
> +
> +       switch (kasan_arg_fault) {
> +       case KASAN_ARG_FAULT_REPORT:
> +               kasan_panic = false;
> +               break;
> +       case KASAN_ARG_FAULT_PANIC:
> +               kasan_panic = true;
> +               break;
> +       default:
> +               break;
> +       }
> +
> +       /* TODO: choose between sync and async based on kasan_sync. */
> +       init_tags(KASAN_TAG_MAX);
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index f7ae0c23f023..00b47bc753aa 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -2,9 +2,18 @@
>  #ifndef __MM_KASAN_KASAN_H
>  #define __MM_KASAN_KASAN_H
>
> +#include <linux/jump_label.h>
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +DECLARE_STATIC_KEY_FALSE(kasan_stack);
> +#else
> +DECLARE_STATIC_KEY_TRUE(kasan_stack);
> +#endif

kasan_stack and kasan_enabled make sense and changed only in hw_tags mode.
It would be cleaner (and faster for other modes) to abstract static keys as:

#ifdef CONFIG_KASAN_HW_TAGS
#include <linux/jump_label.h>
DECLARE_STATIC_KEY_FALSE(kasan_stack);
static inline bool kasan_stack_collection_enabled()
{
  return static_branch_unlikely(&kasan_stack);
}
#else
static inline bool kasan_stack_collection_enabled() { return true; }
#endif

This way we don't need to include and define static keys for other modes.

> +extern bool kasan_panic __ro_after_init;
> +
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
>  #else
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index dee5350b459c..426dd1962d3c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -97,6 +97,10 @@ static void end_report(unsigned long *flags)
>                 panic_on_warn = 0;
>                 panic("panic_on_warn set ...\n");
>         }
> +#ifdef CONFIG_KASAN_HW_TAGS
> +       if (kasan_panic)
> +               panic("kasan.fault=panic set ...\n");
> +#endif
>         kasan_enable_current();
>  }
>
> @@ -159,8 +163,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>                 (void *)(object_addr + cache->object_size));
>  }
>
> -static void describe_object(struct kmem_cache *cache, void *object,
> -                               const void *addr, u8 tag)
> +static void describe_object_stacks(struct kmem_cache *cache, void *object,
> +                                       const void *addr, u8 tag)
>  {
>         struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
>
> @@ -188,7 +192,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 }
>  #endif
>         }
> +}
>
> +static void describe_object(struct kmem_cache *cache, void *object,
> +                               const void *addr, u8 tag)
> +{
> +       if (static_branch_unlikely(&kasan_stack))
> +               describe_object_stacks(cache, object, addr, tag);
>         describe_object_addr(cache, object, addr);
>  }
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 4db41f274702..b6d185adf2c5 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -33,6 +33,11 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +/* See the comments in hw_tags.c */
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
> +EXPORT_SYMBOL(kasan_enabled);
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_stack);
> +
>  static DEFINE_PER_CPU(u32, prng_state);
>
>  void __init kasan_init_tags(void)
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZNenL3B91huwk%3D0oMJFj6FN8ShsrO9w_mnQg4wgmjSdw%40mail.gmail.com.
