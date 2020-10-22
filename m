Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75IY76AKGQEUHLDIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 646002964D6
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 20:50:41 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id z11sf1154389pln.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 11:50:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603392640; cv=pass;
        d=google.com; s=arc-20160816;
        b=sz/TzpK22E/OZGl1Jwa7CCGbAeT4iR5dH/w+9g3ugThOVsHNhgvtY1HFkH0IZD3fIT
         NRnUj3nXn3aNVeFRR2mLQ0StEum3uxfpVfu2WzncKMEpayy0E+XwbY/oNP2G/5gLyoEv
         BeKbxSmii+HlwGQltY7wvI2J60yseccF8LL/YGxXOIDw+5WX1AUPp7zg1Gnwm8ELtmC1
         sO/ivtVjqO3DyH7UPdFU31Nv36RFz01+QG9/FrsBzYjCR8rIh6rTh3HHfJX+QskG/M1p
         UvOBkByA5W6rwFLxqpgdw77n+DwnwMSaqtrL2LtOH7hvDqWCGFXUp1fl2fHMJryiYhms
         5VpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aW8OusedL1nmTRcpeC2fOd3UQP9nQU3iC1OXrL7VIt0=;
        b=qTKFbzxkvJCeY+x8B+UpQ2pXfjW6IgDd22gDdgK5xEDQKC/mjvmfLVeCu718esZmQ2
         mOWL2eul7MI9DaolwgETaMlGP2GNYnlDoD1LQIiKVPw9jA8mcD9LtUoLG4f7KD6Wvxwx
         ZFc3MZjTxJ5XBxnwsA2tPCJVF0kfYObKyogvDgi42nIphOoQu75L9kTo+ysU89EEJJhK
         8c6ss0OPEHE262kZz9sFSKZ3N+zXvIt6IQnZ96dhXejdmAOfzYTQw0YI/isqorfG95xl
         cWXDga9j8h932Qk8aHRhFhLOn+7VQcqpznuJk2rQybTrT6I52991zI0ny0mc70PkDEdz
         u8Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g2EE9Nly;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aW8OusedL1nmTRcpeC2fOd3UQP9nQU3iC1OXrL7VIt0=;
        b=LoMoNuA/hDQA8hFj/NthiW4V14DzVDfMdsSkmulrMdMXjlTplyEfdZ+Co5G+gOZC2f
         5TpQdeM8B6xCCCK93RY/BqCK5pHESiaXW60Nd4deiRIMLjlBDFEMUmP2SY0xcB2+H7ho
         FQuoPTMIyBMXUJK1BPwHzne053SOiLtBc6vYK6irjNmM7ofMkaVyUWP+b1ZliHA9MZOb
         klXyx7ApKkvhCMU1wwTHR0Uf7pb5DA14Ww4iJ6LzxDJS6pR8XJUd5zi0lCLIK7goM0Q9
         WW8de63ywp1r5DignPXFGMRsMkD/nlQ56s1ID/nQ++mPRZ11EWMot5VYcpq7TJE5gkHR
         9nvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aW8OusedL1nmTRcpeC2fOd3UQP9nQU3iC1OXrL7VIt0=;
        b=RqvZlUwK3WV2E6z1dNESjXjN9c8oe0zqVh92lONcm5Rw4krpPbXayKT7RQLkYcSl2q
         YI2jruFOZGSlYQU2XFsgt9wuWA1E0qgC4OOzHKhDOuKzShE1Z1Tib2XbBo93OzYG411/
         FFYpPn716JcQms0Ry9J2xkW9iqBnknB1gT+CILMc5gT8P/rBHavriUv5BaEar1geBmnm
         v5OlTXthT37rT4LZeQkCZclkfvJurVj/sPlyb59Px4HwOcijArV7Z94S2mnlYnD1VELW
         w64nHT8fGAi8ZHb4hz48ovYpw6y8ha7F2UJhi2kJAFJ+5zFRIlG0q/xbUbJJFDVobLdB
         d6Dw==
X-Gm-Message-State: AOAM531l0sK2DObo9BUWXt9sM5TYCpy2uBsCcxskGBZSwnYKPQLQ8yjo
	U67VavzrSvOyOTa61/KAX28=
X-Google-Smtp-Source: ABdhPJxzZ4pb2ZC4bk1wx5AaV2EGqdIK6P0vYfRGeFOjlQgJXh8I7NqF62NRHTDylokqJcVyQdjAgw==
X-Received: by 2002:a17:90a:9414:: with SMTP id r20mr3738657pjo.29.1603392640081;
        Thu, 22 Oct 2020 11:50:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1382265plr.3.gmail; Thu, 22
 Oct 2020 11:50:39 -0700 (PDT)
X-Received: by 2002:a17:902:6505:b029:d5:f870:4d20 with SMTP id b5-20020a1709026505b02900d5f8704d20mr3887270plk.34.1603392639482;
        Thu, 22 Oct 2020 11:50:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603392639; cv=none;
        d=google.com; s=arc-20160816;
        b=cl3XeQ0M9EzF4XxdXT8+Cn4gO6PAMReg8gTuTguc6+gwBaeY7tK3jx8d68KmFCY2u4
         kWJdNo9+qGW/yZi++6QVV0a5NtTLvZt4+/vYUiXHk9rT6irb21jUBjppxobF4jw++oZa
         NbHwcl3TrRfmam8jD+RZbwg1dfjmBn91pQ+OBqo1kbhI1vVY/vrh0EPDNm8ImP+X7CKN
         OuoGUf42CVy+IclvMcUsx7Q6dd2GDbOr4mk/m8o1ygJOVGc0NXj2E+Hwtg0HL0gx7TGv
         r4SCYfG1+Tl/89PNV1BsELjDxnMCU4h1DNcLQLmdqH2Ivfw6Wxfv5c43cNGFb/nD98PV
         6lxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nGFs8jKx1+okGk/sPcUAndnGVmWSXbPG3hh1KHn+qbA=;
        b=0OHbFsJvvBiHtlDhkcSUavcXsT+qRY/5G9NEAvTYl3eZ1wB3xYxM3AXhBJ8TgZKE/b
         uzZL5atXw1pnGyUBLrAsANraFQMBCw6MWgZoX8rr0fe4pYYmEe7OIX67o/hUL41CP1br
         B4uNPXsI7EogFCh4gEWrBEzbCfvvpnFcC6B1xqyBTg7PQQwY9SRdLKojkCnJsXtntyGE
         tWWgIN0aMlN/3NJWbyYxk8fWM+Yh+u5UKS/VYSIYGTSuTXo2/t19/EIHjZJE6txcmKwS
         9etXPuI9hich9TveImvwWVAUxibe+2zwVge8dQMFl77tpewrqEhK+5qxf5EwSDCb8RY7
         2iOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g2EE9Nly;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id t13si162835ply.2.2020.10.22.11.50.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 11:50:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id s21so2869742oij.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 11:50:39 -0700 (PDT)
X-Received: by 2002:a54:4812:: with SMTP id j18mr2624235oij.70.1603392638417;
 Thu, 22 Oct 2020 11:50:38 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
In-Reply-To: <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 20:50:27 +0200
Message-ID: <CANpmjNMcPb9dzynnxDGp0QNMB2oJQmbqxRnbsu8hds=SVx9-9g@mail.gmail.com>
Subject: Re: [PATCH RFC v2 14/21] kasan: add and integrate kasan boot parameters
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g2EE9Nly;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Thu, 22 Oct 2020 at 15:19, Andrey Konovalov <andreyknvl@google.com> wrote:
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

Why is this "ASYNC" and not "async"?

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
> +
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMcPb9dzynnxDGp0QNMB2oJQmbqxRnbsu8hds%3DSVx9-9g%40mail.gmail.com.
