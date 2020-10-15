Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIFKUH6AKGQE7CMW5AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 01A3228F405
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 15:56:50 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id bo4sf2107897pjb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 06:56:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602770208; cv=pass;
        d=google.com; s=arc-20160816;
        b=uqob9KsgyunUr5eyY1o3ygarcpvvDAFNvOUjVBhI+TXVaR8KXAnPW59p6iQ/IF13lw
         AUC7XSyHyu6mBoxDpsTqdb/ObMU4Rvupg9jlAfpFeZQchozRre+eCiMXVOj9/IY8+sdq
         6oT7AXVlPmWMNH4zJbunalZUpaWUWIYr3JacbsXi0qvmUAWd5cFjG/sz5DU0YMBHzwFj
         ktHmblbWjKleKB6sudar7Nr0ITwnDJI62ze0x7f2m7uWoSqyUHPRtpIVcT1NUGeEATou
         9te/9BzvvGh74NhgJgcB3nHiRYT7gS+l3IwYnHYTaGFgRk1Ibkvg+WlH9CbhztUUuBbf
         u0Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pkDGp1uBvv9A1Sdomns4VATNAb2YO4N0841P8i9s2tE=;
        b=ugf74+1fAUl0OrYLOG+aa0sfQzmIdKVadDXUZmjr3qmglmf5NNsuSTqA3xyQ3ZWzTr
         Y8XhsXX8t3gbhLU+XsOBd8X2iTHqKMl372XXxBnYl1x79xTUbfT7fHsNHBBwwNusjB+q
         OylLCqpmkwIDufs734L5j3gEkIFfGlLH/gQG1wwdtcxe0XYGhbzOA9AYH8vCBi+yQcyD
         N74mza8cvPAHJX+ZHG3KlKRmK5zXb0CF88aT3P48cVpfTKPjvSB3DImFc5vj6QCymC3d
         OOUXo9ObuDsHJYYJzASxP84gYDI/V0y3AMaBb29Q3bc9jKG7PxsyIEo/+UMzXY3dDnah
         midw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KiIrGHou;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pkDGp1uBvv9A1Sdomns4VATNAb2YO4N0841P8i9s2tE=;
        b=ZnUuFn/rmP1n0o1vaFwrWOBQzDWRJRZaCrT2C8jZYuNwG6RnfmgMHWKTWjFltuqM4+
         OSLVHKMhuOLrZu6Y4XqoNZwt466gdGj/2nhcdbp6CCdbGBKirJrC77+/SaPjW1EFwx77
         n8Gm7QnFG1ctaYHvgqhu7hy12S19xJQtttlwek030MZtBo5OE5eEZQRytE+0qL1xaKKm
         Bv18d1P6vob938Ad14Yj5wqte8WmyjxpOn//0H9georVd36bj/9Lzk5EihKPs7d/dchG
         csdLAI8HfiNnqJadhuBESFV7yNR8YSyN85kNjPnGA779qHh/enayJZJpFgWF46tEWau2
         Pr4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pkDGp1uBvv9A1Sdomns4VATNAb2YO4N0841P8i9s2tE=;
        b=W3l3MEG8oEqw837qpWo88ZOfnMAtrNKmfNccadv3yWKs0+5u38drKvcgbTSRr12/Hx
         Vz2xvckQD/BhlFNu6amcHE0qS67m7bq6D1SkkM87MGiRiXvns4tpykEqge1/YKJCHfE2
         evw+2L15Z7zEsaPIdysMO+141daA0UgkDL3/G+ySIqXNCPVbsNtb6nG7VZHEQaa/KMJm
         N9xNj9afB6ZLCZ6N74HGiBudI80yeHRk7IZlA16WSmrTYsarBf1myFb+6sKBNs5E35m1
         gBUAMmHy+sqQRpQxz1HebAVQNhT6kZOMedu0YRpFtNQnbl0oMXMbCb9Ne/bzmZH8+Vb+
         CfwA==
X-Gm-Message-State: AOAM531QOhW0fjWXgfbZoeK0pJn3CABg7wLwxs3PFK9pUSkazawHb6kP
	66bgtDtn3nv66tJy4MlvJnY=
X-Google-Smtp-Source: ABdhPJx2K37ZU6KbUrmx7ZXhtZjv9FwIPrcSI0844GN/csk7wlpwfk4pgdMX24i/jpuNhcr3Z+yJdA==
X-Received: by 2002:a17:90b:882:: with SMTP id bj2mr4542132pjb.126.1602770208563;
        Thu, 15 Oct 2020 06:56:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1353740plr.3.gmail; Thu, 15
 Oct 2020 06:56:47 -0700 (PDT)
X-Received: by 2002:a17:902:b68d:b029:d3:e6e4:3d99 with SMTP id c13-20020a170902b68db02900d3e6e43d99mr4126800pls.62.1602770207408;
        Thu, 15 Oct 2020 06:56:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602770207; cv=none;
        d=google.com; s=arc-20160816;
        b=MEjt0gQUAveh3DPVlu6jl+B1hMadGhhaQp3yYAAcg7pMXXQ3ePz7xAIV21kaOE+v+2
         pSz0kVijkDPF29+Imio95JcwK0oFQv/5JkMluEfLQYuW0uH6gxcV8yfBGY2s581yn1FB
         qCaIN9HOeoGQil/4uiYpYDhRwy/Ed4RjTrN1Bk8qU8SvZbh3TaCjMzZOyXvo+y68xAeD
         au4dgN8zVZ8f1p0znn8DhM32sQsFeFiObcKcrYB2xqtfL/qNCd+yxvp1tOhQ6jGrMqog
         gguf1Ctf1RBZiifiAsPnM7ToOZ5Ow02qqPA0F1b3j8nR2TpFWk2hFgVfhVntcVboNnD/
         WMCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=azn7RcXRIW2AkXttJaklQSujumQoQGs8XWpCExsNCq0=;
        b=VRMOfGkxgOt1J/V+VFg5+aJSH2QsqniPyUZKiJgqo+b/QrlaV1zKVrOKmJ284LRkn1
         BDYMEQTec9FMCD8tLdFeNmdBqNAkmz/YhwX3Lol9qpTqWjZIv3q6FF/v9ta09LnWRZhf
         RVWaBTRrOtEpzrng5EoVZLkRnJqhE0Iq7REYQB+vzBiFAtmenA5unWcJ4jWlcfjEJCSn
         op/LNt3vIyIxktlAT9CwhDmgEdtBVGZgTz/UIZgJ4x/cgL0vAW666uI8/7xYDtIFj+/2
         M9obBYg4mo0fwGJUUgftrIFbvAsj9ZJMV1IGrwPWQ8OyBF6gPjRGiDoMtePPe3tvXl0P
         L/xQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KiIrGHou;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id m62si226177pgm.2.2020.10.15.06.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Oct 2020 06:56:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id e20so2927198otj.11
        for <kasan-dev@googlegroups.com>; Thu, 15 Oct 2020 06:56:47 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr2884474otn.233.1602770206303;
 Thu, 15 Oct 2020 06:56:46 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <c44b27703fb2fa11029ecd92522a66988295dfb6.1602708025.git.andreyknvl@google.com>
In-Reply-To: <c44b27703fb2fa11029ecd92522a66988295dfb6.1602708025.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Oct 2020 15:56:34 +0200
Message-ID: <CANpmjNMkZc6X+Z=Bw-hOXO3n9fzq4F3mOnHgieyifkoZM=_Mdw@mail.gmail.com>
Subject: Re: [PATCH RFC 8/8] kasan: add and integrate kasan_mode boot param
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KiIrGHou;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 14 Oct 2020 at 22:45, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> TODO: no meaningful description here yet, please see the cover letter
>       for this RFC series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
> ---
>  mm/kasan/common.c  | 69 +++++++++++++++++++++++++---------------------
>  mm/kasan/generic.c |  4 +++
>  mm/kasan/hw_tags.c | 53 +++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h   |  8 ++++++
>  mm/kasan/report.c  | 10 +++++--
>  mm/kasan/sw_tags.c |  4 +++
>  6 files changed, 115 insertions(+), 33 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a3e67d49b893..d642d5fce1e5 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -135,35 +135,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
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
> +       if (static_branch_unlikely(&kasan_debug)) {
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
> @@ -180,6 +182,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>                                               const void *object)
>  {
> +       WARN_ON(!static_branch_unlikely(&kasan_debug));

The WARN_ON condition itself should be unlikely, so that would imply
that the static branch here should be likely since you're negating it.
And AFAIK, this function should only be called if kasan_debug is true.

>         return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>
> @@ -187,6 +190,7 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>                                             const void *object)
>  {
>         BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> +       WARN_ON(!static_branch_unlikely(&kasan_debug));

Same here.

>         return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>
> @@ -266,8 +270,10 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>         if (!(cache->flags & SLAB_KASAN))
>                 return (void *)object;
>
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +       if (static_branch_unlikely(&kasan_debug)) {
> +               alloc_meta = kasan_get_alloc_meta(cache, object);
> +               __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +       }
>
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 object = set_tag(object, assign_tag(cache, object, true, false));
> @@ -305,6 +311,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>         kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
>
>         if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> +                       !static_branch_unlikely(&kasan_debug) ||
>                         unlikely(!(cache->flags & SLAB_KASAN)))
>                 return false;
>
> @@ -351,7 +358,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>                 KASAN_KMALLOC_REDZONE);
>
> -       if (cache->flags & SLAB_KASAN)
> +       if (static_branch_unlikely(&kasan_debug) && cache->flags & SLAB_KASAN)
>                 set_alloc_info(cache, (void *)object, flags);
>
>         return set_tag(object, tag);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d259e4c3aefd..9d968eaedc98 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -33,6 +33,10 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +/* See the comments in hw_tags.c */
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_debug);
> +
>  /*
>   * All functions below always inlined so compiler could
>   * perform better optimizations in each of __asan_loadX/__assn_storeX
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index b372421258c8..fc6ab1c8b155 100644
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
> @@ -17,8 +19,57 @@
>
>  #include "kasan.h"
>
> +enum kasan_mode {
> +       KASAN_MODE_OFF,
> +       KASAN_MODE_ON,
> +       KASAN_MODE_DEBUG,
> +};
> +
> +static enum kasan_mode kasan_mode __ro_after_init;
> +
> +/* Whether KASAN is enabled at all. */
> +/* TODO: ideally no KASAN callbacks when this is disabled. */
> +DEFINE_STATIC_KEY_FALSE_RO(kasan_enabled);
> +
> +/* Whether to collect debugging info, e.g. alloc/free stack traces. */
> +DEFINE_STATIC_KEY_FALSE_RO(kasan_debug);
> +
> +/* Whether to use syncronous or asynchronous tag checking. */
> +static bool kasan_sync __ro_after_init;

s/syncronous/synchronous/

> +static int __init early_kasan_mode(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (strcmp(arg, "on") == 0)
> +               kasan_mode = KASAN_MODE_ON;
> +       else if (strcmp(arg, "debug") == 0)

s/strcmp(..) == 0/!strcmp(..)/  ?

> +               kasan_mode = KASAN_MODE_DEBUG;
> +       return 0;
> +}
> +early_param("kasan_mode", early_kasan_mode);
> +
>  void __init kasan_init_tags(void)
>  {
> +       /* TODO: system_supports_tags() always returns 0 here, fix. */
> +       if (0 /*!system_supports_tags()*/)
> +               return;
> +
> +       switch (kasan_mode) {
> +       case KASAN_MODE_OFF:
> +               return;
> +       case KASAN_MODE_ON:
> +               static_branch_enable(&kasan_enabled);
> +               break;
> +       case KASAN_MODE_DEBUG:
> +               static_branch_enable(&kasan_enabled);
> +               static_branch_enable(&kasan_debug);
> +               kasan_sync = true;
> +               break;
> +       }
> +
> +       /* TODO: choose between sync and async based on kasan_sync. */
>         init_tags(KASAN_TAG_MAX);
>
>         pr_info("KernelAddressSanitizer initialized\n");
> @@ -60,6 +111,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  {
>         struct kasan_alloc_meta *alloc_meta;
>
> +       WARN_ON(!static_branch_unlikely(&kasan_debug));

What actually happens if any of these are called with !kasan_debug and
the warning triggers? Is it still valid to execute the below, or
should it bail out? Or possibly even disable KASAN entirely?

>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
>  }
> @@ -69,6 +121,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  {
>         struct kasan_alloc_meta *alloc_meta;
>
> +       WARN_ON(!static_branch_unlikely(&kasan_debug));
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         return &alloc_meta->free_track[0];
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 47d6074c7958..3712e7a39717 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -279,6 +279,14 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define get_mem_tag(addr)                      arch_get_mem_tag(addr)
>  #define set_mem_tag_range(addr, size, tag)     arch_set_mem_tag_range((addr), (size), (tag))
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +DECLARE_STATIC_KEY_FALSE(kasan_enabled);
> +DECLARE_STATIC_KEY_FALSE(kasan_debug);
> +#else
> +DECLARE_STATIC_KEY_TRUE(kasan_enabled);
> +DECLARE_STATIC_KEY_TRUE(kasan_debug);
> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index dee5350b459c..ae956a29ad4e 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -159,8 +159,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
> @@ -188,7 +188,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 }
>  #endif
>         }
> +}
>
> +static void describe_object(struct kmem_cache *cache, void *object,
> +                               const void *addr, u8 tag)
> +{
> +       if (static_branch_unlikely(&kasan_debug))
> +               describe_object_stacks(cache, object, addr, tag);
>         describe_object_addr(cache, object, addr);
>  }
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 099af6dc8f7e..50e797a16e17 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -33,6 +33,10 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +/* See the comments in hw_tags.c */
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
> +DEFINE_STATIC_KEY_TRUE_RO(kasan_debug);
> +
>  static DEFINE_PER_CPU(u32, prng_state);
>
>  void __init kasan_init_tags(void)
> --
> 2.28.0.1011.ga647a8990f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMkZc6X%2BZ%3DBw-hOXO3n9fzq4F3mOnHgieyifkoZM%3D_Mdw%40mail.gmail.com.
