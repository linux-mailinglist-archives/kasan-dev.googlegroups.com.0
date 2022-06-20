Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ7RYGKQMGQEUWAIZYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id CBD46551AD0
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:21 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id z13-20020a17090ab10d00b001ec86329c08sf1382077pjq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732420; cv=pass;
        d=google.com; s=arc-20160816;
        b=EpNXOWyBaX9AiAwtj5/IZEma6IrtITZG0RIFbv3xOi6A1zwq1cCVxutgGAACVds9AR
         BfG5J+fWrdn1STDj09pr/deUPDuPOd6Xt9kaGDcy2zc/lbTR6snUG6lB7szt9/XyOMB3
         QX3m5mnfQcoGxKB4ByzNC8rM6CQ7gMhsqfCwRY/+kw6PfIy+5B0e2FQdbwWGcaPktrqq
         e3dVkYjtskUuWLBXQEpi159qSnetO1dNt1SaO94BZKG6xVWrwKiUToGShHett6Y0XYRg
         z3WkhJRFsSAT5Rh6mu7cUewAx8lyPha/6URQ9zF3jbGzPNnTd6TAD2FG7SGp6D8Nson8
         gcgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SqnXNhyFkuSdmp2v3T2K6HRmboRKhkpPX9XICyOpP9I=;
        b=FXA97GYNTsSw9yc5/EpO01pOZs1u6tVoiWT34NK/2CX3AIJCDlsFoo/Sxse/kHnUDQ
         MsGpkQsvTsLwlk454RW824q6KqROJO/KaiFM1d4lqzymWu6xtfkuVUA0Uylmsu/X7Lu7
         Ur8UDCR2TE+nG3vA4NmzX31b24/ChwAMuO2QCtbxSzEwd+L5oxZ/3+mbK8nW/n0yJaJs
         rfQqrAnYwCRF1pzgq8PHuXGeWEvoHXKbrDzQcltNlAvefg0gu2S2tIxSdgQXE2NxOa8X
         BqDAp8Bctu+SnF5G89DSCnXNeGNXRerl+6xE3pSc+sHtfpoDenSO9ywhMDY80W4jRsdG
         oXJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rcNec0L2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SqnXNhyFkuSdmp2v3T2K6HRmboRKhkpPX9XICyOpP9I=;
        b=a5VrFW49QjZYwfOhC9HaUiZlwZPzZTqW2OIi0sYnNfjwb+Xg0tM5zawltF5ET11USp
         0w6MW7O6MmS3AuQqEPSmh1lv1eP7v8z4FXROVllulRWecWFX+tSIwCPM6zPrHq2aS4DA
         jXiCxZyUKf9wV3nsAgkal7j1ZbmDgnSoUhLcsYMQAsRzQLbMke+kbyzj81y+bJD/h+Sa
         Nl6mvEjk7K66o3IuoJD6bGAWHMwpE/6wvBaf/+TQ0RNMm+1BPjINqDFDatEYfSoMMIk5
         8LTRgVHE929XjYB76HJy+zkv8mbAP6n53uYf0/HN3vY9KKvIV0ETY3F+UIF1uINjr1/P
         dhIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SqnXNhyFkuSdmp2v3T2K6HRmboRKhkpPX9XICyOpP9I=;
        b=s1AQs2/y+dZMts4YK199TP/iwVKt72erwxBcAjCi8qzBNAR0n4oGdM69fTR5QG30j/
         FqkopudOmr6MT4iM07ONhbEJD4lXFiy2+BRYGNGyDAsUYBwbOlmNO0FresvawFcfIQWQ
         DyFjTI21HkHjggrtwI/B0Q9uculBEH7llIAa1x0klDkOp5d9FtnDdII7LyLJ0dCp6Zrz
         MRxPzeJWLzWgV4ksYPvGRm1SyiRev1utbFwkDGMsTusVj/wlCQ74zdntfwHJ6DMF/5sl
         uLRvNhIu6XyXvBbweEF/NQhzJtCfNzOQ43IxrTnkZjYR8u1m5rIxuegGlcR5Z1REO8Th
         VOkg==
X-Gm-Message-State: AJIora8A/qa4CvKE2hSDH/YCKSsIz913Cg02zZGbIlrL+8qv1IeAp4yC
	k/RRcrNswfeANjl9HHeB7IA=
X-Google-Smtp-Source: AGRyM1uQEs7mD/yDw8jPkQGh9/ZAyKa4ZWar2HndzM82DSW8VvyVRxjseEnYmd74+RxrvV5r0pTRlQ==
X-Received: by 2002:a17:90b:3911:b0:1ec:bd65:a307 with SMTP id ob17-20020a17090b391100b001ecbd65a307mr931839pjb.4.1655732420101;
        Mon, 20 Jun 2022 06:40:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eccf:b0:164:1958:c864 with SMTP id
 a15-20020a170902eccf00b001641958c864ls8096443plh.5.gmail; Mon, 20 Jun 2022
 06:40:19 -0700 (PDT)
X-Received: by 2002:a17:903:1c7:b0:16a:2844:8c1f with SMTP id e7-20020a17090301c700b0016a28448c1fmr4470332plh.30.1655732419307;
        Mon, 20 Jun 2022 06:40:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732419; cv=none;
        d=google.com; s=arc-20160816;
        b=SgMuv3RjnxohSt8Eim/wbRiO9VjWpHrFFma3dbWF6QX7P9AKSEpUNd/HDpbVXoX12c
         I5mSson/T88CVhyqA6ag5RTS4DkUHHb+kVD/rEUHOiEBa9PdHGQbJk95lvnmnRRkg/y8
         hDCWvI1mRrQugJWG0T78HdOgntq++NzsDqHpFY0YJHfKdXF5uPRoZzZATSg8t24GMHCk
         +GPBRfDHKb6W1vxZeqD7dfb1KEP5wrPxET9fWiFIIharWCrro/BL/TVOUJWdKvXOYug3
         NG0Sb4HgDd9UEycZxIS8zPp2qTLZoWuEfIzanca4Wnr1zXVH0NJVNZsNbpOhI6dHZXx9
         hJWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mK//W8+alc6U2SRanqIfp5lLUuphqu6jqWQbXvYHju8=;
        b=EYUhXBwqAlOBXNObgBmScbrEXlmCw8U/pSEzXdt8s/GZke39on3VbGjSkfZ6ThikuT
         5m5lsBZBNTmmmodAiSrwI7/MuEYUQbIvwLkvVTEz5H4pQn9rrrKuFUUN/ImsYePiD5RS
         TEWVgQ/kJDtBI0iWFBAfT3qragkTlOKh1ZmulvKZsr2lM0E0TKi2nPSJ2zbgQWqk09uj
         E57uKL7jGJurNusQRlt0MtvjiISRgkhKGecl7K52sCt0MpZwwWAfHQItW/6mGbNRH2fo
         MNzMGJZTwFTjfj3gSyDzkB+Pet0msM2lTEZC/6XiB+2Lbk6HseaNrGNolenY6DF1Pj1z
         0zQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rcNec0L2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id 10-20020a170902c14a00b0016a1a4a3ad5si222183plj.11.2022.06.20.06.40.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id i15so14169041ybp.1
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:19 -0700 (PDT)
X-Received: by 2002:a25:bfc8:0:b0:664:a5a8:d518 with SMTP id
 q8-20020a25bfc8000000b00664a5a8d518mr25666775ybm.625.1655732418326; Mon, 20
 Jun 2022 06:40:18 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <cfc1744f4a5eb6f50eddee53238af1a2fb4e8583.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cfc1744f4a5eb6f50eddee53238af1a2fb4e8583.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:42 +0200
Message-ID: <CANpmjNNKKUkxOnOQBf5EZ3kCMv_wqd0V74R5Rx8K1+MhbXmSJQ@mail.gmail.com>
Subject: Re: [PATCH 05/32] kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rcNec0L2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
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

On Mon, 13 Jun 2022 at 22:15, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Drop CONFIG_KASAN_TAGS_IDENTIFY and related code to simplify making
> changes to the reporting code.
>
> The dropped functionality will be restored in the following patches in
> this series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/Kconfig.kasan      |  8 --------
>  mm/kasan/kasan.h       | 12 +-----------
>  mm/kasan/report_tags.c | 28 ----------------------------
>  mm/kasan/tags.c        | 21 ++-------------------
>  4 files changed, 3 insertions(+), 66 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f0973da583e0..ca09b1cf8ee9 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -167,14 +167,6 @@ config KASAN_STACK
>           as well, as it adds inline-style instrumentation that is run
>           unconditionally.
>
> -config KASAN_TAGS_IDENTIFY
> -       bool "Memory corruption type identification"
> -       depends on KASAN_SW_TAGS || KASAN_HW_TAGS
> -       help
> -         Enables best-effort identification of the bug types (use-after-free
> -         or out-of-bounds) at the cost of increased memory consumption.
> -         Only applicable for the tag-based KASAN modes.
> -
>  config KASAN_VMALLOC
>         bool "Check accesses to vmalloc allocations"
>         depends on HAVE_ARCH_KASAN_VMALLOC
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 610057e651d2..aa6b43936f8d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -168,23 +168,13 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> -#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
> -#define KASAN_NR_FREE_STACKS 5
> -#else
> -#define KASAN_NR_FREE_STACKS 1
> -#endif
> -
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>         /* Generic mode stores free track in kasan_free_meta. */
>  #ifdef CONFIG_KASAN_GENERIC
>         depot_stack_handle_t aux_stack[2];
>  #else
> -       struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> -#endif
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> -       u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> -       u8 free_track_idx;
> +       struct kasan_track free_track;
>  #endif
>  };
>
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index e25d2166e813..35cf3cae4aa4 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -5,37 +5,9 @@
>   */
>
>  #include "kasan.h"
> -#include "../slab.h"
>
>  const char *kasan_get_bug_type(struct kasan_report_info *info)
>  {
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> -       struct kasan_alloc_meta *alloc_meta;
> -       struct kmem_cache *cache;
> -       struct slab *slab;
> -       const void *addr;
> -       void *object;
> -       u8 tag;
> -       int i;
> -
> -       tag = get_tag(info->access_addr);
> -       addr = kasan_reset_tag(info->access_addr);
> -       slab = kasan_addr_to_slab(addr);
> -       if (slab) {
> -               cache = slab->slab_cache;
> -               object = nearest_obj(cache, slab, (void *)addr);
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
> -#endif
> -
>         /*
>          * If access_size is a negative number, then it has reason to be
>          * defined as out-of-bounds bug type.
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 1ba3c8399f72..e0e5de8ce834 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -30,39 +30,22 @@ void kasan_save_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> -       u8 idx = 0;
>
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         if (!alloc_meta)
>                 return;
>
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> -       idx = alloc_meta->free_track_idx;
> -       alloc_meta->free_pointer_tag[idx] = tag;
> -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> -#endif
> -
> -       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> +       kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
>  }
>
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> -       int i = 0;
>
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         if (!alloc_meta)
>                 return NULL;
>
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
> +       return &alloc_meta->free_track;
>  }
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfc1744f4a5eb6f50eddee53238af1a2fb4e8583.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNKKUkxOnOQBf5EZ3kCMv_wqd0V74R5Rx8K1%2BMhbXmSJQ%40mail.gmail.com.
