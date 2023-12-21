Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUFWSKWAMGQEYC4YILI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5036A81BF6E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:08:49 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-33689c90957sf611988f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:08:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189329; cv=pass;
        d=google.com; s=arc-20160816;
        b=W16GrCqvCQIn4ZFDqnccEvJLgS0UAO1EEhUybDxdVolODd8CI57BoM0i8L1SZmiV9B
         YFYkaYpdfbahFgr0xsgTCEh/+m6JUKkvEsApGQ17RmklaEfbvhUOpPPMokmzZn8dcocV
         FTBGQQacMkClS/T+UmdqhGo6m9+q93argAtP33TNTpQX1W4jgF0XoPy2kjpmtodgM5I7
         Ms0ZSjlPg2IfKgxtd6y8+K6bRJr4cOPGBvDQaqU2z+8Iao1DwqiVGPfhQ3O2BniTYkpE
         c8ZkGf8G65/dLz9hmmpEKO21tRGFJ06tna+9zugU3Ab5ftoG0G57j/Se1NEfwxL2IBt2
         vGdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gsRz/MpJSA98QOz2AHde1oM13oYlFYaR8wMJmQ7MOBE=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=eHoTcxA7VwIzWtx3UTXuNiP5HVMy97rQ7DBuCgfmo7/EHXDrsVDmt7Y3NQGjZs1Nrx
         vVeeDpWjic0QgaFcfsQbS8UukkWuJ6B/a0DSKyjs5WQSmxjqIv1OToTANltIt6Vjo66b
         Ud4qlPguPhQw8YkhcKxnxvRhZtn1Q1GmFuepvA0iBf5wsNAsNFct5R91e35Zb7gu7RAO
         xhVbPdIroax20VaH5Q4P2Zie3v2Zx24e6Jc99SbAof0CzRWu/3HtJBjyG1izjfIwFfXB
         pwOSdE97Gp2sLRjZTuQi+1n78xeoB1RdPdF3DOaqSZFwf6+cOijmh2D9qwzpUPrctr4A
         0xrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JfTnZ7z6;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189329; x=1703794129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gsRz/MpJSA98QOz2AHde1oM13oYlFYaR8wMJmQ7MOBE=;
        b=buIBzW5iqnzQlBT0anh88CeTd3sbeTXojiW9X08EdE67gYD2Yxg5TMe9j78pwtqU1n
         NS83KBimiXJLsmXec3MIBDpyckndJ6tIQtiu34HzTbMiSjJo2YXrYE8CyPvXwnK7NcuA
         4XMS7Pfb/KEdPavFabHENbnUuHSSkJXuLs2jjefD6NqQ+B07NSeXA0fFtRAdot+LQ91q
         +EqMMeNCIPwy5KI2U+411Cp/Q36Y9cIwHfxlUmX542hr7Sc5xonFTP4D5hqPeDMlRMJ3
         ShkfVhAeduLYCXPI7oE6iyqqFtVe1yY5o0HQ/M/TecZ99OWn4EvUWWI3OlB4gx5ul4UJ
         AfHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189329; x=1703794129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gsRz/MpJSA98QOz2AHde1oM13oYlFYaR8wMJmQ7MOBE=;
        b=d7EEvJGtx1jtERjvDhyxjrPhPkskUqnotZg0UwntJs0+KSCLm/hX/+2U8TbBPD/s73
         PgLL9HFFAmCjNjZEOCCc67aipSg9punVhf0D0WHcaJtVpEMe29wVDK01y7s7b4cGR/7+
         znA1YbHzbbPFBhLGJyBSAzgYgma/jxtnPDlxPm74bPdGTKMyJfMWa3SqAo9lom7mYBiy
         APfwRnwgwmjLyX1q7W7uLfrbPEURwhJ2Phb2yW+dnxiFxA/mztPxyZbvza1FwqB53QTA
         wYUiENd53dINC6AQSynzUzfB46h7ZCYDhxCUN6OBKbnrQQUtW2HiPFLiehNeqM1dLMWw
         6xAA==
X-Gm-Message-State: AOJu0YxARozrlAIEGnvgDetBab9lWqIxI6nLCx9XLD1ZKk+MitvHf3Xp
	Zusfq8Y9BrW6fHq/hjp5fWw=
X-Google-Smtp-Source: AGHT+IH/CIcf+eyfSEPuontLaOCB32oextLaUUaRZNoiDDAVQTvOou+BXH5OkcOxzVXVtK++slIwSw==
X-Received: by 2002:adf:e4d1:0:b0:331:72f5:8ce7 with SMTP id v17-20020adfe4d1000000b0033172f58ce7mr204976wrm.24.1703189328482;
        Thu, 21 Dec 2023 12:08:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5185:0:b0:336:7659:12d4 with SMTP id k5-20020a5d5185000000b00336765912d4ls521465wrv.2.-pod-prod-07-eu;
 Thu, 21 Dec 2023 12:08:46 -0800 (PST)
X-Received: by 2002:a05:600c:5389:b0:40c:66bf:c6a2 with SMTP id hg9-20020a05600c538900b0040c66bfc6a2mr144151wmb.92.1703189326516;
        Thu, 21 Dec 2023 12:08:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189326; cv=none;
        d=google.com; s=arc-20160816;
        b=rJ1tK/IfO+ihKCIUHWG4betP5qP+GPmCvc5mw8t29D9XDOxiY6NAG/VZhLDMutjJBD
         nfKngElvWRmh8EyA4CVOG4B1SipM5EOo82WISMKStl6M0snUcX3zpNchn8DgmQXm6nmb
         FceaR0YuyAX1YxJgWNAI20pDoJmV0Ya9PnqjtmdXy7sPYpm6tmHlvstP4NHSrgQfBfot
         SjZsLOWPsXJKvUk4Gtjr4vEy04pols7+kP1MbGOxxxDh1IXXgS2dJFo4hyUtFN3wrKhP
         6CNYnCOof902JKhNmNsMmNKG8oFWkyltKQl1HUR7u1ZiGYyIkUwf/epk95TkqPOpLwJT
         Zcfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CI7GB6u39MLbqZUFzJg2hzBKBi/8Q4CxwH4rHsWQ8yc=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=ZNG9HlfcV7ZUw0tzmoSIPD5ai/32dOcgvK++UU6h8w/ZaqmxiB3eKseMe0ccqHEva0
         1A430Ulzj0wXyeR/cMEAvD9+1F21+Uitac3UGD+iVN5+idiTjhxtQlPiTK1aFe9Qhece
         5xGxBELP5zXeGJykDB7nTMZwSIaSjgepCa7NLIRoFFRz8CG9sBHh9jbaqoz2c/RR+PnN
         SAUQGdfaiLh2q+BxT32/PsZJpE9FpoaS3yb1uryLb9OLhxAIdF6Q3UXIuEzl/McZUq56
         72swZP2KxoZ+lkrSlrhrwnmkdi9B4tJPU6ycAELsK78yDzgJjV2TiL3PL1RfXsu/ARAV
         YPHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JfTnZ7z6;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id l42-20020a05600c1d2a00b0040d2cb644ddsi76768wms.1.2023.12.21.12.08.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:08:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-50e62c1245eso943208e87.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:08:46 -0800 (PST)
X-Received: by 2002:a05:6512:23a2:b0:50e:3777:f779 with SMTP id
 c34-20020a05651223a200b0050e3777f779mr116972lfv.31.1703189325320; Thu, 21 Dec
 2023 12:08:45 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Dec 2023 21:08:04 +0100
Message-ID: <CANpmjNMezNWBoH8m38XO2=dP9KQk+_Vb8bo41F7ytQVdbEe-3g@mail.gmail.com>
Subject: Re: [PATCH mm 1/4] kasan: clean up kasan_cache_create
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Juntong Deng <juntong.deng@outlook.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JfTnZ7z6;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::136 as
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

On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Reorganize the code to avoid nested if/else checks to improve the
> readability.
>
> Also drop the confusing comments about KMALLOC_MAX_SIZE checks: they
> are relevant for both SLUB and SLAB (originally, the comments likely
> confused KMALLOC_MAX_SIZE with KMALLOC_MAX_CACHE_SIZE).
>
> Fixes: a5989d4ed40c ("kasan: improve free meta storage in Generic KASAN")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/generic.c | 67 +++++++++++++++++++++++++++-------------------
>  1 file changed, 39 insertions(+), 28 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 54e20b2bc3e1..769e43e05d0b 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -381,16 +381,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>
>         ok_size = *size;
>
> -       /* Add alloc meta into redzone. */
> +       /* Add alloc meta into the redzone. */
>         cache->kasan_info.alloc_meta_offset = *size;
>         *size += sizeof(struct kasan_alloc_meta);
>
> -       /*
> -        * If alloc meta doesn't fit, don't add it.
> -        * This can only happen with SLAB, as it has KMALLOC_MAX_SIZE equal
> -        * to KMALLOC_MAX_CACHE_SIZE and doesn't fall back to page_alloc for
> -        * larger sizes.
> -        */
> +       /* If alloc meta doesn't fit, don't add it. */
>         if (*size > KMALLOC_MAX_SIZE) {
>                 cache->kasan_info.alloc_meta_offset = 0;
>                 *size = ok_size;
> @@ -401,36 +396,52 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>         orig_alloc_meta_offset = cache->kasan_info.alloc_meta_offset;
>
>         /*
> -        * Add free meta into redzone when it's not possible to store
> +        * Store free meta in the redzone when it's not possible to store
>          * it in the object. This is the case when:
>          * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
>          *    be touched after it was freed, or
>          * 2. Object has a constructor, which means it's expected to
> -        *    retain its content until the next allocation, or
> -        * 3. Object is too small and SLUB DEBUG is enabled. Avoid
> -        *    free meta that exceeds the object size corrupts the
> -        *    SLUB DEBUG metadata.
> -        * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
> -        * If the object is smaller than the free meta and SLUB DEBUG
> -        * is not enabled, it is still possible to store part of the
> -        * free meta in the object.
> +        *    retain its content until the next allocation.
>          */
>         if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
>                 cache->kasan_info.free_meta_offset = *size;
>                 *size += sizeof(struct kasan_free_meta);
> -       } else if (cache->object_size < sizeof(struct kasan_free_meta)) {
> -               if (__slub_debug_enabled()) {
> -                       cache->kasan_info.free_meta_offset = *size;
> -                       *size += sizeof(struct kasan_free_meta);
> -               } else {
> -                       rem_free_meta_size = sizeof(struct kasan_free_meta) -
> -                                                                       cache->object_size;
> -                       *size += rem_free_meta_size;
> -                       if (cache->kasan_info.alloc_meta_offset != 0)
> -                               cache->kasan_info.alloc_meta_offset += rem_free_meta_size;
> -               }
> +               goto free_meta_added;
> +       }
> +
> +       /*
> +        * Otherwise, if the object is large enough to contain free meta,
> +        * store it within the object.
> +        */
> +       if (sizeof(struct kasan_free_meta) <= cache->object_size) {
> +               /* cache->kasan_info.free_meta_offset = 0 is implied. */
> +               goto free_meta_added;
>         }
>
> +       /*
> +        * For smaller objects, store the beginning of free meta within the
> +        * object and the end in the redzone. And thus shift the location of
> +        * alloc meta to free up space for free meta.
> +        * This is only possible when slub_debug is disabled, as otherwise
> +        * the end of free meta will overlap with slub_debug metadata.
> +        */
> +       if (!__slub_debug_enabled()) {
> +               rem_free_meta_size = sizeof(struct kasan_free_meta) -
> +                                                       cache->object_size;
> +               *size += rem_free_meta_size;
> +               if (cache->kasan_info.alloc_meta_offset != 0)
> +                       cache->kasan_info.alloc_meta_offset += rem_free_meta_size;
> +               goto free_meta_added;
> +       }
> +
> +       /*
> +        * If the object is small and slub_debug is enabled, store free meta
> +        * in the redzone after alloc meta.
> +        */
> +       cache->kasan_info.free_meta_offset = *size;
> +       *size += sizeof(struct kasan_free_meta);
> +
> +free_meta_added:
>         /* If free meta doesn't fit, don't add it. */
>         if (*size > KMALLOC_MAX_SIZE) {
>                 cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
> @@ -440,7 +451,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>
>         /* Calculate size with optimal redzone. */
>         optimal_size = cache->object_size + optimal_redzone(cache->object_size);
> -       /* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
> +       /* Limit it with KMALLOC_MAX_SIZE. */
>         if (optimal_size > KMALLOC_MAX_SIZE)
>                 optimal_size = KMALLOC_MAX_SIZE;
>         /* Use optimal size if the size with added metas is not large enough. */
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMezNWBoH8m38XO2%3DdP9KQk%2B_Vb8bo41F7ytQVdbEe-3g%40mail.gmail.com.
