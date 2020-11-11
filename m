Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7WVV76QKGQE67I6ZRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 16D822AF26B
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 14:45:36 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id o11sf1330363pgj.21
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 05:45:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605102334; cv=pass;
        d=google.com; s=arc-20160816;
        b=DzyYh2GhL7LT+rsT3haDNrquw/ZdviYQnzfvFq8lfccn20+BYvi+eIQLvNufj6kwld
         uUqUPaG0CR94nIEDkj8VQYjD5f6Sz7Fvum0dssU+mnHRJQq5PaAeaJeZ9BBPiXURIkx4
         TvVla8iJG8gm8MhGWyW3zFK9X0kwMkFYTzeFdnAY9EiV56xMfQhHa4V0y6AD6z/N+pKG
         HN1ZMAAa/PdxBBnLrOpY/4wY1PJJamEeTVETAs3EegJqXLk+iomexcp+FLrZBlfsTCMf
         e3H+gsxyAbSCSKeH8lhxS7bILgx6IxRk0uoi1MLQGb6hfoEtUNqIGbLOdsOf3Yme7ZAA
         4g5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qTgDge+cP1HdayQcswp5daQkXQVG9q0JzR/U5zT/DkQ=;
        b=HgWLIZ63yoB4hpjpuOt3pWhcmRBdg6NWS3bOOnOf23Y6eidDQhOrOpWW/pJdJT2jsN
         ap7nSjh5yIumqsouTHL0m8/3ncLH6M7GB8fF+nH9HAKnAecQ5GQ+E8c5WMOhpeSSwRd8
         OnxDs7f4dWpNg/MMpQ+bCcGYqq7gPzGDr6u4RgLgpOkTGYf7J/NxAcq2Ot2DeyLgnlUm
         GK+7KQvICX3gegZxYJIzObeoywB6emuqRwJDi1fwHN6sPZXyu56H2MoFvg+YjRyQfM9u
         KFQP+DoX5BNNUuxoab0EPvrOqPhksfHk+5l1mGhIuDSCmR170vx8XILpataPGGjpECD0
         x+Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tQNJjgXZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qTgDge+cP1HdayQcswp5daQkXQVG9q0JzR/U5zT/DkQ=;
        b=QyCCH7sE/BRIoczeIPtkz4L2UIU8o1DzAg3JSQ/pv4D3w2O4MB8KxekP0DqZqV5ptM
         9VdKuDHWwVueq5rJOVE0I2JzKDWpTt1cS7gbG8gAmb1Ka+AM19XDVld3oPxz74z7+IOP
         lEUojZaaQRuXY/r3ywDA/Y/GQ38V07oCHIxztgyfqc77ZPb2G5e7OoUWVWEKQTmig4md
         WoBrk8V6YMhT03Qva8+XGVJ5Pr7adJgBDlAeuyVtolVtTrhCuYZ7sg7p6Ea++cUzAOSK
         F32gmuIAC/5gD5cZF3NWnmEDjwP5ovlqf7qstWcEsWJxRoTUXFAl3VeTYPvhjDtM58ja
         kgqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qTgDge+cP1HdayQcswp5daQkXQVG9q0JzR/U5zT/DkQ=;
        b=GrB5yurzS+BEyJXgi12OAjqfO33hdsmVEcXlq0AHpH9cIrr/T5g/HT119PAF07f12B
         HLFF8u4TFlqETOOOWYn0xrE4TKJyjaePjVZ5HH+r7UG+hSUrjJPn9pYvZBaLYl5UJuMY
         QdLIzqIYFCKTLJ2d+Hau2Mf/J9fzhCQvHEKop2jjUe1RfbsCPcf7jj1hCku+DJHypqiw
         /EriFaCjTvtnIpGEi7n0xIelOgva/FNk8+SBagvpYGGaz5mqZRFOA3HpM+ZxOtHoChae
         ajVrkZJjblZHz3bzFEbC+rVBXBif0+7GbXhaBkqeR0mIV8rMONk+4hBoTyQ/t1fNNaXs
         hIhA==
X-Gm-Message-State: AOAM531A9xaQyfN54P5aN1NrkzhWqxcLU5WTXVfAxLfthIV5tDq4E1p9
	BQRCwkNzy7rFRlC2Bwm1Z14=
X-Google-Smtp-Source: ABdhPJw3ymBjPCf8RYhXV4ZrN4hJ+Us3e90b7qmN7ws4SgW3El1gJfr3o2TTW0vDIPdRb/VeeIJvZg==
X-Received: by 2002:a17:902:b487:b029:d8:b3b1:a594 with SMTP id y7-20020a170902b487b02900d8b3b1a594mr4885821plr.6.1605102334377;
        Wed, 11 Nov 2020 05:45:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls6937188pld.8.gmail; Wed, 11
 Nov 2020 05:45:33 -0800 (PST)
X-Received: by 2002:a17:902:74c7:b029:d7:e593:fcb with SMTP id f7-20020a17090274c7b02900d7e5930fcbmr12756469plt.71.1605102333823;
        Wed, 11 Nov 2020 05:45:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605102333; cv=none;
        d=google.com; s=arc-20160816;
        b=ErQ75MVTkbhPGU5dqxhEVSegCHF2679F2JavWmwrzSSGhamexx+vZXA/k54MePlALi
         /oOyw0nBQA0FOV81/ZlYKgT1PVd3PSQxw9I6jdCjyMehK5YFsMdbUBOZ0MUMSh/QoB6r
         wV8o3G6uGGAnbrXWvoegqVCKFnHs+M1WnveR8RITwVlIf7XtF29JobZkrjeNcQdBqR90
         vBnZNkV44+6E2jvAlyH1gxyYzzfB4T1W6/+eMTBawmQhLeWAexDA19rGT9Kbwc3EKA+J
         NRaqf1CxyK8Q1M9vHR7rS1P3V95pGBt9A+91dts5FskudM5gBBWs6h7uCY2f+X3uVHVT
         zJuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zfrCLSoByU9NgG4o3jcHELMAqNPrqebQ7Nz1EgEVlIk=;
        b=f1FX3TscvmLtUPEjz2dHUvcVe7P2EQt7jha/JjnTEa2rfluy5ERarL+Px0r54C/3nx
         PwVMVB1PmRJ1GPp7JTb1Oz6Td3UsoE7bYiAVafNs5SKYkyKHrW3o5d3vTt6ABObRs+y1
         SUqgdFUjuTDFvA/CTx/jISWaBANZs9g8kbAfrFbg0GFfhsdSzQTuVFs63VKGEQI7wCnv
         ousorlMUTB2h+3rtVPi8zHXrM3vHX+ZLH87Bq65L6aTL5DbS7gvELcROqvl+Y+OgVNGv
         5BqulNg2I/f7LY+X3TLiD1Y2g7z1wWnOlMfhOhwDykn7Qq0tZuzi9/vkI5KyWBhHc50W
         C5zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tQNJjgXZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id h17si117527pjv.3.2020.11.11.05.45.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 05:45:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id v11so1231899qtq.12
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 05:45:33 -0800 (PST)
X-Received: by 2002:ac8:4884:: with SMTP id i4mr23761034qtq.300.1605102332572;
 Wed, 11 Nov 2020 05:45:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <29bbfde90235ab7ac985e8bae79866cf885e4a29.1605046192.git.andreyknvl@google.com>
In-Reply-To: <29bbfde90235ab7ac985e8bae79866cf885e4a29.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 14:45:21 +0100
Message-ID: <CAG_fn=VukPaEerSHW=sTmMumiJbPkQUnsmg6-Dena7kXyZBaSw@mail.gmail.com>
Subject: Re: [PATCH v9 07/44] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tQNJjgXZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> The new mode won't be using shadow memory, but will still use the concept
> of memory granules. Each memory granule maps to a single metadata entry:
> 8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byt=
e
> for software tag-based mode, and 16 bytes per one allocation tag for
> hardware tag-based mode.
>
> Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MA=
SK
> to KASAN_GRANULE_MASK.
>
> Also use MASK when used as a mask, otherwise use SIZE.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> ---
>  Documentation/dev-tools/kasan.rst |  2 +-
>  lib/test_kasan.c                  |  2 +-
>  lib/test_kasan_module.c           |  2 +-
>  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
>  mm/kasan/generic.c                | 14 +++++------
>  mm/kasan/generic_report.c         |  8 +++----
>  mm/kasan/init.c                   |  8 +++----
>  mm/kasan/kasan.h                  |  4 ++--
>  mm/kasan/report.c                 | 10 ++++----
>  mm/kasan/tags_report.c            |  2 +-
>  10 files changed, 46 insertions(+), 45 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 2b68addaadcd..edca4be5e405 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -264,7 +264,7 @@ Most mappings in vmalloc space are small, requiring l=
ess than a full
>  page of shadow space. Allocating a full shadow page per mapping would
>  therefore be wasteful. Furthermore, to ensure that different mappings
>  use different shadow pages, mappings would have to be aligned to
> -``KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE``.
> +``KASAN_GRANULE_SIZE * PAGE_SIZE``.
>
>  Instead, we share backing space across multiple mappings. We allocate
>  a backing page when a mapping in vmalloc space uses a particular page
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 662f862702fc..2947274cc2d3 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -25,7 +25,7 @@
>
>  #include "../mm/kasan/kasan.h"
>
> -#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW=
_SCALE_SIZE)
> +#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANUL=
E_SIZE)
>
>  /*
>   * We assign some test results to these globals to make sure the tests
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index 2d68db6ae67b..fcb991c3aaf8 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -15,7 +15,7 @@
>
>  #include "../mm/kasan/kasan.h"
>
> -#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW=
_SCALE_SIZE)
> +#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANUL=
E_SIZE)
>
>  static noinline void __init copy_user_test(void)
>  {
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a4b73fa0dd7e..f65c9f792f8f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -106,7 +106,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>
>  /*
>   * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> - * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
> + * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
>   */
>  void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
> @@ -138,13 +138,13 @@ void kasan_unpoison_memory(const void *address, siz=
e_t size)
>
>         kasan_poison_memory(address, size, tag);
>
> -       if (size & KASAN_SHADOW_MASK) {
> +       if (size & KASAN_GRANULE_MASK) {
>                 u8 *shadow =3D (u8 *)kasan_mem_to_shadow(address + size);
>
>                 if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                         *shadow =3D tag;
>                 else
> -                       *shadow =3D size & KASAN_SHADOW_MASK;
> +                       *shadow =3D size & KASAN_GRANULE_MASK;
>         }
>  }
>
> @@ -296,7 +296,7 @@ void kasan_unpoison_object_data(struct kmem_cache *ca=
che, void *object)
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
>         kasan_poison_memory(object,
> -                       round_up(cache->object_size, KASAN_SHADOW_SCALE_S=
IZE),
> +                       round_up(cache->object_size, KASAN_GRANULE_SIZE),
>                         KASAN_KMALLOC_REDZONE);
>  }
>
> @@ -368,7 +368,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_b=
yte)
>  {
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 return shadow_byte < 0 ||
> -                       shadow_byte >=3D KASAN_SHADOW_SCALE_SIZE;
> +                       shadow_byte >=3D KASAN_GRANULE_SIZE;
>
>         /* else CONFIG_KASAN_SW_TAGS: */
>         if ((u8)shadow_byte =3D=3D KASAN_TAG_INVALID)
> @@ -407,7 +407,7 @@ static bool __kasan_slab_free(struct kmem_cache *cach=
e, void *object,
>                 return true;
>         }
>
> -       rounded_up_size =3D round_up(cache->object_size, KASAN_SHADOW_SCA=
LE_SIZE);
> +       rounded_up_size =3D round_up(cache->object_size, KASAN_GRANULE_SI=
ZE);
>         kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
>
>         if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> @@ -440,9 +440,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache=
, const void *object,
>                 return NULL;
>
>         redzone_start =3D round_up((unsigned long)(object + size),
> -                               KASAN_SHADOW_SCALE_SIZE);
> +                               KASAN_GRANULE_SIZE);
>         redzone_end =3D round_up((unsigned long)object + cache->object_si=
ze,
> -                               KASAN_SHADOW_SCALE_SIZE);
> +                               KASAN_GRANULE_SIZE);
>
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                 tag =3D assign_tag(cache, object, false, keep_tag);
> @@ -486,7 +486,7 @@ void * __must_check kasan_kmalloc_large(const void *p=
tr, size_t size,
>
>         page =3D virt_to_page(ptr);
>         redzone_start =3D round_up((unsigned long)(ptr + size),
> -                               KASAN_SHADOW_SCALE_SIZE);
> +                               KASAN_GRANULE_SIZE);
>         redzone_end =3D (unsigned long)ptr + page_size(page);
>
>         kasan_unpoison_memory(ptr, size);
> @@ -584,8 +584,8 @@ static int __meminit kasan_mem_notifier(struct notifi=
er_block *nb,
>         shadow_size =3D nr_shadow_pages << PAGE_SHIFT;
>         shadow_end =3D shadow_start + shadow_size;
>
> -       if (WARN_ON(mem_data->nr_pages % KASAN_SHADOW_SCALE_SIZE) ||
> -               WARN_ON(start_kaddr % (KASAN_SHADOW_SCALE_SIZE << PAGE_SH=
IFT)))
> +       if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> +               WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT))=
)
>                 return NOTIFY_BAD;
>
>         switch (action) {
> @@ -743,7 +743,7 @@ void kasan_poison_vmalloc(const void *start, unsigned=
 long size)
>         if (!is_vmalloc_or_module_addr(start))
>                 return;
>
> -       size =3D round_up(size, KASAN_SHADOW_SCALE_SIZE);
> +       size =3D round_up(size, KASAN_GRANULE_SIZE);
>         kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
>  }
>
> @@ -856,22 +856,22 @@ void kasan_release_vmalloc(unsigned long start, uns=
igned long end,
>         unsigned long region_start, region_end;
>         unsigned long size;
>
> -       region_start =3D ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE=
);
> -       region_end =3D ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZ=
E);
> +       region_start =3D ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       region_end =3D ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
>
>         free_region_start =3D ALIGN(free_region_start,
> -                                 PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +                                 PAGE_SIZE * KASAN_GRANULE_SIZE);
>
>         if (start !=3D region_start &&
>             free_region_start < region_start)
> -               region_start -=3D PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +               region_start -=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
>
>         free_region_end =3D ALIGN_DOWN(free_region_end,
> -                                    PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE)=
;
> +                                    PAGE_SIZE * KASAN_GRANULE_SIZE);
>
>         if (end !=3D region_end &&
>             free_region_end > region_end)
> -               region_end +=3D PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +               region_end +=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
>
>         shadow_start =3D kasan_mem_to_shadow((void *)region_start);
>         shadow_end =3D kasan_mem_to_shadow((void *)region_end);
> @@ -897,7 +897,8 @@ int kasan_module_alloc(void *addr, size_t size)
>         unsigned long shadow_start;
>
>         shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
> -       scaled_size =3D (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_=
SHIFT;
> +       scaled_size =3D (size + KASAN_GRANULE_SIZE - 1) >>
> +                               KASAN_SHADOW_SCALE_SHIFT;
>         shadow_size =3D round_up(scaled_size, PAGE_SIZE);
>
>         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 7006157c674b..ec4417156943 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -46,7 +46,7 @@ static __always_inline bool memory_is_poisoned_1(unsign=
ed long addr)
>         s8 shadow_value =3D *(s8 *)kasan_mem_to_shadow((void *)addr);
>
>         if (unlikely(shadow_value)) {
> -               s8 last_accessible_byte =3D addr & KASAN_SHADOW_MASK;
> +               s8 last_accessible_byte =3D addr & KASAN_GRANULE_MASK;
>                 return unlikely(last_accessible_byte >=3D shadow_value);
>         }
>
> @@ -62,7 +62,7 @@ static __always_inline bool memory_is_poisoned_2_4_8(un=
signed long addr,
>          * Access crosses 8(shadow size)-byte boundary. Such access maps
>          * into 2 shadow bytes, so we need to check them both.
>          */
> -       if (unlikely(((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1))
> +       if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1)=
)
>                 return *shadow_addr || memory_is_poisoned_1(addr + size -=
 1);
>
>         return memory_is_poisoned_1(addr + size - 1);
> @@ -73,7 +73,7 @@ static __always_inline bool memory_is_poisoned_16(unsig=
ned long addr)
>         u16 *shadow_addr =3D (u16 *)kasan_mem_to_shadow((void *)addr);
>
>         /* Unaligned 16-bytes access maps into 3 shadow bytes. */
> -       if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
> +       if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
>                 return *shadow_addr || memory_is_poisoned_1(addr + 15);
>
>         return *shadow_addr;
> @@ -134,7 +134,7 @@ static __always_inline bool memory_is_poisoned_n(unsi=
gned long addr,
>                 s8 *last_shadow =3D (s8 *)kasan_mem_to_shadow((void *)las=
t_byte);
>
>                 if (unlikely(ret !=3D (unsigned long)last_shadow ||
> -                       ((long)(last_byte & KASAN_SHADOW_MASK) >=3D *last=
_shadow)))
> +                       ((long)(last_byte & KASAN_GRANULE_MASK) >=3D *las=
t_shadow)))
>                         return true;
>         }
>         return false;
> @@ -200,7 +200,7 @@ void kasan_cache_shutdown(struct kmem_cache *cache)
>
>  static void register_global(struct kasan_global *global)
>  {
> -       size_t aligned_size =3D round_up(global->size, KASAN_SHADOW_SCALE=
_SIZE);
> +       size_t aligned_size =3D round_up(global->size, KASAN_GRANULE_SIZE=
);
>
>         kasan_unpoison_memory(global->beg, global->size);
>
> @@ -274,10 +274,10 @@ EXPORT_SYMBOL(__asan_handle_no_return);
>  /* Emitted by compiler to poison alloca()ed objects. */
>  void __asan_alloca_poison(unsigned long addr, size_t size)
>  {
> -       size_t rounded_up_size =3D round_up(size, KASAN_SHADOW_SCALE_SIZE=
);
> +       size_t rounded_up_size =3D round_up(size, KASAN_GRANULE_SIZE);
>         size_t padding_size =3D round_up(size, KASAN_ALLOCA_REDZONE_SIZE)=
 -
>                         rounded_up_size;
> -       size_t rounded_down_size =3D round_down(size, KASAN_SHADOW_SCALE_=
SIZE);
> +       size_t rounded_down_size =3D round_down(size, KASAN_GRANULE_SIZE)=
;
>
>         const void *left_redzone =3D (const void *)(addr -
>                         KASAN_ALLOCA_REDZONE_SIZE);
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 6bb3f66992df..7d5b9e5c7cfe 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -34,7 +34,7 @@ void *find_first_bad_addr(void *addr, size_t size)
>         void *p =3D addr;
>
>         while (p < addr + size && !(*(u8 *)kasan_mem_to_shadow(p)))
> -               p +=3D KASAN_SHADOW_SCALE_SIZE;
> +               p +=3D KASAN_GRANULE_SIZE;
>         return p;
>  }
>
> @@ -46,14 +46,14 @@ static const char *get_shadow_bug_type(struct kasan_a=
ccess_info *info)
>         shadow_addr =3D (u8 *)kasan_mem_to_shadow(info->first_bad_addr);
>
>         /*
> -        * If shadow byte value is in [0, KASAN_SHADOW_SCALE_SIZE) we can=
 look
> +        * If shadow byte value is in [0, KASAN_GRANULE_SIZE) we can look
>          * at the next shadow byte to determine the type of the bad acces=
s.
>          */
> -       if (*shadow_addr > 0 && *shadow_addr <=3D KASAN_SHADOW_SCALE_SIZE=
 - 1)
> +       if (*shadow_addr > 0 && *shadow_addr <=3D KASAN_GRANULE_SIZE - 1)
>                 shadow_addr++;
>
>         switch (*shadow_addr) {
> -       case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
> +       case 0 ... KASAN_GRANULE_SIZE - 1:
>                 /*
>                  * In theory it's still possible to see these shadow valu=
es
>                  * due to a data race in the kernel code.
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 9ce8cc5b8621..dfddd6c39fe6 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -442,8 +442,8 @@ void kasan_remove_zero_shadow(void *start, unsigned l=
ong size)
>         end =3D addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
>
>         if (WARN_ON((unsigned long)start %
> -                       (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
> -           WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
> +                       (KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> +           WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
>                 return;
>
>         for (; addr < end; addr =3D next) {
> @@ -477,8 +477,8 @@ int kasan_add_zero_shadow(void *start, unsigned long =
size)
>         shadow_end =3D shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
>
>         if (WARN_ON((unsigned long)start %
> -                       (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
> -           WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
> +                       (KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> +           WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
>                 return -EINVAL;
>
>         ret =3D kasan_populate_early_shadow(shadow_start, shadow_end);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 03450d3b31f7..c31e2c739301 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -5,8 +5,8 @@
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>
> -#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
> -#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)
> +#define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
> +#define KASAN_GRANULE_MASK     (KASAN_GRANULE_SIZE - 1)
>
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
>  #define KASAN_TAG_INVALID      0xFE /* inaccessible memory tag */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index d500923abc8b..7b8dcb799a78 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -314,24 +314,24 @@ static bool __must_check get_address_stack_frame_in=
fo(const void *addr,
>                 return false;
>
>         aligned_addr =3D round_down((unsigned long)addr, sizeof(long));
> -       mem_ptr =3D round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
> +       mem_ptr =3D round_down(aligned_addr, KASAN_GRANULE_SIZE);
>         shadow_ptr =3D kasan_mem_to_shadow((void *)aligned_addr);
>         shadow_bottom =3D kasan_mem_to_shadow(end_of_stack(current));
>
>         while (shadow_ptr >=3D shadow_bottom && *shadow_ptr !=3D KASAN_ST=
ACK_LEFT) {
>                 shadow_ptr--;
> -               mem_ptr -=3D KASAN_SHADOW_SCALE_SIZE;
> +               mem_ptr -=3D KASAN_GRANULE_SIZE;
>         }
>
>         while (shadow_ptr >=3D shadow_bottom && *shadow_ptr =3D=3D KASAN_=
STACK_LEFT) {
>                 shadow_ptr--;
> -               mem_ptr -=3D KASAN_SHADOW_SCALE_SIZE;
> +               mem_ptr -=3D KASAN_GRANULE_SIZE;
>         }
>
>         if (shadow_ptr < shadow_bottom)
>                 return false;
>
> -       frame =3D (const unsigned long *)(mem_ptr + KASAN_SHADOW_SCALE_SI=
ZE);
> +       frame =3D (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
>         if (frame[0] !=3D KASAN_CURRENT_STACK_FRAME_MAGIC) {
>                 pr_err("KASAN internal error: frame info validation faile=
d; invalid marker: %lu\n",
>                        frame[0]);
> @@ -599,6 +599,6 @@ void kasan_non_canonical_hook(unsigned long addr)
>         else
>                 bug_type =3D "maybe wild-memory-access";
>         pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
> -                orig_addr, orig_addr + KASAN_SHADOW_MASK);
> +                orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
>  }
>  #endif
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 5f183501b871..c87d5a343b4e 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -76,7 +76,7 @@ void *find_first_bad_addr(void *addr, size_t size)
>         void *end =3D p + size;
>
>         while (p < end && tag =3D=3D *(u8 *)kasan_mem_to_shadow(p))
> -               p +=3D KASAN_SHADOW_SCALE_SIZE;
> +               p +=3D KASAN_GRANULE_SIZE;
>         return p;
>  }
>
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVukPaEerSHW%3DsTmMumiJbPkQUnsmg6-Dena7kXyZBaSw%40mail.gm=
ail.com.
