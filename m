Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAWUSH5QKGQENJQZUWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 210FD26F7A4
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 10:04:19 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id a4sf859725lff.21
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 01:04:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600416258; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yy4e8e8XIPvlUGvJF4gbjHqkVy2Xf9vqsYDXyfeC5yzqhtZUBiVIWFirs4WR4cagaI
         ZW08CrKxVxuCVHnh43VF+qdYf1LhgOlqomjsnwshJxj+Kebax94oXdu4NlSsWbUCgn0Q
         13y/Vh/bk8V9ubMPv9fkBAnjcoiYa+eZ9p+DJyCHePZ/Nk3a17eG9Y7MCLerfxAtw0wR
         OX14hTZv3f51kznHHWhRuZAH/M9RPocGMiJw/pOkaI/aNfGIWH1WvNzmlqWtDV6w7gaV
         hkNX2ln0mTx/TswRxg7BpWfHtawxSwQX/NkpwXJDb02Jrkef9+ssb56BjZGC8MvZ1Frk
         RYRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fbZeQZVKo5YSvIfKGMDUUmu88n/y4JTkaBiYc3FVbxM=;
        b=tFDZA9/wisX/wKZO1x8Q7XT7yozJDLBs44zVic5sOg6hWIETghWcRdNRP7Omz70jWI
         FyQB8bLyrt2OoUIRJZQXrpmtTUuQqwaTlw1NIpvPcIiVvHcl8Mnqvg70lFfs9RwnVUly
         9ZUUEba4DKRvzdiFq9zmBkLCuGVq3288P3l0At5krTGXV2XRtFHr9t60sgTykuE3Z6Rx
         luDfMWr3DuAjRD/ZYF8v0+Xh3zM6r9QvkiWP7qfJaF+CpwZjMyZP4OsWWCsrB9QWLDhv
         gJ64wR3yqKmjZgsREtMCo4665Zsn+H/ryfCEdgEr2OQCWHjzbtUB4bdqvBLN+NBCO+5c
         jOqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PZk5MVq7;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fbZeQZVKo5YSvIfKGMDUUmu88n/y4JTkaBiYc3FVbxM=;
        b=pCEK3MAMYGD0iFY5bY0Sp0u+v5gKeRzRfKp8G4sfOJZfdtPlO+VyA5uQVVhZd4Lwku
         ZV/lodb+3Eb+bRMBk5lVGHhe5ZeVXgFL9E+povdG0lORK/cz5IWnVJ2X/X8sM61BlFUK
         aWmJR6QUl9oblASKE3bvXlJAA3cuCTIoduurf9/nweupY+ysoDcS2Y6QbfvbFSvOnxDY
         /ygwfYvAem4B74J8hxr2vdszQi3sq57c5HqxYI5mgTtQ+yR3DW46++iw+y4O7obv92ym
         yB7Xq86ByOs94ErY5tpzVC2qbl51reNpMqno9CtAr8Z/E5Wv59c8Y6HmQYBhxUGV7u7N
         E+HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fbZeQZVKo5YSvIfKGMDUUmu88n/y4JTkaBiYc3FVbxM=;
        b=iJHFknawqricLr8n3SJzKv1ypUZdfHlQi7c3SYfpLUGNLgDgjJi2grsy9stHQeBf3T
         lUKdLZbpMvIpVoPO8KbfVuxBHEAQ4iGJVqBpK4InqQo1ZUc2rrLsaNUd3pzxgw0OX8rW
         ktgd4xn554uS6qg4oJi8PGAVtJGGGRjLSDJK6EnTLjLdgX9KUKBTO/+acD0Mm4vDq1Vw
         gH9ym0Z7oUmR02tzSqfwcpJ8iuVzNlSVUYSq7L2Sh0E0WDyTnBQryLoQu2rMe5IRS370
         50ej/BBRltZaGQkcq6oPT1mEqo3lyQ0dJPFMM40Ci9rViMuTZcgHFu6NGeUg9Z8cW34N
         XU1w==
X-Gm-Message-State: AOAM530efGp7MnSDeDG/okjsV/Hp/BmasdTS8PlvuKssEh8tBX02TScB
	AFu8szOcXXBJQEMVDwn9ODk=
X-Google-Smtp-Source: ABdhPJw8A6zEBki37Q9fxGuc/EMp6svXVrUP+1o8TwNA2ORV8zeQTLCoSmo3NAWpwZLMkXeaPrUOKA==
X-Received: by 2002:a19:4344:: with SMTP id m4mr11877544lfj.181.1600416258605;
        Fri, 18 Sep 2020 01:04:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls1400959lfp.3.gmail; Fri, 18 Sep
 2020 01:04:17 -0700 (PDT)
X-Received: by 2002:a19:be0b:: with SMTP id o11mr10637775lff.117.1600416257558;
        Fri, 18 Sep 2020 01:04:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600416257; cv=none;
        d=google.com; s=arc-20160816;
        b=aST3efvJqioJ7gOF29BCgM0IUqLp43cPc4bbSJDH3X/WXCvXwFpGeI88/dltuit4F3
         J+a3LWAJ1lqKEsfQ47YseaVBRGYIYcNRYRkjrTzXeDMSzoB5Uz8rVO6+Ug2NM//4T3kG
         FeAlFnIvzN+QwH1c2q36mAJytXfU/AY6MiPppx5qU/TZ04eUfaFHSWIsweze0mnNVPnZ
         1eSCc2//9zUM+Zt3WFFfr0vx/pDc9y94baW5iCFCS3u6tZcq59Fm9+jNcr7u+UeQX0nd
         NrwlOZbyzA/TgpxQ89L/tikHghV3aCbSq5doGF9IR4hh0WMIoG/czqdJGHUwMMutOzND
         +TvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sN6WRoJbr99xIOpz0jJ0Fxcd65Efp6vGcy18bVZTF7Y=;
        b=LTkZic3PL6bSUFiGUia8cslIpnETGLgl1Kq7tek8O3WeMfm5o8ddUXfECHXXQDnjO/
         6ETRsSTMHVikT419MowLlbkYkf2oXXEQUjBJfbeOIdxFoYnHxx/MCsmRdJ+q/phqsstN
         LJHFf/QIOrmlQ2Svt+WcYClAPfXQ/Tsa+aKDVPbVe38VctTE+pUKpiapQYQKvFFVQQRY
         5gSv3ZaggvbmOqlTnCiML8T81o08kOh1bRkQ2hCxgTmaTn51x2p//7/YK7eRSeqEHWuP
         AVvjilW8BHCoNNgGsd0tRBym2goYte+wbSr7Ko96NglSpwW4LzOS96cHdz/TJe51DiYx
         8ZAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PZk5MVq7;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id t80si46914lff.9.2020.09.18.01.04.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 01:04:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id e16so4649609wrm.2
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 01:04:17 -0700 (PDT)
X-Received: by 2002:adf:e312:: with SMTP id b18mr14018593wrj.372.1600416256553;
 Fri, 18 Sep 2020 01:04:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <0d1862fec200eec644bbf0e2d5969fb94d2e923e.1600204505.git.andreyknvl@google.com>
In-Reply-To: <0d1862fec200eec644bbf0e2d5969fb94d2e923e.1600204505.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 10:04:05 +0200
Message-ID: <CAG_fn=X8uQoZUXM0cU8NwF41znWiFQS1GjSNtrh5-xM02-nnJw@mail.gmail.com>
Subject: Re: [PATCH v2 05/37] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PZk5MVq7;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as
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

On Tue, Sep 15, 2020 at 11:16 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> The new mode won't be using shadow memory, but will still use the concept
> of memory granules.

KASAN documentation doesn't seem to explain this concept anywhere (I
also checked the "kasan: add documentation for hardware tag-based
mode" patch), looks like it's only mentioned in MTE documentation.
Could you please elaborate on what we consider a granule in each of KASAN m=
odes?

> Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE,
> and KASAN_SHADOW_MASK to KASAN_GRANULE_MASK.
>
> Also use MASK when used as a mask, otherwise use SIZE.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
> Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> ---
>  Documentation/dev-tools/kasan.rst |  2 +-
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
>  mm/kasan/generic.c                | 14 +++++------
>  mm/kasan/generic_report.c         |  8 +++----
>  mm/kasan/init.c                   |  8 +++----
>  mm/kasan/kasan.h                  |  4 ++--
>  mm/kasan/report.c                 | 10 ++++----
>  mm/kasan/tags_report.c            |  2 +-
>  9 files changed, 45 insertions(+), 44 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 38fd5681fade..a3030fc6afe5 100644
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
> index 53e953bb1d1d..ddd0b80f24a1 100644
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
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 65933b27df81..c9daf2c33651 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -111,7 +111,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>
>  /*
>   * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> - * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
> + * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
>   */
>  void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
> @@ -143,13 +143,13 @@ void kasan_unpoison_memory(const void *address, siz=
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
> @@ -301,7 +301,7 @@ void kasan_unpoison_object_data(struct kmem_cache *ca=
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
> @@ -373,7 +373,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_b=
yte)
>  {
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 return shadow_byte < 0 ||
> -                       shadow_byte >=3D KASAN_SHADOW_SCALE_SIZE;
> +                       shadow_byte >=3D KASAN_GRANULE_SIZE;
>
>         /* else CONFIG_KASAN_SW_TAGS: */
>         if ((u8)shadow_byte =3D=3D KASAN_TAG_INVALID)
> @@ -412,7 +412,7 @@ static bool __kasan_slab_free(struct kmem_cache *cach=
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
> @@ -445,9 +445,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache=
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
> @@ -491,7 +491,7 @@ void * __must_check kasan_kmalloc_large(const void *p=
tr, size_t size,
>
>         page =3D virt_to_page(ptr);
>         redzone_start =3D round_up((unsigned long)(ptr + size),
> -                               KASAN_SHADOW_SCALE_SIZE);
> +                               KASAN_GRANULE_SIZE);
>         redzone_end =3D (unsigned long)ptr + page_size(page);
>
>         kasan_unpoison_memory(ptr, size);
> @@ -589,8 +589,8 @@ static int __meminit kasan_mem_notifier(struct notifi=
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
> @@ -748,7 +748,7 @@ void kasan_poison_vmalloc(const void *start, unsigned=
 long size)
>         if (!is_vmalloc_or_module_addr(start))
>                 return;
>
> -       size =3D round_up(size, KASAN_SHADOW_SCALE_SIZE);
> +       size =3D round_up(size, KASAN_GRANULE_SIZE);
>         kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
>  }
>
> @@ -861,22 +861,22 @@ void kasan_release_vmalloc(unsigned long start, uns=
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
> @@ -902,7 +902,8 @@ int kasan_module_alloc(void *addr, size_t size)
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
> index 4b5f905198d8..f6d68aa9872f 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -51,7 +51,7 @@ static __always_inline bool memory_is_poisoned_1(unsign=
ed long addr)
>         s8 shadow_value =3D *(s8 *)kasan_mem_to_shadow((void *)addr);
>
>         if (unlikely(shadow_value)) {
> -               s8 last_accessible_byte =3D addr & KASAN_SHADOW_MASK;
> +               s8 last_accessible_byte =3D addr & KASAN_GRANULE_MASK;
>                 return unlikely(last_accessible_byte >=3D shadow_value);
>         }
>
> @@ -67,7 +67,7 @@ static __always_inline bool memory_is_poisoned_2_4_8(un=
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
> @@ -78,7 +78,7 @@ static __always_inline bool memory_is_poisoned_16(unsig=
ned long addr)
>         u16 *shadow_addr =3D (u16 *)kasan_mem_to_shadow((void *)addr);
>
>         /* Unaligned 16-bytes access maps into 3 shadow bytes. */
> -       if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
> +       if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
>                 return *shadow_addr || memory_is_poisoned_1(addr + 15);
>
>         return *shadow_addr;
> @@ -139,7 +139,7 @@ static __always_inline bool memory_is_poisoned_n(unsi=
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
> @@ -205,7 +205,7 @@ void kasan_cache_shutdown(struct kmem_cache *cache)
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
> @@ -279,10 +279,10 @@ EXPORT_SYMBOL(__asan_handle_no_return);
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
> index a38c7a9e192a..4dce1633b082 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -39,7 +39,7 @@ void *find_first_bad_addr(void *addr, size_t size)
>         void *p =3D addr;
>
>         while (p < addr + size && !(*(u8 *)kasan_mem_to_shadow(p)))
> -               p +=3D KASAN_SHADOW_SCALE_SIZE;
> +               p +=3D KASAN_GRANULE_SIZE;
>         return p;
>  }
>
> @@ -51,14 +51,14 @@ static const char *get_shadow_bug_type(struct kasan_a=
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
> index fe6be0be1f76..754b641c83c7 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -447,8 +447,8 @@ void kasan_remove_zero_shadow(void *start, unsigned l=
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
> @@ -482,8 +482,8 @@ int kasan_add_zero_shadow(void *start, unsigned long =
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
> index 4f49fa6cd1aa..7c025d792e2f 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -317,24 +317,24 @@ static bool __must_check get_address_stack_frame_in=
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
> @@ -572,6 +572,6 @@ void kasan_non_canonical_hook(unsigned long addr)
>         else
>                 bug_type =3D "maybe wild-memory-access";
>         pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
> -                orig_addr, orig_addr + KASAN_SHADOW_MASK);
> +                orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
>  }
>  #endif
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index bee43717d6f0..6ddb55676a7c 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -81,7 +81,7 @@ void *find_first_bad_addr(void *addr, size_t size)
>         void *end =3D p + size;
>
>         while (p < end && tag =3D=3D *(u8 *)kasan_mem_to_shadow(p))
> -               p +=3D KASAN_SHADOW_SCALE_SIZE;
> +               p +=3D KASAN_GRANULE_SIZE;
>         return p;
>  }
>
> --
> 2.28.0.618.gf4bc123cb7-goog
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
kasan-dev/CAG_fn%3DX8uQoZUXM0cU8NwF41znWiFQS1GjSNtrh5-xM02-nnJw%40mail.gmai=
l.com.
