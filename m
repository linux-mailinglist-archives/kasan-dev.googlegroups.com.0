Return-Path: <kasan-dev+bncBCMIZB7QWENRBZOI436AKGQEKXGQZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D192029D135
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 18:03:34 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id i1sf3799204iog.15
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 10:03:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603904614; cv=pass;
        d=google.com; s=arc-20160816;
        b=S4tIGlGAguzZRgydULrfCN/IiUbIT6rgUkYj/1PA9ELZmjIKcuQRUrhTeKC+/PTLsY
         Aqw0A3DgHhbT6pjNDEa5A9f5U+0JlA+zlcJE3Up2XVS/N4Wx6B+1ryt1MGHvpxVKmSXn
         YcZMvgy91ESfD3JRj90YANSPd31HHxbO1FNbyu1b92EXpl8zFTcSBOkGNetRPQg0SYdV
         OM793+ngIPxkcbhfau1ODYTugHvL19UJtl0dzsYJvDq+veZZGTgC8ZKPElkSdZYLTvgd
         4WBOH1Ia5xSoY1aeu5hMBMSsHEWwwFIdwa0j8cc2rmxrRBZDP8pTYsNcIjcnSOSwQH0Z
         VEiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uomBLEzk46MJPrxXFDc7h8i/S6lEQpRsX/wKO54M93o=;
        b=U+ixYcwhzh9HzU5Sg3ufwQks64t38pzGq2an3X45S8ofyccbepGDELeYvb0LP/kLBh
         L/jEbOZ9+wUQ7Lqfs5MGnHeeyf88L6LcFZefrKgF59HUoo80FdiEjEbEbmvcyeK9TzCK
         jO+yMWgzFdffdgJU8sRgX5POJ2fubfTW5EcZ6KsXzKLY4lqVJ2IDBgvXZ94h75+ktq3c
         B+i9MmRuMapdHFsmRb9rIkVST1D4zbqbgrMjv6crr99GUzNpNhPbdR0pW02U11i7LAYo
         wDRB6lzmPfPS5KJUMrzOA/OezWWkbIZw1es6Aif/oM8EHv1itD5gBDxJslq9xlGan16B
         yuUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=beYPvEBL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uomBLEzk46MJPrxXFDc7h8i/S6lEQpRsX/wKO54M93o=;
        b=ExUhwDwX+2StdLXLJsBd+Sdw7nBCViBCXZpiw+06Lj0mkvg/i7PH2sMbXgvklEUXjP
         Tp2o61Fq+mSpV2K/94RMH/jyMJf2BbZRvyR/7jmKxqlcA/hxbwsuLRMKvw/25b0CrOrg
         b16nWOb4G+fLpIvY7/0WdD4cW67OeFqsrsg/Qiq+GYd52x+vza5fCmySCQcW3cEjT79r
         abC9xIwZPqTGKw7eMsn/QL6QIO0NxmmCHiloE6jc6aweKtDtBcFWH7EhoTEVH2eXny+D
         V5uP5bu+5hSfg8A4SRmFxI+Uieu/8fCp0VMgZlvOY5/WkJJVwn35Bm2X3GqHsbr+5wUa
         2qqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uomBLEzk46MJPrxXFDc7h8i/S6lEQpRsX/wKO54M93o=;
        b=R7mAgl5YnM6YHTDHldAJ4jlbanakOk5ZEwwEGkKTarMfi29XS9eKd0O1VRuG5knFEV
         39IaJolPtkqcHAEowCnBl9EQzjjKr56ae6GWKudVa2OAKimNamXyIB6UxcH5rhjZnnIN
         3qTYHGohhvR0ntbFKiZ23qI8sU60ndebM0aUYUmH5UETELAdVFYoKyDidH+ovPWMhPZn
         esn8KjvHBPucCu5VuFZUf1DYSYxBwmj9h64dECEd6B0ucNTXYzJnC+Tc1jXmMbvp+Top
         +hJr2bXJuiXpa3F7Bxu963/tEgQ2pl6sIaS5vJ7VGWcH4xpjGsiAHSDYbva0psMFF+IQ
         51Wg==
X-Gm-Message-State: AOAM532al58+cXvHCwxbc3cev0hyTaa59eh+5NHMNbCcl4gzCLFCcokD
	27xDfRF86JuHflGaQiDFBHs=
X-Google-Smtp-Source: ABdhPJw5h/tgmwTRJKwCAUvdbaVKajdbgmwWraf6AVqJ71wrjy2UCcDXxydWtF8g0CIEwsDDNp6PSQ==
X-Received: by 2002:a05:6638:97:: with SMTP id v23mr105323jao.7.1603904613788;
        Wed, 28 Oct 2020 10:03:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2d0e:: with SMTP id c14ls6707iow.2.gmail; Wed, 28
 Oct 2020 10:03:33 -0700 (PDT)
X-Received: by 2002:a5e:9319:: with SMTP id k25mr261269iom.153.1603904613392;
        Wed, 28 Oct 2020 10:03:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603904613; cv=none;
        d=google.com; s=arc-20160816;
        b=ySRlx1PayKaMMoHZnvgY1pl5ljg/MH5b6AWONU1rFNsL6/YMVsswGr0Flx/VSTjuMe
         SQn8utcqOdht5BnVl9P8E9m9a5i67mT8cssauZzgezOu5JP0pbiXPgBdVVV4laAur1Df
         NfNsvElNHOQ7xpgttsGJD0D7b6TrokFTmEAIBo16q7fJHzXvVXyUQqVyajY+/pPWPRHA
         +bRs8kUz21lqBKHIy3Zmisfiw4buih14O0/X63fAPiO4uqmQI7zkhHLS24Bn4nShBbPq
         /7MC7gObFIaWiruqoftFvatybqR5B7P5MzUZxdBP8KlKj9kg/IUGSW9QeBjjYP5NECty
         EVLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Om/J11Dz/+K3ysCSaEysgFFu7qTF4HlL0YVwwzZ7OVM=;
        b=oFyVtcER8QOPAqVNCpkx4hVeDFT1B6E/tmBj830EsQwBeMs9/DEOHoCZLH2RNwWZTR
         T5YSXl9iI/gwVFzePN6vTEM3wRybEZfPQK8gUBUqR0dmWiZBl4sAowYq+OS5fOsX/8i4
         R8tCjS8UVKEtxOyFVf03uzPuHKFJL6BksuFO1oXtCHbATMlkOvzUkqsHJChHld79g/hf
         I55A/KlAem4mltPZzji1SpZyzihadlhOrz+b99UIDVoZFrspw/IoJ6vCNm0xdjE1YhQk
         gLx0xLqiyZF6Eaw4sXUe41Gw1R4ozJzvy9pWobss2Sf+owoM6Q9/uDZn6HEmdSl/5h/I
         f5kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=beYPvEBL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id d25si12459ioz.2.2020.10.28.10.03.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 10:03:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id l2so1625735qkf.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 10:03:33 -0700 (PDT)
X-Received: by 2002:a37:a00c:: with SMTP id j12mr2444824qke.231.1603904612589;
 Wed, 28 Oct 2020 10:03:32 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6e866efaa7620162a9824914186ce54b29c17788.1603372719.git.andreyknvl@google.com>
In-Reply-To: <6e866efaa7620162a9824914186ce54b29c17788.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 18:03:21 +0100
Message-ID: <CACT4Y+aL_yQCd5POP96yzXfQjgc-6PGweY1N2ozbiD2Y8uRAAA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 20/21] kasan: simplify assign_tag and set_tag calls
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
 header.i=@google.com header.s=20161025 header.b=beYPvEBL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> set_tag() already ignores the tag for the generic mode, so just call it
> as is. Add a check for the generic mode to assign_tag(), and simplify its
> call in ____kasan_kmalloc().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c | 11 ++++++-----
>  1 file changed, 6 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 983383ebe32a..3cd56861eb11 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -235,6 +235,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  static u8 assign_tag(struct kmem_cache *cache, const void *object,
>                         bool init, bool keep_tag)
>  {
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               return 0xff;
> +
>         /*
>          * 1. When an object is kmalloc()'ed, two hooks are called:
>          *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
> @@ -277,8 +280,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
>         }
>
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> -               object = set_tag(object, assign_tag(cache, object, true, false));
> +       /* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
> +       object = set_tag(object, assign_tag(cache, object, true, false));
>
>         return (void *)object;
>  }
> @@ -360,9 +363,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                                 KASAN_GRANULE_SIZE);
>         redzone_end = round_up((unsigned long)object + cache->object_size,
>                                 KASAN_GRANULE_SIZE);
> -
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> -               tag = assign_tag(cache, object, false, keep_tag);
> +       tag = assign_tag(cache, object, false, keep_tag);
>
>         /*
>          * Don't unpoison the object when keeping the tag. Tag is kept for:
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaL_yQCd5POP96yzXfQjgc-6PGweY1N2ozbiD2Y8uRAAA%40mail.gmail.com.
