Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIWOUOGQMGQEBSAYHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EE476466681
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 16:32:50 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id n4-20020a0ce944000000b003bdcabf4cdfsf39461380qvo.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 07:32:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638459170; cv=pass;
        d=google.com; s=arc-20160816;
        b=rbxkU4lGP5pE/n+yho3ao5hvEoDwHQSzSfweFotHZlAmc28ppM0OjQPiiZIzdBZkvf
         RxJSs+hMrWFLw2sXJmdW25eGWZfdYWITrPZ16ZzM4DkfIYX/rC7GNYjBNW0RyBrJ/1br
         1Ra4C225qd0VjgwxAT7BYe+6G0mFQG/NSqAILL4b5uEWDrUwodXpKmokaCbEhRPBjj3j
         tPKv7qPqb/W07s+p3PZSZ75kKzHEn0tTI6+3tbhGG2guIDcrFtpzfYgoEOzOpIoZcSfA
         l9yfKgMGaIFYeNvOJ5Nu13bz4BwfDDqg069QVZ3o+7U3OH+Zv09SVZ3OgY89ERuNJ/ck
         iqww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U1t+4+S6ZDb8vuceJb96Tfb83HfIVU7foGCxtviDLyM=;
        b=ZcqDoUPJ4PyohLY/++gkSnh8Bh+P4gJglDCzuYpc0BwM/9FuU7NO7ilc4735jb1/lX
         uZeUMQ4TKhIZac8LjXdVTjLsKgx3uhp703pj+sP0d12x8q3M3X5vB1xUDCBC8gpZ3XBw
         W6ytG2iWpFDhGYd+gzv41deRk1a4YY95VmfFhFDF2aydDNq0wKHqqM1woXWy661MIzAE
         LPdfKRm9/vzMps5x4+Ain/TGD58Rvrp0Mc05yTRsmrCOpR1BLfzbgL3pV+VkNJXPPNK0
         Y9nufucddXMjMhIFxITlXxld44VWctfMVEHbvd5D7kB67Hr9uxLJFnyk+luO2C77CZLG
         muJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dnoa81zG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=U1t+4+S6ZDb8vuceJb96Tfb83HfIVU7foGCxtviDLyM=;
        b=gcL5+D8dzJ0l++vwEdoZKjPHDZnxylrTAByC+fqzQ4Ml2IqLDLCzDG5jy/fFkVeApH
         Zg845rjCxTxyiA0OmPotT2XdeOCYNxwQQxrHh2uT3kWm0gtQbdFNb93R43Uh0xqHwtRl
         KgAgn1w3Dk9lZqom7dWpq1TRq+IZughEhiukSQyedU00FVZOt3Ws9/VAFMNUBNen0Qvq
         ZZV2sDLAFlqX6wc/0RZMbjy/GhvmF4lvJMnZBwl8QlgvSlesSN4ktk2lSXXvmfJSacID
         YGYwx99tV6f38d5GgxAjwrRXrXRnPwY075daQ7MrgQiIyyQ+BTQmgipwDqnBzgsVUp1k
         gxZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U1t+4+S6ZDb8vuceJb96Tfb83HfIVU7foGCxtviDLyM=;
        b=JLPtD5DePyWsE4p9IRpt9RfWVgiI6tfn5qncO3bMz+NYIyXQXOgUX0TxtCXsSq5YYF
         hSsaFAdDFy0OyR73zr6bJPwQ0EwMYW3HnBpKgmbHwG1QfUvBCSO66WJ0s7ydrOL5bDGZ
         01dlAt/x227/96NawNfElo1JdbB9dFqi3/cWgTNOmRy1V5tcuoYLuXNItarhj8ZXhFji
         oNMbcUsBR7bGmJkmJm927gUrVUbS5+xSi4msMgNfmtmp/ztYd8PN3IYC83sQltvw3QSl
         qlUzHaUN12xKUK+t9hITp1C7xA19pqR/2XXbxzaJ1vIvYH+QkkB8p/Z5anfFaLWng/wA
         s1EQ==
X-Gm-Message-State: AOAM531TuzvYgDujyoEhboKV0JYlIw4Ux6K9UqWC2nzIo68Nv+G3Wuis
	bQsp2nIe/z1TQUIrofMNrdU=
X-Google-Smtp-Source: ABdhPJzgmZLJMEGzguufjpM34VZ3waS/PYivgGEjmHubxitDQ5fAO+dtsNh+E3P7UYR9XK2KDfRROQ==
X-Received: by 2002:a05:620a:1794:: with SMTP id ay20mr13028865qkb.5.1638459170091;
        Thu, 02 Dec 2021 07:32:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:dd13:: with SMTP id u19ls3009561qvk.3.gmail; Thu, 02 Dec
 2021 07:32:49 -0800 (PST)
X-Received: by 2002:a05:6214:e8b:: with SMTP id hf11mr13316549qvb.40.1638459169664;
        Thu, 02 Dec 2021 07:32:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638459169; cv=none;
        d=google.com; s=arc-20160816;
        b=H4IZYCR8TjxFxjGhTj0Va2oLK3LYT2FVXrhsRB3ewvcTp9J9Hha+wiGP/94uz5aMhY
         smRgLX+OCGa0AR4UiykcWLcCQuM9hPO3pG37qcvn9bjQG88UO2O4p3QYlX7jMrXGjWPW
         aNfc3ppROb3RGoAftbajvB18qPqZvl7ZpCNzzarLV2Ko5jLNTvIsvIZ28Ez2d5mac6BC
         YWXyVjTt0y8JByJQu/+UoYrzPesJkO4WmO6lb5lMTK8NDU00VLUiuvql7VsYFwT4bIZX
         aH7s4glVM406UKacbhNjuHrBhUWfJh6+WbvYTo0+5rAYsGafRXR3rN2a21wMPnuZ78LF
         xUIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=evmGFi4x3OMEuAhoToZgbOGTd3Zzv0LAm/HoRCUBdXY=;
        b=Na1y5Xk9j/o5z6oCLsKNKz86yMOp52FYiysGaJkeuTFhDFG88Y8iOebA6YB51bg1Z2
         np6tjqqHmpah90imdVsT1vJtkM9+SI/VT/37rTHEkiL2NNRMGDoIiGo+8Ep58GBSlfD+
         ne86KiaFgPiD6eEmghyMXe7D86NPM6hwtSlnL2S3ZppHusp81+UP5F19FRnsFC1+QYAS
         NsXvkCiIGLnmyqnkH5L/kqeb1a+uvwp1Cua5lVYQODtEpWbWr13GxyUVSp78n0ieKH2r
         rrRA0PL9X5aYD48M/MW68xsyNpZxp3lUJiZ3QvgP1FDrnQvJrqrJCNNqNGpbFWemdgQS
         o2fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dnoa81zG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id i6si30431qko.3.2021.12.02.07.32.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 07:32:49 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id m25so16984qtq.13
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 07:32:49 -0800 (PST)
X-Received: by 2002:ac8:7fc5:: with SMTP id b5mr14623476qtk.492.1638459169188;
 Thu, 02 Dec 2021 07:32:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <64f8b74a4766f886a6df77438e7e098205fd0863.1638308023.git.andreyknvl@google.com>
In-Reply-To: <64f8b74a4766f886a6df77438e7e098205fd0863.1638308023.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Dec 2021 16:32:12 +0100
Message-ID: <CAG_fn=V2PmihoVkyaNLJ2LMf4N1YsDJN1ZFbdsYecZdNHMdSpw@mail.gmail.com>
Subject: Re: [PATCH 03/31] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dnoa81zG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as
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

On Tue, Nov 30, 2021 at 10:40 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, the code responsible for initializing and poisoning memory
> in free_pages_prepare() is scattered across two locations:
> kasan_free_pages() for HW_TAGS KASAN and free_pages_prepare() itself.
> This is confusing.
>
> This and a few following patches combine the code from these two
> locations. Along the way, these patches also simplify the performed
> checks to make them easier to follow.
>
> This patch replaces the only caller of kasan_free_pages() with its
> implementation.
>
> As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
> is enabled, moving the code does no functional changes.
>
> This patch is not useful by itself but makes the simplifications in
> the following patches easier to follow.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  include/linux/kasan.h |  8 --------
>  mm/kasan/common.c     |  2 +-
>  mm/kasan/hw_tags.c    | 11 -----------
>  mm/page_alloc.c       |  6 ++++--
>  4 files changed, 5 insertions(+), 22 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d8783b682669..89a43d8ae4fe 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -95,7 +95,6 @@ static inline bool kasan_hw_tags_enabled(void)
>  }
>
>  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flag=
s);
> -void kasan_free_pages(struct page *page, unsigned int order);
>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
> @@ -116,13 +115,6 @@ static __always_inline void kasan_alloc_pages(struct=
 page *page,
>         BUILD_BUG();
>  }
>
> -static __always_inline void kasan_free_pages(struct page *page,
> -                                            unsigned int order)
> -{
> -       /* Only available for integrated init. */
> -       BUILD_BUG();
> -}
> -
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
>  static inline bool kasan_has_integrated_init(void)
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8428da2aaf17..66078cc1b4f0 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -387,7 +387,7 @@ static inline bool ____kasan_kfree_large(void *ptr, u=
nsigned long ip)
>         }
>
>         /*
> -        * The object will be poisoned by kasan_free_pages() or
> +        * The object will be poisoned by kasan_poison_pages() or
>          * kasan_slab_free_mempool().
>          */
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 7355cb534e4f..0b8225add2e4 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -213,17 +213,6 @@ void kasan_alloc_pages(struct page *page, unsigned i=
nt order, gfp_t flags)
>         }
>  }
>
> -void kasan_free_pages(struct page *page, unsigned int order)
> -{
> -       /*
> -        * This condition should match the one in free_pages_prepare() in
> -        * page_alloc.c.
> -        */
> -       bool init =3D want_init_on_free();
> -
> -       kasan_poison_pages(page, order, init);
> -}
> -
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
>  void kasan_enable_tagging_sync(void)
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 3589333b5b77..3f3ea41f8c64 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1353,15 +1353,17 @@ static __always_inline bool free_pages_prepare(st=
ruct page *page,
>
>         /*
>          * As memory initialization might be integrated into KASAN,
> -        * kasan_free_pages and kernel_init_free_pages must be
> +        * KASAN poisoning and memory initialization code must be
>          * kept together to avoid discrepancies in behavior.
>          *
>          * With hardware tag-based KASAN, memory tags must be set before =
the
>          * page becomes unavailable via debug_pagealloc or arch_free_page=
.
>          */
>         if (kasan_has_integrated_init()) {
> +               bool init =3D want_init_on_free();
> +
>                 if (!skip_kasan_poison)
> -                       kasan_free_pages(page, order);
> +                       kasan_poison_pages(page, order, init);
>         } else {
>                 bool init =3D want_init_on_free();
>
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/64f8b74a4766f886a6df77438e7e098205fd0863.1638308023.git.andreyk=
nvl%40google.com.



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
kasan-dev/CAG_fn%3DV2PmihoVkyaNLJ2LMf4N1YsDJN1ZFbdsYecZdNHMdSpw%40mail.gmai=
l.com.
