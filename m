Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBXDV76QKGQELQAA6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 309032AF341
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:13:27 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id b22sf1021129otp.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:13:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605104006; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+U4rn/LIVwMDasg6Bw/V1bmAx+Hd842/c0T4orVOp0LXdksVPxiPkudU5mavc581A
         9JkpKXby2kA/wAXCLyIB665DyIVZQXcNJZxOWDCOptq8jOqDogS0tTmmgwYSWbslobwU
         tbJ+Mfn8d82BC3tzKj7srzYYCi55oFH/fEA2XK9gMzsLAxokjq0Tebpnjg23OZIu/rHw
         OFwnmNOfSmWbGp3ciultsBlzZGJH7sfp5ysXYRZmfDCBe+OUMtzkD1Pu7I+AbhSXX6fZ
         4dIE2zQK2o6TzIExSv13DDZf4fGD19xV0c9OYSEi+hRgjOSyh980RY7HcuY1XdTUbDgZ
         oGVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CIEn1OHGYohn/a+MxZDsa6jQpb2yAX+1i+UN13KCP34=;
        b=Uoa/iaZSJnkrj/yde7Faqnw5gR6/+pEPToflphImDCGovrUk+6UbEH+G/Ys0jj4ytN
         ND+NRfbNOfTOmiMCzwnBtxYLSRC5glpONKltJmzoMG2pUVS2N0cdqSwbVE23eSi5YUlf
         WKYYMJgdO5309I80PKps205jHHDWPne4TyKai5kLYWiRz3SNTeqVEFcVzbJ2v1EoZqv7
         IdBVCZHDbWKB/hbjTeUeZrm09/6et3hEkJea25V/4NPxgQqsWyeJ7kK1LZFylgkjcdSz
         lh3lEgL6QqS/72AYhJZR3R/Xp0TQbr4brr2HFUzgA5BVSNlJNWDNmrRi1vI5mFpZpY+i
         gRDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xw7CFjGz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CIEn1OHGYohn/a+MxZDsa6jQpb2yAX+1i+UN13KCP34=;
        b=WzC5s9bhvdxK6zz4kz1nVCmlgjRNLbzkX1q6oP6hxz71AzUXnjAm5Qz6NBPbFhaSpF
         QKxYozBdnG5ROhiiQRtr0bPqtk11QfeMczl0LwDmGyQ4JO2D2LiLEo7BX9NlJkmlkGV2
         z42w0hTlaCIWMhfrZE/lTZ0tH4rXu428kaFGCx2vRRcPXlxiu5mKSVMnV7Sqr0ey/YCz
         GtmsuQ8HAhNNl9QF32jLFCfwABz68id7W6AdBlNYX7FeqwHy//bKLkDcd8X6iQ+ugDP/
         O7z9XX/wEUirdYNnNn6o1RRKY4Ry+JZ5dNg+NXsdSDc/FL0Tn9SnEgL34rYbzklWoQqX
         GOGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CIEn1OHGYohn/a+MxZDsa6jQpb2yAX+1i+UN13KCP34=;
        b=PTHm4CjXhwpoJubVlZmYrSbGwhzTgXwUqUhuUZ6xXAx0QjoW06E5tdMTR5I5l79Tn6
         q4Un+cloqDNFbjqQTlpoBluTTSSYL2KMsVbXwfOJpoDa090Qi29o995F9DRzDALpEw7r
         Cf43G0ou8/BddQueqP+gaT/qbIMfAKS/ZM70dLEN37Xzc/9t1GYTwDP74OnOwlu779rI
         pGQOIov917OU6VRsIgECiZD98d4vR57FZN7rj4oS3Dz5tN0F8TihWU4mm1rECRPbTRpN
         qdX2vX2XMUOTnD1hLxsR0hjfbAQsdLMThw6mUO4nY2Yc7hNDjhdQtjeaI7GMpeTp1SgY
         C+IA==
X-Gm-Message-State: AOAM533YQtYrjQI4poY6Pmji1U3H0uhpEsLHkqgWnI9r8HMxM9flPoAL
	pDs0jO5sjRigcv4MqrZrEV4=
X-Google-Smtp-Source: ABdhPJzwAoi8Xix3bakY5eaaJirCj7HpeqA1D8Jc4gWAoewCiCka9IUXswVF1XJjvKfJNIj9FUMJlQ==
X-Received: by 2002:a4a:83d7:: with SMTP id r23mr17354184oog.5.1605104006157;
        Wed, 11 Nov 2020 06:13:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls3941054oie.2.gmail; Wed, 11 Nov
 2020 06:13:25 -0800 (PST)
X-Received: by 2002:aca:4e02:: with SMTP id c2mr2272019oib.97.1605104005781;
        Wed, 11 Nov 2020 06:13:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605104005; cv=none;
        d=google.com; s=arc-20160816;
        b=lDLlUb0YCOl8ssMeAn/raMnTv2AFyI448JBBA7dgl4Pskj7eNI97MU3EowwvScCTod
         2mjUXdD+Fzh48o7eh2whJeIiuhblb95AMXzFqoLUGwMpKpTJysYz9x5CAfoEoIJoUv1R
         mCKdd8OaFB/GnW+Tc02jX9TnIKgbl23Fe7YFLLeHQxa7p1WuzAJJghhtCeAts8GvZv6K
         tgPMunusWf1zDms/OZlfN3yHer062IPTIKdu6EezPFv8FVZykg1imIeUpBFS/t/G2qZZ
         r17bKBqGK2KjmDM6lP+w5c9qLe/4pHRWWjIfv5M/1yjMRFKxPdHitTvGzFDIUShztA6N
         Dl0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aZg/3dO+K+3/7egp9giqF6NxjGJW8QC5duS9to8aMlY=;
        b=JkmJ0gMQtMQ8Olszzno8OWF9QshjUGY5Rtr//Qkz+sZYwfx7FYr9RbG9zGNs+MJlAh
         HLIGq6BqLl7d5F/jOb/p+JEMcFGSBJg1GmqiKq341enIXOkN8kVG2HYPW6pfTQ7403KJ
         r9C7/pmVsqTaUcATM3oLcKSnzaLD8mVpX3bO2EcLIPO+Nv2KazfkyeHu4tM55BlWfurg
         yR1Ur7tbvnYzgF0LZkEBQDjhlTiZeIAleu4C6fL1zQoSK7df9tzYKY0lSKtm6kJyiINz
         aps61olt6k8L+VriGA/2XIHo/PEqsKESO4N7unqjjsIxxf1+9uVsE8VwKr1ZW6GOkCkX
         8YMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xw7CFjGz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id r6si318295oth.4.2020.11.11.06.13.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:13:25 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id ed14so929920qvb.4
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:13:25 -0800 (PST)
X-Received: by 2002:a0c:9e53:: with SMTP id z19mr24630768qve.23.1605104005104;
 Wed, 11 Nov 2020 06:13:25 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl@google.com>
In-Reply-To: <85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:13:13 +0100
Message-ID: <CAG_fn=VuM=4axS6ex7_MgCeZ47o+Scon1WuFGStF78T36sHayw@mail.gmail.com>
Subject: Re: [PATCH v9 10/44] kasan: define KASAN_GRANULE_PAGE
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
 header.i=@google.com header.s=20161025 header.b=Xw7CFjGz;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as
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
> Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
> the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN cod=
e
> to simplify it.

What's the physical sense behind KASAN_GRANULE_PAGE? Is it something
more than just a product of two constants?
The name suggests it might be something page-sized, but in reality it is no=
t.

>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
> ---
>  mm/kasan/init.c   | 10 ++++------
>  mm/kasan/kasan.h  |  1 +
>  mm/kasan/shadow.c | 16 +++++++---------
>  3 files changed, 12 insertions(+), 15 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 1a71eaa8c5f9..26b2663b3a42 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned l=
ong size)
>         addr =3D (unsigned long)kasan_mem_to_shadow(start);
>         end =3D addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
>
> -       if (WARN_ON((unsigned long)start %
> -                       (KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> -           WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
> +       if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
> +           WARN_ON(size % KASAN_GRANULE_PAGE))
>                 return;
>
>         for (; addr < end; addr =3D next) {
> @@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long =
size)
>         shadow_start =3D kasan_mem_to_shadow(start);
>         shadow_end =3D shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
>
> -       if (WARN_ON((unsigned long)start %
> -                       (KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> -           WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
> +       if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
> +           WARN_ON(size % KASAN_GRANULE_PAGE))
>                 return -EINVAL;
>
>         ret =3D kasan_populate_early_shadow(shadow_start, shadow_end);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index c31e2c739301..1865bb92d47a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -7,6 +7,7 @@
>
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
>  #define KASAN_GRANULE_MASK     (KASAN_GRANULE_SIZE - 1)
> +#define KASAN_GRANULE_PAGE     (KASAN_GRANULE_SIZE << PAGE_SHIFT)
>
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
>  #define KASAN_TAG_INVALID      0xFE /* inaccessible memory tag */
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index ca0cc4c31454..1fadd4930d54 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -161,7 +161,7 @@ static int __meminit kasan_mem_notifier(struct notifi=
er_block *nb,
>         shadow_end =3D shadow_start + shadow_size;
>
>         if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> -               WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT))=
)
> +               WARN_ON(start_kaddr % KASAN_GRANULE_PAGE))
>                 return NOTIFY_BAD;
>
>         switch (action) {
> @@ -432,22 +432,20 @@ void kasan_release_vmalloc(unsigned long start, uns=
igned long end,
>         unsigned long region_start, region_end;
>         unsigned long size;
>
> -       region_start =3D ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -       region_end =3D ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       region_start =3D ALIGN(start, KASAN_GRANULE_PAGE);
> +       region_end =3D ALIGN_DOWN(end, KASAN_GRANULE_PAGE);
>
> -       free_region_start =3D ALIGN(free_region_start,
> -                                 PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       free_region_start =3D ALIGN(free_region_start, KASAN_GRANULE_PAGE=
);
>
>         if (start !=3D region_start &&
>             free_region_start < region_start)
> -               region_start -=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> +               region_start -=3D KASAN_GRANULE_PAGE;
>
> -       free_region_end =3D ALIGN_DOWN(free_region_end,
> -                                    PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       free_region_end =3D ALIGN_DOWN(free_region_end, KASAN_GRANULE_PAG=
E);
>
>         if (end !=3D region_end &&
>             free_region_end > region_end)
> -               region_end +=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> +               region_end +=3D KASAN_GRANULE_PAGE;
>
>         shadow_start =3D kasan_mem_to_shadow((void *)region_start);
>         shadow_end =3D kasan_mem_to_shadow((void *)region_end);
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
kasan-dev/CAG_fn%3DVuM%3D4axS6ex7_MgCeZ47o%2BScon1WuFGStF78T36sHayw%40mail.=
gmail.com.
