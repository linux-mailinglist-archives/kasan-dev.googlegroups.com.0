Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5762T6QKGQE363SY7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id AD4712B809E
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 16:36:25 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id s130sf1478222pgc.22
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 07:36:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605713784; cv=pass;
        d=google.com; s=arc-20160816;
        b=IjamKOBVDb5Fg3626E5blKW97ULcKLMAHvUHZuQo7J8OBOC27DTYqfzoIc2gljA0N3
         pCGUjLd3aAJU3xEhjmG2zuZVIbDhqpeIyiBh+EVvEMxYGvp2PUflytpfyt4yAtGLeVz9
         TkdY4WlnQ4xFXHuJc7J74cic6fUioOcR020XBJF3xySk/oSC79IF0XdxhKsizy/iEdN4
         fINyb6qk2sOBSfvSDrlxjToVVHPwSXp1ILId9oniXk8g2F0z37FX+tTk5ngW+YMo8F/K
         O5zNiycPYYxCzIprIELogLL/5fdhoqzzcKG1aIqzEzHr1sFG333vYjjDWSQjOf32mL0z
         dYrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=exRV/xubiucLIb6Pb2vk3FdJObbomh15RGaOsiE/2zU=;
        b=piE5COehwMn96oRkPvgj/HK2FY5StabLWPgXo4NdYYLWUw/V1hNOncp0Bwy2LkmpEw
         IoQOipNED8cX3X8E0l3IPSkfrKkGd2r0+KxNZBLNSMJ/NwpDuXow6a++T4DqRmLWwyPO
         bHbpeXhDdKNTh4qJVxQK21s2mhf+5Gyu5NfIB+SiFChNUGZsaePDiSidLs01D51Q/Dd0
         8V7atKC7+uiO7alKI5fEB8beTo97IbDkoHpW7yvaAFkjvR/C3uyEd2PJY22GU9iABbJp
         ijiBgWCoyF1YtQ6eJ84B0r4VmEUSCmq3Ui/2fTRpS0wBbaZ7KiulUXMekRskGORIR05K
         jMxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PCVKLLBR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=exRV/xubiucLIb6Pb2vk3FdJObbomh15RGaOsiE/2zU=;
        b=QASwR/FCZ6yWqV3pcuCVbWAFNRvbUItWEpvUOWnwVQ6mwIbhqT9h78wsMf/J9aXzVP
         49jzKHMpkOwetbufmm/rGBK+g2R0xa20icVf07uXcnqrZsRiLFumfWKe8bqr1x+CczxI
         cLiAXLRs0nOPEjma0iRvq/4zed9zCcFlfi/OVFTvubtxfYH6WHI8lrGIXm+3FtsVS2af
         2MbVYpliYCIjNxv/2fH13nLc9hX5QhS2E/EZjes8q8DPSJL/RgBaFTUNVDclxy72KAox
         rbE5z5rGVCJbKZqUQONgPnXhcJYa8ZgaOFnsstscsqiUlH1mUWs4kf54yyi1q1Gc/p/w
         hkZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=exRV/xubiucLIb6Pb2vk3FdJObbomh15RGaOsiE/2zU=;
        b=l2NlUbg8BLeLGnyjSFlap9YLuuGYLGH2bWesHca80XLct3bJXkkR5t7G6GiKvPTvHw
         BkBRa93aDrf/2toGcPE8xDaQfd0jVdPEPxvDfnjMdCeDJetEfw5hx4rBPk4L3h1DMhww
         Rzd+OXyNk8dVNcXCjvwznG4UzBB0q3jMfcbz0I36binVwLTMZ3hHhSvWnVRd98FtzBao
         0+I4/jTFGcEn0+JPwZ9EN9OK4lBicT1AMzgKQrtMD8X6hikRdDOSF19KWVQdfOBqn1DU
         XCpV7TYVV6SHY4LjAfOSm6P6eLL+tNr2kmBWXmgw1xGZQIxXM98HdahTllGKnFzYFuBk
         /itg==
X-Gm-Message-State: AOAM531lne1Q6aO0mxEXXcCgLDnQKrdQ7ynYbZdTLUuLWqigUBmhr5Oi
	ITJAOABWpgpDvn4A9XNO1z4=
X-Google-Smtp-Source: ABdhPJx/mqttCGFJ1PLxZFv0qGrjDNZV11zq64pWw3nQ7vWTejnvGRkd1BcSudG0TsDPffVXzQEk6g==
X-Received: by 2002:aa7:8a01:0:b029:18b:b71f:ce82 with SMTP id m1-20020aa78a010000b029018bb71fce82mr5327232pfa.52.1605713783795;
        Wed, 18 Nov 2020 07:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a0e:: with SMTP id o14ls3465597pjo.1.canary-gmail;
 Wed, 18 Nov 2020 07:36:23 -0800 (PST)
X-Received: by 2002:a17:90a:ce8c:: with SMTP id g12mr457598pju.181.1605713783268;
        Wed, 18 Nov 2020 07:36:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605713783; cv=none;
        d=google.com; s=arc-20160816;
        b=tMduOmbVFuWiCTSm47OKU4cNP+03wx2ese48CYZl/ybEaakj8CMvTeRHVU8VL7RTNq
         9t0rAoWDtXugKVx/DirKsesAsNl9iONhI+7Y2l6u2rurtlneFSIEQue+ReHORWVbhiwt
         AxD4aZuwhJp2VW+FEKOmfnu0Hh4h81DB2AI8h2HuwvYRrLInzRgssF7uYqkUxpGsb3bl
         aMCG88ri7vSzvYMU9ThEabS25lGw1tPcejxNQVrrAjm/EFcHuTFznOy3ZZ3UzS/+wwpS
         3VRIheE75oj2TOLV/eHgMZJcrKckMUdwVEpPWlk0RZlXL6VNAAsYFRMS/ansh1Y3zPZH
         YZTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DAmalSkle6LseckfE0Oz3lBRGT6/gmH8HIzwoCuD14c=;
        b=WSE/ilSONgLfni46XTa/pGEhIWj/DCBLbZPNx64CucOXb1hK8lNNLvZtL0PVAVXok4
         gBTBD9WEJo5wblXVSAbsuBfc4br3bN4H4qFZX3U63aC/n2o6G2FKNp/BWpsw5zTnLdls
         kYcLHqr7GwzudtpnaP+pmm1jJEhdwLV0qF68TaY6h4pHZqexryXrgF1fSn8qkBTAVbCw
         +7l12mGpijFfEDqC2EV41T8MoWjrTLBsyd3ilnZXEHbgWy2Ib5Hh/aOji/xw03rmCoz5
         ET5vCaQtKBaxsWmkPGCKNUOt3MrYorD0X8zud5ui3bdvDybjya8wwYJf34tPJbsnvw9V
         N4aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PCVKLLBR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id b26si1607705pfd.5.2020.11.18.07.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 07:36:23 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id g15so1834537qtq.13
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 07:36:23 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr5115177qta.8.1605713782397;
 Wed, 18 Nov 2020 07:36:22 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com> <19601c2110760228adf7594385db4508f62a5721.1605305705.git.andreyknvl@google.com>
In-Reply-To: <19601c2110760228adf7594385db4508f62a5721.1605305705.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 16:36:10 +0100
Message-ID: <CAG_fn=U3uSm3-dDoDJ6RG2-p4SmcG0sB0z3yjX4Xypf7U67qVg@mail.gmail.com>
Subject: Re: [PATCH mm v10 09/42] kasan: define KASAN_MEMORY_PER_SHADOW_PAGE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PCVKLLBR;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as
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

On Fri, Nov 13, 2020 at 11:16 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Define KASAN_MEMORY_PER_SHADOW_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT)=
,
> which is the same as (KASAN_GRANULE_SIZE * PAGE_SIZE) for software modes
> that use shadow memory, and use it across KASAN code to simplify it.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
> ---
>  mm/kasan/init.c   | 10 ++++------
>  mm/kasan/kasan.h  |  2 ++
>  mm/kasan/shadow.c | 16 +++++++---------
>  3 files changed, 13 insertions(+), 15 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 1a71eaa8c5f9..bc0ad208b3a7 100644
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
> +       if (WARN_ON((unsigned long)start % KASAN_MEMORY_PER_SHADOW_PAGE) =
||
> +           WARN_ON(size % KASAN_MEMORY_PER_SHADOW_PAGE))
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
> +       if (WARN_ON((unsigned long)start % KASAN_MEMORY_PER_SHADOW_PAGE) =
||
> +           WARN_ON(size % KASAN_MEMORY_PER_SHADOW_PAGE))
>                 return -EINVAL;
>
>         ret =3D kasan_populate_early_shadow(shadow_start, shadow_end);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 53b095f56f28..eec88bf28c64 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -8,6 +8,8 @@
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
>  #define KASAN_GRANULE_MASK     (KASAN_GRANULE_SIZE - 1)
>
> +#define KASAN_MEMORY_PER_SHADOW_PAGE   (KASAN_GRANULE_SIZE << PAGE_SHIFT=
)
> +
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
>  #define KASAN_TAG_INVALID      0xFE /* inaccessible memory tag */
>  #define KASAN_TAG_MAX          0xFD /* maximum value for random tags */
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 4264bfbdca1a..80522d2c447b 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -174,7 +174,7 @@ static int __meminit kasan_mem_notifier(struct notifi=
er_block *nb,
>         shadow_end =3D shadow_start + shadow_size;
>
>         if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> -               WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT))=
)
> +               WARN_ON(start_kaddr % KASAN_MEMORY_PER_SHADOW_PAGE))
>                 return NOTIFY_BAD;
>
>         switch (action) {
> @@ -445,22 +445,20 @@ void kasan_release_vmalloc(unsigned long start, uns=
igned long end,
>         unsigned long region_start, region_end;
>         unsigned long size;
>
> -       region_start =3D ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -       region_end =3D ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       region_start =3D ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
> +       region_end =3D ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
>
> -       free_region_start =3D ALIGN(free_region_start,
> -                                 PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       free_region_start =3D ALIGN(free_region_start, KASAN_MEMORY_PER_S=
HADOW_PAGE);
>
>         if (start !=3D region_start &&
>             free_region_start < region_start)
> -               region_start -=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> +               region_start -=3D KASAN_MEMORY_PER_SHADOW_PAGE;
>
> -       free_region_end =3D ALIGN_DOWN(free_region_end,
> -                                    PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       free_region_end =3D ALIGN_DOWN(free_region_end, KASAN_MEMORY_PER_=
SHADOW_PAGE);
>
>         if (end !=3D region_end &&
>             free_region_end > region_end)
> -               region_end +=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> +               region_end +=3D KASAN_MEMORY_PER_SHADOW_PAGE;
>
>         shadow_start =3D kasan_mem_to_shadow((void *)region_start);
>         shadow_end =3D kasan_mem_to_shadow((void *)region_end);
> --
> 2.29.2.299.gdc1121823c-goog
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
kasan-dev/CAG_fn%3DU3uSm3-dDoDJ6RG2-p4SmcG0sB0z3yjX4Xypf7U67qVg%40mail.gmai=
l.com.
