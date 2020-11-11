Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFU2WD6QKGQEZNNBWVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F8212AF5DE
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:11:03 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id h19sf1046405oib.7
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:11:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111062; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ruAJdQ0m0TT4VYELceZE4vp18ZeMwQ4pBrCQiH05VLZPLFwX5/G5ve3Mg+GWGVm86
         v4zpbQ7ZU78V6IbRRY/EhOvsg9Rkia8sm+wBmD9ljwqtYq7x2Ldi1wdFmJH0D58ALkzH
         P3R9NbRXpep7OiTqvFvgyv/rwp8LB/qqjS1v7cRYNVrICPQRz3pPFb05733AALXSzmqa
         bFg932mX51l3CpkQCIywIqSOtHVInYZpArixyV49uVuQARoBm3G5YuadEBYAfNvFrsc0
         pqpV5//a/sbfhaJ7ig0hz6StmPdTbxWMTnnh1OHriErS9CtdWavbUMkWLwj+zZVbczZc
         HE3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0PcomtVVOng1qv60dA47/Wygp+Q9qRxjqXBJASL+hp0=;
        b=V4ywIb0I3/DOuPfW5C4KJrqgEqR0u6/HIYXLXwplnKV0GenxiSYpi3EJwJNrKOxQ+Z
         1c5p2Q+y3PrjOGapsrF/t+ceiQmDhQU4s8r4E6ijWAY/JnPZtQ95/jZFTpLBQkti6T9n
         BL26V+vU8GkiAymicSFmKrcwZYITi8lVeb3qoJMNQjLbRz6l9gH9z0y0t4PYRY9jFHt6
         kcfwf8ATV9euF3yVIKFWCrCg4dEQcUEabeoO8axKev/NsiD49vyIEeU+toPxHoLBRKUY
         PkZ7Z43b91ywzPGOetu7NW+w5xmJrjiIKaEQHwBH1TXUrRX9z01ZmoPfrJDNIK5EVb6i
         vqjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EyFkI0AP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0PcomtVVOng1qv60dA47/Wygp+Q9qRxjqXBJASL+hp0=;
        b=dVbfLEGEt6JRm+4GSSkaw0EVKn61C6VoUg2zkOtJeZrgbsqK89Q39ZsTz1SffwHp8/
         ohtRUFYgb3o1RR8J7LSzIFp89SnANXHmgxJ0cPvtJu1qWV2UGPsIG/OUv3ObUzog72WU
         L4quB7dCl0y+r97MigNPzqQgjays1Jccm0RiKlbLrcocRzVvSnjUSyW0+UyBZM1iVvlk
         dMN1uRjTsrpDQxOLXBL9lDUNeTDRZ9FCH3rq9JCWvjJPdbxQ0QpvAG3bvws8wMwyPUME
         4/V+jDkF/AZuB6+mU/WfERBUWo1SV35n5FHtBuj+VUCVF1f3EBMYtj9C0Wxu3o6XbY11
         LNrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0PcomtVVOng1qv60dA47/Wygp+Q9qRxjqXBJASL+hp0=;
        b=S5Munrgo65G1E5YGoPqIKHBFVDijzWkmF28Xd1Mbcshzu2qAMmIlkn/AcZ3USWQAq5
         ilv1YYGSgxUPVRc9u5UaWufhw5JIoRw+F00GKj7x1QkgTPENE339rgHQ4Jy6HsJB+wa9
         zWaGZGA20aZ1O/zdY7NuP2y3juHdIJ0nC+dbpZOMSUnNI3xWfSYrI0L7rClrEERpmUwg
         TT/PReTyY315QJ9ll2ggDC/g1qvYWmgKnceyvCfZXiq4f81vJK0kvrggsG1HhyVr9lGE
         ucmdxArAVBw2FkwoP/kBwAbx78/NUIEvanm5+mnwSJxFlMVbR0a9ggVRMlNidcGRUoMW
         6OLQ==
X-Gm-Message-State: AOAM530HF1wYIupN+5ctAkexDZXhcMsG/3kNfDOuKGKMnY8eUOpSGEKM
	tTLuUdwPoMjOAjtxtemVMrs=
X-Google-Smtp-Source: ABdhPJzZxAzFVKPm1JIJpKJUC4MJUmaKuQUQUiRQwoRI2g0SzgMmCjh53jypntb1DzVQcLtldVYJVA==
X-Received: by 2002:a4a:b209:: with SMTP id d9mr17442808ooo.70.1605111062470;
        Wed, 11 Nov 2020 08:11:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b0f:: with SMTP id g15ls11223otp.0.gmail; Wed, 11 Nov
 2020 08:11:02 -0800 (PST)
X-Received: by 2002:a9d:6186:: with SMTP id g6mr11819024otk.86.1605111062143;
        Wed, 11 Nov 2020 08:11:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111062; cv=none;
        d=google.com; s=arc-20160816;
        b=YXjCDtioVpJVITHoKizFljctt0ru72ZzpxlO0T7gMaaSAJATMje1VGjZxgGq9Zvtk5
         hFTmpnSsNniny9+yeyDLcl27DaXrTQBYCy2VuFyRIw1NsGt0vVRgWKv1PZo3zct9JGs1
         WBGxQdSquJRIfTiVSddEGIxkKaOnc6TUaywaKkDZzK7iw9WiSJoQrjEFd2inHhGhahmD
         GMuOXSwcCTW2kihhzpiCMEItD4wbZgKFPN4x82fY2Md3+RJlwxtLQWxo40Bes4E7P1Kr
         tmHoqUclqtJNTmFdqvPp4mROUWqE94Chna17j+JLQpvl3U5+ymp5z+s2sCm2u1NVrFsy
         5Xvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=225dH83D48RrYMdcBweixtFsm7zoRRCV87kzdcWWgZw=;
        b=SwfrK4AhVlp3F9Wj7W0U/z49Vnb0TU/UqXvTGeO2teXM3crxh3dD8L0R5gJNba60Yr
         K5v78rsWsoiajcpMXrRWnrIMESykCihZ6QHlgn3DYFBlp6cEAjJKCryzPOFdjS/OuRGw
         wzv3qdAFm5VDLjWvpHYjLYD8M9MS8GvNvrZ0Opx968T/zcgWiNwBbJ6G1sqlxfxa2SHj
         KDIpuPEzqquyCwzp/6XOv4v2wliNqIEdpVJb1QVD0CFzIeLHLmcl1oL9hTKcyDMtcaXM
         OUspBzBy6gw0qzJQPasTYVp2BfsmE4cuutio4i0MzAo1/ATL3CVF3zWvtO59crkrjHki
         TqlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EyFkI0AP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id r6si372702oth.4.2020.11.11.08.11.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:11:02 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id t5so1649944qtp.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:11:02 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr19357172qta.8.1605111060119;
 Wed, 11 Nov 2020 08:11:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <76b91f88120fc8c3e5923d6432a1d537ee584fc8.1605046192.git.andreyknvl@google.com>
In-Reply-To: <76b91f88120fc8c3e5923d6432a1d537ee584fc8.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:10:48 +0100
Message-ID: <CAG_fn=XnPQCyzJXp1YtM0swhzr2W89yMxe5FkFL6n0vAOeBoYw@mail.gmail.com>
Subject: Re: [PATCH v9 34/44] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=EyFkI0AP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Hardware tag-based KASAN uses the memory tagging approach, which requires
> all allocations to be aligned to the memory granule size. Align the
> allocations to MTE_GRANULE_SIZE via ARCH_SLAB_MINALIGN when
> CONFIG_KASAN_HW_TAGS is enabled.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I51ebd3f9645e6330e5a92973bf7c86b62d632c2b
> ---
>  arch/arm64/include/asm/cache.h | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cach=
e.h
> index 63d43b5f82f6..77cbbe3625f2 100644
> --- a/arch/arm64/include/asm/cache.h
> +++ b/arch/arm64/include/asm/cache.h
> @@ -6,6 +6,7 @@
>  #define __ASM_CACHE_H
>
>  #include <asm/cputype.h>
> +#include <asm/mte-kasan.h>
>
>  #define CTR_L1IP_SHIFT         14
>  #define CTR_L1IP_MASK          3
> @@ -51,6 +52,8 @@
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>  #define ARCH_SLAB_MINALIGN     (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> +#elif defined(CONFIG_KASAN_HW_TAGS)
> +#define ARCH_SLAB_MINALIGN     MTE_GRANULE_SIZE
>  #endif
>
>  #ifndef __ASSEMBLY__
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
kasan-dev/CAG_fn%3DXnPQCyzJXp1YtM0swhzr2W89yMxe5FkFL6n0vAOeBoYw%40mail.gmai=
l.com.
