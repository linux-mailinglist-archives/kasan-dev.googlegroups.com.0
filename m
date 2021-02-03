Return-Path: <kasan-dev+bncBCU4TIPXUUFRB5WX5OAAMGQESVDS4RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D9D830E288
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 19:31:19 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id j24sf221919pgn.20
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 10:31:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612377078; cv=pass;
        d=google.com; s=arc-20160816;
        b=bExmty+nzJwJJ0mbJ/snJwnAIg07LM69BDuGSXE6XgbrlHO/fXy3esP32XWSDcNm1f
         vLPA8v00afbjKaM2G6A7a4p1OREfLCJn4mDkVc3I3u47ZX9Bw5+E7M4+lNMqDfR8Fi07
         AfRoNJSn7YPYASCqUgWKsqNew5iNoAH3Jae7EtZEv/hYcAXdRN6enCGhBM1C1MSvYA6i
         AMBVVTPAMPJtsA30Md7seE5ECNdErrXdC6H/XtCCVHopO/wRw6Xjoq/M1SMUt5EViQLo
         Hn3bXcQcVG+IL1EMB1S9tuY6whMuBWhsb7aAtn2Q7pk8ISJgQ8+wFmiQQt/ljQGQfN3M
         VAWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ubEHNLTlFXFzI3DEijKWRlU8yjCp70YTOKsWM1/jxIo=;
        b=PDaX2RHEeVxd4z3pFDno7a48lwnV7pU750jYyq42xTmUKv4wobPNQTjrnbFa/71gsq
         pz1y/4qd+g43Teu+jW6JfGIkhOICKlcSs2mU3JawlBbkdbDjtVt9kVqfYCK3MQMekV/f
         WHYyi5UUDdW00S28dDm1vO+E96Oaxgb9Zv/xmv6w6OdY0OMqdYs7kA/97uvihJ1GbS+l
         p1mL59l5mcQtG+IIY4dlbhZ5kZ7wZ8LawyRobzB0jalntZZfohdGt+bD4Pi63KeKpD4y
         BCq5ofVMC6RgGOh3OHkTumdxFFImF/rVHASkeBaJgg7Uybv9L7DB5BkwUcY+Bo1m1GQF
         59xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b4uhGDj5;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ubEHNLTlFXFzI3DEijKWRlU8yjCp70YTOKsWM1/jxIo=;
        b=hddGHJLAWN3dqw7w3OeTHP/q/dPqFl1bUQ5MsZqk/+5iElnD3og1vOWf+sNmNRRUup
         Tl+WKxzgTl5/LbOhiDDwHasT3YtsqlbbLv2aN1O+Gt+1vFZBrxosGcnUNuHI5f9xYWee
         rL1tnOGVkPSGcerQdwrz3VftOCEJhTz5Ii7MUZ47WQsTUn1HulDtM0b1tXMzin1vNwdR
         brnN7nxjyXiysJHYOMBwRCayibIvu93RbbpBPkT4dx/yGgMNQw/rgh9WWENH+nb1y5yz
         SeqZFTbgV1wme9t8jigAdssyGVRWVE6TioNZs0uCpr2q+dJ0eTWrjw7FD4Cl3IHf70SS
         yC/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ubEHNLTlFXFzI3DEijKWRlU8yjCp70YTOKsWM1/jxIo=;
        b=TIqkzCx6xMBU+GlfEg/G2gz+snRoNvzoG0M0YZx8GnOQ1uVUZPVIKpoiN8HvA1vZsz
         FSE2bdqIowfvSt68XbdZ5YvblEjh9FIpWGaAV4cTx8qFtyDgNQbsFVJA/KZOwYtznV/l
         eQRmyyAIewUUskOOWWd0+79UL39D6ritE+iRNCaqa1bfXJAlkUUVqTtSKLCUGSUim2px
         SNHuG/1xhHOFFvYn1VewcvuB7Fy5+Zg/CjplD//CmaAct0Aef6NO6A59aNrR2Hjdsomr
         wdulXiHjkE37SoFypHmwevgNg/2UtGfD1vTOYvcj+kttSCcsdJkJmgn976si/cImQAfp
         4PWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531v5bM1bgycp+EmoCVY3W9v0HON8flZByt2tm8LhF5GCsazV1QM
	bHDkfVa+2BRXcXXyPIZO8kE=
X-Google-Smtp-Source: ABdhPJwbU4egXms++5vYTbuvr74bFjyFWzhjh0CzPvpne+xCsQcRg3DUPZUWcTOt6p14D9sPTSdkbA==
X-Received: by 2002:a17:90a:fa09:: with SMTP id cm9mr4132272pjb.160.1612377078124;
        Wed, 03 Feb 2021 10:31:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls1416763pll.0.gmail; Wed, 03
 Feb 2021 10:31:17 -0800 (PST)
X-Received: by 2002:a17:90b:204d:: with SMTP id ji13mr4328154pjb.51.1612377077450;
        Wed, 03 Feb 2021 10:31:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612377077; cv=none;
        d=google.com; s=arc-20160816;
        b=zhaOGvRXqmaf3hEqjCHQlZTUojnn0GZTFlHQgIzzNCzgcL0CMnNY33H2yxVGsELB+v
         tWbFb42ViGm2Nj543p6qCNG91obbi8Ktz+umBnegMjK17oprXhO5qnDJUt6QJyI5F9el
         ByD49daPQLRAovldk8nLObJBGgFM6PGKe7DZgSg5gZVlDTMO30H+zQj4FANlj1OShhxR
         9bXeuuCYlYyflWMAdvgIA/zWT1RZeCJbWtvRETn4U1g6pDWS/GRfOfRvRfKtDe3iJGPL
         hB0vQEkXQHTUshvLgAiZwuCDRWBjtA6rTqA7xH7+YaAh/AlbJbZASyeG4TBZqd7aSfXg
         C3+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4JDeBq5HrKRpwJMlLAsWZ6FU0zBrvhZRXwEAlt4FPmE=;
        b=Ria/n5PfXBwpYpkB627wezVH/BnbqISORQolCV4YINF1JL+lMton0O+mlZjumBV6TY
         0GCUlnVsLMW/hRiyY/6wW6HSFiIy1MkYaU1mtUt3/rXNeaNaRysBwZrTNJNuUOrkjdEv
         Yp8ENP4J0pIB+KjTARUKmn2T7Bp89msUbzsFN7MwtB9fjs1IwRQozp9J7KcGt8T78e0n
         INTz9uRewfeIkb0ag875MvRfKXngR6WBPsY3WARiNSK+Q/ouEbJtZLb0woCv5SNhH9m/
         80h+eCjPHz+f9I64EUSxYL5ThLzYWiJqrKakq7MVMga/cV6wVWofxqT3NhjF0Lj0fIwu
         /puQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b4uhGDj5;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n13si161859pfd.1.2021.02.03.10.31.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 10:31:17 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8945764E36
	for <kasan-dev@googlegroups.com>; Wed,  3 Feb 2021 18:31:16 +0000 (UTC)
Received: by mail-oo1-f48.google.com with SMTP id d3so112540ool.7
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 10:31:16 -0800 (PST)
X-Received: by 2002:a05:6820:283:: with SMTP id q3mr2987191ood.13.1612377075690;
 Wed, 03 Feb 2021 10:31:15 -0800 (PST)
MIME-Version: 1.0
References: <20210109103252.812517-1-lecopzer@gmail.com>
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Wed, 3 Feb 2021 19:31:04 +0100
X-Gmail-Original-Message-ID: <CAMj1kXE3NHBt2YdQ4ESygRZUdUZbpD66rZ6wziPi8OAqfKvNJQ@mail.gmail.com>
Message-ID: <CAMj1kXE3NHBt2YdQ4ESygRZUdUZbpD66rZ6wziPi8OAqfKvNJQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Brown <broonie@kernel.org>, Guenter Roeck <linux@roeck-us.net>, Mike Rapoport <rppt@kernel.org>, 
	Tyler Hicks <tyhicks@linux.microsoft.com>, Robin Murphy <robin.murphy@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=b4uhGDj5;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Sat, 9 Jan 2021 at 11:33, Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
>
> Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> by not to populate the vmalloc area except for kimg address.
>
> Test environment:
>     4G and 8G Qemu virt,
>     39-bit VA + 4k PAGE_SIZE with 3-level page table,
>     test by lib/test_kasan.ko and lib/test_kasan_module.ko
>
> It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL
> and randomize module region inside vmalloc area.
>
>
> [1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> Acked-by: Andrey Konovalov <andreyknvl@google.com>
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
>
>
> v2 -> v1
>         1. kasan_init.c tweak indent
>         2. change Kconfig depends only on HAVE_ARCH_KASAN
>         3. support randomized module region.
>
> v1:
> https://lore.kernel.org/lkml/20210103171137.153834-1-lecopzer@gmail.com/
>
> Lecopzer Chen (4):
>   arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
>   arm64: kasan: abstract _text and _end to KERNEL_START/END
>   arm64: Kconfig: support CONFIG_KASAN_VMALLOC
>   arm64: kaslr: support randomized module area with KASAN_VMALLOC
>

I failed to realize that VMAP_STACK and KASAN are currently mutually
exclusive on arm64, and that this series actually fixes that, which is
a big improvement, so it would make sense to call that out.

This builds and runs fine for me on a VM running under KVM.

Tested-by: Ard Biesheuvel <ardb@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXE3NHBt2YdQ4ESygRZUdUZbpD66rZ6wziPi8OAqfKvNJQ%40mail.gmail.com.
