Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI43WD6QKGQEK7TS2BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id E78532AF5EA
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:13:24 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id p6sf1182325ooo.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:13:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111204; cv=pass;
        d=google.com; s=arc-20160816;
        b=apbdVW/Ouelw1pxTa6C2zKRWCjrItVZAPxcGdUfv1TfuA4jncWckFFElrSCa4K2Zmw
         PCnnKfInUHmBlyg/SxuyWnz5QHLeAJu8+ahkaCgv2S62QgU65KX8U1jjx+EmBVExMyXF
         WN3cu55UW3JUQmlDrMvMwdYLNyCyOWMlRyLESogFqEcXcUQb8x2x8vAM2W6FwzRLvVAk
         8N7/RvcyNGuqe0Fw9sVw3vWc2oxdMN7WDedHbHJ5+KpKcdaIuWSbat/NOsyaM23gGld6
         rrHOazJ83AgEr1dsnGzHuP41mcXPaJU68t216DD8sa0f/NBY3JKojSigj0KvoGSVJS+A
         lu/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=86qzZrK+cjXjJ5u7SBQg5CzvDDkrbvEqQ/5VtUtbEZ0=;
        b=fgXCvD+IfAvxA39j0SY4vafyzieZYTP+J/POkykA2uiN4NPah2PBf28QRCKrG+yJiq
         1agILh0unzJpN1VBDD9Cr5MvXOca25/uhnd+u7WzNg2gKsOS7SoiUvKk4/1T+qLvGanp
         Vsj5JEsdrNTYvtK1koxuEbdqkJIfT1UTcYWbHRIU0N+7YafJAkK4zqQ1TDNSL1/GIho2
         eljBaUV7cMoT3qoVOfCCTGPUMtiojuuqXo0IJqOSFWlsWoTrS0J9znOOXy5TWWYKx6hK
         N5a01jemhNiwGMtyvsk0HyjfsnUy55ZWj82noaV7+LfUSWr3GnTaCEdP8vBlv3yGBnNw
         eLxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JbnLgZIz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=86qzZrK+cjXjJ5u7SBQg5CzvDDkrbvEqQ/5VtUtbEZ0=;
        b=JUXl45G5SgeUZq5ynfb2J7YU73FqwevFq2RbeL0e+CUGFHRXYEN+tY/AWpFgNsRIy9
         q/N2c4jhVIL08Cz0oYMPBIv1rt+skK7aJxDUZeUCBEUOQS1+wMVhPFePXx92QHOkf5xE
         U45+m+2CvBba4I2U46+PkkV8PWMgnRirtf73mmTgi8RipLvPwTstXi+odrLXyQ68EJpl
         V0xGb2iDrF8DjaYLWo2wpKBKHdnS8eL1lM+fV4KceVLMkZhNAqrGXecEmrfDPQfVMrOW
         vH/bClMUNyOWqdj97OOTrCNG2FmkarmfXnSo9CWfeHKvrX9ky6ghjjFrnaR23WnXSU6H
         CZSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=86qzZrK+cjXjJ5u7SBQg5CzvDDkrbvEqQ/5VtUtbEZ0=;
        b=VVCZutgEG9qqmiO7a0NWF8iMbW65gWQowbMy6MfOMyXbhKPw1wiguiwT5D8xq+5Laf
         2VBk7URum0/DindYQhuQavDhMNZHnkZagr9oOD2wQwideM7mvEmI6eKOLsinjrWaMh9M
         8AkBkroQwHOGkXiPrjRIiWY72vFVap1ddglxUs7jC2dPALPdBadsRSenWfW6fHNU2q0D
         N7e/Vg/wUjHDI8wte3MY7T5j0NnG8bKAx3VzOXLnYmPKbvUu9WOa+UyZiDZgseJQfxtw
         MF4emsiRbikeZkdeXfoNX81NRRB8RLpDLzeGpdZArQfHIbagNtPWcYI0H02gcBBgCjEw
         0p4A==
X-Gm-Message-State: AOAM531zOAC1H9o8K1FGMLfpKt0JCCa6sZ8nXIsEtbji6oZ0ttD4ndmr
	DXx4wVViRmqlmar1I6JCNDc=
X-Google-Smtp-Source: ABdhPJwhhe9nGgQ4f+Q6FjUJInTOUeIwUiUUoBhK6DO6yo55vlc2bfS0D+EG2TX6eOWAUjNuWS/VEg==
X-Received: by 2002:a05:6830:164a:: with SMTP id h10mr18744507otr.325.1605111203955;
        Wed, 11 Nov 2020 08:13:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls8591otm.2.gmail; Wed, 11 Nov
 2020 08:13:23 -0800 (PST)
X-Received: by 2002:a9d:12ca:: with SMTP id g68mr18622161otg.322.1605111203611;
        Wed, 11 Nov 2020 08:13:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111203; cv=none;
        d=google.com; s=arc-20160816;
        b=vtgwU/OhXv8d/eowOTV+QyjLgUv5BDMqWdqIpbtm9PCDDf55nuICytoGawujQNkZrd
         l4vi+VuhevuUdQziTrspwLOT/oIlJa3Xz+x16RQRKUP0PUtI0oydw7XpV/B2J212fFxI
         3IT+N928vM+W0M5bqiwUFhG0yDb+wpUL2S3YqbY68GuUnYE1LExUYTakpE+7jYrsorzy
         WpA/Gf0+UlFAVA7noIXl+33c/2ZhjMmSARNNGXlzivQaixh5aNLY40TxnqbkwRkvP2T8
         JHB+7lYDDDmQc/pu7EJjzUVYFehZER2WW/XRfHNVUGPZZ8SiddtF4bU7uQK3h7cvXdjU
         fKzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Y9knGGnUVAWh7DTdx+ZTxdFDVkNgQfbAnELeGfW+RdY=;
        b=VEIeAV0Abckx0etVBdsvpHIiN0OcdiC7b6h9CxzVJZyChsNohMgs7ObZcYrTsKpuQN
         RNhhi4M8krP0+7cqEIHwj8AGnvxof+KygR2XQxvkMqPdC0EnBeRdY2k6nRNGArSHXocy
         x03jfJ66qxNpzcCQNNe3vZOHMjpcaGT9pmx/c7Bx31tuWoCDczh9uNkC/wBacRyBgG+y
         0n3gkveLvxuSLdTGO0n1cRYuJpd/hvyx3DTOivwrpPmJbwxsp95Pf9YaZsFjQVwU9zss
         9F4sCTn54gDdZyEkMsZMz1qafwVMJzhsyEJH/remPLuiQJHLYShG1Re4m5oVc7jW9kwW
         KZoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JbnLgZIz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id r6si373552oth.4.2020.11.11.08.13.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:13:23 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id n132so2175130qke.1
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:13:23 -0800 (PST)
X-Received: by 2002:a05:620a:211b:: with SMTP id l27mr2667134qkl.352.1605111203127;
 Wed, 11 Nov 2020 08:13:23 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <71fcf23cd66d690afce1d80dc2f4659b2342152c.1605046192.git.andreyknvl@google.com>
In-Reply-To: <71fcf23cd66d690afce1d80dc2f4659b2342152c.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:13:11 +0100
Message-ID: <CAG_fn=WS2vA=j-j=uXLpmLh9Fcaj2WO7ahEwQfpPG9H51RFC4g@mail.gmail.com>
Subject: Re: [PATCH v9 36/44] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=JbnLgZIz;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as
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
> Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
> KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
> ---
>  mm/kasan/kasan.h | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index ae7def3b725b..d745a78745dd 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -5,7 +5,13 @@
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
> +#else
> +#include <asm/mte-kasan.h>
> +#define KASAN_GRANULE_SIZE     MTE_GRANULE_SIZE
> +#endif
> +
>  #define KASAN_GRANULE_MASK     (KASAN_GRANULE_SIZE - 1)
>  #define KASAN_GRANULE_PAGE     (KASAN_GRANULE_SIZE << PAGE_SHIFT)
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
kasan-dev/CAG_fn%3DWS2vA%3Dj-j%3DuXLpmLh9Fcaj2WO7ahEwQfpPG9H51RFC4g%40mail.=
gmail.com.
