Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWWWV76QKGQEY3W67VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 590D22AF270
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 14:47:07 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id s6sf628706vsl.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 05:47:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605102426; cv=pass;
        d=google.com; s=arc-20160816;
        b=BZqVw3ARweYniM4uVCHZiyzk7xDNcvy+X88FpQ8WAeBGiXrBFAdH873sgbIJT+Zz+P
         +axohbTGfOA0cXo2uznDWHdkHkuDWVVJRYDLJjUSiAS39r9Apb0N9hC4CmhwPNbI9LU2
         H/bET+Ztew7kgCZvk6HMZM9TS2LwV8xhnkttKDHMmD1xyJVvAt+i95E2y+t/righyo28
         E1LId8e7hhyzZrxPtTdMbuEO6hy/fXaRds771EuCrn9Cr/o8mq64NJJkVt26sTPZL3fe
         DpvfbFSbB6CixIc55MYCMdoyxgME4PNkUcLw9D5rqRxoa59uiIhhgMyzXbW8VE6YbnNn
         sGxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EEMj04QPCED3ZkM0yf3LNqC8KGTgoZafwdWRVd1E0oU=;
        b=SfoiPemor5k89KDRUWx9ooGKPiclZdKuD8UWOEJoLoPdjISaw/B5GEUirxJ0qiot5W
         hYF97AKmY1HzfSpj01l2GtgYZY5nyxvjnyJl70tcKoAvI0sblYaUIabepafR5G9Yf0mC
         HQsKuApwIps/fLl/dI7Y3GaNk6pDVN8d3mOVdr01gXIcO43BPk/3+8TT1oN4BaWvy/0D
         eqSfbssrPANiMf6ubjjk8VJqQu2tu6vxpfFyj81qcwlaWoyDncRSFACS2oSOgG4w8m1G
         6PgEmJ0q0X37yEJ/CyBJ0ehZAebKPrV2g4Fb/rN4T7KlaQp69RyVJ8CwalvNOkXiNhhI
         jlWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rNZcWRwL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EEMj04QPCED3ZkM0yf3LNqC8KGTgoZafwdWRVd1E0oU=;
        b=aJFKe629QCmDUGDBTPkey6YQnWHoAGRtU8ANNzRyoMBqSLdky/IT1WxzzXk2roa6ew
         wEn/EXxv0i6Idfzy+cYThlasvV/AkdmFKvKBWaG31jqMSYkUJq5qKYvaG6FvFAm3mMO3
         pAxU7khWerKno8a3Ow1J6cr+gKFWfT5qJX3kz21Mimee1SM6nefJDsRagcmeGp0y3mUi
         agzvBb/RByv1/Fq9u6aw7bGw7ZuduBtVTjPmnh65LDOKUaDBvLf0s6okqYwTOUHq+IVG
         eODR4FoYrI9n6aaYF+jC9KKZYFTBj4e3g1wMKvzfSnVDUQKz2bUM+kpL4wzjv9Wdk75i
         PQGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EEMj04QPCED3ZkM0yf3LNqC8KGTgoZafwdWRVd1E0oU=;
        b=aBGsGLu7VcMnjQYxgVSfTGW7l2Y9OB+SgBaRYTbHFjncWLktxzkAMZF06fJYshj3Gw
         7TdILT4OMt2LlQvuJwbnVR67bCe01EbUcA9S/ZXksRcKhz90V9PW3rD6VQnm5EMf4OIt
         bnczEhNzGSAIvYKxcN3dHzmknqpWd67wLp5moH4btfJ1s+1TxPMbdY4p87zVkTFljPxU
         Jl/eZPWOvyfktVx2X++KWm/HwF0SM1UBvatHW1GnVnLasKwtZ0gjNaJZipQrgv5kAA+0
         4fy9QSNLwqdDrBlLxYoXiRLUb9/GNKLLUj2kXuH0vxU/Ulv2VyDVzRqzr8+x5TL4C9U3
         PvYg==
X-Gm-Message-State: AOAM5313HGCGBQlYoD5w5AWrXfnBbeDjB6dkDnGkNBYa8VlL1skr0KpX
	TqaErVrpSOJZES7dFrgLIhs=
X-Google-Smtp-Source: ABdhPJzvpLYTOxh0DLZjhmCj9GtNXQQRohw90j9fx2YlGXuTH7gzzWK7UD6PMkGwFCLh6ib+1cvy9w==
X-Received: by 2002:a1f:a454:: with SMTP id n81mr10360152vke.12.1605102426221;
        Wed, 11 Nov 2020 05:47:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5adb:: with SMTP id x27ls1044228uae.1.gmail; Wed, 11 Nov
 2020 05:47:05 -0800 (PST)
X-Received: by 2002:ab0:4e0e:: with SMTP id g14mr13073075uah.19.1605102425556;
        Wed, 11 Nov 2020 05:47:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605102425; cv=none;
        d=google.com; s=arc-20160816;
        b=PPfJQ79z/qLBAbTYdngGGEf8KRaFrb0elh8/IFjwcKfh4PnKhcmwerFWIkx/Hhn38a
         a+mfJNGIzfbIP5AjtFnHfWmvjdbmQuVLnhKeBu9My4mrjRJ/S+zkeiqVZ8za6C6v275L
         uNssIzbpkGntpHbk47yIfg1+dZ+GzXUYxO6MjYPydkzKmHOYCTeiY4pOEe3bhPOzkw5H
         uwf9azpjzqjId6uentHrp5yOi2Q/ZVTyJh251sC/xp37KjkWIyO1fQmMjoCNoahpXSIc
         XeM3oVOnDjMA/rxehVsWZvAfT2yMO0gFE7CfBLYXTXwtO+UlLVnDPTHZpZPf7vnbmjzx
         7k+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=abCIw+qBhh3O/GScLoUzmdV0ZiAv0OKYISMWyJ4sHI4=;
        b=czj7AOeO2cf5o50V3E34zGRwL4piFjax/fvKCLwF8mvTxMhjEwn/XMaGqPgZq5DzId
         kc/G0UMhvDVVEjnw5i+2xhULKWUk5Agrb8E17vD0BhEHUbhn3X/H6xqAYKpVz9/Z8jZH
         Uy82kFp78CWQeE94atCKTF6IlV32kCcvjBgoqbGk9FpBpxQXpdw7Osd370UzgK/CLsmu
         nz2nbrsm6akVhJWhO2WsYAKEUgyaXjOJ5OwmgI7WsCPxHQmm6wSNiS7M3/8J8MZd8hTK
         83+IrnM5Y8iLDCBAXnw6LFQ+DkuzpcJuR9lW62Tbu7uWRkaGZ+dUUI1589dlEgfrZDQj
         D5Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rNZcWRwL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id p17si165832vki.0.2020.11.11.05.47.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 05:47:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id u4so1613658qkk.10
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 05:47:05 -0800 (PST)
X-Received: by 2002:a05:620a:211b:: with SMTP id l27mr1923525qkl.352.1605102424991;
 Wed, 11 Nov 2020 05:47:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <8f1316319d050f2019e03dac28a37ce1dd5206db.1605046192.git.andreyknvl@google.com>
In-Reply-To: <8f1316319d050f2019e03dac28a37ce1dd5206db.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 14:46:53 +0100
Message-ID: <CAG_fn=WsQmcmw2tEY5hdZuCXXWHDoFb05r0BAGZt8BxUM4U2gQ@mail.gmail.com>
Subject: Re: [PATCH v9 08/44] kasan: only build init.c for software modes
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
 header.i=@google.com header.s=20161025 header.b=rNZcWRwL;       spf=pass
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> The new mode won't be using shadow memory, so only build init.c that
> contains shadow initialization code for software modes.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I8d68c47345afc1dbedadde738f34a874dcae5080
> ---
>  mm/kasan/Makefile | 6 +++---
>  mm/kasan/init.c   | 2 +-
>  2 files changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 370d970e5ab5..7cf685bb51bd 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -29,6 +29,6 @@ CFLAGS_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>
> -obj-$(CONFIG_KASAN) :=3D common.o init.o report.o
> -obj-$(CONFIG_KASAN_GENERIC) +=3D generic.o generic_report.o quarantine.o
> -obj-$(CONFIG_KASAN_SW_TAGS) +=3D tags.o tags_report.o
> +obj-$(CONFIG_KASAN) :=3D common.o report.o
> +obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o generic_report.o quara=
ntine.o
> +obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o tags.o tags_report.o
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index dfddd6c39fe6..1a71eaa8c5f9 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains some kasan initialization code.
> + * This file contains KASAN shadow initialization code.
>   *
>   * Copyright (c) 2015 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
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
kasan-dev/CAG_fn%3DWsQmcmw2tEY5hdZuCXXWHDoFb05r0BAGZt8BxUM4U2gQ%40mail.gmai=
l.com.
