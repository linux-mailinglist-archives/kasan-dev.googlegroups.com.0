Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGVMWD6QKGQEJHLR2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 982632AF6E5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:49:31 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id m13sf1232546ooq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:49:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605113370; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAt4wP42EVaD1OL0Golv6J/iF8pEysPWXnoBZEMh7RaAosHLdIlOUeuEzgCDwjpiG1
         KjFVZ1B56meQ4soRVpaYhPPeit0MPKKPuCc6xj00gXSjgq6la+GiA0W9nQwMOfO/14dm
         W4SahGytq78zOogvddzewFFbfg8VNq3nwT9Sl2IeP2uIgA8fqxbt3R0ZLzAhM3ge5kP6
         IvUsKJ81PloeXF0H86bqlYCmSBR37DQiWgqzGEO+kuCn+3qHbOT+Xe2tc4qyN65SkSSI
         lJe3Pn/G3xUPa3XvzNn/kKphDgCTQEWZrQruEheYCHWazHAH1x9Lhibax6YUtp1FhFZ/
         Ou5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6NpPgZCMmhDTiFsO4tKgR5RMnTMzj5V9m0KG83R7pPk=;
        b=ZtJVvKzx+x/TIu+YLACoECzXhZ2mMwges9sKmTTz32WFckJscRpoiKpQpeEVsPt2QR
         3Gtz5zavTKGdWmlbdrMhLgaUIdg5xshIf88zYZy2d0tAe/4ZtRyoNg4XzX1ceRZx68xQ
         tY5iUHTW2KXI42AjdBw12g1ATw4bwToxzxyGiMGK+TDVUwigU/XDqxdOCqGOaVuiDEcH
         RH+HsFIg9EICCOh900WpNQ8cEak01P/VpMjDaoOQWpmeAGwNsy2N40qr0zVA4IeOIc3Z
         3lKUlq+X0fYUDl4eKwS5BMLY17+wcRDLaVCoEd6Hm7m8gdhei5WdQQhiG7gxF5TvXcQ6
         j+GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AJNMeYOa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6NpPgZCMmhDTiFsO4tKgR5RMnTMzj5V9m0KG83R7pPk=;
        b=nFbaMI2/wXl9Z9LcnKPGXmUkVJjshDeKhO0AZF2hcJoVA1durgJ2Za/zYgW059dz9m
         RmKUCTRMxsUf+zkiA995fj7FIqm21raXa2GGF/ZHgpGanatlE+OhC+U7NdH74oMYUYac
         P+DXGZbBnf86difWL/2wMYL27YyBXm7K2ctm8dsWQhgyO9W4hd9kMhKx3nNmZFUZ+gPU
         t85hwQiiOeouVmsY2dimOKr3xNZJqjmyr1IEMUG2GFyrQ9YerPudWK4jbkhL8Tee0fgI
         LlQhETP/TxMkh2F6h9KDwT4SrKFPYV8orpBkyGcqtd466UmP/RJWWfbW3Iz3b4ycXfC+
         UaMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6NpPgZCMmhDTiFsO4tKgR5RMnTMzj5V9m0KG83R7pPk=;
        b=btw1WF5AsLKhCVTWxD70RItA2trGK8LGpUaZXClslqktjOVs+MjsmktmFg15sX2FAW
         277il3+R8A5Pa5jgwyGXwRKcUoRNQDS4fvMgMOaOvGOkZS39TLXAm9MyofpWL6N6DpS1
         tyBaLhuJAf/WV2LRVXZpTtggqmI22Y8/nOSVsA4S8z4anDIfm4OarxRwLXIL+aLqbo6Y
         yKJioB5eQr2PSW+L+nWyXWssZ+Ss0GjdJxUTuJRuv/cyxVS9mxTQKV9H4E/OAITpI5dH
         eUiuFPlZyAFQ81dptB7MImjiXX19rKLloyBhJSQNvTKtBXCy3WE0q3QahLnQTyV++Asd
         xE0w==
X-Gm-Message-State: AOAM530pxTkeDZJLKxlCOcGMXevoKTNth8xnQpcyoizFeNl6YozwUSWH
	HMH5h2YxPysS6WckWOb0dEU=
X-Google-Smtp-Source: ABdhPJwdHTA6CYlN+bXIq/gGTknIP6wJOewPEAcKjCJRIjldTdKu8wf5w7FBxZtNZxNluWej7pwDrw==
X-Received: by 2002:a9d:2206:: with SMTP id o6mr19543773ota.244.1605113370572;
        Wed, 11 Nov 2020 08:49:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls34464otm.2.gmail; Wed, 11 Nov
 2020 08:49:30 -0800 (PST)
X-Received: by 2002:a9d:5cc:: with SMTP id 70mr19192983otd.34.1605113370213;
        Wed, 11 Nov 2020 08:49:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605113370; cv=none;
        d=google.com; s=arc-20160816;
        b=ynhrUsSOZPHYnIHZRcsV00Vc1U4zPtm+V4IuHAm9YmsXtoqVnMwo7asUEOFMbkLlcs
         q94JiTjveWOY2r+b4Yyl3zazxhr0BeYtcqovhDqy6XdGaWy2IJW0biX7I19OtGBb4g2O
         ZbsN9VzhOeQ2nW8Axd3+zrNITbs/feD27t2vjzgjFSomPIMxqn04dYTTDOIdxPWRcHv7
         k4jpH8/HZMuTz+k0gmt2xZpBPOiE4zuAJtnvjeVkaLNUg6y5H1GSZV8Zf4y//yRgGWjW
         CK4UOzJpbJc8kSn4yGKtBFfXJw6MDS/HEw7Bk+WZxtoYmE7HdYErWc2jk6uEA5J8krJB
         Be5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dHIwVHj/jWzL1sw9rtjN4XGVp52gznrPRFC4/UO5JAw=;
        b=y/oF6z7mgNGYD/u7wfIijkTlCQkXeDibtaAv+nGRUyZjvYWJ4OovuWonjMlh9o/hWR
         KGwwj3roFay6yjGBgRhuMO8Sa2udQ7VEH7wubjQhlEWifnOxNPss+Yf7nx5IeTXhD8t3
         +lun1UfBJHzj/3hS33gDFS3H0Ps8jn1Khm1xbARmtt38TZvlkhSuit3hbXG+q8Q72c7z
         WKbmTbaeUp1gTEhs0PXEhro6GfWqvXJ1CcI3XMOIyqmtCkMKX1GakNGaaLgb1bUCPm4h
         r9bsFXRw5WPOwj+oteOX2+SujLhd8pGm3qlzRccLxfWP6JJj19Ig8qpTh/LD6dkAvWo0
         6YzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AJNMeYOa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id e13si246861oth.3.2020.11.11.08.49.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:49:30 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id b16so1494107qtb.6
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:49:30 -0800 (PST)
X-Received: by 2002:ac8:454d:: with SMTP id z13mr21816261qtn.175.1605113369540;
 Wed, 11 Nov 2020 08:49:29 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <3d24722ca600b65a186a55ae47777a00a7c9407c.1605046192.git.andreyknvl@google.com>
In-Reply-To: <3d24722ca600b65a186a55ae47777a00a7c9407c.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:49:17 +0100
Message-ID: <CAG_fn=XsoJeoYQvO4vi2W0RyxnwBQ5N=wcaRD84OEZy2+Gxtbw@mail.gmail.com>
Subject: Re: [PATCH v9 42/44] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=AJNMeYOa;       spf=pass
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Hardware tag-based KASAN is now ready, enable the configuration option.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
> ---
>  arch/arm64/Kconfig | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 456741645f01..c35e73efd407 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -135,6 +135,7 @@ config ARM64
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
>         select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
> +       select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
>         select HAVE_ARCH_KGDB
>         select HAVE_ARCH_MMAP_RND_BITS
>         select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
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
kasan-dev/CAG_fn%3DXsoJeoYQvO4vi2W0RyxnwBQ5N%3DwcaRD84OEZy2%2BGxtbw%40mail.=
gmail.com.
