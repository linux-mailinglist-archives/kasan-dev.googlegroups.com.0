Return-Path: <kasan-dev+bncBCCMH5WKTMGRBP44WD6QKGQEZZA47ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 540742AF5F6
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:16:00 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id t3sf1035507oij.18
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:16:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111359; cv=pass;
        d=google.com; s=arc-20160816;
        b=ISOSfPHQYsfP7YYM+9aToSZ4H07ebVhAx89/YTdyjUwZJRf+Bl5CJOUNE3k57pHULY
         6FclPnrDcqKN1pZcM6BTZMqePrky8Ka5X11WEaqAwiZw0VNsqaj2betIkzB04aa0b9F7
         RJSnZ0v+4i3bPi0Vl/i81RK8+jXPHZ/CLMG87y+FbQSHvJyngSiG99AEjR5BUIaR2iA2
         uU/KDFPpqbuaYBD5Y/HqY657dGtN9zmgmHBoytV9XXIEdfc4bqdiFPLGMgjPueBj7dtP
         +lpl67cZx6lHL6CI5C3Sfd7vDwD1m1Q3/0lNLg4jrucXTy2JV59+hoCZJlCqmWKtGIbO
         n2Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=82R79ZJa5aDl+bWPzPM688wPVo1YHavYEhq9ogPs7/4=;
        b=eIoztm4ISgg2NxUY3b8imGNL4r3NZMkyEtUtYRGChwqLodgMZmPOUV3W5Elw/d22cx
         yAfKXFuAOYwmRmmq4CAoYFUScGXjcOI+AQ4bJ9hiFRgIDkMCOtOrnnb6DTp4J19EQCrm
         YAXbMW9k9iFxouHRqi32JCKMg+2HXzAWuARLBqgrUjyTdZMQyq0DMxOcDMFmmRV07o8v
         FgLf2Olkf7vN6B4fbrcXdrt+VmH6sG3cBndy1ZKV4G8uQYFEqwdTU8KZxEKoO9acyBbd
         dDSVUqYth0oSY3vIs8A6vwbKj2G5lHbaddI8mcDS5aN7mVwGHigq1eyOJrLDqG9Mb0+s
         5Mgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vjz+TKcm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=82R79ZJa5aDl+bWPzPM688wPVo1YHavYEhq9ogPs7/4=;
        b=TaOfDgyZ6jBTOKlzzgRSyE2z22qErICzD1eY2e5XTKTo+seEoS7hpvKDzbgLUV993v
         YCjtYWw8USVeYPxQY6T5bSF526RJm68ggG46NJMZBhrIDq6TZ0g6yoG6xD54mdNo5AFz
         hcc3PKH0YKV0th/PNxHW7TcZAl75j0D0lwO8XFFPeJ1QpmDW8floZWJR5Nx6fxPdWRt5
         2/lwFBQSngAdqK3DfS/7Io+b3E3XCjcg65U9u81i9MPOB+Rco6dkq3uwOUEOkcdtpGfJ
         43beahDEZWU2dfeiiS0sJ6440Azml0q45VZLfTMBnsD1skRj1F4zVQEq3UGw8cIbX/Sd
         Wiug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=82R79ZJa5aDl+bWPzPM688wPVo1YHavYEhq9ogPs7/4=;
        b=rCFGE/3Vpp+r8jiznInl6iI6btFhfXs46mhmdHGv93djzYeyTfSPcbHkDgihnt7/tI
         wiU/sa8mmCJwGjg2NSBsesRL6DdGXBqk1Kxdf+cH33T/LzFGuFaEPZq2bft1yLN9t2GF
         fyBfQcn87j4FObuFDrbSPyJI+XagbFym3GBiQNeHHdjHCft9gwZQYq5Wld6Au49obx9h
         g+rodKh14fMNeizXg4UVyI7NyK1vBWwcw8WZevNGCy1X4hSOEqv8qTlZLYybkIBICtAs
         I+6WpEpa7jFdtZIgQcoKxLDwXdLxQNp61RSO0hdXAiiWjYKv+cD7dwC5/+Ihfed4WCjF
         TW0A==
X-Gm-Message-State: AOAM531d7YdfOGxIwRCBGDbmwsqGzsmAi7ZQlcY8NX9C0DSqadMFbmGl
	ywzvFKpb1Pw2hVIqPpAtQ00=
X-Google-Smtp-Source: ABdhPJwFcUJwYqd9DhYce73f8QnXsupO7JevFHJGlekceUM9yIL1MU5/MGwvU6+ZQaa+9eXSBZKp7Q==
X-Received: by 2002:a9d:66ca:: with SMTP id t10mr16394270otm.13.1605111359340;
        Wed, 11 Nov 2020 08:15:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66cd:: with SMTP id t13ls1159otm.8.gmail; Wed, 11 Nov
 2020 08:15:59 -0800 (PST)
X-Received: by 2002:a9d:76d7:: with SMTP id p23mr12042336otl.180.1605111358979;
        Wed, 11 Nov 2020 08:15:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111358; cv=none;
        d=google.com; s=arc-20160816;
        b=a7XU7tttpgI+f7IiQ9uRFWxlap8z/TqhDliU0XCZRMMY/v3olhOI0LORWa3hil8OX8
         lVq/sQOBqtWtpVaWwSD565RDibLE7uxFOL0thxAYtaU3LgQB0cQYz5AhTVDBQc7lJlKU
         2hXPZ7pqInGoUncwAtGD1pxfNHe0WJdGxzAoHOUj4/x+h8JwnAwo5MODllUw4K5L6ZwR
         qQ02jee9uoR8HRRIyjnUuQMYqLYEk52EUgiGNN/FS0kmS9s1GKSjlkWvKt2ehZ+47/o0
         a+/rap9d9OgR7SlST/aIzn0WXsCl9YsFT8DIoBJYi2sZoLnGew7suLcLl0dcbd3G5Lfh
         YkPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OzAPueyrhVv88UcsvPpSA8EQHYLLbDVW6Lc+mOLNNXQ=;
        b=fIxJFpoPMLDTAKQ7+2GLCMAc783vT8qQKwOT2LFE3jCXBc3p+BFBxIGrMRYD9Yd9xD
         T0CiVs/cQFWLiQiyid+AMJCzYDzqTBgiv42EQiMkru+bvwwZgFAfZaTIx+Lrmx6fFQ+8
         E8DNa0m4vNuPQoOc5bhE7Vq0e726xKGmmX0jVqic+1/LgaE6QV6DPtFGP/ly77zShR1d
         Fg3dl2SI+8K8vYy4IN3zD5LerpF4kwofCfWxbK2uPFva46SEwhATiE+urlQNMWtCpAH2
         XJctBcqsOBRD663LxAEe9sabki86g4jnIHrxdPvlZ0qA+wobhh2atFhO1bjwm2sQmKls
         oWkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vjz+TKcm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id k134si131093oib.5.2020.11.11.08.15.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:15:58 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id 11so2162300qkd.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:15:58 -0800 (PST)
X-Received: by 2002:a37:b545:: with SMTP id e66mr8798166qkf.392.1605111358447;
 Wed, 11 Nov 2020 08:15:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <096906ff06c532bbd0e9bda53bcba2ba0a1da873.1605046192.git.andreyknvl@google.com>
In-Reply-To: <096906ff06c532bbd0e9bda53bcba2ba0a1da873.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:15:46 +0100
Message-ID: <CAG_fn=U5bs8U8uw1765wDXuWg+0uGWkxUw4THjmW5cgVv3rrVw@mail.gmail.com>
Subject: Re: [PATCH v9 37/44] kasan, x86, s390: update undef CONFIG_KASAN
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Vjz+TKcm;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as
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
> With the intoduction of hardware tag-based KASAN some kernel checks of
> this kind:
>
>   ifdef CONFIG_KASAN
>
> will be updated to:
>
>   if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
> x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
> that isn't linked with KASAN runtime and shouldn't have any KASAN
> annotations.
>
> Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> Acked-by: Vasily Gorbik <gor@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
> ---
>  arch/s390/boot/string.c         | 1 +
>  arch/x86/boot/compressed/misc.h | 1 +
>  2 files changed, 2 insertions(+)
>
> diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
> index b11e8108773a..faccb33b462c 100644
> --- a/arch/s390/boot/string.c
> +++ b/arch/s390/boot/string.c
> @@ -3,6 +3,7 @@
>  #include <linux/kernel.h>
>  #include <linux/errno.h>
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>  #include "../lib/string.c"
>
>  int strncmp(const char *cs, const char *ct, size_t count)
> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/m=
isc.h
> index d9a631c5973c..901ea5ebec22 100644
> --- a/arch/x86/boot/compressed/misc.h
> +++ b/arch/x86/boot/compressed/misc.h
> @@ -12,6 +12,7 @@
>  #undef CONFIG_PARAVIRT_XXL
>  #undef CONFIG_PARAVIRT_SPINLOCKS
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>
>  /* cpu_feature_enabled() cannot be used this early */
>  #define USE_EARLY_PGTABLE_L5
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
kasan-dev/CAG_fn%3DU5bs8U8uw1765wDXuWg%2B0uGWkxUw4THjmW5cgVv3rrVw%40mail.gm=
ail.com.
