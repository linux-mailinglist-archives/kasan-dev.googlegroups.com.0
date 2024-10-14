Return-Path: <kasan-dev+bncBCMIZB7QWENRBCNDWO4AMGQEW2FRQRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 38E0199C293
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 10:08:43 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-539fbf73a2fsf175494e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 01:08:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728893322; cv=pass;
        d=google.com; s=arc-20240605;
        b=RvZAE9ny4o6baqnBW06g9mCHw8nNH+7n0mjKrNGMgxt9q0YY7nJ7Ty6DJKnedRlwoI
         noNSq7PVxnB9z7Hz7Tsz8dS/ZADi1Ak+lcT9hiom0WzL3cOiTqq1qrdU6xtwyfIRFWEa
         muhXc++EAZSQx/uE7Sx3pTMXE2NSTLaLa00jPTpFo7uu8g1O6jMvPTVVmXSXbFXhTIWT
         6csbzfPoslhm5XtjG4cj0RJ+aBgIuIuE992ac6pMI1X1N93c5k77Pk6jon/yhNzQH/ca
         NhQ4VFHs2vGeZNOJe/Fqh47Eou22jpIQJtAWVyAHln3Tya1ISAJc/bfboPnekKBJf3u8
         +keQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=m2SYLmKnZFtVE/g4frijb9am703IRxfE3PTo8Vs5R0g=;
        fh=t1cnyd4Ru5hoD+L32WopJf/gWfibyhmh91lbsZTrjbo=;
        b=hFJKRq5b5PFhq2M1eg5mJvWkWRp5+CCjcgkOqpyo0frx7dMiS++wFoVF3nzrSGkQhK
         bjrgTcFNLrEckJWU1nZjIHk6sfup75Muv36UvVYDldTrqU39U42Q8zkuzhj/wZIkMAl9
         S5mKkCGkD6MGJhevK1724B6Xk/xouor+KUr3AJGDNMM7eX0dtbIbuRHWHYaXuy5BZXbd
         LZ5CtQ3qGC4laRo6Gzmi8STGBEb80RQ1LS4X3LsBAH2DnhP4OtBttZFV9C8H1vixuXfr
         20zWsL8+LENdryvO2thduioCsBsm3QUYA8b4BHvYnEs/R1r+miSYFYb6KqhEYLCfo2jh
         sxgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hHN+Ms67;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728893322; x=1729498122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=m2SYLmKnZFtVE/g4frijb9am703IRxfE3PTo8Vs5R0g=;
        b=dsvJ1Bxn219+m3+FVAx519vkjz82xvnROIa4GBnOKtx7xYyEDGFERPQGjjtPDaJpqL
         P79w/37r+1MbU3pG6zLH85ugJ5mb3QH7y7zkbxTeZlSlCcLtX8+zGcAV0+jJoSn1B1ON
         7UlZXInbQrjmegzcojX/pjbd75dtKOAjpKGCGeOK5MI/9TpgeWdjgvEBznnUD1VKvdVp
         jsLUUcc19sk3YKf54X5dzkK04DIaf+tkJMYFQXfo/Ms/+DYgnsQUSBYzrlaZwvdUVifo
         vcx/lIGQu+he+f6QrpuZzFnSKXEPhHXU2ERY4HzpWTKRJHI91KEOOhAzwmhKdj7b2sHQ
         kctw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728893322; x=1729498122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=m2SYLmKnZFtVE/g4frijb9am703IRxfE3PTo8Vs5R0g=;
        b=k5FBf81uAWwBVHhdxYjtLh703dT8eegN09hYcVIUuXmAvKu0piew9209rGValkzxHj
         mLy7HNsaKn4OyrZmouNl7eF5yFUbOKW2tGdnnGdaLVlYet21MwQRKHw/FMacSHLlQ2W7
         wEkoAXESH7ugt3Qp3g/196MEZY9X1uAy8a0up4iLKhBVFRralvghEINHfPDngqAQ+SDP
         1IRjGKUx4/UcwYMMRvYXXtm46LyvGAFuHAX/744lRxOA15zGlWqHC3SOOBzt0r2ydgy0
         HUjvTRMAnbg/X6gEjqiiLvJ0oJfEsaTHCJP7Y8KItv4AzER4KUFjGDhDr8YeQYCuroXK
         yvyQ==
X-Forwarded-Encrypted: i=2; AJvYcCW9ks/eILDMefLQvcvMFC8UVp6bd72YA3xhHMkUGh15BlJLOlAeCasy6D22aikkrO/9+sudHg==@lfdr.de
X-Gm-Message-State: AOJu0YzWCCYLBEcLhe8xNSqPKCCXLFp0n9ECSIF3UQJ5TNS5xoOPSDA2
	LM8+sYZ5SOpGqSSrvUNYYhR4IdbRIuDhCX4l13zoUmnqMrSgDJ3p
X-Google-Smtp-Source: AGHT+IG9zpFs/hOM/zRihf/+5ySoPb/gEd7Z0TKZFTptwmd5yN300cVJY/MkbARHkd6oqgZm3pNsYg==
X-Received: by 2002:a05:6512:e9d:b0:536:52ed:a23f with SMTP id 2adb3069b0e04-539e540baffmr2713596e87.0.1728893321554;
        Mon, 14 Oct 2024 01:08:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1111:b0:539:f863:bf7a with SMTP id
 2adb3069b0e04-539f863c1b3ls150873e87.2.-pod-prod-04-eu; Mon, 14 Oct 2024
 01:08:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwV+xr1Z8lODpRhGoGIKbCWlkV6lAdUWVmNdyYcHuEdd72OkBg+f7q2zQ9WVdcxo1yw8Ax6PEeVdI=@googlegroups.com
X-Received: by 2002:a05:6512:3402:b0:535:68ab:7fdd with SMTP id 2adb3069b0e04-539e54f023amr2544216e87.19.1728893319351;
        Mon, 14 Oct 2024 01:08:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728893319; cv=none;
        d=google.com; s=arc-20240605;
        b=P7J8z5xYmmZfmY+yy+jojIAxsoCUrLMnFBf2FSE8ZVkryjRbs0VZ/PpzRmgBbDBN7f
         o+cr9vE4OMeb/k1puvznTzeFuWZj7bFqzZemx4T4raOsn9Dem5L8lSM0blFoYbA9oG37
         8GOn6Sk6N+DAyfEzy/pYA6Nvo8wuwzXzyE2KK7BKsuTPpSx4+Z3YKAeCVbK4mwItqo+h
         aYgT6C3CeMP4jFrz5aBxUaHGUSeYAtOmX/yXBrSixfJeIJrzyEsolIxKgvA1rIQy/ASB
         0dOZsRyQCkEl3UT7sf5LZCaHGY/1csZdpwkVQ1n50SUW857GS2xO6/WkOry4OBjrYVps
         ZQMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PiUD3POxK4R2Vjsmnvv6htZOxYD0NUhQkka4uTSkr18=;
        fh=Hb4L2iVw280KayC98Kvr68HAyXwOl97FdeVq7i6JJlA=;
        b=ff3tc7M9cdSlYwQGq/os8zoAllcYCqYj3nQ63lDNr32rOmbqfc/UCdBMvI/qj2GXLy
         ZwiS2OPPTElif2qAzQZZDVhW3C1mTNW302UL8A8KG9hxQ82RVlGTTyagNS/NRX/gI2kN
         U2aRpwlHyCOy+NwJghBiGjWSY3Lq1a54fRkIaNYcS4OPuEWejLnjjfoKaP4eBsWDJYka
         NYiaMI5Rpc5/Ta9/y9+lfoF2OACnJGj7nGYEcVBu7IiBJIAZjHaj35xAOhJ7IW0Y3sJx
         tUpBdjUtnkiGM1BvqTAmp9DAv2U8AUuieT2VeCTC5QzE6R0VoFyxZ+llbnBpCldGdR9U
         GNjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hHN+Ms67;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43118357425si1548565e9.1.2024.10.14.01.08.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 01:08:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id 38308e7fff4ca-2fac9eaeafcso37924161fa.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 01:08:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXsNafLjk734lgiw7e43L6ypZ7cQwy081rf+K9J+3z/JZSUmJDYj0wAM5n0LpEJ+CHh8cJ0Vgx7Pp0=@googlegroups.com
X-Received: by 2002:a2e:82ca:0:b0:2fb:2ebf:3259 with SMTP id
 38308e7fff4ca-2fb3f197c72mr20149671fa.13.1728893318227; Mon, 14 Oct 2024
 01:08:38 -0700 (PDT)
MIME-Version: 1.0
References: <20241012225524.117871-1-andrey.konovalov@linux.dev>
In-Reply-To: <20241012225524.117871-1-andrey.konovalov@linux.dev>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2024 10:08:23 +0200
Message-ID: <CACT4Y+YS4UTMwk_j+Fjah3bCQd0zFcr2XqsUJ5K8HC991Soyhg@mail.gmail.com>
Subject: Re: [PATCH] MAINTAINERS: kasan, kcov: add bugzilla links
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hHN+Ms67;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sun, 13 Oct 2024 at 00:55, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Add links to the Bugzilla component that's used to track KASAN and KCOV
> issues.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> ---
>  MAINTAINERS | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 7ad507f49324a..c9b6fc55f84a6 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -12242,6 +12242,7 @@ R:      Dmitry Vyukov <dvyukov@google.com>
>  R:     Vincenzo Frascino <vincenzo.frascino@arm.com>
>  L:     kasan-dev@googlegroups.com
>  S:     Maintained
> +B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizers&pr=
oduct=3DMemory%20Management

Do we want a link to buglist.cgi, or to enter_bug.cgi, or both? =F0=9F=A4=
=94

>  F:     Documentation/dev-tools/kasan.rst
>  F:     arch/*/include/asm/*kasan.h
>  F:     arch/*/mm/kasan_init*
> @@ -12265,6 +12266,7 @@ R:      Dmitry Vyukov <dvyukov@google.com>
>  R:     Andrey Konovalov <andreyknvl@gmail.com>
>  L:     kasan-dev@googlegroups.com
>  S:     Maintained
> +B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizers&pr=
oduct=3DMemory%20Management
>  F:     Documentation/dev-tools/kcov.rst
>  F:     include/linux/kcov.h
>  F:     include/uapi/linux/kcov.h
> --
> 2.25.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYS4UTMwk_j%2BFjah3bCQd0zFcr2XqsUJ5K8HC991Soyhg%40mail.gm=
ail.com.
