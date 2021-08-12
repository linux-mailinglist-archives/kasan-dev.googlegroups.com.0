Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTGE2OEAMGQEMF3NA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DFF53EA113
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:56:46 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id h21-20020a17090adb95b029017797967ffbsf4585211pjv.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758605; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z6JBfq/motqYcq2tT8ANP3ssLdGsOIxumKNzAe3ykkX5E7dzzE3IN4p1Zr2r1y5hr6
         FB8gbHxPix4f3V7/x6+DvaM1n08+bz5aCPFf03x8HMmn2PT8AH6GrLWaIljhuWOLXpb4
         94ffrdEUOLkk2ejQ8itw5vLTOfP5qkQ42MpivruTb+ZpH/g1FPsO95pgureNI1nakm66
         3eCEzEouTP5qQdYKwsblwsLsAvgbkmk4n8oN7Az128aylaqQv5stb9gzCzF3FXMyQDQq
         LNCbvbNbGJEyFYc1V+FXk9CTqS8d12E9zanUj6v4aETGd0ejtpmw2a/QFAzFgc/4k2LU
         JCqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ahfOfIjWbfZvIb+o9xb+UlHz52WjURSeOCmqfUcp1r8=;
        b=lPY4pJDqChEtscXZ78WMvWGfgEBUUGr38a8Ce5m1Xl6OzVWgUEmwQPhZYHcdjPzirl
         ArqDim4VRmTRWS6qmCZWSJCGDSN903UOoNAboTCDdLr6xAUeRHecVc1n2HAeVIaCw4pR
         FqjkzkZIitaGQEJlbqbsVnaXnH27LOASPVFnCLOx+NxPo2CO46Cyr4p9IVeatgQyZwGw
         22Z5Y/K4zSq8pkmg6GDeeBkKSgkDoUs79OzWioTtITq3hdj9AkZLxgubBHESqcgd+hnA
         3GHsfn2RGqPy6iA9H5dp3JsN06k3QfPPrTHzQ299/FhruLR7rq1RMwA0fIu+aBwYVKkg
         j92A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hPI9bp/G";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ahfOfIjWbfZvIb+o9xb+UlHz52WjURSeOCmqfUcp1r8=;
        b=Hru9r6J3QRKZ9Yw7S9moCNb4xWvE1K+xYTnkW2dvtY4dIlUmWhK1aMX+YGtmUbULa3
         lBan1vE5JpCtMzbsZdRd7pawnbm6Vbnu2wWlwFDTs0qTZOiTIeGe45p33lGA2PyICTcG
         9TOdfq47Kf4gscZxVMPzlwnKg5fK3Nbom9NiF/6cAFbLW8012EpJLk0beT2PPrqRhQQG
         czySACtthMm2ZD6ItOS9Clu/nbJ2r0yzNSzwKWYr65I3celjR9OcWFBttkY/4q6SS4Gi
         1ffJfgR6kdcrGnz+j6E1B6GWBmrBdkq1bmDq6yadlpn9l7Ac8jDjkEd4p/KXvK/XaZYD
         QwPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ahfOfIjWbfZvIb+o9xb+UlHz52WjURSeOCmqfUcp1r8=;
        b=B2+kwaNkLGspqpg7pS/2tFId09fSj0hSXezfVP3AG3Yg3uiQnW9Z0evOcOPbORsZld
         BRngb/jE7hNta8/Y50PcUVcDu4k5r/znh5ZMUIVs2yyJdw+RKcGj2TLyPzE3gkSlFEdX
         7pMvJwrLVbeTFrJO2mSdhWLjjWzrItcXfDwWRqngT6dPQp6yjb8y6U6JlvuANxdeiDs2
         ws64q2A0cp6L2I++DqsgMaCwRJxEwmKf2nkeCKjW676tHQv+NVC0kYywaDSJL+YErO5a
         UFYI6C8DAVs1fHCSjv5p2IbhBH87VbCpD76WvHzIyDJ38ojMYvdfGnt62MDunyAeZmWR
         rvLw==
X-Gm-Message-State: AOAM531unTn/Klu7bM2ULcbYxm2Y+IxrYyxCy6Dylws6HD2sc/zV351p
	M6PXADjxi3BF4J9PYENRd+Q=
X-Google-Smtp-Source: ABdhPJw7c2GFv+HKm9bZAwZ3cvxHnjz7AF7kfN1hS3w/ORa/iCtlX+3z/z/bnCubsoTTHgi4SUv2Kg==
X-Received: by 2002:a17:90b:18f:: with SMTP id t15mr14927936pjs.168.1628758604865;
        Thu, 12 Aug 2021 01:56:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d98:: with SMTP id v24ls2280898plo.8.gmail; Thu, 12
 Aug 2021 01:56:44 -0700 (PDT)
X-Received: by 2002:a17:90b:1493:: with SMTP id js19mr2807166pjb.53.1628758604234;
        Thu, 12 Aug 2021 01:56:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758604; cv=none;
        d=google.com; s=arc-20160816;
        b=PTwIeCp35yfBuFMvACgWM2ddvR7qmgyGFjaLeaI2C6vpDQ+xWztZFz54XMN9WetitJ
         ozndTIPaIzgGoXsFmn1UG/pCepsCYbTdXrzoPjrYjQNzTQt7rA9igxzeISj+9VrbztRR
         XpEupAse5Iz3x4jeQIlRwYGAXbrQO5Qremqi6qeAbtILegB8rtKlm6UxdJSMrQDSHJlT
         jEOW97mZHSQUljZRKLdEJPcGIADrKKv4aS8O5lkTM0c1Vfjuy3HEvg9ui19gEHq/i2Dm
         OCsp4QGC7qOPhw44P3orcbnGOWN6vOJ9osza9T0wziGXfBkPlTiSLoTCfwIj6TT2OJP8
         b7MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I29wkPGgO6NQxXu1JpY/V8GMi3CkTzzZeeIK4bDLNvw=;
        b=zLT0m4rCayZnX+7qPAf67nvZSY5hPU/WaLR8q/tdTyB3SdZZrE2b7ZHq8UlxC2x8nF
         OR8DpsG7W6x/V6MoiKFJAzufzO+6x8+z3iDf9q1twY+jpzNggT9Iokg+KWWs+qfpVHwL
         eV8D+t4nfZiH6BqIfXDLm3eBUQrEhGNHPB58VXvkiRhcS0YlfjJMW0tl/RuBaR0tWURF
         Qx/fYqT7+hJWu6EVkusGXQxrfTVnJ8xye6zWw2LTEB9/zFz1WDuAjE69PC0KcGe30T9X
         GWSMswJ6kQMaz01cp3uwbjhorTqkS+NbT0mSSDhQobSobxOG9ZLYWpluod1NuZvWfbUT
         Fd0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hPI9bp/G";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id p1si100378plo.3.2021.08.12.01.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:56:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id h63-20020a9d14450000b02904ce97efee36so6883520oth.7
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:56:44 -0700 (PDT)
X-Received: by 2002:a05:6830:1490:: with SMTP id s16mr2632529otq.233.1628758603786;
 Thu, 12 Aug 2021 01:56:43 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <3773f984cbd64f008af9b03e82fc1b317cda9fda.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <3773f984cbd64f008af9b03e82fc1b317cda9fda.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:56:32 +0200
Message-ID: <CANpmjNMgkSG=QGKn-iOcUONTCxKtFHr2upbKcv46RsTYTcCx_Q@mail.gmail.com>
Subject: Re: [PATCH 6/8] kasan: test: clean up ksize_uaf
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="hPI9bp/G";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 11 Aug 2021 at 21:23, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Some KASAN tests use global variables to store function returns values
> so that the compiler doesn't optimize away these functions.
>
> ksize_uaf() doesn't call any functions, so it doesn't need to use
> kasan_int_result. Use volatile accesses instead, to be consistent with
> other similar tests.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>

Although I do wonder if the compiler might one day mess with the
volatile reads. At least this way we might also catch if the compiler
messes up volatile reads. ;-)

> ---
>  lib/test_kasan.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index efd0da5c750f..e159d24b3b49 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -731,8 +731,8 @@ static void ksize_uaf(struct kunit *test)
>         kfree(ptr);
>
>         KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
>  }
>
>  static void kasan_stack_oob(struct kunit *test)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMgkSG%3DQGKn-iOcUONTCxKtFHr2upbKcv46RsTYTcCx_Q%40mail.gmail.com.
