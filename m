Return-Path: <kasan-dev+bncBCA2BG6MWAHBBSHYQWIAMGQEZVLVQ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EF8E4ACA09
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:08:42 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id n8-20020a4abd08000000b002eabaaab571sf9626081oop.11
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:08:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644264520; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pas6url+reLlg33f+hT94vmT8z+iJTaEihueAEZGTIS6qkFYk7fo0txYPaKgHWhn+l
         sxhX4DCQXkymGPRLE3jgWMzWFSOSkqi+qu2bAoCPYrFwT+R7F0XzQFOXiy6LgabYomEq
         8lzjflO3Fx3tqnV6sq0TKCSxKx3JTwqqdGSJMwoCq47caCX4met/XiwsHjwMwJBszbBM
         WsfCiqTcauP/wvWsRa7IlHbRnrg/W87Hx5gc3k00D42N6PI9CbgF4zJ4Kuv6Hep7WeaL
         w0O/cubZybGjUR0JAwmuKA9pJu2tuPDpy24YGmuTwnaPf/O2bhlhKYo4x9+I0WvAQczf
         mvdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MBUbh6X6De2Yga3f4GMtvKRO8rgtXVYcktgzzN8Kw7s=;
        b=QiTzlwZshqVzpQDfJTz5WS6hVOjjiATAi5HancmgBwlwy2t6IHd0F3wHkZ8cEd9q1k
         bPnJa71vbG/9MDBoT5+v9ySQzqAOz8CI95+paEs1KAmpbmq/DqoRbsLci3hAsKMhegHi
         jDgaUCCQkrvHYRwN36M0gjAj6+iUAyd8ziIujLrVzG7Y0CmOeRhJuEgXW/UDFNOSlpMh
         /pQZ75A0ALAFE3pJlDMxwWB1F8ZIhn30SqTPueTSnFvJzqlD+JDiSXmuwONkGetbqjxl
         yLMGaYlV0yuiMD17Ih0clwrs7B716JOIP40OlYgVHposjrSzIB83mRXrmq/Y3HJgOwAk
         r6fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j258jgaQ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MBUbh6X6De2Yga3f4GMtvKRO8rgtXVYcktgzzN8Kw7s=;
        b=jQMmyS9MJw7MP92kObm0BNpniONJ5SdlrpM/22Sr2JgYsWasesjMOK2lkgcNx3y4Br
         9QUbcnKthAfIfRajxyJ5HI65kX+axEmR9NXDApAP1WiuX8vjLTo6ll6vzO7oMsNXjqv4
         ezoUlMjTOp6Le4ts4N3scsLcva2eh2vYJ/XA206SncrkuYeqgnd/S634pL6EXZYlxxwj
         a4cK/sqm93kurEESAv1McR4NNskXjlePg1w8iy1nSSrH3KEIdfpwSIfZqq6eOUHM1o7l
         aGLSkbQXqnXRxDrY1LU8H3m+GKj/V2QMcnKPzVL3VyHE5G3Ph8+if8AWZOZbSwvvrGle
         Lhtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MBUbh6X6De2Yga3f4GMtvKRO8rgtXVYcktgzzN8Kw7s=;
        b=foc5CA1AmUKR2Y5LPfzOlSYyjFPYX6Qifn9GFyHcUFEm6MNQNl8vaa82GnesW7hUM1
         S2xGULxHGwF18qAHz9lz+iQc1l9SB92/LWfvtI4DIRAJ4yXIBAwMAv6/ZkdotkXcqClj
         obw8aLs/3lE4dPXliiMJ544GO+lydB2eNfaLeCh93sUvGcalAxCC0k4amTT52g3mSvkW
         mdBMFBUdyJuQg2FDetHrKfB+aj8ri9iqd31JpQuDoHgMyIXPTZagQhwX+pUPMsjin9wD
         RSyVd7/tV03IRXprDFy45MWWZU0j3dGgmNGyhJOQeh0htiL3CPMgDB/PFaFESmkwGxYE
         GWpw==
X-Gm-Message-State: AOAM530UCHstbjYXjiXyrCywqOmAeuDGTy9jSr4yH2K4yWQW445dR3oI
	XoA8MaN8F7Y0wXDAYPPE3GM=
X-Google-Smtp-Source: ABdhPJwXdloYUM15dX5jNArKmJu16i+sDY7QsEFA1BZUzuws+w+x2kUIT0FCcyQVZZToIxagqnZkZw==
X-Received: by 2002:a05:6808:3014:: with SMTP id ay20mr284175oib.257.1644264520617;
        Mon, 07 Feb 2022 12:08:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:e84:: with SMTP id k4ls2940321oil.9.gmail; Mon, 07
 Feb 2022 12:08:40 -0800 (PST)
X-Received: by 2002:a05:6808:1391:: with SMTP id c17mr259482oiw.333.1644264520221;
        Mon, 07 Feb 2022 12:08:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644264520; cv=none;
        d=google.com; s=arc-20160816;
        b=AlITMfaQ6CuKIkEC4F21tYu0qw+UdKo6F9yuJox5aurwW/C7QwMrBcyglDa/BHLRAj
         nc1ax7QBlWUAT+Fvx9HbLWU3PSV52pGAmJ7NezM4kPymQVQiQdcAaj1+9Abn1FF8YEqq
         lYqeY2pypsMXqkqP0Z6v6xPrhGdIoYhINb/OcXooPF3beZSyyi4ww0+eqsaI/wh0+3v4
         u7ikevq3++AjL5K+QdIWwNudLhCoI73nOY0AMeg/Vf8cF7MWW+7pC2cSPMkBPjQG4FtN
         JiboJoU0jXWE/8dkRTuEoNpjpEocs7gsHMmIkeuysPxRN/jm1pTMLZ7H/upzBaXDmXkG
         XNLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LNwds3cgV6uMX28QySXkXVMQplA0HsKCenltQ/gMoBA=;
        b=OcQ1imJlrBs7rkqr5jqQ5pbpTmbrXUYjZErwLBgpjdpK6q6Jyw3u6RjwOKyVlFiBV5
         OPzXm2ahk2KrzWf1NJi5KWfVNUFcn8ZbxdH43wy8JGf4ja/ylW4Hs4JBuYOKb1SAaF3R
         EvEU3tiAiPYcKSmb1KhG2vBSkD/k8hIOG4E2meSq4hCtewbSvuxk9aPETDdncROd9kGX
         1VcfxWiL9nHEy9ExFnkDs8Ipc05kYqLdluQBaiOim9WegachTvCTmaw4YzGBt3TeVmEI
         pJKYFqe7raWiZADzKtxYwKGAptMS9yqWiFDV2xGlRiuUszRZWDAX4kLfuSMUjun87dVf
         4MJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j258jgaQ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id t38si1060332oap.2.2022.02.07.12.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:08:40 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id my12-20020a17090b4c8c00b001b528ba1cd7so227918pjb.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:08:40 -0800 (PST)
X-Received: by 2002:a17:902:b682:: with SMTP id c2mr1313446pls.126.1644264519213;
 Mon, 07 Feb 2022 12:08:39 -0800 (PST)
MIME-Version: 1.0
References: <20220207183308.1829495-1-ribalda@chromium.org>
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 15:08:30 -0500
Message-ID: <CAFd5g46X_jptwL5UsebR2Ooq7ubneSZ5p-Qp4BOL9dt2gFhMAw@mail.gmail.com>
Subject: Re: [PATCH 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=j258jgaQ;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Mon, Feb 7, 2022 at 1:33 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Today, when we want to check if a pointer is NULL and not ERR we have
> two options:
>
> EXPECT_TRUE(test, ptr == NULL);
>
> or
>
> EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);
>
> Create a new set of macros that take care of NULL checks.

Also worth mentioning that we have a KUNIT_EXPECT_NOT_ERR_OR_NULL()
(as well as an ASSERT flavor); however, I can imagine circumstances
where you don't want to check if a pointer is potentially an err_ptr:

https://elixir.bootlin.com/linux/v5.17-rc3/source/include/kunit/test.h#L1586

Otherwise - aside from a minor nit below - this looks good. Send me
the rebased version that Daniel mentioned, and I'll give it a
reviewed-by.

> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> ---
>  include/kunit/test.h | 91 ++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 91 insertions(+)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index b26400731c02..a84bf065e64b 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -1395,6 +1395,51 @@ do {                                                                            \
>                                           ##__VA_ARGS__)
>
>  /**
> + * KUNIT_EXPECT_NULL() - Expects that @ptr is null.
> + * @test: The test context object.
> + * @ptr: an arbitrary pointer.
> + *
> + * Sets an expectation that the value that @ptr evaluates to is null. This is
> + * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, NULL, ptr).
> + * See KUNIT_EXPECT_TRUE() for more information.
> + */
> +#define KUNIT_EXPECT_NULL(test, ptr)                                          \
> +       KUNIT_BINARY_PTR_EQ_ASSERTION(test,                                    \
> +                                     KUNIT_EXPECTATION,                       \
> +                                     (typeof(ptr))NULL,                       \
> +                                     ptr)

Minor nit: can you put these new declarations just ahead of the
existing KUNIT_{EXPECT|ASSERT}_NOT_ERR_OR_NULL() macros that I
mentioned above respectively?

> +#define KUNIT_EXPECT_NULL_MSG(test, ptr, fmt, ...)                            \
> +       KUNIT_BINARY_PTR_EQ_MSG_ASSERTION(test,                                \
> +                                         KUNIT_EXPECTATION,                   \
> +                                         (typeof(ptr))NULL,                   \
> +                                         ptr,                                 \
> +                                         fmt,                                 \
> +                                         ##__VA_ARGS__)
> +/**
> + * KUNIT_EXPECT_NOT_NULL() - Expects that @ptr is not null.
> + * @test: The test context object.
> + * @ptr: an arbitrary pointer.
> + *
> + * Sets an expectation that the value that @ptr evaluates to is not null. This
> + * is semantically equivalent to KUNIT_EXPECT_PTR_NE(@test, NULL, ptr).
> + * See KUNIT_EXPECT_TRUE() for more information.
> + */
> +#define KUNIT_EXPECT_NOT_NULL(test, ptr)                                      \
> +       KUNIT_BINARY_PTR_NE_ASSERTION(test,                                    \
> +                                     KUNIT_EXPECTATION,                       \
> +                                     (typeof(ptr))NULL,                       \
> +                                     ptr)
> +
> +#define KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, fmt, ...)                        \
> +       KUNIT_BINARY_PTR_NE_MSG_ASSERTION(test,                                \
> +                                         KUNIT_EXPECTATION,                   \
> +                                         (typeof(ptr))NULL,                   \
> +                                         ptr,                                 \
> +                                         fmt,                                 \
> +                                         ##__VA_ARGS__)
> +
> +                          /**
>   * KUNIT_EXPECT_NE() - An expectation that @left and @right are not equal.
>   * @test: The test context object.
>   * @left: an arbitrary expression that evaluates to a primitive C type.
> @@ -1678,6 +1723,52 @@ do {                                                                            \
>                                           fmt,                                 \
>                                           ##__VA_ARGS__)
>
> +/**
> + * KUNIT_ASSERT_NULL() - Asserts that pointers @ptr is null.
> + * @test: The test context object.
> + * @ptr: an arbitrary pointer.
> + *
> + * Sets an assertion that the values that @ptr evaluates to is null. This is
> + * the same as KUNIT_EXPECT_NULL(), except it causes an assertion
> + * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
> + */
> +#define KUNIT_ASSERT_NULL(test, ptr) \
> +       KUNIT_BINARY_PTR_EQ_ASSERTION(test,                                    \
> +                                     KUNIT_ASSERTION,                         \
> +                                     (typeof(ptr))NULL,                       \
> +                                     ptr)
> +
> +#define KUNIT_ASSERT_NULL_MSG(test, ptr, fmt, ...) \
> +       KUNIT_BINARY_PTR_EQ_MSG_ASSERTION(test,                                \
> +                                         KUNIT_ASSERTION,                     \
> +                                         (typeof(ptr))NULL,                   \
> +                                         ptr,                                 \
> +                                         fmt,                                 \
> +                                         ##__VA_ARGS__)
> +
> +/**
> + * KUNIT_ASSERT_NOT_NULL() - Asserts that pointers @ptr is not null.
> + * @test: The test context object.
> + * @ptr: an arbitrary pointer.
> + *
> + * Sets an assertion that the values that @ptr evaluates to is not null. This
> + * is the same as KUNIT_EXPECT_NOT_NULL(), except it causes an assertion
> + * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
> + */
> +#define KUNIT_ASSERT_NOT_NULL(test, ptr) \
> +       KUNIT_BINARY_PTR_NE_ASSERTION(test,                                    \
> +                                     KUNIT_ASSERTION,                         \
> +                                     (typeof(ptr))NULL,                       \
> +                                     ptr)
> +
> +#define KUNIT_ASSERT_NOT_NULL_MSG(test, ptr, fmt, ...)                        \
> +       KUNIT_BINARY_PTR_NE_MSG_ASSERTION(test,                                \
> +                                         KUNIT_ASSERTION,                     \
> +                                         (typeof(ptr))NULL,                   \
> +                                         ptr,                                 \
> +                                         fmt,                                 \
> +                                         ##__VA_ARGS__)
> +
>  /**
>   * KUNIT_ASSERT_NE() - An assertion that @left and @right are not equal.
>   * @test: The test context object.

Cheers!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g46X_jptwL5UsebR2Ooq7ubneSZ5p-Qp4BOL9dt2gFhMAw%40mail.gmail.com.
