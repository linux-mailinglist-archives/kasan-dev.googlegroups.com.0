Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB7NEQ6IAMGQEI2NB27Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 232084ACEBE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 03:16:30 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id p9-20020a2ea409000000b0023ced6b0f51sf5317182ljn.19
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 18:16:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644286589; cv=pass;
        d=google.com; s=arc-20160816;
        b=cYHIev2KxHjDvRNfk3WywKE+bqKWjXZI6LwJxR3kzI+kj8bhedPcgGUXFIoQLJFvYC
         N6ZGR0PMEadQ9EizcElUu0+U+ylQgDXYMgBLoIcKUKPrulGfb3id2wvy8SyyMludWZsU
         +poPsi1OA6FVTMDIkcJSsd4y6ln7NxiijYhwmKdS/vUA1xV023ctO2zrhVgkmBOG/+kg
         MDwSBfaF+Ice9gDP4/PtqyfxOkidsd4VV+mao+sjHp8vRL+G0sn2tqrPVfrxcMJV5H0a
         VISHeUEjCNvZylF1E7yRu4vpZVq9oNsqOCgai5ivRdxcGcTlh7Xj4eP3UmP5BMSRMzbk
         /f1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jixxpQrgusxXNw9Dki6iyQu0Z6Ph+dL/scPDy/ri3bY=;
        b=sFUwTD5kU9iTNWoOPq/H5ufqnHD8HA7++KH7SeLso/LldYUoLRTG4MsJSPemgrpDEy
         NmLCTT5ZaoZ+HPLLeblUcglCfapZmb4N/nSdzNgeMB7QhmqyDsI7dxX4z12/U4Rf0oY0
         FHOZmDIi14XGJNeSdH1CgFqxkorpTNZokUEFRNOa2yzDQf+ozqWTh9LRm1VPf9apo4K6
         TfvJ9LkQukRi3j38Ub+WSFbExZTsf8q81ZjqVuMcLYtX+Zb/3iJvZ7vX6SxUCmQg+Xp6
         k9pAYqn3XkpfPdxYfd19AgUR9nApk+dPnCl71MVrdPbInI7yI7p+eP1amFjk3crsA5iy
         wZCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QDVZNEai;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jixxpQrgusxXNw9Dki6iyQu0Z6Ph+dL/scPDy/ri3bY=;
        b=IxkJzmBMLtKiuy0vScRGOnRNNnzhwOSQffjOrecOpiEF4Cw8EtF07W5wmVJgscUPI0
         t/qExOJrnzpznHaSV/nSafIMhw+aq/24CYNXa/AErZZY31L9ue2B0RqFCMLSkpRtqn5p
         ENEAEX/OMEL3uSONY9pMCmqvg7RZ53IMglbA1iHJq4u27AGbLW4bYD1dWywLMiqlZ3NW
         mSTzvJfH/dmhWrPwuzO1zyLnYRnMgHogrhiwPO/j8WH6taJn0I9dTYGSiKU0xaGntTBU
         9TE41/g8RZwoZKtIWsBmZiQuZr1jB+HujND8UrsHjNp8sEn3J/ZUJObakB/aUlNLmIqA
         9Z2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jixxpQrgusxXNw9Dki6iyQu0Z6Ph+dL/scPDy/ri3bY=;
        b=gmAlOcZSyYI4p3worRCDNjWUDoMtoY8FbPgyNUzdDAMNet2aulnFvTJsMDRu8c0pZV
         O3AepE0tOJbEqlyCWlF9LVN/P0FfJ7rG636h2vxw+zmwmfG+0Vae6u4QGdZ9wy+ZU95r
         qgHGBCgX/DlZcmqG7Jg7mUrTlp5FcHKMS5lx1hmw2mPGh0rYc3OpZbTh8KRcrol1j/zc
         F6JrfCiBydLyw4ULGJGuhH0ggC4MQ2s3XAbcZLVrDkG3ScHffE105UiSFXNY/F+crCEM
         +5+eBN1YJ6atmCQd02iUNjGRopzjKYmyqbfx+DY2kzHfWDGisYN5piBzPIUbKnjkJbtk
         7ZWA==
X-Gm-Message-State: AOAM531/38vaLxkcTwZJwPPaCG1IR89H5g/WW0AxCn0GzmQCICgOfZ9S
	REYMNAVCWHToA8oiH0Z7xgQ=
X-Google-Smtp-Source: ABdhPJzxu+q8BK9pLmc163aSm7iE+Tgt0KA3al3Lwosw5NXu4tydXsYASeETriMhXW3DrtcualSKeg==
X-Received: by 2002:a2e:7f10:: with SMTP id a16mr1465714ljd.48.1644286589573;
        Mon, 07 Feb 2022 18:16:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls6826151lfr.1.gmail; Mon, 07 Feb
 2022 18:16:28 -0800 (PST)
X-Received: by 2002:a19:f014:: with SMTP id p20mr1567868lfc.68.1644286588572;
        Mon, 07 Feb 2022 18:16:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644286588; cv=none;
        d=google.com; s=arc-20160816;
        b=SCCZ3kN5dPUJfs/RldVZkGbLSmUlfpoXIPWKuxBFIIyEBiMiB98BCFh3M0RzyztC4P
         gVTRq+T1anw5t7NNPx5mzy7lQrtnujC3UL76cqtGgJQ2PyXak6rbqHxS62A5XBbjhCGI
         lZXyNWw6yfgMeK4zwTXqgxxcYOI8UsA/jF6IZKeH8SlmpNlWH4yhyw0xYgj+Mo59N5Ug
         JEIkTehFXn0lW/DRPk3ilJT9h7NCJ+SMErWs9PcKm9nMoHgPGvHsBMJgWRbyTQCUetPJ
         j/HR6qVC99jP/pDzo1Nwcj2TlojK0INBL5Snjc2QQfECq1C+PqGchj2fTjhZocHM/8W5
         DfPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pO7I7nK4McHm1CFdvaegV9HUAp48DVdwilqK64U5UCE=;
        b=hf1pgP/Y7Fw3isCI7DD+7W8NpxFYrZU6YyNLtFrxBRLLKvBj1bH4ZzAiRDt2p2bj5S
         ykt3hHDvz4hzdiT6TJCGLPnIxDiW1GftNNJY7lrVKIq9OP0sQ57xb8EZ6TTun2FHSQEN
         owvPF0F5dzhkg9GXIFlA/VEJyl9dN3QKwNHYs6n/N5Rd0WMho0RoIl6B2fQkl42kABUh
         1vClVKIuWPD+VWB6OX86ljVXFI5X8j3j1g3vJyTfANQrAE3dBHJ130mxSGTk/9jfaRsQ
         wLQi8iYsxTEsGuUajAfDNOGY5j4pKo3+VsGjih3+5hn3xezAjYfwC0iplzuNe8oLbAsy
         e1cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QDVZNEai;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id x16si546295lfr.10.2022.02.07.18.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 18:16:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id s7so7626648edd.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 18:16:28 -0800 (PST)
X-Received: by 2002:aa7:d297:: with SMTP id w23mr2211700edq.313.1644286587831;
 Mon, 07 Feb 2022 18:16:27 -0800 (PST)
MIME-Version: 1.0
References: <20220207211144.1948690-1-ribalda@chromium.org>
In-Reply-To: <20220207211144.1948690-1-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 18:16:16 -0800
Message-ID: <CAGS_qxoO6HFXZjpm689gfHVwFj=ViWya=opY0FLMf7FDQOoS5Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QDVZNEai;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Mon, Feb 7, 2022 at 1:11 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Today, when we want to check if a pointer is NULL and not ERR we have
> two options:
>
> KUNIT_EXPECT_TRUE(test, ptr == NULL);
>
> or
>
> KUNIT_EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);
>
> Create a new set of macros that take care of NULL checks.
>
> Reviewed-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> ---
>  include/kunit/test.h | 88 ++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 88 insertions(+)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 00b9ff7783ab..340169723669 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -1218,6 +1218,50 @@ do {                                                                            \
>                                    fmt,                                        \
>                                    ##__VA_ARGS__)
>
> +/**
> + * KUNIT_EXPECT_NULL() - Expects that @ptr is null.
> + * @test: The test context object.
> + * @ptr: an arbitrary pointer.
> + *
> + * Sets an expectation that the value that @ptr evaluates to is null. This is
> + * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, ptr, NULL).
> + * See KUNIT_EXPECT_TRUE() for more information.
> + */
> +#define KUNIT_EXPECT_NULL(test, ptr)                                          \
> +       KUNIT_EXPECT_PTR_EQ_MSG(test,                                          \
> +                               ptr,                                           \
> +                               NULL,                                  \
> +                               NULL)
> +
> +#define KUNIT_EXPECT_NULL_MSG(test, ptr, fmt, ...)                            \
> +       KUNIT_BINARY_PTR_ASSERTION(test,                                       \
> +                                  KUNIT_EXPECTATION,                          \
> +                                  ptr, ==, NULL,                              \
> +                                  fmt,                                        \
> +                                  ##__VA_ARGS__)

Sorry, I mentally skipped over this even while reading over it several times.
Not sure how. My brain just mentally rewrote it to what I was expecting.

I see you copy-pasted KUNIT_EXPECT_PTR_EQ() and then did s/right/NULL.
It works, but...

These macros would be more in line with their counterparts if we instead did

#define KUNIT_EXPECT_NULL(test, ptr) \
  KUNIT_EXPECT_NULL_MSG(test, ptr, NULL)

instead of having it go through *PTR_EQ_MSG()

> +
> +/**
> + * KUNIT_EXPECT_NOT_NULL() - Expects that @ptr is not null.
> + * @test: The test context object.
> + * @ptr: an arbitrary pointer.
> + *
> + * Sets an expectation that the value that @ptr evaluates to is not null. This
> + * is semantically equivalent to KUNIT_EXPECT_PTR_NE(@test, ptr, NULL).
> + * See KUNIT_EXPECT_TRUE() for more information.
> + */
> +#define KUNIT_EXPECT_NOT_NULL(test, ptr)                                      \
> +       KUNIT_EXPECT_PTR_NE_MSG(test,                                          \
> +                               ptr,                                           \
> +                               NULL,                                          \
> +                               NULL)

ditto here, KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, NULL) would be more consistent.

> +
> +#define KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, fmt, ...)                        \
> +       KUNIT_BINARY_PTR_ASSERTION(test,                                       \
> +                                  KUNIT_EXPECTATION,                          \
> +                                  ptr, !=, NULL,                              \
> +                                  fmt,                                        \
> +                                  ##__VA_ARGS__)
> +
>  /**
>   * KUNIT_EXPECT_NOT_ERR_OR_NULL() - Expects that @ptr is not null and not err.
>   * @test: The test context object.
> @@ -1485,6 +1529,50 @@ do {                                                                            \
>                                    fmt,                                        \
>                                    ##__VA_ARGS__)
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
> +       KUNIT_ASSERT_PTR_EQ_MSG(test,                                          \
> +                               ptr,                                           \
> +                               NULL,                                          \
> +                               NULL)
> +
> +#define KUNIT_ASSERT_NULL_MSG(test, ptr, fmt, ...) \
> +       KUNIT_BINARY_PTR_ASSERTION(test,                                       \
> +                                  KUNIT_ASSERTION,                            \
> +                                  ptr, ==, NULL,                              \
> +                                  fmt,                                        \
> +                                  ##__VA_ARGS__)
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
> +       KUNIT_ASSERT_PTR_NE_MSG(test,                                          \
> +                               ptr,                                           \
> +                               NULL,                                          \
> +                               NULL)
> +
> +#define KUNIT_ASSERT_NOT_NULL_MSG(test, ptr, fmt, ...) \
> +       KUNIT_BINARY_PTR_ASSERTION(test,                                       \
> +                                  KUNIT_ASSERTION,                            \
> +                                  ptr, !=, NULL,                              \
> +                                  fmt,                                        \
> +                                  ##__VA_ARGS__)
> +
>  /**
>   * KUNIT_ASSERT_NOT_ERR_OR_NULL() - Assertion that @ptr is not null and not err.
>   * @test: The test context object.
> --
> 2.35.0.263.gb82422642f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxoO6HFXZjpm689gfHVwFj%3DViWya%3DopY0FLMf7FDQOoS5Q%40mail.gmail.com.
