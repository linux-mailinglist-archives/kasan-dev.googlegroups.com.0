Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBTEMQ2IAMGQE4OE4ULA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 71A784ACABE
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:51:25 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id v185-20020a1cacc2000000b0034906580813sf145436wme.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:51:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644267085; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+k9dF5FYK85f8QI5rn6mVeDed2FKVGA3V9MoUSQnNR/wJcjV0NYIkSNXmAcvq6Z0T
         CyKpgUQQDYgTnGtqLiHXDPC/VAyu9BviFwevnQJNvor6qJdxyI+K18IJzEc7z49sHeOT
         nnJczAuF+Vn7dJYGFr4V/UhF4REVbmnGwEPTrlHHN0JnRAbRD4xh6t4UVa2nEDKSWUEM
         cydG+Eb+6Hmsr1whhCcGhbSrGAocYV/pgjK/so4lh4hrh61e0N22GHsOjUbIdCKDDE2m
         CFl1LHAYt9rx7OjinoiBnY2Ae0xFve3NM96UHCbAqotlm233seYli6E+aas4OS8yCgQ9
         ujJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e0stwhn0iPvQ5vFj2ZUuh3s6Yzfz1AIhIhspUxmV5L8=;
        b=pLxwESaXwBdQZQC6PxM0W3AlApdGQzU3kkqeUEULSTHSsghf7zcw4VmXnNiXdm3j68
         84VRYGtwieluabe4l3dLns8EasDC7gD/FskFwCg5vv3cuTWOYORHrFb7U70cnGYuepA6
         8TyNH08+KZaeJvBVo7PCGIDP7fM+svyLrb4wcFo/7hM66GRaCm0Mu7kju635C8voypb4
         wNa20PtPEAwK71PCYJbJu0g1iV9vXbtU8PvOM7rHMtunfZAaki8GXrHapv+c1R/IB4nj
         opENuVuWg/Y4NT28v6dIst767WRNx/KNLQWBScMUgawZO9s7KjqZW/Q/cC1A/qTwYxiS
         otuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mS6jSDKY;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0stwhn0iPvQ5vFj2ZUuh3s6Yzfz1AIhIhspUxmV5L8=;
        b=j9l7Q9+xTJ/Ec6eYBeNHIY8qsMQWMLXnQkuTX7kwHyNTEONX3QWNwK5Ax86QmvCel9
         PsoT46kM8eadCfsSdKbn86yzaUjmA3KYQorUHO4n2gRFCER29Ti00y3z2X7l8fzZkb2u
         sQskJpkUaOUwWnSt4GbIVa748Wj05/W41+93Bbwi7w/QVwYa2qU+FjR0Y1mLwg7me2ak
         suRmlLNz7H1ywn0cseHcPZEsxfF83PfkDTpy4xyBCGS2iqbJBm9+T25bmLCHPrG3wpMX
         ZhZS/DvAvqVpAt9YQMRMnu61f+yGRx9KDSiSWDes/S8BdPIhnQzdDFgOVnHL7ZMmuV82
         Yjgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0stwhn0iPvQ5vFj2ZUuh3s6Yzfz1AIhIhspUxmV5L8=;
        b=8Mk6HlybX13fOSXj0SvKy2m7BBbIOYLgKP93qpDGvAPVv37c4LWpsE8xsVCTOKKetB
         +KOekOa0wvxLLziW35mS84jPtRyG5PvqG59Kb4CNtGdCW3agNxFodkxCN1oMeC6M+NeF
         5KiYVQYdQutqHt8CO4SyvpXQ5oe+bDPM+T9A7NGHOFtu0MlXCF1SFrcWZG1psUBypZ5H
         HBHLtramw/UIhWuUuSd/zhcX4bsVZo5XWItBulw/xfDfDjrZ+PO/dS97QErq//j4pTEn
         rW8CDVYEUmewG0pnUMuUXGd/a6v7PdULtFbmMtz7WMGrXP17Dh3xw+r7J71SfKgePNIo
         umLA==
X-Gm-Message-State: AOAM530ecHSBKIRZx4JwghN7KFppIl+zrKAtz0BwQCVbIqsUEhAqT32v
	QocO/vnTU6LrVy6ms76nFao=
X-Google-Smtp-Source: ABdhPJxgMFKMvW4bNfmDGsB2495mpG1LghBGZ1r4xx9A7oWSptOrpAqOg1CNRD0KJW28n/e7g5kfoQ==
X-Received: by 2002:a5d:4dc7:: with SMTP id f7mr928380wru.629.1644267085081;
        Mon, 07 Feb 2022 12:51:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3487:: with SMTP id a7ls184844wmq.2.canary-gmail;
 Mon, 07 Feb 2022 12:51:24 -0800 (PST)
X-Received: by 2002:a7b:c202:: with SMTP id x2mr555619wmi.80.1644267084231;
        Mon, 07 Feb 2022 12:51:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644267084; cv=none;
        d=google.com; s=arc-20160816;
        b=TTUA5xB+SzBU/9q5FWoouG2zcJPTwolsTlzgMMGX8MlJ61pw9BAbWa6dBYBjj4VtJD
         r6Q8fFSB5+RLLwsqoUyvNpvcF1uAUQWmOAJnegZnl3gVUPqz97feMB9RDnaWfeIrqGHh
         Puzjt7eLl4TwQaKJOho9EkV+F5r7ap6FJ5hChfxDqw2Q3NEyEwdqtnYNl5LzgWCkhmV9
         SSQLMdO662JtwE0tiQ9J+WicPEkCwAPKKJYWuF4EsPzwSr/R8mqLY1jqZxw15F/ZlNwS
         1+r43bwWtOx6psDYYqdSacYKrFXZa0u6AqWIh+roBTbefjN3ZwxhfmWNdgH5fwZt99bb
         EdkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZNlSwKrPwSead3UlRii3n77Lkm90XPxm3oVtpWfrGKc=;
        b=rA4fthM4IxuFCKrivVPHXfhAVmgYuoWaIqTzQSdIxZ7q+MCqv9fBjSxbA7EPdpZ3XA
         g5b7j5qXRI9LZhnMB53rYh1UCV6DHukWjYXkKBDBr9WYrmIwafZLXsDB09advSmbKeir
         Ms1cWeS/3d3/Oc1MERgKWaU2B0Zj23x6L0V78hYb/o1l7LfTnyqv9S2XmSs7wIOc/J2q
         P5dZkh7FFCJDYb/i+LDGGGbHqcrdwQr/lms5Hdgw6UljkSCfV5TTrJK7IVtZK/7n9PxV
         WmH+e/dFbrAgoz7BTr4HQrB9W3k34XNKG3T7YwvemWKWq2T4PLUmlDUoKVsDF87HxgD/
         P3ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mS6jSDKY;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ba13si357142wrb.3.2022.02.07.12.51.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:51:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id b13so32814637edn.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:51:24 -0800 (PST)
X-Received: by 2002:aa7:c155:: with SMTP id r21mr1254502edp.327.1644267083805;
 Mon, 07 Feb 2022 12:51:23 -0800 (PST)
MIME-Version: 1.0
References: <20220207202714.1890024-1-ribalda@chromium.org>
In-Reply-To: <20220207202714.1890024-1-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 12:51:12 -0800
Message-ID: <CAGS_qxoMTqpGW9EwSbgTafKRbTdG+kaTw+Ea6BfbzMHRiCN=FA@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mS6jSDKY;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::534
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

On Mon, Feb 7, 2022 at 12:27 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Today, when we want to check if a pointer is NULL and not ERR we have
> two options:
>
> EXPECT_TRUE(test, ptr == NULL);
>
> or
>
> EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);

Reviewed-by: Daniel Latypov <dlatypov@google.com>

Sorry, some minor nits I forgot to include in my previous mail:

minor nit: perhaps KUNIT_EXPECT_TRUE(...)
I don't think most people would be confused by this, but if we send a
v3, might be good to be more precise.

>
> Create a new set of macros that take care of NULL checks.
>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> ---
>  include/kunit/test.h | 88 ++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 88 insertions(+)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 00b9ff7783ab..5970d3a0e4af 100644
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
> + * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, NULL, ptr).
> + * See KUNIT_EXPECT_TRUE() for more information.
> + */
> +#define KUNIT_EXPECT_NULL(test, ptr)                                          \
> +       KUNIT_EXPECT_PTR_EQ_MSG(test,                                          \
> +                               (typeof(ptr))NULL,                             \

First point: hmm, I dropped the (typeof(ptr)) casting and didn't have
any build warnings.
So I don't think the cast is strictly necessary.
We use this value in the comparison (left == right) and when we store
them in the assert struct.
The former is fine since `myptr == NULL` is valid, and the latter is
fine since we store both left/right as `void *` in the end.

It does have the benefit of making the comparison operand more
distinct from the NULL `msg` parameter, however.
I personally would lean towards dropping it still.
A bit less to read, and it also generates less code after the
preprocessing step.

Second point: I think it might be more natural to have the NULL be the
`right` parameter.

Right now we get
      Expected ((void *)0) == test, but
        ((void *)0) == 0000000000000000
        test == 00000000a1803d18

I think it's a bit more natural for the user to see the expression
they provided first, i.e.
    Expected test == ((void *)0), but
        test == 00000000a1003d18
        ((void *)0) == 0000000000000000

If we do flip the order, let's remember to update the comments as
well, the "semantically equivalent to" bit.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxoMTqpGW9EwSbgTafKRbTdG%2BkaTw%2BEa6BfbzMHRiCN%3DFA%40mail.gmail.com.
