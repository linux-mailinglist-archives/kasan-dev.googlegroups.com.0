Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBZ7MQ2IAMGQE3SVKW6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9DA4ACCB7
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:16:40 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id o25-20020a05651205d900b0043e6c10892bsf4580502lfo.14
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644279400; cv=pass;
        d=google.com; s=arc-20160816;
        b=PRnc5Yqq11QpM6OVO/S5YPLY/jvMToKi+htO1iOxqVND+1Vd/NvvXfV9a2Wz8OQ8ge
         CFLIKJ4RSPdEluMNTPKAA746zS5VS+kqw5f5SbHmRn1KzHn2hQWjd5WNY33NKA39QO6p
         1cdGHzr6KzhYxCMRTcMdEAHx3jvk+lYWr8rWILgfzBxoZoSqkqifrZiCFkIVTSsBooXq
         yZ7xQpkj7Klq00wbL2RzeszWWVq0q1uzuX6vU03qZv5RZ/J0SF7FHBXWsHWTMf6yV6kP
         mEFxQqG54+dzAjNEiIduWrmN5mXOoelVQCz4m03UKlaKSU6rqyRf/OrXxP2Apr9/30OG
         DCQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Iq+UdVmaFJD2EGAL+eSbN8qtK6wuHIayT7YrueOftQ=;
        b=KJWByFV4/bEGfyBxepmpm5HpGAuiFXBReCghWwK6MRDCYhVte+ehFJyWzrIJW/LI/3
         YbnQi6aRjVc7E+ajW9jy6b82TQ4TcUOFFIX0+aLoMp96Ccosd7NFA6YCVs6ZPQGFj59E
         tMoRSZZOfeELseQyY2Aszbn+yTJ4iIeL/onFSSw+bNUEyDKG3JPKSm/Sthn2M8chw2en
         tIREjesr/HhigKVfWJn8AE24CmIA8IEffBhNKP6XXQceEva/pXxR19AQIFHvab0drNL3
         L+jcGv4yNqvS+KOWJPIRUQzdnfliFKmZr9V8DTE0rUJOnmEX0z3t5Wpug1vYWst4qrxX
         0maw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cW4AAOG6;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Iq+UdVmaFJD2EGAL+eSbN8qtK6wuHIayT7YrueOftQ=;
        b=p0vT9vzcJwU8eGtw6P/105Sf2JXQDXLCn2pvfZJ+bAjG0DqjNq/DrtLKYXQL7jiztv
         3hVF8baQl885GRdoljYT1Tq1oeLq02N14gt9BXdUPYoHSUE0ghDS7YiPvFHue21D2p1E
         /uPi/eR/BuojvvGwx3txfOgMvXazfC2wJgKgRbAd69XuSdiMWeWXYJbR1qtvWvxuEjX9
         3K5hrj4TGOMNfg8ur39V/FKhBWcETenYh5s7yMkr9qnbMF77m8ERtkQXHXcIS9b7k87A
         uRWBDbq3eOBH/0s8OtxRI+RBp6HhvAxOZQ9Z6JIs1EtePvQpHtvajdom9h/QJxf8d/nU
         7q7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Iq+UdVmaFJD2EGAL+eSbN8qtK6wuHIayT7YrueOftQ=;
        b=5JxM7fS9McJITOrehpTXBk9BXq3sTXnNDO1yP9C6KoQXPrbdhnOC5ZLfxfgrpCWveB
         vhryByFQ1jMG2SzWGCnIu9D5yyx0hiYMe88JzTA4M6bZMy2uw6m/YVS04Hh5Mtbi2eM+
         mz9EbywSF5x1kkfuJn67IjYWr30O9pdwc3ytqVCqmWez559Vtpcb8PNPr9Jb13uUiC3b
         rqJInABCc1Os7Qx4rxklVxsoHCBaeZ+HKp44nlZzH/T9a5KIDkXIycK2XJna+WMSV2TG
         b4jh5oNftNnMtKT2tp5gV5+gfjbgZL49H2nt209OvYitq+P2EXS7jSBpTbI1otLmgsxD
         9kOA==
X-Gm-Message-State: AOAM532lGOTjNSHRiORO3iNdiZ+XlQUKtm8NvL2cAI22Hqi74d+jKWfS
	IOBVJDogcz7w5yFNwdrj5VI=
X-Google-Smtp-Source: ABdhPJyqiEAntG8nMXHctg1eqUc6p57facC7gHV2LuHmT8LnXxLFNLZ1vTrZLlUiXdngBAAM5zLA/w==
X-Received: by 2002:a19:7413:: with SMTP id v19mr1292899lfe.250.1644279400129;
        Mon, 07 Feb 2022 16:16:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls6691163lfr.1.gmail; Mon, 07 Feb
 2022 16:16:39 -0800 (PST)
X-Received: by 2002:a05:6512:3991:: with SMTP id j17mr1319266lfu.602.1644279399190;
        Mon, 07 Feb 2022 16:16:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644279399; cv=none;
        d=google.com; s=arc-20160816;
        b=qGKDpJ4IEz7fHjCWFfIvZjuS0vR/KZGq6z9C+Zpzmv0dhkJtwpsSUQxzio/fu67/LU
         Vjy65PQ04kBkmOJgPt+Y5YQPTwVjd+W6Kxbi+zgaM3BvVUJQHghahK+/zznLy0uTrFvL
         PdNcpnexttmLoH6uYMKT5DL349DPNedxfpaV57k+fFmo6qWItV8jzccDj6XYDp1N/64h
         iRwoS+V2tHysP2md7AmC5fUMG91ftrY+uEtzrxu8WOJoqzr39Q5P4CDFtQcuq677ox8Q
         m0g3sDWI4h+bOVc4fylDhAYXxdUM2As6dj/gZ/EJmX4ZGx8A8YVMqAHB5N4gYYGP27Do
         HhlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2FUC6ZAqrJKqRqsz2dka0HA9ZqAZrYwhb0gCpwv/n5I=;
        b=sZ0m3STfe7eIsul+OEdIzwRpuH1Duwb764scd+Tf6N8StZzw03eYDBc1TRcu2Em5Fd
         e/30H3SPbaLPXqXU8C/dlr5ALVQiYthhd7KixzMXxmtRIdwr7rdYw1pbRagcvt4ebva5
         FK/zr/GJ3cy2L2zMcpfR8wbSXTjTNli+CJ9HJf8dUUoDMvOvCwsMTdUNZtG9uZdn6ibI
         1W2HZWhtkgCWdWc2CZXpP6Pi2e8U9mr8bQtDl7xnG6UjzjgkrZzfhdp+q1c0IsGZeNXG
         hD9aSCyusdlz/Iaa5xZLTDtYhrfKnKzTY9apYRvzQCYWUsvfo4P7ltTDXerH5Q8+aBm7
         i3GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cW4AAOG6;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id d4si66545lfs.13.2022.02.07.16.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:16:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id w14so33837955edd.10
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:16:39 -0800 (PST)
X-Received: by 2002:a05:6402:42d4:: with SMTP id i20mr1961564edc.306.1644279398782;
 Mon, 07 Feb 2022 16:16:38 -0800 (PST)
MIME-Version: 1.0
References: <20220207211144.1948690-1-ribalda@chromium.org> <20220207211144.1948690-5-ribalda@chromium.org>
In-Reply-To: <20220207211144.1948690-5-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 16:16:27 -0800
Message-ID: <CAGS_qxqYVagWo=CWBmYvhnsFU7=mcELzkKLsB3_VO-rgPxqu0A@mail.gmail.com>
Subject: Re: [PATCH v3 5/6] mctp: test: Use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cW4AAOG6;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::535
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
> Replace the PTR_EQ NULL checks wit the NULL macros. More idiomatic and
> specific.
>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Daniel Latypov <dlatypov@google.com>

> ---
>  net/mctp/test/route-test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/net/mctp/test/route-test.c b/net/mctp/test/route-test.c
> index 750f9f9b4daf..eb70b524c78e 100644
> --- a/net/mctp/test/route-test.c
> +++ b/net/mctp/test/route-test.c
> @@ -361,7 +361,7 @@ static void mctp_test_route_input_sk(struct kunit *test)
>         } else {
>                 KUNIT_EXPECT_NE(test, rc, 0);
>                 skb2 = skb_recv_datagram(sock->sk, 0, 1, &rc);
> -               KUNIT_EXPECT_PTR_EQ(test, skb2, NULL);
> +               KUNIT_EXPECT_NULL(test, skb2);
>         }
>
>         __mctp_route_test_fini(test, dev, rt, sock);
> @@ -430,7 +430,7 @@ static void mctp_test_route_input_sk_reasm(struct kunit *test)
>                 skb_free_datagram(sock->sk, skb2);
>
>         } else {
> -               KUNIT_EXPECT_PTR_EQ(test, skb2, NULL);
> +               KUNIT_EXPECT_NULL(test, skb2);
>         }
>
>         __mctp_route_test_fini(test, dev, rt, sock);
> --
> 2.35.0.263.gb82422642f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxqYVagWo%3DCWBmYvhnsFU7%3DmcELzkKLsB3_VO-rgPxqu0A%40mail.gmail.com.
