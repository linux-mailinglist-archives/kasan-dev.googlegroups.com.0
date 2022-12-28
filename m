Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR7CWKOQMGQEUQRZMLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id ADADD6586ED
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Dec 2022 22:12:43 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id w18-20020ab05a92000000b00419da160be9sf6050467uae.15
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Dec 2022 13:12:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672261959; cv=pass;
        d=google.com; s=arc-20160816;
        b=jMPBPyDt1pBbpCzmpx4CLzzL9a4ooQDADwHMnV5jFVARFRZeoE+EHp/8TdWX4s2f1E
         yDkc0hHyPqH3Jy5VT2deyP97Yq+s36uxoiSpToOicqBoZ5WuRB7/YE4+atcdmnNRmlr0
         gZZ9ktBoc0HDmiuOuAhMtWLpjQ4tUbIK2uXP758s7VD3EajQ+TKxzL8m8sJEJv31i+Hs
         iTmVVfRSvnf8Mw0RfqAhh1dL9kG7SRDB78YmaGscmiKW3w3dmzZslTazRZqb4l8Sf1+G
         3MumwZagniYmdUcMPYFMW5NdVV8mOIRPfSaOhn7L7ln1REeKinrOpkcoXJMDYBOjI0aN
         lEZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HVcNM2jC8r/EaW6OLx9X20sp8YkvyWucGubCypRiozY=;
        b=obXbNw4TIGfdR5GY37g3KYjKgX7MGQc3y5D05Xea1PdabkkfPvLn+vnYzArh7gkeE2
         oWKACfwV4vI/vy+aQXbjAisyMXoPO+FsBmpEVlksuGzySbuOGgFFiuLroQwp1kgcu2Ym
         DM2rvaFj/KFcuIcfpEAuOzmyUpPRPaompr76mU8cDReDZ1SpZm/sDGjuNpT0GRYwMxPW
         aWgNmOafGyHTBXDaJYhGaK+Ex7uzAukDlFUqYxuYFulp2AkMp885vMYFM0CDGTI67rKX
         N6SO5CuSKbuE61DbN0AKI9wiwl3ky1N1X2RdM2pHVYTaAgPwVJWKBDfB5xg8svAqTzT5
         cpwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ih97jiTj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HVcNM2jC8r/EaW6OLx9X20sp8YkvyWucGubCypRiozY=;
        b=jP4I0+4mHPpkp+ZTaZOiFgde6YwBID4lZlI7LCt4Y+3Wei4rmpBaZrfpzv8ceThm89
         MZbJ3MOtPwKtFOR1E+9tuSItTks2ElBV5ksGQgUPLCuSp0cE7iWnELKXEUtb5VOzUhHN
         nmk3VRmmEElRZ9oYkr89/qXRiY6QUDqtyLhZokbAuCg7y+dEv6rDXUMic13fn0pm/38R
         WuT+jbwywn/RDOCHDOI5CzdHze+Zlf0Q0Ru09Zrs+Y7eGrTcnA/ZZzeVyWAmHAKVMSnv
         ELj8rNPGr5hsE7V9bnOz4njwXPaGkxcXCv2jOEfkiOIqHq7Wc4TqbYO/dcP/fOkifs+D
         HT4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HVcNM2jC8r/EaW6OLx9X20sp8YkvyWucGubCypRiozY=;
        b=EVfApu+aOUoQaIaFbFU+pRwx0lhIhGrzmianesJovHzDQQITiSUkZHI35vcrAJmKie
         n1B0+YCsCuoT/qTrN44w6xRXuGVseeTGpC7eRD3P3skGkajcISD1QcvxXpZWdO35+H41
         uso3J61m/meyVoqaQHxclj9siXBbbBqse4qa+75UzQDtXBCAiOpuhQKperFArf6x5MCM
         r6aeLzwUMBvJjUHJN2Oj8m1oDff+qkBG96wxzHoHDcmO7lfNI3vp1JaXsS6ohwS0PzSV
         bdQGtvqD1RY0ZGkvv6WHAIjo1mxRWGnGw2aR10gYZpplrLC3JrVKcTLz3QG2hGp8Ig1C
         g5XQ==
X-Gm-Message-State: AFqh2ko5gvkIqYpt/FqIQDhbH/XwQ2FfZOvCZYjyxQM0TKHLhIIkEGw2
	E0OQSer2zRI/hwqJUSrt+CE=
X-Google-Smtp-Source: AMrXdXupyWls26SgphXEc0XncQSh4J6IyO/iOJrzkki5bTtFEKnHAgNG3s0R4J9RxfO6j20lbD0cNQ==
X-Received: by 2002:a05:6102:c8b:b0:3b2:ebc9:6307 with SMTP id f11-20020a0561020c8b00b003b2ebc96307mr3287100vst.73.1672261959451;
        Wed, 28 Dec 2022 13:12:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3106:0:b0:3d2:6934:6234 with SMTP id x6-20020a1f3106000000b003d269346234ls2350763vkx.1.-pod-prod-gmail;
 Wed, 28 Dec 2022 13:12:38 -0800 (PST)
X-Received: by 2002:a1f:de87:0:b0:3d5:7838:1f30 with SMTP id v129-20020a1fde87000000b003d578381f30mr3133235vkg.14.1672261958762;
        Wed, 28 Dec 2022 13:12:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672261958; cv=none;
        d=google.com; s=arc-20160816;
        b=nwkwSvkbS2ioa/GbeX2En119e7IFlxR+i2F8JW85NAs/z4NBrQ2rPW4F1rNjk9zveG
         SetcX74bpYUh23XB0K5zAxr4flGC7nAFSR/A3xaUYai7NZx/gvmKwML4ltPaZUCPRhLw
         cTbQpbc8XRS7p5iSjBfdT1T388j0C9M+hrsR2x+kUoDaZvBxvT+TTGijJoqH6NakoOcK
         yS5Ni0LtVHvNvtJMTd4/cjL0+e+uQ3y/DhAEAt3PKEXkU/Dk7GvAEr/2MSDrIuctYlsC
         a/xYne5ipvHZ56wBKm5yzrPwINReyWlfTPDH49cMXVeODpfHOIrmU6uUSK8e64Gc8iqN
         PMOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+7ooGxz+slyS/E6q6mPR6pfactn5WEBlXeWzI+mnkNI=;
        b=Cg51FvaJI3a/QscGeyZNuKPDsuo5x0GBsgJjgQ8PYOJSxI05xqCdosCiAN9aICVRke
         9Ri2tB17EjkS8WLg9vqHAXcJHW25bx0o7RK+MkVSQlfOmoYeUdWeMoY9/aqCMzXKTP7J
         xEZz7PWCZkuUrdgAPVHTR3cRHryYnE9HM+fFFBTzWUEvY3px7Ha71KjmSZBdKWbpm3Pe
         h6FVhfOD5ELwztFVd9b6nS+z8wJ2SeG+WrHVkCgOAJpnUlPpUo+otSlcnVyYAn6HUk/+
         eau0h6B47Pq6spPVkM37Y0FxDBhsuwkvyRY0HgeWyeXGf4NZzOCu35f3pPCCDA1KTufJ
         RWtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ih97jiTj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id r131-20020a1f2b89000000b003b87d0d4e7bsi1191211vkr.1.2022.12.28.13.12.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Dec 2022 13:12:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-45c11d1bfc8so236859817b3.9
        for <kasan-dev@googlegroups.com>; Wed, 28 Dec 2022 13:12:38 -0800 (PST)
X-Received: by 2002:a0d:d5cf:0:b0:3dd:b7d7:ae7e with SMTP id
 x198-20020a0dd5cf000000b003ddb7d7ae7emr2597695ywd.11.1672261958348; Wed, 28
 Dec 2022 13:12:38 -0800 (PST)
MIME-Version: 1.0
References: <20221223074238.4092772-1-jcmvbkbc@gmail.com>
In-Reply-To: <20221223074238.4092772-1-jcmvbkbc@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Dec 2022 22:12:01 +0100
Message-ID: <CANpmjNOs6vyX+y0XuNaz5J=8p1yKxfsWcNGL=vA1Dzjua=fsYg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: don't put the expect array on the stack
To: Max Filippov <jcmvbkbc@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-xtensa@linux-xtensa.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ih97jiTj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as
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

On Fri, 23 Dec 2022 at 08:42, Max Filippov <jcmvbkbc@gmail.com> wrote:
>
> Size of the 'expect' array in the __report_matches is 1536 bytes, which
> is exactly the default frame size warning limit of the xtensa
> architecture.
> As a result allmodconfig xtensa kernel builds with the gcc that does not
> support the compiler plugins (which otherwise would push the said
> warning limit to 2K) fail with the following message:
>
>   kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
>     is larger than 1536 bytes
>
> Fix it by dynamically alocating the 'expect' array.
>
> Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
> ---
>  kernel/kcsan/kcsan_test.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index dcec1b743c69..af62ec51bd5f 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -159,7 +159,7 @@ static bool __report_matches(const struct expect_report *r)
>         const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
>         bool ret = false;
>         unsigned long flags;
> -       typeof(observed.lines) expect;
> +       typeof(*observed.lines) *expect;
>         const char *end;
>         char *cur;
>         int i;
> @@ -168,6 +168,10 @@ static bool __report_matches(const struct expect_report *r)
>         if (!report_available())
>                 return false;
>
> +       expect = kmalloc(sizeof(observed.lines), GFP_KERNEL);
> +       if (!expect)

WARN_ON(), because this may either spuriously fail or pass a test
case, and we'd want to know about that.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOs6vyX%2By0XuNaz5J%3D8p1yKxfsWcNGL%3DvA1Dzjua%3DfsYg%40mail.gmail.com.
