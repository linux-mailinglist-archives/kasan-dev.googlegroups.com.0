Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB7PCUKIQMGQE7BYRY2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E87CD4D3096
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 14:54:05 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id z1-20020adfec81000000b001f1f7e7ec99sf786524wrn.17
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 05:54:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646834045; cv=pass;
        d=google.com; s=arc-20160816;
        b=YKQiY4cQfGw/1IvnT+3zTmkploMggOgnaWWFjVVqllJeFhFrz8zBaifv0jVDHO9j8A
         qfB1EdjVcmquQgJZhwLIJ9xH925WTIG0RooHyeR/KQQ/3EyaYCjZysC95qIse4Etqoxw
         Qpayun5tqMOlNzfMfLClRpB/cRIzmiXDMVkd3nzNT+aGQyw2Ai/CjdBlNY9T434aCpyA
         dKX/PaxNxxL/CfNNEmCKaA14NLWQggivd9Xh2odI8JxpFF2BcTrmgekClqctPJ228yDC
         bdn7ZNtc3uAsyURzW1eX2KM0U2PApMPWsMwuogJ2Ix61aP6d1v1bJtOCFIu/MWIiHBaC
         cZww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EHEkgkEfmpjit6PyRwVe8s9S4KYfVo/Lm+FP9hvT2ew=;
        b=kvWFozuCHNJMp3HwYJK2FD4u6Rt0aR9qE4XZqRLNyUG11KsSheWQFPacttjBqONKsT
         sUTObEcI7nzQceZ7Lk6225Kir42Pl9baXkZ8Lcs4SAV4KkXBIRbOdW+hMXeog6XY446u
         d5FpP4jn0U3z28l5ZqgTG/oD9ZWPrLmQYzfLgkUHGg8s48xaG4i0gd6W2NOUQ0qb7W2+
         7RtLzvq4e0ySYZURG28JCIa86+qiLMB6hxd1U151/pvLHq4k04NfKuVVwWDkp9BGpKqH
         NwLHLIsNbzejgSecmNuCirImZvBUUkriRv1+qJ1xKvgaTP6oomkqOAvjw1fhwTPbZ6Kr
         ay3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LYmpyqEh;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHEkgkEfmpjit6PyRwVe8s9S4KYfVo/Lm+FP9hvT2ew=;
        b=LN7ILsdL9u3uCY/RKjG1IuvRjZVBXXwMq6jy9r4aNzF5i+c5dHtb5S97tmULmr7lfJ
         lvOs8ypXCBhxjZ+0GZJS8zi7Gy0ATqe8Ks/67R/jUp9HD6OueUx6+FB7+GsZ9kOohNz+
         bt1VfhG0BZ4bnUtLwl4BHH4qYyBZBezPpcX2TBVF29XYKOtLKv8HmobUPL4WXkZ40ufO
         ibrP9xA2grzrQpF37vDNZwCamcH48i4BYcsauB8aYpwRYwxrALrKyG5w26DZxCUcAoe6
         gZ+mBDXw/vohtoLg3mmyUDFFj4TMp6zrIggGklEQeyokgZZApOxm1ITqrqukCq5ZKHW/
         8Ycg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHEkgkEfmpjit6PyRwVe8s9S4KYfVo/Lm+FP9hvT2ew=;
        b=mBY5x+NFS/WFkoA59qxBGshb0yEXiVaWJXGm2DXdBR2lgeqAW3+F/+i3gFVO+yW9aZ
         FNQ0T6ceoGdW7yJj9a0VdB81Rc9SlHY+BE5E/CodNPftThg8ZyyYgUGLq/dNmpes2aEY
         8IbIGzeeWlI1/PfibvNqTdrGsMTYfyUpJFaNgqCt4S9xo+6aRNoxFCFdg47fmKFKa8bv
         rKUeAHv9NEfTESRVABwlum+6GUpk+1EwqImkm+qwMRhxNfqUwtFDwRSSkOHl+kR57qVg
         jdv16MhiDPrA0mdWOYRGPbwOrH7tnbtXPM/Am2BUNMJZhoCf7VVVzrN/uYWNkDfhL5lN
         xHZw==
X-Gm-Message-State: AOAM531cXnn7q60QthMItOh8+Gk0/OLhlceA+dUHsENsf2+Noicb342+
	827+1zMfz2JQeD5Y93VhKh4=
X-Google-Smtp-Source: ABdhPJx3sOU1z2ib3M2+VpI2KgRzHSbR7UnfxEXt9HPy0o69IYBhj9TSP+UCMbjdEKZ6emadg08KIw==
X-Received: by 2002:a05:600c:4ed0:b0:389:d26a:3fd9 with SMTP id g16-20020a05600c4ed000b00389d26a3fd9mr2259878wmq.186.1646834045473;
        Wed, 09 Mar 2022 05:54:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f0b:b0:37b:e8d3:90a1 with SMTP id
 bd11-20020a05600c1f0b00b0037be8d390a1ls2764902wmb.0.canary-gmail; Wed, 09 Mar
 2022 05:54:04 -0800 (PST)
X-Received: by 2002:a05:600c:501e:b0:389:ab60:2f6e with SMTP id n30-20020a05600c501e00b00389ab602f6emr3419926wmr.2.1646834044613;
        Wed, 09 Mar 2022 05:54:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646834044; cv=none;
        d=google.com; s=arc-20160816;
        b=M2kL1xuHNM2XaB1bkAP0k3Wijfb0wi3PmYKC9d7iCgUsQjU5qKBRrfMyrx8JX2Skif
         MAscSc+hmGvMH5dih747qp+aFbAsGZez8uenKjb4vpq20ekUUJMk2u77z3WsH35yrhd3
         u8UF2hwG31ObezkFDFaiFI8QqRB6x3Qm7Bvh4Q0UWZDtYV/KVYjsQM9Wxev3ZqhwfGRh
         nAOho8Uod1Z/5eWA/q/zvES7/hy7MoTOJZ+DB8pZuh68wd+7W+5ymaPlTseUDrtqrH1F
         v6cr6fSuJWe3fxRu8n6uUArRXCshOWmPYpJCpJwvi9CyTz9/6NnPINIUrndauQ4mXl1K
         5mmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=58ItMAXsny1L+anxiMU9T6c9Palwcv7/9rI4u4RF93Y=;
        b=eUK78ZJq2h+aH1/YfFv89Sc/V97FcdbAtk4IV8zg3ZUE9ZXCcbOY+dz45+t1ZeR111
         1+Us1tOEKUA7quLCfwxkghM1HCYJLfJXmds5wvO3LzQnNavDpa7Kwm7lA5syM8OrCNCn
         YO2PViD8W4fTxh2UMap1xLEHvgyru5SmOHWmWSBa5I6zLFq8Qyma+r50oPW04gqFPCjP
         SoEHTESedjZke2icHVfE4FCQzNQdKUSaMhhLdOyfgyRRftRRQN77g/98KhRQJrUmjgnA
         KSdtjvz9TfEmcHhprt8U9TkyPOaxMTFVCZQBIqtsUxC6DLJeSrxH60Oy3JBtFA4IQWAj
         +9tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LYmpyqEh;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id w15-20020a1cf60f000000b003497ca2a0f8si305278wmc.1.2022.03.09.05.54.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 05:54:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id m12so2909011edc.12
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 05:54:04 -0800 (PST)
X-Received: by 2002:a05:6402:1747:b0:415:ee04:47e1 with SMTP id
 v7-20020a056402174700b00415ee0447e1mr21018226edx.229.1646834044075; Wed, 09
 Mar 2022 05:54:04 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com> <20220309083753.1561921-3-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-3-liupeng256@huawei.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 07:53:52 -0600
Message-ID: <CAGS_qxp_aaWEhuKQ9P897HHndRqbNpdS-vUsJooikQiOXrqL7g@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kunit: make kunit_test_timeout compatible with comment
To: Peng Liu <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, elver@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LYmpyqEh;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52d
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

On Wed, Mar 9, 2022 at 2:19 AM 'Peng Liu' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
>
> In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
> represent 5min. However, it is wrong when dealing with arm64 whose
> default HZ = 250, or some other situations. Use msecs_to_jiffies to
> fix this, and kunit_test_timeout will work as desired.
>
> Fixes: 5f3e06208920 ("kunit: test: add support for test abort")
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Daniel Latypov <dlatypov@google.com>

Thanks for catching this!

> ---
>  lib/kunit/try-catch.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
> index 6b3d4db94077..f7825991d576 100644
> --- a/lib/kunit/try-catch.c
> +++ b/lib/kunit/try-catch.c
> @@ -52,7 +52,7 @@ static unsigned long kunit_test_timeout(void)
>          * If tests timeout due to exceeding sysctl_hung_task_timeout_secs,
>          * the task will be killed and an oops generated.
>          */
> -       return 300 * MSEC_PER_SEC; /* 5 min */
> +       return 300 * msecs_to_jiffies(MSEC_PER_SEC); /* 5 min */
>  }
>
>  void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "KUnit Development" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kunit-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kunit-dev/20220309083753.1561921-3-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxp_aaWEhuKQ9P897HHndRqbNpdS-vUsJooikQiOXrqL7g%40mail.gmail.com.
