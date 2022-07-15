Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBK5CY2LAMGQEWVH4CUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 937B6576519
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 18:09:16 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id t13-20020adfe10d000000b0021bae3def1esf1246313wrz.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 09:09:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657901356; cv=pass;
        d=google.com; s=arc-20160816;
        b=F4AmCRF0IXtHeaOucVdmlBzIqKUqoQJ0i3dvSGKjSVF1/elsMmcPFaEVLqCzU9mZMA
         DRSJnbdjVeDecCfncfWZdEN/smvMHUj6vWVaNIOONysofa4QoxZLkGrpeTke7j7tj1HX
         zfbW+5qXM5YgLD3x3/3uUG1OVR5hVyQsGVAh9eOWiJpHDtP5RL8ceYiJ09K5jTbhwZ4s
         g1wAZ9GF9kq67ozabHOprYBXyp2z81KlRo6Cw7MbUsRzECCwQIdnGSsIpia7LD11a+hu
         y2DH7xaFe7M+IvHCBmSAXs2i7FO7ua76dSnTJhFXhKhsY0IVanyl+t98oLWSNPfPCIlz
         qDmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4tqqaQcVaWUSM/GiC2JySW26W5VoHClnud/Wj+LHxc0=;
        b=EOhODdt8i2w4qapRyGDqRC4m4dwFkPb13A0P+LrSae7/2JaT3TiXg9k4syn2xlY2Gt
         KYrAo8G+jm3bDxwp9TNAqPtifo1y8i4dKOZRJfnDj3l9TPbaD6Vafj02CCLpRhKYZgyR
         JluXBRkjyYleUbEPT/4ySvqcn6qW3T8O7YxqRXsHmdd7wMoJvkzFcjonkejq52SYGn5e
         8u9nVjmr3ZSzx5MLAtidcPNY/t/PDKdQivZQmvps6mpO8H7/XrTgSBvCwcG2DLg5zf3V
         xUqFoarwYDWkUDh5kH0kvM5hSOnvzjmWFS6RxmCEBktaGbbm9BSwx/bBqOBesq4hG6kA
         2giw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eE19BX8P;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4tqqaQcVaWUSM/GiC2JySW26W5VoHClnud/Wj+LHxc0=;
        b=pTV2+r3efg1mjsVtPhT4BT9rcqdYYLBcbsfsHxlo31vXOyzRg+3uSpWZP6FY7pUSIq
         EpGz8BvkHTrG6Li2vlDyS9LvUcvXgDzUucOv40Z2TwtwoNFrZwC1cTXQamUjpg2q371a
         u3FrQ6J99F9N1ruu2UIyuNK8wRjwKcsvn8tTH/IhHiQyrk/Hum4/kvtaYbvY3TtEpzNm
         UyOBUwe6HySXq3skOBiXNd08yp7pc4FtAdc8SCOtJBvfVuDoG0i+J8mrtdLSyVLAKiDn
         8+MdINoOr25ZLv+r7kSn/3P8K8gNoS4N4o2jDYPfK79mZcZjZk2x8rLtB8hdsKI1+dFu
         Ti9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4tqqaQcVaWUSM/GiC2JySW26W5VoHClnud/Wj+LHxc0=;
        b=2dLq+aMxQ64L8ivv6jWR7D9VACiIYig/KoSjc7yYeJZ2PdzGsno6AzNrEBQqTNDsr5
         w/jCwhYvTnY89KO21+Hga8XDG6pAaCNZytGLDsK4nEnLngNIvL2YPZ3yrPa0wmy2DepH
         bk0NtNfpOmc3Msrh91wWIHV31ruC2qVjowk+J6rVw/pEXIEfWNkEBkaiBdxsnd+ol4/V
         Ml+KS8SKVz+/CPeVMIo5HflOULbLauJJOh8JKwv3udbF5QlovU3qb/2DTcdJIn/nEAhP
         MWqN9U1nxyL3bvmGLHvL3vQj6As79OQYd47ZXEJAwpwv0ydbi7Rmza96NngQjgdVKzkO
         jJww==
X-Gm-Message-State: AJIora/90t69k6qg+qqy+yF3h1AipgpyOTUuaU8Y3GBD6LS2VUN2ozcq
	AVJVdaFzW0c98XQu3+2zhsY=
X-Google-Smtp-Source: AGRyM1uTb6mUK9x4iGVQ0OQtOROHkTq9hblxZ+wtrMTqxA7HU+9jq88lPbqvhZUJNFNS7FhU4svuTQ==
X-Received: by 2002:a1c:1902:0:b0:3a2:ee85:3934 with SMTP id 2-20020a1c1902000000b003a2ee853934mr20312239wmz.31.1657901355869;
        Fri, 15 Jul 2022 09:09:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da7:b0:3a0:3b20:d119 with SMTP id
 p39-20020a05600c1da700b003a03b20d119ls22616063wms.1.canary-gmail; Fri, 15 Jul
 2022 09:09:14 -0700 (PDT)
X-Received: by 2002:a7b:c4d3:0:b0:3a2:aef9:2415 with SMTP id g19-20020a7bc4d3000000b003a2aef92415mr14933677wmk.72.1657901354880;
        Fri, 15 Jul 2022 09:09:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657901354; cv=none;
        d=google.com; s=arc-20160816;
        b=n4a4NihX8U95GAqeAENCpLz4a429iEjWkUGUFBTMJfZLY4d3BWHqMIHYSgJoodBxjr
         tcOMxeyfHHt0ljfBWFihz1J3nMcoNChA1ELe7tBUmHV0ZyDN3uHIp4fURCHvbpjq8eHo
         BAUx2I+1Vnot8y0r0MWRj5qdz+3g4waL8MxwhlyL1/AUbrLEG1Jp03oMMMjR+cP4pp/X
         o/mF3NP6yh6t7wcYnQ77V06sgs8qp1XGN8bgpOZbk5F/u5P7mQOqxbfxhcQ/lxybQNzP
         i7NkcPc9qE013bFaPedd9FcJvw2KU6udOqc1aftvKm6dLxAHJiH0OAoJb0nRrZRUPTii
         84wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bJX3p7X7GOK9qVv2gnItONL7YBZZiTBUGOlCpJZhZxY=;
        b=EogvDUyMz3jp77pfozq5I8JZIezQhj6+BOvwStd7+00zHtcpMKexTp5eIy5eSLY05x
         El23hImK+vJY+oxP/ncl1iMgK6DQuR4ZcsaGuTWueAdfs90i0gHwGLkTcmREHkPgcsYP
         CHz1QK3IG48sZUMVefUQwJSVCCNIXFYbNwTetoiUz40uecy3ZpsEfentgs9LwvSbi0JM
         XZ9jagr4E5PY3TxgI3MJdeNcJ+8RPRqFYxJD+WICmo22C/ACj1GmzaYAV8/zdLl56/6K
         hZGcNxTOKSbCdyTUTmj4Lf3UVT3qurk/4xpt+A7+eJ2g7/72aggTC5Jvl4vC2V4UvAef
         uwsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eE19BX8P;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id p18-20020a05600c1d9200b0039c6559434bsi213083wms.1.2022.07.15.09.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jul 2022 09:09:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id va17so9854412ejb.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 09:09:14 -0700 (PDT)
X-Received: by 2002:a17:906:8a45:b0:72b:31d4:d537 with SMTP id
 gx5-20020a1709068a4500b0072b31d4d537mr14666472ejc.170.1657901354531; Fri, 15
 Jul 2022 09:09:14 -0700 (PDT)
MIME-Version: 1.0
References: <20220715064052.2673958-1-davidgow@google.com>
In-Reply-To: <20220715064052.2673958-1-davidgow@google.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jul 2022 09:09:03 -0700
Message-ID: <CAGS_qxpMJtuqOvOhqXa-dMzvQX_88hnidCPxZhWFVdedxxSfoQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eE19BX8P;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632
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

On Thu, Jul 14, 2022 at 11:41 PM 'David Gow' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
>
> Add a .kunitconfig file, which provides a default, working config for
> running the KCSAN tests. Note that it needs to run on an SMP machine, so
> to run under kunit_tool, the --qemu_args option should be used (on a
> supported architecture, like x86_64). For example:
> ./tools/testing/kunit/kunit.py run --arch=x86_64 --qemu_args='-smp 8'
>                                         --kunitconfig=kernel/kcsan
>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Marco Elver <elver@google.com>
> Acked-by: Brendan Higgins <brendanhiggins@google.com>

Tested-by: Daniel Latypov <dlatypov@google.com>

Ran it and everything worked as expected.
[16:06:34] Testing complete. Ran 141 tests: passed: 140, skipped: 1
[16:06:34] Elapsed time: 70.861s total, 0.002s configuring, 3.519s
building, 67.276s running

Ran again with --kconfig_add=CONFIG_KCSAN_STRICT=y
[16:08:29] Testing complete. Ran 141 tests: passed: 141
[16:08:29] Elapsed time: 83.355s total, 1.557s configuring, 24.188s
building, 57.582s running

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxpMJtuqOvOhqXa-dMzvQX_88hnidCPxZhWFVdedxxSfoQ%40mail.gmail.com.
