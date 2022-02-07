Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBDG5QWIAMGQEECWG5ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 753EF4AC92E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 20:10:05 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id c7-20020a1c3507000000b0034a0dfc86aasf5884wma.6
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 11:10:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644261005; cv=pass;
        d=google.com; s=arc-20160816;
        b=n0UAHVBbqLloZa9QfrTElf0VbuF2mri/vb20ba6A5eu5+kVbiLppANADzt0eTVU0ZX
         /8uSO6snEtyI8wuOx7I1nGYD0RoqOpHwD6hV7NdMgRe15+iayajBGswBlOaS6V1BnrUD
         sLYsfF9ro1pWIif7QA/O2ba23gnNsmsLuLbYKZcGGwP5dgcIGr2uH8463UCGEiMIl812
         6YBAE3LGP/202ru6WdiYGhTNx/QkSPsyH3GRXfkG2SuPmFrcV4lECSXAQ0CCWvCLSq54
         fa8luCONKLxEyKRFsPE4mQosSLmEdPr6vqlhvqM+XMVdPSQphZihm3XLvnk42W9Q5J/Q
         48Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iYNE0U6206NHf/XYZjZUXrGaNjHZyHkVsyyhwUwpw2Y=;
        b=YIHGCP1xMzcFATMTe15Fr4/HTTrrEtcUdQX+TVse0ntTtZNCkaKvXc/GMw9v8yERQH
         DTpvi9TVpGjnL188yyXRdG9P5Y9ltpMeOsXenDupHrlh0TEzD6F5RVNN+6R81p4JeTWz
         6PH1mT1++g0lgOE18YHVE1k54mQjiyXzhEyrXIcFUZ6bbAA0VbY128nP1pr8tW8IhLQm
         a4Cf69MFTbc+WfuV9fQLLK5INK977u2xu6DgnA2UAEDRWRinqKlAOf36N1EGvKwkmizV
         959uZbeI8SkqL0aPauN1h2KXDkC7ioxHKCMgiBZyhZGjKudN3v/AtPNawyGyqbXMdp0q
         FL1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BY2v58yp;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYNE0U6206NHf/XYZjZUXrGaNjHZyHkVsyyhwUwpw2Y=;
        b=I0+s8Ts65wnNVKuIf23RPtk/qMqSXketNpUjvJwTqrq+hnf+pLXyPKRiJpDc3+HcWS
         yZtogPSeecUHxQKszCqr6syLp7GiRoptf2caDUyV8X/oroW4Q/F7IcVJ5mWPOmSR17Jg
         XNN7G4HUiOIZhO+XSiKfhP44+w9hoaE9FRLlzY+q9MRi9p/hlOlJP9M99YUz0e6TqpTW
         zg7d1lJRquzwPk0G+rgB/M2KZfOgR+6iDD+Hk5R/Qy9Ki/EX9IAYOUmoLYdBqTWqi3wA
         mr5uBGbt3CeK5SkV27Sp6ChACSj5RLItTiQAbEn6SJiLaxt7UJoSThzhtuEDlfpOMvC0
         e5lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYNE0U6206NHf/XYZjZUXrGaNjHZyHkVsyyhwUwpw2Y=;
        b=dI7IUW1CefoS6nF/+5CMwCy5yQn9YfYHvzZ3KNYswoBHicTDHRTwkDt3Uv0JuU1CoS
         JGQVt85JcjpPuDc4gChyzF1gljn73xN24qXkhus1ay9CNOF4BfFvs4gfee5CRQqaqd3U
         b1t18mekWEyqfTvczdYiB5vCYAr2sAgWA1eUSv7Vyo5b/0EViJuOUwMDN3NlP6fqHW8f
         oGF8uo6efROZxpj/j0aA2CtX/b0G19LpFcJZlDT6oF4ZkWMzCrX20bm7D9xd02Y9NLoc
         KzrqfNCOjXizfi9PPCgbZUTzmh2kphfUfwT1/4YcjlQ7LPoIMjC0myOkYF1QtJctLkl2
         zL6A==
X-Gm-Message-State: AOAM532zageYPge6UbYif3gDpzkcDTKPastZz46d22kX1qNzBuzP3aTx
	tvpIbjtFKzFl+bmCfh1oTpg=
X-Google-Smtp-Source: ABdhPJwQdhC8qFOsrOfQ7Ap4ShIDXU+iexAZDM2LFj/Nw9mN7CXxw+R+pp2IglXUgJM47Vj6gTxI2g==
X-Received: by 2002:a5d:4247:: with SMTP id s7mr678568wrr.704.1644261005116;
        Mon, 07 Feb 2022 11:10:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c8:: with SMTP id b8ls114033wrg.0.gmail; Mon, 07
 Feb 2022 11:10:04 -0800 (PST)
X-Received: by 2002:a5d:6d4b:: with SMTP id k11mr655357wri.623.1644261004216;
        Mon, 07 Feb 2022 11:10:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644261004; cv=none;
        d=google.com; s=arc-20160816;
        b=eKGxSrPV56XTAq5WPlUgIiSZXu9pqC0NE9MDKbVzybmJIOozu6DdA8rOlOJP/vBHND
         Wri7NURvrqyxWxYU1PLXf6TcrgSL1I8FspU17Ot5Jf1Ur3lUHFpCLc5dDUb7ng0cNrwX
         +DwEmmTmdZSeBkSwOPj6aPjmQ5DRDFZ05HTyw/pP3G+IWflRk9nvHmlTThTYWEe53gr2
         8HaK9i9pLRFx6HuUZNtI6M2F18cCPE7ji1mcWFLy7BGfVrsp+21i+iOCLnDkrwyq4XrT
         w/9j9aEPBirUJWz4zguPbd0B8EVetuWfltoLbMy3babycUNGGutsS8h1JsPraVzJ8CHY
         BpNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SWmI0He58+fGpGTA8Rm8gAObvQo4qEHhiPU07NkhsrU=;
        b=iJqCDnxM8nbnfJfbmRA5zcFxuSJhLS4KkxdM5tZnusX4XCfgFZEOUeCikJOdA2gpvK
         jvGgwiFUzHERxHam3j/h8fw93IfUhrWPIlhhMCfWE82NGYnHGlw9eMOiXjVUhZONxDv8
         QEqo/Zg/QjXfbUbT/M2R1GrXv6BazVXYcCKNNV6yWH61N1zHuHkwLyb+bke0s0iMyt5Q
         7H2Mf/YsEv/2/BvTENbUpjW2ne3iKflrjIv0MACim4oqHUBgE9bmFYrWIhnwKgrlwqNA
         CjXaDG9B4KpzjZ6CniKT+OUWn5LJ3FhTWukDzjCVBXzrIDlcl10AQ10MsV1w8kQaepxD
         h2TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BY2v58yp;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id e5si566384wrj.8.2022.02.07.11.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 11:10:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id d10so45087450eje.10
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 11:10:04 -0800 (PST)
X-Received: by 2002:a17:906:94e:: with SMTP id j14mr844785ejd.369.1644261003744;
 Mon, 07 Feb 2022 11:10:03 -0800 (PST)
MIME-Version: 1.0
References: <20220207183308.1829495-1-ribalda@chromium.org>
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 11:09:52 -0800
Message-ID: <CAGS_qxoTLwvVjDGbfeOjMrGvh7sck7TDmiVeDXS2S5oyDWiKzA@mail.gmail.com>
Subject: Re: [PATCH 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BY2v58yp;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631
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

On Mon, Feb 7, 2022 at 10:33 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
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

I think we've usually had people do
  KUNIT_EXPECT_FALSE(test, nullptr);

I'm not personally against having an explicit NULL check, however.

But if we want to continue with this, we'll want to rebase on top of
https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/?h=kunit
since a lot of this code has been deleted or refactored.
E.g. see https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/tree/include/kunit/test.h?h=kunit

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxoTLwvVjDGbfeOjMrGvh7sck7TDmiVeDXS2S5oyDWiKzA%40mail.gmail.com.
