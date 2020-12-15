Return-Path: <kasan-dev+bncBD63B2HX4EPBB7HH4T7AKGQE2A5MWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id B05A42DB651
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 23:09:01 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id l7sf16259487qkl.16
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 14:09:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608070140; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQRBI5oXBc3mm6Xmrny6sVFokQ05dqn1gEk7jpLn2+GPvFysQZf45wC7iqmGl6geaF
         KtFX7iOcPWHdj5xsioWxM7En/6yeq5Br1Fuh51Gwaj9Ly5YbtD6QRzft0sq1fj55PAIL
         rmU8nRYadi08VoKAvupZSmk3jZ6Gt5XQAzQS3gScuGa/qL1is5siINKMSQ7rxg3JoQkr
         slvpGuwI2EQvlUYrUlqgdrEoLphixAIKYmTTMk2M8WQhRFgx+Ng75CMARQ9TdJsbNqAa
         KIPOOASy5Ik4wpgdiDNMVY40bCvnOueyEiVauiobKmDevSyN+FmxM7uCdwpDYekybShe
         jIOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Yr6K/juZx8Qakv2txD8548im5ZHljrkJ9FszXtKKtKI=;
        b=sFB6spOWfwPU5XNs1oEiSS5urgu/rk4RPccYceka0UoeXzEZdhSvcnYnQrxbmn3qTc
         OICDpsM2L9qk1qhnoReb2BgBg4M9u2RY0QzY2qEwTqhHUbCUzZ5wLjrv1YSD/pZe9xfw
         2H3/GFKBUp2DYQjxYYzOk4GbYWbgAfHuoCqrTmZfsRvxAuL4HxUBRjVU3JpaGr/Zhee1
         bpReOcyLtuTpvxrZux2cjVjjwnjti0ngdpMefExEIJShFaZb1CTLTUjTK08skEhvdAao
         ZwFPwN98MdTPHKknbVMrmqR8FI2FEJ1BE+HFgXaoBw3EzVEA08Q8o/RvO+aW0JOZSXRa
         0fCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=PEZMfrYs;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yr6K/juZx8Qakv2txD8548im5ZHljrkJ9FszXtKKtKI=;
        b=oyRaUJZ6HxEdc9rPUk6WSQ88wnUEVHX8y+WJe6IgOqeIh5trCUdfxe12woQ4CoxFlu
         0dtatPO6C+smmuvpn1AOadIPqndWGbEDdw/CqTtQtukxP3oEqGwWYQ7L2bOVekPluR+m
         UWqy0R+NgLBraBIPpRkC3/T3XMoLuApItYGZaBFJNicGpoYuaaeY82Xgi7lphW8mUtCW
         fh2KpoBoZgFjB2wIfWdbzOS6KAvPG3eiCwPLZg3tVwlrL1yfYpPilbUUneWHGyEQFu8c
         IN3uGVO38yqM1v0BZi6E47cFJxA1F+KyuCq2xz1T7P6gacoARInK2mydPmmQcBwlRnM+
         7n8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yr6K/juZx8Qakv2txD8548im5ZHljrkJ9FszXtKKtKI=;
        b=eYVGTmc3EUkXiuD0eYVzUugrdt+KuCZIXGvdUsmmmyW3aQctEJ7Go2MGudXSHb8lBS
         fpUEiv4/1LPlf42VH1SRkjmXxJMW1GPdtXAQhI8mUXcMz/ZobL6L0LDbc4Sc2BY4ioaX
         tC/I0uTbGenxUpNeFtntgYO7r/SrQ4KsYTenK2Jrjyr4FlVfCOv4avXGFCVKIxL0gdgh
         s5z6G5+DleO1bbAG6vIK5upI5I6lZmKDADxyxaGSvnpYvdTU44idKCG0WUUnG3La5Jti
         wYDEPTyYU6aDLkZASq/ptyrc4piov0AOL7OTQNpKCtLJj+qeDEqOEblnYAsFgwBqgeNv
         D92g==
X-Gm-Message-State: AOAM532AF92/tPeXF49807SShDt7EdPYCAd0OxPLwBdRlgvulLiLsF9r
	ro6BbAHhL0WqrlqngPoKEvs=
X-Google-Smtp-Source: ABdhPJyftn7lqKBEhxY7+hHHeFFumRNlW+EKZ/3+mpHy30juSuFEDFKNmuF4wJKFVXkdDUHEW3vgcQ==
X-Received: by 2002:a0c:e90a:: with SMTP id a10mr32925036qvo.38.1608070140630;
        Tue, 15 Dec 2020 14:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c2e:: with SMTP id a14ls5058668qvd.9.gmail; Tue, 15
 Dec 2020 14:09:00 -0800 (PST)
X-Received: by 2002:a0c:80ed:: with SMTP id 100mr35805849qvb.40.1608070139968;
        Tue, 15 Dec 2020 14:08:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608070139; cv=none;
        d=google.com; s=arc-20160816;
        b=WdC2uPYtBXR28sioAu2TvP7jeBmqmEOZ6w4C3M1xhMC0+fVPnbTVjpSvNbzer9dz7B
         BNDwSMTO90zHnLLhtoxZrR4VPgskhf/TDW2AdTglk+TWQOjjfNQZDL1mUYmFyRGjjYSx
         7a/Gy8HCT/sjsIPf5mbtdMdKwmdschukrYxtxJD0vcVgyWVwtVRtWP8DaMcpuTQ5hfaP
         5KGoLEEbbiCQJKi6V286nNUU2sPqZyJS9JMdHZ5OEGu6tXoiSpINd0bsn+jSiu+Ac8w6
         TxsHOO6YsFdlBt481tHm2y5Vgj4Isk60WvCgMRBEoBHAckcnzTjEw9/ukrjpU9tgnuXU
         K9Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=M0GhLjZA4zfDKp+dzSrSRXpP834rl3DvecCKOsWrJqs=;
        b=0NHb/IgPWMFHTRwhIcg45DbkOGQivwZQnvYrUgF3C50S3ZQ+3nhtpV2Op/5i6aiYuS
         SLSm6uXy5xcZME7Id0c+DBk90zPyBoIsdM0Ynm4ut0FCcGL7gdtcqPZSWl4/sQBeHjH/
         LEfQXU9oxaBxaKUkkLISw2ewEkW83O/6Sa6Kr1o2UYzqdswKeEKd/1MvO+/YlAeYwzrw
         qwj8rj0SRauwv/kCQKPcURdFo8Z0KbClxKYLgOhWXNIo8SDUOhN2NDk4DD+uMms4qV3v
         6pL8+EhU3PJ+QpXdLfc9hEGDUhpi3I2UP4311x4M0Vzzq0PA1xw/KIai0CmsR3tnRu9C
         OEYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=PEZMfrYs;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id y56si1611qtb.4.2020.12.15.14.08.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 14:08:59 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id g20so10945874plo.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 14:08:59 -0800 (PST)
X-Received: by 2002:a17:902:52a:b029:da:989f:6c01 with SMTP id 39-20020a170902052ab02900da989f6c01mr19766632plf.45.1608070139142;
        Tue, 15 Dec 2020 14:08:59 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id nk11sm92235pjb.26.2020.12.15.14.08.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 14:08:58 -0800 (PST)
Date: Tue, 15 Dec 2020 14:08:56 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: stack_trace_save skip
Message-ID: <20201215220856.GG3865940@cork>
References: <20201215151401.GA3865940@cork>
 <20201215161749.GC3865940@cork>
 <X9kAeqWoWIVuVKLq@elver.google.com>
 <20201215200217.GE3865940@cork>
 <CANpmjNM29k68CZXnS4mfzsdW3YJf5FdXBA3mZtuLcSQA7+EfTA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNM29k68CZXnS4mfzsdW3YJf5FdXBA3mZtuLcSQA7+EfTA@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=PEZMfrYs;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Tue, Dec 15, 2020 at 09:48:36PM +0100, Marco Elver wrote:
>=20
> For ASan etc. LLVM's compiler-rt has its own stack unwinders so that won'=
t help.
>=20
> Perhaps libunwind is the right balance?
> For C++ maybe https://github.com/abseil/abseil-cpp/blob/master/absl/debug=
ging/symbolize.h
> could be useful?

libunwind and abseil are probably not what I want.  Either the code is
too complicated or my brain too limited.  My goal is to require frame
pointers and simply follow their chain, bail out if anything smells
remotely wrong and prints the function pointer.  Pretty awful, but the
kernel currently has no mechanism to dump userspace stacks.

Going from address to file+offset would be better.  Getting the function
name would be better still.  But right now the address alone would
already be an improvement.

J=C3=B6rn

--
It's really common to hear stories of bugs that can take an unbounded
amount of time to debug if the proper tools aren't available.
-- Dan Luu

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201215220856.GG3865940%40cork.
