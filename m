Return-Path: <kasan-dev+bncBDE6RCFOWIARBTMRST6QKGQEFY4WFQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4650A2A913F
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 09:26:54 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id b16sf246559edn.6
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 00:26:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604651214; cv=pass;
        d=google.com; s=arc-20160816;
        b=c9rir3Z5J05zR9eMZ02Ds1a1Yu/YdjuP9ucljabsNrvSzVbjWzZwkxLQDZ8ITS/q1K
         VVXtQOm53Gvzlaj7lnlyciI+HzVxH9lN8xSi4WLBftLlDnQ0l9xTXFSYlfEu6tEfZVNL
         7zkJaRvbWFqa+cvsGJHbMc6Ojj3nH4NCC7N56s4905lTPmMubmUWETYlks6w99hcqSD7
         8/YP7fxe/sBNNxcOl5TmSmCw2FwZViuV2r9CEGK2WHbrpSe+F50+Wb16FCFl12GPq6r3
         ZUZ9gqzbnoD6WwlDc7tHmb2bglff3eveu7tELE3m5Wx9Fz2s4+L0l2jrlxEaxlSfBBZO
         3z2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=QcKzqygoedS0S6pGDE2rCQsCI5rzYQeORmlSfZdE1u0=;
        b=UWWVrcsiAP/HPnQYydszi6SKaAcdcqa2n4Zy55nN90yXbZnnSHPOk0cewMrpl3etM9
         8guKuMvH3wAiSp1upfIP7AqnDM/5MXj6G+YR6jzcajrJg8+2By+DX+EYrSeZfgLEifxX
         q1MHtEKFGi/s/I/SOT89u5QvmkE96VlIVie1JQG8IUqCaXbROGUrp+ejhHAmb5056tSM
         KZD1KTxPaQATlGifc/snPfaI1lYvl4LuSE5VUIG+LmWmIekY8iY1LQbmAOD5u55sA0Ck
         SUFLTaBbG+AJNreAbfSM2+b/2QipNhtsDuqeddhxL0F8tEqo4cPAMPdAS61lPaxSoASM
         fx3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XW4NMtB+;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QcKzqygoedS0S6pGDE2rCQsCI5rzYQeORmlSfZdE1u0=;
        b=s3a/TZdXu+CZB4JlW0GENk7mqCiSzVpLsDmHWb1asTJNZY4QPQlSdr9b/Ng8CeS/J8
         1P7ewvdHarWKd65wHTKrSihlRy5wzZji4BE7NcQ/0GhbzsCn2P9iquZWq3eOeUK3eyxW
         tvJs+QMCTDAjYD4F8y4Gkxgt8qb9Q9ish+iCrXJ5FaHuRuy5hZY9P1lMrGoAlEWTzy7N
         vSR6wruJSYIgdm6SLy92X33+d+I2Rwj7XekIDXNVJWhpZOmHnDVogZXm2LZRaJqEkjiB
         mhRgGyRUHRFlcbCpTkuKVwFJpWZ04GMSQUVQ5ubeUdGqRotan13Muihf0vlI7wDk2HeL
         RVuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QcKzqygoedS0S6pGDE2rCQsCI5rzYQeORmlSfZdE1u0=;
        b=tZLitYAAXO7ndkbmmx6rsl6XDGo3xUaXvx763cJCeA1RgIXRV7C8MXMexv+TDKoCWy
         d2+OZYlfLgnEwZ4GRcPcP21mqYBSm3HLkjHM8he3i28EoZKJnfL4UaIj0BwVpHgrXQti
         6b/B3Ga6kZD7po+UUUIyR33nJJeTcZcpizGpMbyqTscUCI4XJYu9c8HRjdt1Bvymf0Ue
         T7ms/tDQj8OucfHb/TwBp1eSs3xqTBvMIny8UZnGbRGgIPaigIzRc0aSQurvRKYcYJBy
         cBRLQD4Yt3a3rooMIsT3F98zV5X4NXz8QgQY+hpWIe1KQgKkx6SAYaeCNzZ/yzUI/sXm
         mJaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531akgI69BPDUvCCIMzGK4JVQlDmHDpT6gGOjUftsyoegJUkIQuC
	AlgtQMDVJChNl7SSG6xgkpM=
X-Google-Smtp-Source: ABdhPJxoip8uXJthGhlMk+f297Jc2O8K1VhxznwXn8EVBdEd+iELw1hjvgE81A+K4Dg2Qckxvg8jag==
X-Received: by 2002:a17:906:3ed0:: with SMTP id d16mr975181ejj.477.1604651214003;
        Fri, 06 Nov 2020 00:26:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1351:: with SMTP id x17ls381467ejb.4.gmail; Fri, 06
 Nov 2020 00:26:53 -0800 (PST)
X-Received: by 2002:a17:906:2697:: with SMTP id t23mr987325ejc.292.1604651213001;
        Fri, 06 Nov 2020 00:26:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604651212; cv=none;
        d=google.com; s=arc-20160816;
        b=wBjzlWy+tROTQelxhtLU1+f2VE6z2dqoERTrgbXx4sGfFRp/v8INvfRnbAlyH9ifOd
         FDrPQdOb1SShuaUelMz+On9HDnVESs1nKvtBl5+XVUuYkuY7ou//E7WGrx8VJNTZrh6j
         V1go8e4DiWmHXs2SK0/Y6N8/6zO+67LQWwiCfFP5nFeYgwWq/vXUPCptyD1Tk0G799HJ
         DSSLI6hn4IKXlP6ajigLlQcDjtW7I5pnkywZxkbalp3bvPHRvipg5G2unN7Nz4s1Xotq
         4LX8HKGVmeTgIfkK+uQf/eA35GnkNiKzQweC5fnIgQz8Q77WppclyLCbixx6H77nmkPp
         XiRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VC/T1FT9GsTzXt8MrK2U0stjqybJMsRT6B8SzwuOs7A=;
        b=uCGCsZ3+POLf8gmEheaEf7Ng6JfFE+v4wqf9xuRo9fLU2N1UXjG242hqaWBKh4m0L1
         yU+YJitPvOj2S0Bino+t2AdfyFjgiy9/P5ge0jTe2hj1XKaHwO1uIrtwxNgCPprsr5GZ
         Jpq0ofnO0RTxKnVG9wtFESi2Eu9LdXvkAXyINtMlILFsw9kf//BgvTFk0ilgKEGeXU9e
         oadftGPD3TI/lK7ANAHMXC+eqLi0APi/RNb7rTRajbVQrQY0+szL6YtmYsQP7xwY5VVz
         w0UItsQy0CBQLUHTqPfY5TZkDr6G9ydCMp16wbUdo111O6gKFjKA3VBWb7xrdNJXVtEL
         47kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XW4NMtB+;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id u2si21525edp.5.2020.11.06.00.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 00:26:52 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id e27so731344lfn.7
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 00:26:52 -0800 (PST)
X-Received: by 2002:a19:5e0b:: with SMTP id s11mr405072lfb.502.1604651212485;
 Fri, 06 Nov 2020 00:26:52 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
In-Reply-To: <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 6 Nov 2020 09:26:41 +0100
Message-ID: <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Linux-Next Mailing List <linux-next@vger.kernel.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=XW4NMtB+;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, Nov 6, 2020 at 8:49 AM Naresh Kamboju <naresh.kamboju@linaro.org> wrote:

> arm KASAN build failure noticed on linux next 20201106 tag.
> gcc: 9.x
>
> Build error:
> ---------------
> arch/arm/boot/compressed/string.c:24:1: error: attribute 'alias'
> argument not a string
>    24 | void *__memcpy(void *__dest, __const void *__src, size_t __n)
> __alias(memcpy);
>       | ^~~~
> arch/arm/boot/compressed/string.c:25:1: error: attribute 'alias'
> argument not a string
>    25 | void *__memmove(void *__dest, __const void *__src, size_t
> count) __alias(memmove);
>       | ^~~~
> arch/arm/boot/compressed/string.c:26:1: error: attribute 'alias'
> argument not a string
>    26 | void *__memset(void *s, int c, size_t count) __alias(memset);
>       | ^~~~
>
> Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>
>
> Build details link,
> https://builds.tuxbuild.com/1juBs4tXRA6Cwhd1Qnhh4vzCtDx/

This looks like a randconfig build.

Please drill down and try to report which combination of config
options that give rise to this problem so we have a chance of
amending it.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZL7%3D0U6ns3tV972si-fLu3F_A6GbaPcCa9%3Dm28KFZK0w%40mail.gmail.com.
