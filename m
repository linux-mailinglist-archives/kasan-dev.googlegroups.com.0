Return-Path: <kasan-dev+bncBDE6RCFOWIARBDXITKAAMGQE5EBTMZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E45062FB553
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:27:26 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id o12sf9594939wrq.13
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:27:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611052046; cv=pass;
        d=google.com; s=arc-20160816;
        b=KRmsYzOqatEWTC91WBi+dQ5FgPJeoxpwmj8/dynwvaNiqDFYbIePubYIZFfg27XC3L
         DtRXdvIceJ7NyS1RpJYDAYhtPxLUqCvj0txXEFpXsjrhLiB/j8v89reoA7NO23Tv+ga7
         Vrt9DVggsZbmA/nYol+2GHreh5EAh2/ZWZr2+7iyx16+n+64nDML6d2LgouUCI5FHBEJ
         APgpXXi1SeytNxoGCEZVJG0xaUptVUqp3Em6t8zyKs3O4igyk1y37KEMlPhJBuUhPJ1N
         Ahw+Nn9yeO77uSP64KXiNgIH9a0OD0v2tB3ggW3rmrUx6MuMoFqMkLdKBybRefRYpvky
         yx6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=g5Dm1etKbWVUyEYkHus6F4LxOYWwvFwcp4S3LI2fJdc=;
        b=Oq4cMoTQoPwjGU07d6H+80qN5TnzEzA2nIixY6YWUokTjnBMboKp/K3AvHCUdzQMir
         STBzJmV9decRLmcMFiOLGW37S1wiq0hkuQ0yxNHQMgyNxCsTqvb8IpRw5frI+tnJ2dsG
         qYlGsOESM8H7TuHr60q/AUZA3uMxqPVvMv4Pi8rOn5+SzmFDGevpq3BYBdm6VlyqN25J
         kqcmkfNod1J+pGboulAbtNn2X3EgypkaIcPn6+ITI8Hj5wFfDePOuCYiEiUiDV3MFtcn
         yqAIC+oppRe0ip3hSEclkKpz48FSgs9jPbrwshoK7uuq2z2DTWUJGQCbZrI4ojD42LJ/
         dIYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=kcIrmtM8;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5Dm1etKbWVUyEYkHus6F4LxOYWwvFwcp4S3LI2fJdc=;
        b=dXozutqWHDneNJaBl4FdZmOym9bUFLAhrYY7rlgWzxLFYYPGFiNU5ZwruP4GxRhFcB
         4mZRrV+8Vkn4fNGYayPxMf9GXxWGAHXcdkctPduR2c85Vf1rnM6HyHrVkJORBeF3aIWZ
         FkRjt/BdFcYr6ldI1mMw6NDe2OyIbcBAcb8ZUS2GJZPPZGS/875qDImsqnfH8rXJdxKo
         vWJ/bR85Mx7OYRapmT++Y34pRZADt7KwKRWSIVK/6w9WNeQvp2PowFghnLAR8RRtNOAj
         2Y2yJlGyUTxK6v7Dfi9nVJy76xihyjt3Cq9eo5YRYa3fiKnZbv8T3sT7bc8UN5852A/1
         eMjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5Dm1etKbWVUyEYkHus6F4LxOYWwvFwcp4S3LI2fJdc=;
        b=SCeH/5fXekcMZVBqW363V1q1gi751l2mHGr4ZFTlP+Zhpj1uLTNcydX7ED9gCchqgK
         j+tnRcU0EBEgNlBig7zUrOzQyt8SctNtAY9i1NSXCoKeSJjmq9GznUSUByWwo5a2MJrm
         x6mZHfCJLl4kRD67k+yHx6F58dbBU21EWW1lvIz1RVZRNx8NmVYEOjRnr+OtyoTZ8iY+
         Merrfq3hTUeUhDWJj/L8Ksi1w/i3jm/S3e00POypVhTz8ZmCXt+v0DGKFp7xIbXFDW2f
         0MpWFIacXIuEY2iZRv5+SJZY+OOmehxStUJS9v2RScG9gP+tO31dP1kiKOdy+k+zmtWo
         CSmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Kp+VK+AkO5ji+lDyvHX73334+0mcT5PKI05JjrkJWVRBqrI/T
	j9kqR6gyUIaY3SPt5KGpH+A=
X-Google-Smtp-Source: ABdhPJzbj/PyJ2lXaabfl/9JglpmEy7oghg3/gigrUXmy0PGEKL56ykZdtWr8MHNKDDJopf4bi22Xw==
X-Received: by 2002:a05:600c:29cc:: with SMTP id s12mr3403194wmd.180.1611052046729;
        Tue, 19 Jan 2021 02:27:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9916:: with SMTP id b22ls9633800wme.2.canary-gmail; Tue,
 19 Jan 2021 02:27:25 -0800 (PST)
X-Received: by 2002:a7b:c115:: with SMTP id w21mr3460676wmi.114.1611052045880;
        Tue, 19 Jan 2021 02:27:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611052045; cv=none;
        d=google.com; s=arc-20160816;
        b=tu/ctWdUQwwcciwQEU+zQhz21QOZwFKqAtk9/fa4aTQYSVNU8FFWD1LTDzTMm+frb6
         1fzUHuPFjZHFXQLr50foK2icWZOFwxQHYonKnJUsXwcQ9JDig22Bgna1PBQMfmZt8WY6
         IzCz92+TN8R9FfaAykT/PT5M16uULpq0eJPtZ0kcoREdoo1h28qexIq68xNXWMYbDoVX
         dlNSPgS7rYwFIl8JV/85MCJ2wq06kUzpCn6DXT2p6wkDITwUB+AB2J81yRU27yvXQDA7
         ODPepIc/OHoFQ3zsTbl039dQQeEqaia+F4ayxPzsS/z4hzgNy6EdzO3uAL1LJwthT1Kg
         qGUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G29YigCGspMGc+dm0uNvzwZPz3V3gkMWzvwC+tLRswo=;
        b=uGgZQHXfc6ZNeSgdkK6bD31MTnGvvIYIWY9hw1nGpOu5+g5k6l7FhC2jDNtGPy70mX
         3EoTBxl2dBNGq6EJRN3g2xOVCZsrljw+eRi/snojqtbuNBfJ3hLb7jwilZBzlplsCFCo
         9YdVgVgbbuMpS/esKll/wnQgj+y0ZLz56/QLTYUmqGAYO2cAv0q/l7TtHz3tWaH5mFOE
         fWwhWQZJnl+YT5OpborLhc6/2PErECEzzhH9qefIoH/qvMDLJM35hLAMFn0cgkqcoSkI
         niLTL2EwlCxDW0icLf63wBNHHgOAyc7H91EvPsz98D+C+NemtYm+WqN8vrZB63sY7sIZ
         5LWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=kcIrmtM8;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id n8si1140342wrr.0.2021.01.19.02.27.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:27:25 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id n11so21320173lji.5
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:27:25 -0800 (PST)
X-Received: by 2002:a2e:b047:: with SMTP id d7mr1534799ljl.467.1611052045410;
 Tue, 19 Jan 2021 02:27:25 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com> <CACT4Y+Ykw64aRm9xRxqiyD4h-bDNgXG7EnQOp56r82EA6Rzgow@mail.gmail.com>
In-Reply-To: <CACT4Y+Ykw64aRm9xRxqiyD4h-bDNgXG7EnQOp56r82EA6Rzgow@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 11:27:14 +0100
Message-ID: <CACRpkda+jhPO3-BP_F-eBE+9bT2U9bb920YJUi=-PbNN-mfJZg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=kcIrmtM8;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Tue, Jan 19, 2021 at 11:18 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> > Here is my config:
> > https://dflund.se/~triad/krad/vexpress_config.txt
>
> See my previous reply to Krzysztof re syzbot configs. syzbot can't use
> random configs.

What I'm using is based on vexpress_defconfig with a bunch of
stuff added on top (like activating KASAN)...

I derive my .config from vexpress_defconfig using this
Makefile:
https://dflund.se/~triad/krad/makefiles/vexpress.mak

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkda%2BjhPO3-BP_F-eBE%2B9bT2U9bb920YJUi%3D-PbNN-mfJZg%40mail.gmail.com.
