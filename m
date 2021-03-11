Return-Path: <kasan-dev+bncBDE6RCFOWIARBROWVCBAMGQECVZXLSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA433375DB
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 15:37:58 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id au15sf8817924ejc.8
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 06:37:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615473478; cv=pass;
        d=google.com; s=arc-20160816;
        b=oT+2PevlufTbgxPJJYXfc+J7dG/N4YvnU98E4a2yiRkNPyKXuixaXdQ7etcdlG6KfK
         BY0vuXKWHwz9f/ZpSqDRD2DMsXJUVvNqc9nzCk/I2kqbg1CUsTUm4cOt1b+fw5Ijx55/
         UdpthBkqmUe4Qp3otbHi3sLQD/oikvbwj/oYxsm0pF5Pn1L/jxMOB3IutLPAG67XGS8J
         mBZPnxPW4vsz6hn9Mj56qmRQmtCRwwuQ3azBxp+Q8fRY8uMmA8/HMY/TcMuhdMSGagNg
         tlR+fp0LY3dmksZZxEHf+gMnw3LvMzx1Z5dbti8ngwrMGBSbaYdfwi8TKSjirGU/HY5a
         10gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fbamS0QoKw/KAjP1UxBNE0c0D5rFwrjBWon6xFJkmrw=;
        b=BCQT2zZ8w4CRmwfYneA+J0dyIIGMjEHy0tVygeF7ygfEY4PMETKXmMF0ilG8PvQPv7
         fSt4ew/iBin1pfLoWbGtdiAQdsI5GOvwrBGu/TqGW3EKTF/FUWhEnmVHWKBn0M87XeXF
         XXkA8GbBmNenjJsaraHdSbX1jVz2wBCf6QTNvqCvXfxLqjCbapbdQwHnD6NDolHGHMt/
         r/6ZQ0u42sgnhxGTci+Sb32yZIOnJmJ5c/F00GCf00oFQjZ4PyoxiK53cpBW9l7Oq56T
         un1SQfDmNC9b1277zfhAOWPn8CZkSLS00MuXDkGjJD+EQ8mS5rOS9CrKy6t2pflOamYm
         JeKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=hFuwYLV8;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbamS0QoKw/KAjP1UxBNE0c0D5rFwrjBWon6xFJkmrw=;
        b=QpEj0BPqBd2H3KTycSBHCH2TlrbW7yljXCMO19Oz2ePhVRzOkwlD6q5wm6TM41InUc
         MqaKOELWFU/m9wJ8kogTv9FIjGNtloOokTJRMg+mp539GUF069oqJZ+2sxPYJj7W54eH
         gCCekTh7eEnUjGCYCIwo9OFSUxDK8/nSe3lCZMUCP0M78nj9wTrcacyELwwJHOT67tCT
         ynP/K0nGMyzdbTYthEjBIfbGpJdW6z/tWQcof6S0PcfF56EQm6W8B/j/IDxPbRFVXix2
         lq8w6Zl7ZiujyLWcfFK0hps9unp/V0KLCPxn7FUPfPNzUEyNKQKf56sEgFpu4TOTaoNa
         /m2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbamS0QoKw/KAjP1UxBNE0c0D5rFwrjBWon6xFJkmrw=;
        b=BwJOFW0zawuojzraZKhBbJNDWkzS/nbCQFqkmlFM8dzHQ3184oU0hU4NA857bxPzcc
         +eFfZQBbkoeb6jtu4+Oy23rFs0K+mkZjJlIA9kW4qMtnNfpHXqnSnpf0wiM1EGD6A1TQ
         IATMZOm2oyxfWRJpN8ZIfJ/qks/iQOjsqkCYkfCan+PA4gbHTrfSv5LQpXHqDJM2aoIU
         q23w/8YyPuvxRV1u6ehrUuUC8+n0TMuVOkF9enpkWPu/i59lo9/DMDLhUR0sY4JPApG0
         O1tgr/GGZI7Mzc2olEbSJQdrMFcuDqt0RGGJ0YaPXeWxhuUqUa1Nmzo2Yi+Lx/aWEuHJ
         +BiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rngBj1sQHDTmrxhoD8XIZ+8bfGr0fFkYpv26fBwpr+/KIFs+i
	4sG77nFRBVx9nZGAF6atOXw=
X-Google-Smtp-Source: ABdhPJyUkwQuOYVfEB6f5b7gB4LzFwuiCuEb7OLtpvN2dQXRQXkJdhLZUMeGab1m2ZriNFknzq2Cew==
X-Received: by 2002:a17:907:211b:: with SMTP id qn27mr3387136ejb.203.1615473478211;
        Thu, 11 Mar 2021 06:37:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3f15:: with SMTP id hq21ls420539ejc.9.gmail; Thu, 11
 Mar 2021 06:37:57 -0800 (PST)
X-Received: by 2002:a17:906:c1d7:: with SMTP id bw23mr3304713ejb.554.1615473477275;
        Thu, 11 Mar 2021 06:37:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615473477; cv=none;
        d=google.com; s=arc-20160816;
        b=iGEtJBQIK3B5juySeCawGU1Fx26ojIoZdLil/aTy7MWIaIzWwINUM7PZ3O/xI5lY3d
         YiJcRbuKIavGK7ZjFjPR8uVAd6JnVtd1W3l9HiLDGkhGy9y5gJZsS0kx918U467+t1Tw
         Whum/3feDoQvv5nnjxewlq1y6CQwtV1ITVdWWu1JZNTKkS6i7x8d/5p4tbwIOvNfR2Bl
         l6pC7xIdtR+jyjYZ3xbiH14rKCx/pBi5X7RzSVG51m95CSusPpjTYlT78p/BKxy6exzz
         qmgN66xB+0Fbb6lOu4p2hiBdZOwCheEEDDCBUV76jjRq5woR4c8GPsLZxUq5vjHdVK03
         orqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mGTU6p+ERrFxw+rGJsmKg7+V1KkNJpjDJoLYaGxv3SI=;
        b=BeQVRKFtCWQ3srlIrieIINxcodBqr2SjzimeGPA6zmkdJU2AfMMPuJG1RuJr9MdrHB
         ebjlXTxZ6SQ7gEjYhThOk4N/tqO6uw/lpWqPUNLi7g/oGhGTZLI6qHxOCwDkbu98FXqm
         BRF+jhsVm1NFLiQUpz9D4AOxNqS31Y/YLF6rTc0Ie/WHS7On72DKfoAfevXCvJfrp8Ah
         LzGrYV1Cxxq2J3tIp9X8RywCqLckVdDGhJIportYlylrhgS92tODWg5NkSRZW+bTpXAB
         Geas69sMIEwhou/oeSqtZUZIrXkCiydn5gQTvbXPYmCLbJ3hSeUNSzq2NO2XIaVhXyaP
         5N2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=hFuwYLV8;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id w5si97027edv.1.2021.03.11.06.37.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 06:37:57 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id v9so40166573lfa.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 06:37:57 -0800 (PST)
X-Received: by 2002:a19:6b13:: with SMTP id d19mr2423367lfa.291.1615473476819;
 Thu, 11 Mar 2021 06:37:56 -0800 (PST)
MIME-Version: 1.0
References: <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk> <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com> <20210311140904.GJ1463@shell.armlinux.org.uk>
In-Reply-To: <20210311140904.GJ1463@shell.armlinux.org.uk>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 11 Mar 2021 15:37:45 +0100
Message-ID: <CACRpkdaCM9iwLP0L8PhNB9CZEgoZS5DUZxso6vh4-i_rOEtTLg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Dmitry Vyukov <dvyukov@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=hFuwYLV8;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Thu, Mar 11, 2021 at 3:09 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:

> So, I suspect it's basically KASAN upsetting Go somehow that then
> causes the memory usage to spiral out of control.

That's annoying. I have admittedly used KASAN on quite light
distributions such as a minimal busybox or openwrt.

I will try to enable it on a more substantial userspace such
as Phosh or Plasma Mobile and see how it deals with that.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdaCM9iwLP0L8PhNB9CZEgoZS5DUZxso6vh4-i_rOEtTLg%40mail.gmail.com.
