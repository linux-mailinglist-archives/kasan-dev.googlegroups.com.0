Return-Path: <kasan-dev+bncBDGPTM5BQUDRBYXMXX5QKGQEJ6IJFGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id AD0F4279B32
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Sep 2020 19:12:03 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id b9sf2132912vsd.13
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Sep 2020 10:12:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601140322; cv=pass;
        d=google.com; s=arc-20160816;
        b=clvmHjVel0TPyvLRXoivtbnIw1YVUlUotTpHzJ0unVb1TsZuWU5VFvFwHkTb6Df7LL
         pKMtfxPHObzBO9LbDozZH2vQbq9NGUJN2lcYOllpIsKgMhJKDlIaIaVvRpblgCPwNBt5
         ZYhjseNmDGCacWR0hu2Vy3MzODUXJX5Gmf5gB6OHOB3r0QoOBPP1jZDWsVM2cgVBsrQ5
         YEikW3NzMhPHWKNOUGlx0FWxC5oVRkbbtcDi+A4idk+2Md0TQR/3rCqqpU8eqDQNvIAN
         X/qv7/mG8/+DBSIPQHRQJDi/C/8J7B1ouy68l3Jy4Q+txAbT3iN752jRVc8QfIDTLDnh
         MThg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=WVqE85sccFl6H9cMCqFlEwVGpQZl8e/T+o6t/cEeFWc=;
        b=WOYU1VQyRCg9XmNqeepouriCLPf2AQHomy/GiD5EWp7DDjrBCJYV8R1N9LiPFzDzym
         kOURSGEgeFJ+iPLpV6ul7QWB1kmcY8DQi+lIiYVaZcpIT4yuCEK258kP4Bdyf9OOmqZj
         kw9lPS72Hjo7MowO5F4FpIp+Ex6ogI+lk9FFvSY25MzLoEX8GuHzlCK0/MtNqSJH2mdq
         SA4mmAbeuT7PktA2Ce8OPFGg04xdv3fYvtjzmO7WVshPmzQtAu+8e8yHw2VGE1/kl/Ui
         CI0scQlL1V2GV1v7Qs3tLRadgOK5m20VCo6cAt9ddVzSm6UJsneSNfFNXaf1Q52tF7PE
         FjFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ERhpLLwM;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WVqE85sccFl6H9cMCqFlEwVGpQZl8e/T+o6t/cEeFWc=;
        b=AXXExYpY9nR/MKg/EL3TLqbThxnHGX2SKTg+39yi4fQRuecYF+q+6csEEXlcWFNnmv
         6AZ0qOGGq1mgSgQAaaMQZZgdtU76H42KBzqbnvcDkEzqlv0Vb2LRb01vqQthWbEzgwre
         m3krP8qW3dFIz7N+GBOxq1WmYiH3ZB356+RlbIlP9EaoHYVncSTjuso3CbNMQ1VwXJA8
         cBEa8GPIioWSM3MXsD6XK2+xUblRlhfRztTSq/XszRFlKAPR+HSndCgSATjly82C8FcX
         zMri2PQDQdrUhgwypwcTVW28aDZRg49SmjhPzAnY89yYrCqo5Q2LXjelG9FgClRLXjiP
         f3mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WVqE85sccFl6H9cMCqFlEwVGpQZl8e/T+o6t/cEeFWc=;
        b=gao+IMifKSNZsx7fuxHK/E0fBhwEyrZqiahqZZnJmivontmgV5CdwT/zYXdke8HP8x
         TLW3dUObMySW9gSXWWq6KiQsA8bBrkn8xP1ps+qlPDSaV9vAMz2j7aW2Cctgom+GURhu
         Tr/ZVgm/kIvPKW29+bhlNphSPUbFle8sx18kza9YcsGaMNheaxLlk9wZ4CemTryEYuSW
         6dGfCmJuGUTV2nv4yNrWLt1ssLsPR3J8LVt/LcTUP9zKrWpPSnnDDn1gU2g6VrZdwtjz
         fiV07I+9AaXC1M/dWs4wxoB2MCKX5omc9rJwdEqEWfkvac9iokI1Osg+eRRacKxBu6aE
         aDBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YWd740SUWi0F0VdqAW16T/4Plq3cc+qBSbDV8N1sbOXsijHth
	15nHv2VQNJN/tQKXjaQT/y8=
X-Google-Smtp-Source: ABdhPJwEnHCv4X3jWmTYZ1jgbNRx27EfS9pAM9uCiFPWuYY98hqqqO3bGdQbbbAHn1EBkwfea1BhNw==
X-Received: by 2002:a67:18c5:: with SMTP id 188mr2222640vsy.30.1601140322545;
        Sat, 26 Sep 2020 10:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2e6:: with SMTP id j6ls834112vsj.1.gmail; Sat, 26
 Sep 2020 10:12:02 -0700 (PDT)
X-Received: by 2002:a67:fe8f:: with SMTP id b15mr2033057vsr.46.1601140322042;
        Sat, 26 Sep 2020 10:12:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601140322; cv=none;
        d=google.com; s=arc-20160816;
        b=tUNA69IQwmO1hmKtATrwe0ue1O8ppGsX2Wz5hcxi5nLRmeaVOGVi/rcId8q0EAZZPh
         3ZJmkLS1SgicGxfx3qa1IAZL6eoFLNe+E9XhNkYZzmNWzmOcxEUUaktnP3ma7/ajMKrZ
         X8Y3kGfarHdI4boQUsZ4TCKAGZSE/ISUm9Rgymt1WSMoShyMhemV1mA88yDOgD2UbOfC
         w/2Z4EtY2DNW+8zjizwneRK4PdryDWjsfbdqx6UoMP8BwmcejzI5WRWMc5Djf+guQblh
         UmtuK8F5zBns1N8ZuIMqBbcSMkUK25BdEp0zO5h2EbnbVAW1IzYA6pR9qtbLhnBJR6rd
         Y1lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=ftBotKe73TtK65EhVOkqgCswQ7tnRRnYOTiRhxGmAnU=;
        b=W6yLg/0jfInYA4tKREjXLde+13pwU6x+343fQR/6gqKXvCB8ZpOS3rzvfT++Z+Pm5f
         XTjgfWs5ECyowpc+zmgath1ChmNxtvTd/1CZ6ByLSOZiCssjjru1xpqDyYcbyopRGP4G
         cWTXmYvFoemFweBJOMUZ3dyyRa5oWkVzUMKt9pGuoAj/T9MVb26PDzUZ7kzJB7nO4am5
         epm/HEZp7fHFtrk6aml1YVwgdqEy/KIJSNCHh8wV5OJaKxBKZsYDlOQdEqD7Mqpe8T9O
         qbcDE8u1UyIv+AZZoTJZbAAVFFbpj6fZXyNTyNl3RElQ+jz/ekmey2XYCO2w6BvZYcbB
         dEaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ERhpLLwM;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id x127si335186vkc.4.2020.09.26.10.11.59
        for <kasan-dev@googlegroups.com>;
        Sat, 26 Sep 2020 10:12:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1bb9e9cc36024dd6a690cf0789c923d6-20200927
X-UUID: 1bb9e9cc36024dd6a690cf0789c923d6-20200927
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 725674751; Sun, 27 Sep 2020 01:11:54 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sun, 27 Sep 2020 01:11:51 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 27 Sep 2020 01:11:52 +0800
Message-ID: <1601140312.15228.12.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Thomas Gleixner <tglx@linutronix.de>
CC: Andrew Morton <akpm@linux-foundation.org>, John Stultz
	<john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver
	<elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, "Alexander
 Potapenko" <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Sun, 27 Sep 2020 01:11:52 +0800
In-Reply-To: <87wo0htqco.fsf@nanos.tec.linutronix.de>
References: <20200924040335.30934-1-walter-zh.wu@mediatek.com>
	 <87h7rm97js.fsf@nanos.tec.linutronix.de>
	 <1601018323.28162.4.camel@mtksdccf07>
	 <87lfgyutf8.fsf@nanos.tec.linutronix.de>
	 <1601025346.2255.2.camel@mtksdccf07>
	 <87wo0htqco.fsf@nanos.tec.linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ERhpLLwM;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Hi Thomas,

On Sat, 2020-09-26 at 00:59 +0200, Thomas Gleixner wrote:
> On Fri, Sep 25 2020 at 17:15, Walter Wu wrote:
> > On Fri, 2020-09-25 at 10:55 +0200, Thomas Gleixner wrote:
> >> > We don't want to replace DEBUG_OBJECTS_TIMERS with this patches, onl=
y
> >> > hope to use low overhead(compare with DEBUG_OBJECTS_TIMERS) to debug
> >>=20
> >> KASAN has lower overhead than DEBUG_OBJECTS_TIMERS? Maybe in a differe=
nt
> >> universe.
> >>=20
> > I mean KASAN + our patch vs KASAN + DEBUG_OBJECTS_TIMERS. The front one
> > have the information to the original caller and help to debug. It is
> > smaller overhead than the one behind.
>=20
> For ONE specific problem related to timers and you have still not shown
> a single useful debug output where this information helps to debug
> anything.
>=20
> > I agree your saying, so that I need to find out a use case to explain t=
o
> > you.
>=20
> Indeed.
>=20

First, I think the commit log =E2=80=9CBecause if the UAF root cause is in =
timer
init =E2=80=A6=E2=80=9D needs to be removed, this patch hopes to help progr=
ammer gets
timer callback is where is registered. It is useful only if free stack
is called from timer callback, because programmer can see why & where
register this function.

Second, see [1], it should satisfies first point. The free stack is from
timer callback, if we know where register this function, then it should
be useful to solve UAF.

[1]https://lore.kernel.org/linux-usb/000000000000590f6b05a1c05d15@google.co=
m/



Thanks

Walter





> Thanks,
>=20
>         tglx
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1601140312.15228.12.camel%40mtksdccf07.
