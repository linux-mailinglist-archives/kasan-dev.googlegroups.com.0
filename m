Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNWMTD7AKGQEAOX2CVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 144642CA108
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 12:17:12 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id v13sf683403oos.4
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 03:17:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606821431; cv=pass;
        d=google.com; s=arc-20160816;
        b=EwdBD0552ydJwG8SDCaAM2SuzVllDxjduyONWGV7XR4KJGKMIlI7NEjGM4233c5D1D
         FHa715Sk/gCXh00D914Q4lSLypMj1vG/PKXo7kZgLTOJCicCHcH91XiSeXxtCW3EVBl1
         dvicBXSn2cBkh5tCgNo4UtDY8mx/vBNyYBJ5l7mSjmznZGg24NOonnFcdkwzw/zRCkBr
         oZibAcF/4rNsegI3v5HE1gBPjRL7tGIqvNaduwdrTmzatvSYTZxOEcc7Y6tUNrxmH+bh
         Em1P0OC2rEYuYa9FhrKCn80UoqVIOfw4Z4Cjjv230dXu0D9Nt91lTtmu9fw3bL/e/nMu
         sz7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=czmHtRaFiNA5C9CpO0/ruBitrPf6rT8/zeWqoPHoiqw=;
        b=TGOhg/HyOHuBDw2UeO6pi388eP2AJ8sAf0hW8kkJvV4jDBZo8+tZD2yfZ9jz5JiwJU
         YXX/erljA2OSLj8N+h8kHmn4u+WM9rstPIy0hrAkLtFxt4XyfKGMNv0jEjoC+IbCGuWJ
         Lbcjgt+YHt9L7XMUUbnQ8L2zSmrZX2R6RAdFutbY2CID67hayxhxn4mWEYgHNjysagME
         CKcxAr5pqzjtuynyR8++GdnjhHGqTw7TdG3gC20JYEbduHD1jfj1Nrds7VZe0Knd1XK4
         WqFlHgKOv4FFzEID4tHDUxTZ1veZg2HpHZ4c4iJ+mNaqX2mB77Hk4yRo84Phvx/H5PRN
         yJYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kbo2RJQI;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=czmHtRaFiNA5C9CpO0/ruBitrPf6rT8/zeWqoPHoiqw=;
        b=Mky2oqemHETGewFOfA46htaJw37AyhNpK4Jn9gdz8kN0Po9n8p3ZoEdCuswDE2T2Cj
         AVxRK9eRVT1M6BHNWfhnFrT1NokPDKFg8maEJTse3UeLMnWxoZob1bYwKPzUeZKjcyAz
         roD7IvTF1L7VJSaK0J1i3rARFOTWSEWIRXcVrHgs4jxrlO9a0dJCM5GjaABTGP9Wusfz
         Awj2ppCTR3l2EwspXqddxHItMSPSK65o4SM3rxh5TdicQAkON3hhs/6sgodXL0rbLrog
         Kd2UhWJgccGBB5YRGpO5tvPi5aSIRIoOgyV1adFwe7P6puv6Wakv0+71Bdd9/TBZYeIe
         46yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=czmHtRaFiNA5C9CpO0/ruBitrPf6rT8/zeWqoPHoiqw=;
        b=SDNJNfdDRxOC61qDmHJTn8Mvig8mgHllFr3fjb1aWmAZLHpddr21749dGZ3IDfDAAb
         9ONX7j+qX01TAURIZJbTaFiCfqMUqkpFYtuPD3Aw+wIzNZw2dKMfFmIJO0FrfynJ+9dE
         Qyq5muc1WIrhTrggd+EVXVJP0UvFZlZqUFjrYHGY+x3WYgNepYD6NcI6guLrBfeml7sW
         ppaYImv2UxliDlXA5rZCJgU/5UVIkVELWvJeRxebUM5fWIcE5cJCaZZB43GR5VTiuJ01
         T7u+Ilr4qRSmaOh0NiCGPl2FHuXZnJzDwrLidU8Ut9796tPK6xRf2Y5omfzi08xF1cSY
         m2jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531s0wjYNIQTBopsXdwLiaB3libgBlPPra7venhRCT6tsmU7KMCg
	bu3XlrkZNqKMXxZHFL8/xNg=
X-Google-Smtp-Source: ABdhPJy6zXvBnNVjjf1N4MEKniSGFVwOCaKwzaN6YPSNWbcpWjTsn16+oOmHKAhszfMPl4GQEP2wbA==
X-Received: by 2002:a9d:7d06:: with SMTP id v6mr1387408otn.296.1606821431050;
        Tue, 01 Dec 2020 03:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:648d:: with SMTP id g13ls376400otl.0.gmail; Tue, 01 Dec
 2020 03:17:10 -0800 (PST)
X-Received: by 2002:a9d:27a5:: with SMTP id c34mr1335572otb.303.1606821430732;
        Tue, 01 Dec 2020 03:17:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606821430; cv=none;
        d=google.com; s=arc-20160816;
        b=VHA+ht8wl19cVYuERdS3FUyOu72Vp4p9o1kPbF1kfcYmM1zvf9ZCerFF0x1gw7/HLV
         Rq4qUyAIfxNoP6TxXVNKf/j+GkzHzRjEiTQgsD3KbNvTvhmrvHnjAmug5N/iiTI7b+ji
         zYdt1EwBTCMquKjHpHhsGotpRoXr7dd7U7MlaFpz5w6Aoesa3fP9PYkKvFDrkoszOwNk
         JKTp23k6qbALdSaUyVrG/G0exeCMDe/Tz1l+Zd98ZALUD6QDRCHgWSuYlDY7zkUGzeOZ
         4m9o2m9B9wzzNbSW3ST9cnsjX2LzQ3V4wzSu1Wju8aQXgXWXxY+w4uA4zqF8xtFn0MXJ
         7vsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=pDpaexdIMd2G1eFG8LLARx//qLgP1bMHu0BH8xeP5SE=;
        b=oErZTXfU9Ye8/3DSPAh+AfU7mXm3MfQnwUDdRS9cGTHX/j2rKrGZ1eOtdYzYU1qNBg
         n0SbUh02E3H0E1lcpPNayL5a7cI9vAw/v2UyNLlCzKsoQW9gScZIDpBvhLl/+4+RFkaO
         qiI1nO2cZ+hjiWnFwklz2oreiu8qqGruLeLvfA4ezzCO+RoBR9fnR4iFB01L25SNo2+2
         HQcCX0/4mSEh1u5cD3bdnp6PP8Tm8rHoXvZLJla4vFkcEPvAetJxUAp0YUk1meoEOz+i
         LvgylXsZXprRom7T/IDIg8ZIbaXVzAdDwiTKYl2PWKghZAJqAemteybAHRROKyVjCzuX
         4EQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kbo2RJQI;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id i23si85968oto.5.2020.12.01.03.17.09
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Dec 2020 03:17:10 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 32672f8005c64d499a0df082931e5787-20201201
X-UUID: 32672f8005c64d499a0df082931e5787-20201201
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 818032829; Tue, 01 Dec 2020 19:17:04 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 1 Dec 2020 19:17:00 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 1 Dec 2020 19:16:59 +0800
Message-ID: <1606821422.6563.10.camel@mtksdccf07>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic
 KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Thomas Gleixner <tglx@linutronix.de>, Andrew Morton
	<akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, "Stephen
 Boyd" <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Tue, 1 Dec 2020 19:17:02 +0800
In-Reply-To: <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
	 <87h7rfi8pn.fsf@nanos.tec.linutronix.de>
	 <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=kbo2RJQI;       spf=pass
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

Hi Dmitry,

On Tue, 2020-12-01 at 08:59 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> On Wed, Sep 30, 2020 at 5:29 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> >
> > On Thu, Sep 24 2020 at 12:01, Walter Wu wrote:
> > > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> > > In some of these access/allocation happened in process_one_work(),
> > > we see the free stack is useless in KASAN report, it doesn't help
> > > programmers to solve UAF on workqueue. The same may stand for times.
> > >
> > > This patchset improves KASAN reports by making them to have workqueue
> > > queueing stack and timer stack information. It is useful for programmers
> > > to solve use-after-free or double-free memory issue.
> > >
> > > Generic KASAN also records the last two workqueue and timer stacks and
> > > prints them in KASAN report. It is only suitable for generic KASAN.
> 
> Walter, did you mail v5?
> Checking statuses of KASAN issues and this seems to be not in linux-next.
> 

Sorry for the delay in responding to this patch. I'm busy these few
months, so that suspend processing it.
Yes, I will send it next week. But v4 need to confirm the timer stack is
useful. I haven't found an example. Do you have some suggestion about
timer?

Thanks.
Walter

> > > [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> > > [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
> >
> > How are these links useful for people who do not have a gurgle account?
> 
> This is a public mailing list archive, so effectively the same way as
> lore links ;)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606821422.6563.10.camel%40mtksdccf07.
