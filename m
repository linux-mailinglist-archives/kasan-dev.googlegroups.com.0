Return-Path: <kasan-dev+bncBAABBO6QR3VAKGQEUW55WUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E12AC7EA95
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2019 05:04:28 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id d139sf19371941vsc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2019 20:04:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564715067; cv=pass;
        d=google.com; s=arc-20160816;
        b=guNxZ0gqA2qrBVicsgdoPPO51/81lgmahSQQB1nli7HAc0I+lFzuQIJ0b8WOX87NdX
         octEXINvuA/t2G8RhcFj4APyNBcnJA2X+q/ryT6kUgHV3rdTf8KrCI7999QmNr/mkiVY
         TVJpHQH3Im3SscSpQJY1PKEhx6RqttjvrDqwimyndctR/YqqRAVLH53ZAjWpUagIpGfS
         EGAbB1IgdEA23A36MzrcnnSHAD+QgbEdU/SUFVcXrPvcsU6fEXCpoA/sLeLAmkmkVDkD
         dp3gDP1WOr0kQu4achfKArayuC0cVFEPdIQ7Rory0yISErZw+4CVrhm8ZsHuX6uPh0rj
         OVVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=/I/hiTcTqW9cXIAmK/4oFYNn6MfQA4MAfgteCxYmDTs=;
        b=JpuOSQH+57QEqusa1cNZrThFeIwsLNQqv1acFBUS6DXuFtEWRSUhTOZXNCvdh5bCap
         Za9I/+ouguY6SmePMyal/NcoRNOWHpwjrO5R7r+OogxdFjr+UXO90DBw080++yOzu5Ww
         pIxDMdqj2plcPJdyj+0bvXGwvc9gersY95eJOm7hBzywH/+b6FXfTbhrjy3HYGihIOzE
         gBozCeHBgaajfRtXAyNsVOapvXAL1qvIDj4TD0ScxvSeBY28onDnauj56cXq++1Lo6NU
         flUNkjBvn9hEYm8EbI3PYw7+kn2tlNVpn+Dkwg9z2Ss3VLyjo7cqAz4B5CtcefeubAJS
         xwoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/I/hiTcTqW9cXIAmK/4oFYNn6MfQA4MAfgteCxYmDTs=;
        b=kUl2kmTzNSdZKGb17Fx/CrZb/ntn8ywfxwIyWY/p4Dp9Tf+ZxEAy7neRMV9mUVmzKF
         1S84iyk41qortNkntD4q+ghBFKgZUUtbpKitAn1kZxUulIoQ7QJyWDOzJnI3Sh3epYWf
         68R/Ang6lR8xTzxtiXaO9eAht4vFJNXtdf//5cgLhx6thvD7u4taZi8vU2ga3xyydbBX
         Zkbp8UWmFyGi7yAaOsf9gW2dT+pYOqHYt3byMUgKx3MlO1mOWQD3VCO0dYLIXMmKtXeE
         dIR3af1IWBllyTphbHjf8omJuf+xC78zR1qHSC5NcrxNLKe04ENONUPiJ6zuxmBHX2+5
         7xqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/I/hiTcTqW9cXIAmK/4oFYNn6MfQA4MAfgteCxYmDTs=;
        b=iMQBxbTsbjepQPY0YICx6vho1DuRvPZ/LXHXclz0F2J8Q0dT1SYr4S6Jo5dcb7oVuF
         ioO25vBs7DOy6Tt/i7aGkaXfZyfhSCTOld6LEi+uQxCDp69O81BqQGHtgnAmoO+5MU/r
         +ACSkWm2+6urS8tP/EAxH8f84F6Q7XQyPsAbT5PTmUoh+zuf30qPxSkgwTCcH/BccMfp
         uycHySdqDz5Ipm6Ye8zpAq4jNJ8HqbozutkTZoyGyOuACovv8FD3vEIjx946KRb7v1Ng
         Y1xQnPwUpsBDIblpfhqcTmxlVMTZ3abfjrhP4/wCZCJvoHhvhYNmO8bF8MvjgWaZikyn
         0Nwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW4aWKKIwJZwAi0jrISLR1g9VWH9c5gmUqidB7+tlt+ePr8wtQ9
	vyCXfLbjUXiPXvMrdvI3ZaE=
X-Google-Smtp-Source: APXvYqwN1DODgYiIndZl9X5PC/4MyP1G9YzUzYZzK1wiPyToM0BWA50gzUmPQy5PMZ11aI5o5h83KA==
X-Received: by 2002:a05:6102:3d2:: with SMTP id n18mr33834865vsq.123.1564715067674;
        Thu, 01 Aug 2019 20:04:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:471:: with SMTP id 104ls5656929uav.13.gmail; Thu, 01 Aug
 2019 20:04:27 -0700 (PDT)
X-Received: by 2002:a9f:3c24:: with SMTP id u36mr51891408uah.60.1564715067492;
        Thu, 01 Aug 2019 20:04:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564715067; cv=none;
        d=google.com; s=arc-20160816;
        b=kn1UeZOt4KWhWj055ICAkjMCt7MV+VLWNJYBi/3QFBoz9QL4uIAyrMziHHGWP7/q3y
         /3f7db3nWieyIq1TqGJwZD892tzhm7d3lhINFxpJYroRGUrQPMPS7QXoVEcN6ITk2hqc
         XT5AESxvZFqZSfDPG9W+Tj4O7+sRd4t6xm1gyyKjcQlJqqaRkTz0ulUoyj8hOvEAAB5V
         tXC6idysg6DZPFQVjni0PFjBn1qn8w+mwbs/BHzlLDs0KzJEFmpnLcHMkq/9g8YcM6A8
         zsNX4LCiEQXMK2mbaPWlPrBhkwtJ5ySjXCXVB7dyoWiqbLYSE+gh58diAaQjz1jS7oDd
         mL9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=fMGiC+gHRydmpo5zkwmfgrAx10Xxrzh90eBI7yxp1tE=;
        b=mNvqHFcyq1A0c/Oq8qcc0Xmid/d2Zi4hIQYkieW0ZEpvYN91qjBpE83eRcfZSBhybx
         Gaq092j0Jn/WX3F82pWDfCS1m5FC5HMHhW4Bpup8woGuC1WD3n0rEBUJ3abITkRKe5b9
         lCqdeN7I83mgVk7SV1t2Upxm1MyVPU5Tq+p9AZJY2Unkzpbb1zORTEEcxUFgq+CrR7kM
         nOZhosZs1ifQPdF7SO70LXVI7atGJ8w9j7nhdBYTUmUQoi4BYlNQyeDLG10uXGConZDB
         IXMzJCS1qJ2QXHRLUc+lFZnxYEoTLbJgDNkCsTRxiy2gnaJsf8ROaXyEzdhzd+kNqYk5
         b7Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k125si3938296vkh.4.2019.08.01.20.04.26
        for <kasan-dev@googlegroups.com>;
        Thu, 01 Aug 2019 20:04:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c92cdbe318cf414695363abda4ef831d-20190802
X-UUID: c92cdbe318cf414695363abda4ef831d-20190802
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 160514836; Fri, 02 Aug 2019 11:04:20 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 2 Aug 2019 11:04:19 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 2 Aug 2019 11:04:19 +0800
Message-ID: <1564715059.4231.6.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>,
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Fri, 2 Aug 2019 11:04:19 +0800
In-Reply-To: <f29ee964-cf12-1b5d-e570-1d5baa49a580@virtuozzo.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
	 <1560744017.15814.49.camel@mtksdccf07>
	 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
	 <1560774735.15814.54.camel@mtksdccf07>
	 <1561974995.18866.1.camel@mtksdccf07>
	 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
	 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
	 <1562640832.9077.32.camel@mtksdccf07>
	 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
	 <1562839579.5846.12.camel@mtksdccf07>
	 <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
	 <1563160001.4793.4.camel@mtksdccf07>
	 <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
	 <1563789162.31223.3.camel@mtksdccf07>
	 <e62da62a-2a63-3a1c-faeb-9c5561a5170c@virtuozzo.com>
	 <1564144097.515.3.camel@mtksdccf07>
	 <71df2bd5-7bc8-2c82-ee31-3f68c3b6296d@virtuozzo.com>
	 <1564147164.515.10.camel@mtksdccf07>
	 <f29ee964-cf12-1b5d-e570-1d5baa49a580@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: EFC55C8D8568410C5734BD4FCFD4848B3C4EE4673A27E15E32FD2B157FABFEE12000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Wed, 2019-07-31 at 20:04 +0300, Andrey Ryabinin wrote:
> 
> On 7/26/19 4:19 PM, Walter Wu wrote:
> > On Fri, 2019-07-26 at 15:52 +0300, Andrey Ryabinin wrote:
> >>
> >> On 7/26/19 3:28 PM, Walter Wu wrote:
> >>> On Fri, 2019-07-26 at 15:00 +0300, Andrey Ryabinin wrote:
> >>>>
> >>>
> >>>>>
> >>>>>
> >>>>> I remember that there are already the lists which you concern. Maybe we
> >>>>> can try to solve those problems one by one.
> >>>>>
> >>>>> 1. deadlock issue? cause by kmalloc() after kfree()?
> >>>>
> >>>> smp_call_on_cpu()
> >>>
> >>>>> 2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?
> >>>>
> >>>> No, this is not gonna work. Ideally we shouldn't have any allocations there.
> >>>> It's not reliable and it hurts performance.
> >>>>
> >>> I dont know this meaning, we need create a qobject and put into
> >>> quarantine, so may need to call kmem_cache_alloc(), would you agree this
> >>> action?
> >>>
> >>
> >> How is this any different from what you have now?
> > 
> > I originally thought you already agreed the free-list(tag-based
> > quarantine) after fix those issue. If no allocation there,
> 
> If no allocation there, than it must be somewhere else.
> We known exactly the amount of memory we need, so it's possible to preallocate it in advance.
> 
I see. We will implement an extend slub to record five free backtrack
and free pointer tag, and determine whether it is oob or uaf by the free
pointer tag. If you have other ideas, please tell me. Thanks.

 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1564715059.4231.6.camel%40mtksdccf07.
