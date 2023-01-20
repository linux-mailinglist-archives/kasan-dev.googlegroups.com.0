Return-Path: <kasan-dev+bncBC27HSOJ44LBBNX4VGPAMGQESXYLJJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 88DF8675389
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 12:42:47 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id r15-20020a05600c35cf00b003d9a14517b2sf4663757wmq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 03:42:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674214967; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHouy7UM1kFEIvIJCzJRXIngRcFr/84O257OSL9wrhFKiajjPtCEM2vpo2FSDyrrTj
         Wk+u1+uYmUl2HhuVJi6r6wJ5vjVdnDdoR6A3sIKYIDnIG8AQSaDfUogfMQODJxx8r5PN
         PND79v0z4W7dLdPCzZpplg6KMSy98UAaZbBELncuL5kTJJgw1byOjQOI/gDuFYV+Kjb2
         5yAu5mSaSv5yvCgEpBmMDbSoxqZUdOkVpE4r68WEcS/Y+L/8cp3xWR2pPK/wOxqVKkcY
         LrDSxlpUkSRx3YRsnBRoPbtnMNhAmaQ+Cxs4IOQDAabiz7Kv647KST4Kucwgp/rlLtMn
         WA0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=f34Tj84Dp0Cn2gyucZKfU9c5Po4tObBOx+4R6NKAz7s=;
        b=d6tAXZwffoa5IhtWayZKD2+FzGCqgEIYQIpC41g3z53xcocrcaRjlOLHhNwWyB9vjP
         upGv1kae4GlWUw0+h1VBEf8Ncn/fvTlzdQD28cg/k8e+rqotaLqqR2NoPIdPUNj8IT+0
         1HnOAgGr1fCzGYSMnpWv6fHHw1NLW3MXH/E+k1hnBxYLrrDKJhy87jYFBifVaS7EJZPd
         5xcqQm7zEusqUhkVmFDuyySeraPV6iu4NNJrsqqHo68eIkOVWopqdYQvrmJlmFaBMHDy
         bco2JDtfIkqe7spB1jwQMGs9xDybX6AgwNEQCIh2ouSQhPAKDV+7twna6Oy6/3Zzi6Qs
         nS/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f34Tj84Dp0Cn2gyucZKfU9c5Po4tObBOx+4R6NKAz7s=;
        b=q9wK6GlTHD28ZOLGRdyfrZbl+ONIJW2tZXbzuwRnzqejOX4d9/4+t4QNmVtxHi2kDh
         iOEt8Uf9PXzQvLcJ8uIierLj285/7jcuvtMAP8DHDDsGgm7D2zmziGolTZ7fDNhb9jBE
         usy9ouJAPlMIIVLcS8pPldDqStOI4WkDXeIwMBDy8yBmDu8Q1Yow/9NScbgWnmX4KKW2
         EwoRCSObD28jJDmPbk/pL75A/7nRsKDbWtSCU+mu4uK22OZS30cj6PPsxwywEZawEi+c
         rW/OZqTfbhVW4ZA4Rc9phEkOugALlN70wvm6OGM2SmVkNeAZLEyD1ripYXtvsRIZpfjC
         rhRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f34Tj84Dp0Cn2gyucZKfU9c5Po4tObBOx+4R6NKAz7s=;
        b=DSwEdImKw4QzyhVmAOUyytTm3XCPaQNF9EgckfZ08YSsZl3yuXyVbRnfQQL57MkYDX
         WEYWWZddx99BVbJnunR04VhdEFtIx9+GyDy3t1vF8o8ezWmgB0o9t3VYIhGjH4lDencS
         ER9Ow0syTdip2B629EEljCUz033M3+xjIseytRzNu+jmuWuHZpg+IAdLUcvyAyQeub7F
         4K/l+hDJglbJFqcdP886RKKO0xkixSy9CmZSSOfPZHu1tWqelP3FPOq2ch2tOVoqg06D
         Juc6FLSSsx1x8uU/erNyOBCoH5xHyfc+pl9AR6FVLhXngQLux1gBsTtoqe8TfZtqH5aV
         VYDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqNhWpt7NujPWTXglT0zJZvdrEvTrLULYhRDOEG4A7I65p3ntpg
	qa3nLfudluoRcxgul7jI4r8=
X-Google-Smtp-Source: AMrXdXuWn6iG1Qfeme1CPuyiE/0WMFe/YMM1db/zt/zo0+iTJvXjSd6cIdXUcQyYy1a2+XmhJuz5oQ==
X-Received: by 2002:a05:600c:4e0c:b0:3db:15d9:1484 with SMTP id b12-20020a05600c4e0c00b003db15d91484mr628598wmq.200.1674214967032;
        Fri, 20 Jan 2023 03:42:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c7:b0:2be:34f5:ab03 with SMTP id
 b7-20020a05600003c700b002be34f5ab03ls982317wrg.3.-pod-prod-gmail; Fri, 20 Jan
 2023 03:42:46 -0800 (PST)
X-Received: by 2002:a5d:59c7:0:b0:293:1868:3a14 with SMTP id v7-20020a5d59c7000000b0029318683a14mr9676583wry.0.1674214965979;
        Fri, 20 Jan 2023 03:42:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674214965; cv=none;
        d=google.com; s=arc-20160816;
        b=F3IByXf0fjlnS9aNVkn+fJqQsD5j914JHhtgPktkw+XSg1+RY53MSKpcGYfSsRKA3v
         hZcrWA95lC4ntGzza1TkTmtlRVZetj/we/o+IkTjK5io1nLdmlUyHRJn4B9GCgRFCj+n
         ftqf0kH/VRp2Z4cDnycLXexzZ0zhLlCz4yWwER7tt6mBkdEruJxDF1ZukhfcQCJ4qrC6
         hOgHxmOc4s745VhJLtrBE9/mE0nrG8lBiI/l9TaNo2WFQtIGAqKz3MMOjxxzWmLTofsp
         QNpL7CSRdlhMiNHDSmHud9uxlM1ABqvUm36RgjCHS/4WmAJtLzfIuS1zhkf4G6FALEtW
         pUSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=e8FecXcOocV24EzXGtkpJ8Dhj7SttAoq1+DWjNIDOoY=;
        b=jpCGxJkkOirch9q+hfKNhB+zGCmUzG8qSsuYgn04wl0awyOMu5OQf//65E9pTxJnzM
         dlN8M5B9vFmQ+/woN8+TU7Vvwu7V9M6G1/u1O147SrykYb/hxxF1mOws26rXC0RRhHhF
         Gc3bRJvrJAXt3wPBHUqcyjnHtKdr+ibyaAu5JLQB74F+DD5op0GQ64ELEvj3vbsgShTp
         2SjqXHfDumg5fCo6+LW2pRj7rqUg57JY0CCFGamPqgNRqHsAwJfgMQ4Z1juAzlShdOrp
         cJH6HOYc1wYc42450EvJ589YWWu22H+JRMOy8xDaYQFd4MDgvoSxYt3x+/sMyHo5qVjP
         fssw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id ay20-20020a5d6f14000000b002367b2e748esi742096wrb.5.2023.01.20.03.42.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jan 2023 03:42:45 -0800 (PST)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-129-4gsduPDlOrGmwEjdKMB1gA-1; Fri, 20 Jan 2023 11:42:44 +0000
X-MC-Unique: 4gsduPDlOrGmwEjdKMB1gA-1
Received: from AcuMS.Aculab.com (10.202.163.4) by AcuMS.aculab.com
 (10.202.163.4) with Microsoft SMTP Server (TLS) id 15.0.1497.42; Fri, 20 Jan
 2023 11:42:42 +0000
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.044; Fri, 20 Jan 2023 11:42:42 +0000
From: David Laight <David.Laight@ACULAB.COM>
To: 'Segher Boessenkool' <segher@kernel.crashing.org>, Rob Landley
	<rob@landley.net>
CC: "linux-xtensa@linux-xtensa.org" <linux-xtensa@linux-xtensa.org>, "Arnd
 Bergmann" <arnd@arndb.de>, "linux-sh@vger.kernel.org"
	<linux-sh@vger.kernel.org>, Michael.Karcher <Michael.Karcher@fu-berlin.de>,
	Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
	"linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>,
	"amd-gfx@lists.freedesktop.org" <amd-gfx@lists.freedesktop.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, "Geert
 Uytterhoeven" <geert@linux-m68k.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, John Paul Adrian Glaubitz
	<glaubitz@physik.fu-berlin.de>, "linux-f2fs-devel@lists.sourceforge.net"
	<linux-f2fs-devel@lists.sourceforge.net>, "linuxppc-dev@lists.ozlabs.org"
	<linuxppc-dev@lists.ozlabs.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-media@vger.kernel.org"
	<linux-media@vger.kernel.org>
Subject: RE: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
Thread-Topic: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
Thread-Index: AQHZLL5SlbpKhYJiU02AbZRDtfTmb66nLCYA
Date: Fri, 20 Jan 2023 11:42:42 +0000
Message-ID: <931141d03e8748cebad42aff1a508d7f@AcuMS.aculab.com>
References: <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
 <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
 <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
 <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
 <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
 <0f51dac4-836b-0ff2-38c6-5521745c1c88@landley.net>
 <20230120105341.GI25951@gate.crashing.org>
In-Reply-To: <20230120105341.GI25951@gate.crashing.org>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Segher Boessenkool
> Sent: 20 January 2023 10:54
...
> > > I suggest to file a bug against gcc complaining about a "spurious
> > > warning", and using "-Werror -Wno-error-sizeof-pointer-div" until gcc is
> > > adapted to not emit the warning about the pointer division if the result
> > > is not used.
> 
> Yeah.  If the first operand of a conditional operator is non-zero, the
> second operand is not evaluated, and if the first is zero, the third
> operand is not evaluated.  It is better if we do not warn about
> something we do not evaluate.  In cases like here where it is clear at
> compile time which branch is taken, that shouldn't be too hard.
> 
> Can someone please file a GCC PR?  With reduced testcase preferably.

It's not a bug.
All the operands of the conditional operator have to be valid.
It might be that the optimiser can discard one, but that happens
much later on.
Even the operands of choose_expr() have to be valid - but can
have different types.

I'm not sure what the code is trying to do or why it is failing.
Was it a fail in userspace - where the option to allow sizeof (void)
isn't allowed.

FWIW you can check for a compile-time NULL (or 0) with:
#define is_null(x) (sizeof *(0 : (void *)(x) ? (int *)0) != 1)

Although that is a compile-time error for non-NULL unless
'void *' arithmetic is allowed.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/931141d03e8748cebad42aff1a508d7f%40AcuMS.aculab.com.
