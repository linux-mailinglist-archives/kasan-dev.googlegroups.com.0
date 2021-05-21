Return-Path: <kasan-dev+bncBC27HSOJ44LBBU4QT2CQMGQEYCZHLSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 740CE38C472
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 12:15:48 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id w8-20020a05651c1028b02900f6e4f47184sf4905929ljm.5
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 03:15:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621592148; cv=pass;
        d=google.com; s=arc-20160816;
        b=eO9C8w/k5Hcf+VXGmFwmrUCnBe8i1GvFfRCP6H0piZj1VdSx29S1azDyzlXc6b+bZJ
         nRZu+NFMKPfXvbcsmXa/q54jkixvOkUyRwAnIzcjP5IpFc2R90CAkIEm2VoRuQ/fPa12
         T8TA0hMd4Xp4OKwk+wrk8RdZZMzuJ/QcYefJ/EqFQYywUsOvqwM+F1l4Vg1TccY8K6uq
         wm/LR+iAS3dTokjAJjw8BM77y+rp9DZlneTxc5urJNVLCQIMiy1Ky6/+at/CjFR4n60V
         8iuuGX9sH4NSLe1Kw+5pSzFogXr29bu/BjrAjb4co2HwnuBdeG9S+K+zzKsIfvMLQ4aU
         iM6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=4vGODZ1mDweMOLRSOPjtH913wHVfuZUAMC/zfwzCVVE=;
        b=asZfmebaqYbYU4tTCkXdWd9uTQfC9iMHBbbhyw6l1JuxiI186C65/A2wTKmv+WpfcP
         390t4tzbeHJee50Wgh2FXGb9+mtICwWNPUEBViNhEbUGfWq382dGrx6Lbs363PWNgDY+
         ThhQpUeAbPorZv069gO+lT/7Sca2v3iYMVWxuGbHrg4ahxAu9gGACvTNAVURNKjhGkGW
         ATbvy014tamgl10Ieoa8ReET/nhN4BQy4pffYr/UJCfF5eHTyTWRmFRwp50ICdGikahx
         Zn4+xQ9uS/bXgr36AnISyWNl1+uSeTSMDiYzA8MkxxmO+dHq0Y33FpCvnB5YlrxLpgR4
         8aiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4vGODZ1mDweMOLRSOPjtH913wHVfuZUAMC/zfwzCVVE=;
        b=cOBDpe7tbmO6Ha/se9mobi1LLWi3u2nOXFf6d4TKyAeCT9ih9hFhBXNNb6uOVK/ncb
         CYgxmC7RMNiyBlWam2Vnb5ZBZtzmc6NRvwp62/+UEUCnoghS6hzLVEagKvtHkU33X8RH
         xo9lHbBUOjPLDSQ8XcYxrfi79Ec9zsAzhVhb1wKvQv/Jis4HKhIHQhXYISCRf2i9i/1Q
         NdWZyPM5leB8Z6syIWmCdmuca8PsIaX2cDNOvZ9Rf1Jf9VuibsiAqfUK9q023AcEXg0R
         aD4Ek6+L5Ke5ijSoYttfO78UL8NnxCi54/D4zveT+1fMHIMsknyY9HtMaKZ43Nl7VAnF
         KmHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4vGODZ1mDweMOLRSOPjtH913wHVfuZUAMC/zfwzCVVE=;
        b=i5yBbls6jq6XLEoq+i1jQzNAnsFJfgaeX0bi4yF0YUO6zcAVZTdhDAnSOto4TNWI6j
         aMlu+DrLhFgdB6He5zGCsBEAL2tCZmZ3N+NN9L909C1dQO9krWC1pVtj4DvxLBdG7Ut/
         mYWobSNIFN5T3NSgblcpZtm6y/o+CT/Ba6Djz3+KvRHbkaSU5bnRsCrW4AvfF0/cRaj3
         edmLQJHEK+hY+sN+4DPw69n+WYipERVIFHZTDAggt8xShDckkNby7ByhMrVjyQWXjfV2
         oIKsyCzKvL3nJl1nYC+l4YnS+bF2d8WEuiJaIefZxN7GypThVg5KJzgDdyiP7a0iYhsV
         XAzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530V3JLqUG5GKn4/ReqTsQOdM9sNvvPSR/Ktt77ciBQzoqAcS2lh
	iEDlzRJFqshW/o6qDGM19hU=
X-Google-Smtp-Source: ABdhPJx6K6Se3RnBtPU2UwbOu8opqIi3/CrARngX7764cHW8sxmpkWm77DgcEUx0sO+ZanAJ7Rt+Vw==
X-Received: by 2002:ac2:428b:: with SMTP id m11mr1733457lfh.290.1621592147919;
        Fri, 21 May 2021 03:15:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:592a:: with SMTP id v10ls286621lfi.2.gmail; Fri, 21 May
 2021 03:15:46 -0700 (PDT)
X-Received: by 2002:ac2:4f8b:: with SMTP id z11mr1713669lfs.482.1621592146879;
        Fri, 21 May 2021 03:15:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621592146; cv=none;
        d=google.com; s=arc-20160816;
        b=wbNTYWwwNmbdHT2VD9UUjkAoEAKC0Qr1Kg2n32VB2OHvZlr2PgOSXDylJbnqFK9nWb
         gA9K5gQ4Cb9uc9mQEr4Cs8n0ddJsjXzRlTuT5D0SabRDuhUscR9Tcxn0OGszdks0fD+I
         nGfuX73wGUES/lJgjKf+qgaAyvCMAYgqf4cItK3jJE6GGoTI0geI0KgC+W49YUJ6ESB3
         sEopXXDdBzuMZdFmfNi1fWpIAe29o1uo1bEiADfwpb5q8wgTxuaQMG6vu0wXOSZik3/a
         MEA91xfZh8kAfCwbiCOPmo85pvHKbDcb/Vp2qr+NA70tivf5c42GCwj/ow2T0djl3lIy
         ehRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=A0rNKj3/MPT1MOEhh/ors3nTMtR2W02VuVLalY6p+Rw=;
        b=fpNk/g8owncn4Pqt26syW7xDkcovnqR7g4HOHCAqjX3do81s/SBIyAx/8BETYyHViA
         jK5me10FIFpb4/3dnkPYcvuTxuCN0qhBP8Jp+JTKGg+7DS2AWjUZ8Hj2RzSVGA0isls0
         RyQS8Go0cuH96+Ovhquh6hjjO2cXCdyyomX1TyvSw/6KHnRltUdK8FtbatYWdJRvCtl/
         N4UcWOlrq97ojOj2Dto/k9vsCU2bHGjeeRFCQaMHFMlwAmIukGlnLhWzJKZ0xWCjgQ91
         icIAjVklGgXeGHjMsfZwPsYmh2gQT2LchLI/zVl4h32SaTPDxyM6xTZZ4rUKBykVX6OA
         Q6Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id i14si200802ljg.7.2021.05.21.03.15.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 May 2021 03:15:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-60-mPtdTae_O0O4mr9Plldzpg-1; Fri, 21 May 2021 11:15:43 +0100
X-MC-Unique: mPtdTae_O0O4mr9Plldzpg-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.2; Fri, 21 May 2021 11:15:41 +0100
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.015; Fri, 21 May 2021 11:15:41 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Marco Elver' <elver@google.com>
CC: "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"glider@google.com" <glider@google.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Mel Gorman
	<mgorman@suse.de>, "stable@vger.kernel.org" <stable@vger.kernel.org>
Subject: RE: [PATCH] kfence: use TASK_IDLE when awaiting allocation
Thread-Topic: [PATCH] kfence: use TASK_IDLE when awaiting allocation
Thread-Index: AQHXThvT1D7AluRty02nSL8F2LU+eKrtrQGA///ysoCAABhIIA==
Date: Fri, 21 May 2021 10:15:41 +0000
Message-ID: <4a93b6d6c82049fc83004104f3e76fd7@AcuMS.aculab.com>
References: <20210521083209.3740269-1-elver@google.com>
 <bc14f4f1a3874e55bef033246768a775@AcuMS.aculab.com>
 <YKeBvR0sZGTqX4fG@elver.google.com>
In-Reply-To: <YKeBvR0sZGTqX4fG@elver.google.com>
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
 (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as
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

From: Marco Elver
> Sent: 21 May 2021 10:48
> 
> On Fri, May 21, 2021 at 09:39AM +0000, David Laight wrote:
> > From: Marco Elver
> > > Sent: 21 May 2021 09:32
> > >
> > > Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
> > > allocation counts towards load. However, for KFENCE, this does not make
> > > any sense, since there is no busy work we're awaiting.
> > >
> > > Instead, use TASK_IDLE via wait_event_idle() to not count towards load.
> >
> > Doesn't that let the process be interruptible by a signal.
> > Which is probably not desirable.
> >
> > There really ought to be a way of sleeping with TASK_UNINTERRUPTIBLE
> > without changing the load-average.
> 
> That's what TASK_IDLE is:
> 
> 	include/linux/sched.h:#define TASK_IDLE                 (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

That's been added since I last tried to stop tasks updating
the load-average :-)

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a93b6d6c82049fc83004104f3e76fd7%40AcuMS.aculab.com.
