Return-Path: <kasan-dev+bncBC27HSOJ44LBBFWE46TAMGQENKCGTRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4637F77B391
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 10:13:12 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe6141914csf3535233e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 01:13:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692000791; cv=pass;
        d=google.com; s=arc-20160816;
        b=owNtdpBIhStqzGwFXNBljqO0VN7NCz8uWFhAEfhi7Smh1+1+50Tj48+squA9MECYpD
         A/0gSVP5frgu3dlZ7qLoWaxUKCgbnRs3csQE2ndAqFCO2hPSMR4cWqWmQL+4RmuVRMMB
         eS9PGfB9JGDA8bqsuoTv083ynwvlNcuGRwnJX7l0y+r+cqnSUslvHq7Zsgk7MpwEE8h4
         SaZLBH3FtgndcAvy2SfnE3A8Kvji39KOIB2EQLQq+Iu4S2gq6Q7RdLROUdCz7RdqW54s
         Bn9f3qyWRF7b1cajcLY7ry5asfX4zPMzkBJTgiAcXnWo5zqD/Ae9JS0s5cq/yHJ18p1p
         EQoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=OLamtQOjeIUHnACmZfG0qoKmVQgRKOFGC19CJO8zShU=;
        fh=8e35uhb9goEQtdkGmRkZft++HtEPVCFTqu9vUe32zZc=;
        b=JEc2cMlfTvQ/va8dL6vm1GXrC+6/ozzchvg4KXHYNF/zO2pnQ+jtuek6rslPqF9NlZ
         Xak2ETZhL99pps0/fbMPA4OecjHF/QqVn4fkuHqTQlMDXpCIw9BQk1TtSTLgsEeQ8VUd
         oTE+JXkepVa36Yy3lRqy7tF3iG/x7qyWLns6MvzZPDl5YyA+I/g5Lla//Y3SiSpGcZDn
         snp3fa26wsCUOpPy3UhewwoylQ6WEUuNSHBG9YA/HrddRisgthN+tGwMdzncQyx5BZX9
         1X9TU9e+SrH0OjiOs9rGuyohUkJI+5rnGtL4hIaSkzAvkcc+MFiAqxznJIt/XhlV/IRY
         Sh9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692000791; x=1692605591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OLamtQOjeIUHnACmZfG0qoKmVQgRKOFGC19CJO8zShU=;
        b=Wv7mxpis6bnHWz6tZQ0/vH6DQWnq5K352ntqrfaHLJ2nfVyjohlFsPHla9aaAiGN/Y
         LEul2O+4IeZphQDgiwlgr6PHMcw1ATVWQiGrZOhVV9uEU1q8ZSeQsNWR6+RiHtxLsgPH
         01GLpmwePcsyVUG643rRkvtUS0aT/tbAujkGQ4t/yFp/NzoZuf92mSNY7UkTDYVDBG5N
         RYzD3/QC/5EXMJZ7VdBWat8LvMdZwkTD/wGE+J00F908+aO2f5Qit3qYX5EA95CICBX1
         Ygd7a9M9ra82tTc2WlgjzMlr91YGjUcf/SC8Sbn2GCs8ucQHqjEafpf6QuRyrL0bPxnc
         QjLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692000791; x=1692605591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OLamtQOjeIUHnACmZfG0qoKmVQgRKOFGC19CJO8zShU=;
        b=a1Oshu6/aUvrBMivzlpfvXd1i3bmcBSGMYywnm2PTmq9JSVkxG5NqseEk/OnaxkGw7
         eMUBBpFOuaAzZjPyQpJ/4lLhH0wWTc/N+tjm1Qc3g6mef7qeJlHRnIwE2Z+TBZsL1tOm
         OHOIpOtH8vvhzl1pyyHtGlekHHcPwghb7fxb4YudStPRexPpaFM7D1tUiVdRCQuBlHE4
         mKWEYT+awHE50CeVSjzdRBJJCslldCREJqvfSDnLT1XT/rNxvHP7PxDXScsgjNts/5JR
         VZqz1zBkwfow6rKWq+ZCylNTY3p84Popz9igKLYv/vaOPbasGBIv1ewGD0Lp9L+TCHNs
         09ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw69KyzjCpQKZcqd1I+OfHUjOuULpxw+IkoGa3Fk5UtoKCg90jK
	YbIbvfluffBO+9r7IRs2TUU=
X-Google-Smtp-Source: AGHT+IEr2YpGD1ZJoMvne5hHm9bTNz2MA+bLuLRsGUst3/n18+EQ4I4GnxIApVSQpD/clOc43fNJ4w==
X-Received: by 2002:ac2:58e9:0:b0:4fe:8c07:98eb with SMTP id v9-20020ac258e9000000b004fe8c0798ebmr4957545lfo.51.1692000791132;
        Mon, 14 Aug 2023 01:13:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:464e:0:b0:4fe:1116:70d1 with SMTP id s14-20020ac2464e000000b004fe111670d1ls361696lfo.0.-pod-prod-09-eu;
 Mon, 14 Aug 2023 01:13:09 -0700 (PDT)
X-Received: by 2002:ac2:5499:0:b0:4fb:85b2:cf78 with SMTP id t25-20020ac25499000000b004fb85b2cf78mr5057384lfk.37.1692000789270;
        Mon, 14 Aug 2023 01:13:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692000789; cv=none;
        d=google.com; s=arc-20160816;
        b=mZ7I8zRHWWm7Aiq13MnCO5+63potWgwGgxOVx18v3XCuDQS/csjFtMwmsvW2Noo9iv
         sx5ER424gDsJN+v8llIL1wSQsHWo/iclVPuZuNVKVOoMP3PiG+MZoDxQqTyQzX4EV5eC
         bDqQaFUX6djun5N3z7k61IunvVmcBjU7FdeHwZF93vI7ccT9BSy2GjzFs7RUP+fYQrhl
         tlvaeefuH0fRpw4/3PZAvckLcnq37rNWNz0nTgR5Nm7V11GWNWbFu8jJGcmqooweI8e3
         PplZjpYa0EyL2TV3zbwYEkbD539hpMmpZNg6KCef4ppNQkn9Eerfi4mtVPmAYvgj3IK8
         EXtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=6d2fio8+Mc36X6CW3/yWAc+fP5hCiMBhzd3xQJcidbI=;
        fh=8e35uhb9goEQtdkGmRkZft++HtEPVCFTqu9vUe32zZc=;
        b=VeZTgYcP4V4pd060TSY98yDkHq47yd2KBT6oRvHKKcw4XoIiNbzswXPqd03ZO3UTgq
         lW/Lw0w77/fWaS2/TyySMlfxU+LHkB6J9O5Afneja7hPA5qt9p3npfFBbn0mufVAuMvW
         kHDeOEKGmRIenz59JZBiRmnRjFdlrG/RIGU1QAzp4ToFBkMzIC09+D2CIS2zIFaiJRBd
         9YJguAuOlSv8J3LXXXesJD2M7uAc81DUftvpzt9dyEopgw+da6iiHGoCAdp0XdUmUOsq
         78Py/1bE13bMD82BQSBIxqSDaTbZmfn/6V/zmT5qhXFlGvwLVS2c+RL6JSr10rDYmPjr
         Thxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id j2-20020a056512344200b004fe3478235csi657243lfr.7.2023.08.14.01.13.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Aug 2023 01:13:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with both STARTTLS and AUTH (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-72-b-sFahrIMv2qrldd8e66mA-1; Mon, 14 Aug 2023 09:13:06 +0100
X-MC-Unique: b-sFahrIMv2qrldd8e66mA-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Mon, 14 Aug
 2023 09:12:55 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.048; Mon, 14 Aug 2023 09:12:55 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Andy Shevchenko' <andriy.shevchenko@linux.intel.com>
CC: 'Petr Mladek' <pmladek@suse.com>, Marco Elver <elver@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, Steven Rostedt
	<rostedt@goodmis.org>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, "Sergey
 Senozhatsky" <senozhatsky@chromium.org>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>
Subject: RE: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Thread-Topic: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Thread-Index: AQHZycNoqz0YrpkIvk2kVFpZOdRD+K/hpuuggAHNtgCABgRJkA==
Date: Mon, 14 Aug 2023 08:12:55 +0000
Message-ID: <da520d6fa03c4645a28e5f4fae013d35@AcuMS.aculab.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley> <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com> <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley> <900a99a7c90241698c8a2622ca20fa96@AcuMS.aculab.com>
 <ZNTifGaJdQ588/B5@smile.fi.intel.com>
In-Reply-To: <ZNTifGaJdQ588/B5@smile.fi.intel.com>
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

From: Andy Shevchenko
> Sent: 10 August 2023 14:14
> 
> On Wed, Aug 09, 2023 at 08:48:54AM +0000, David Laight wrote:
> > ...
> > > If you split headers into so many small pieces then all
> > > source files will start with 3 screens of includes. I do not see
> > > how this helps with maintainability.
> >
> > You also slow down compilations.
> 
> Ingo's patches showed the opposite. Do you have actual try and numbers?

The compiler has to open the extra file on every compile.
If you include it from lots of different places it has to open
it for each one (to find the include guard).
Any attempted compiler optimisations have the same much the
same problem as #pragma once.

With a long -I list even finding the file can take a while.

Probably most obvious when using NFS mounted filesystems.
Especially the 'traditional' NFS protocol that required a
message 'round trip' for each element of the directory path.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da520d6fa03c4645a28e5f4fae013d35%40AcuMS.aculab.com.
