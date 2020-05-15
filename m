Return-Path: <kasan-dev+bncBC27HSOJ44LBBYV67L2QKGQEYPIA3HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id B16591D4F9E
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 15:55:46 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id qo26sf1115856ejb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 06:55:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589550946; cv=pass;
        d=google.com; s=arc-20160816;
        b=sKJSzD8i0nLICM+ljqldYTEY0jtOvYG8qUO0QUwCtuC07Xbq27Yk8zi1RpDaSmD22y
         Th8/fj6YkuimKfEHtlYTah72ngwmBZ+hyvIMK1HYRE1Zp8riX/PiltG2N9SSEU/253hD
         0Vh+2PG9kH3M/xa1UgyphJeG2+9CqYXwya7Vvt+/XQn4ek1HCT2k+ZX2Ty5/IgB3IJ3S
         hiyAPwppXVcSoQTWPoFM0JutF7Tk9H5EEfpYjgt3cM65LueXSyvo1XG48EdY4eX+Qe6P
         CuyASXlwC4L3Pw3rr15yMwrVvv5QJhBq6poB7GAUDMEB2PVmMFDxtcYvWE0YeDKfKu2f
         yaoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=ZVwcN9i7kP7hddzw/7JY3x3A+iwLYz89s/Ac4j4mmbE=;
        b=EOEEP96EohT3oFGwAS7lNBhTQSlrXZB5xoV4iAuH5pQmQU+kX6/JGJdQAqs3Mt+Wjg
         by4iq1eEVcRx/bLXaHyiiBe3yOc13itMWRV1fgocWSNCB1krhNldb8/bZ38f0hWclQsj
         swUhSW73h5TqAPNmiMKuy2rWJ4WDDefSmCUzvnevIIzyAG08OVoLLoYSLkYU11/3YwXf
         5eYDf3R8uwZu9SzFVZLh7xaxbtTgRnhAcQqk5TcWaoAy3OJPx1eKF6G3w1c/NIQ+DFyY
         MvC4MaSAUM8l07D3fgYefNACtA1uRWzrJc4vlWSl6TUqYAqtCy1bKXK1B3fuxHGZAmsd
         fFWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVwcN9i7kP7hddzw/7JY3x3A+iwLYz89s/Ac4j4mmbE=;
        b=q+VW1e3EFUc5o8SZCy9s9f3QO0psHi/N7wDFBYPm26G0qUe+SVm984618K3PLPjOH3
         zxU2LPRUuBb2nBBUWcJees79IFLm2NcO3hAAm0ZNCmDrieB6o3d2IetbnvNAtf8ReQFf
         FenWPtm4m5WH/WPSscOV+sDk5SzF9LZhMQt7aet0VQse6i1JPNAgpKQJuOiHO4V4wPp7
         atKGN8PKHtIEYynFfr7bTNWW7cegAIFo7XQK8XEF48QzNTO9Hap7K8D7pf8JOdNwWvAT
         SizRPuAKMIhGmyjEIUw9TzsIUUzI5PdM3/4v2l92DN+LawGpWDHoWTIp052PySlvIpbd
         d5kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVwcN9i7kP7hddzw/7JY3x3A+iwLYz89s/Ac4j4mmbE=;
        b=Br1VfqSM44OdG5IO5xUOLzPq0mA1HKktUTW1LrWglBA9JvpOkpXk9aisYTqQ1WgJsm
         GHMZCvdBJzjoQb8aP27J3u29zdddRrqKTghFnSywMbafxx17vmg5yn2RJuoECX0BMhAW
         A/Ip+988kQcIFHg0EK6pTfHWSif+ubeqZqP8/YLgXPmD/XSu3othZVsxw4RHoJXElBf/
         LiZFFJ0vfYaqz2L7cu9J7sx9STY2WR0Ev0ak/Hq+rZ2+pxwsL6ceFuRsGsvVfmon01Db
         3wny612VlnKAvlccU8urWg4PM3vuIBzw7PzhMGSIYfg0b2T+aMDIM1wgHmD3eLt2TaPA
         ZQ1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530yrpVdmjFrWVLFSxFrxZ+mkgTh1L2fHwWiMMg0lrLSt/zavsVl
	x/AsuzSAlZduSSA/EZqIqjg=
X-Google-Smtp-Source: ABdhPJzLxhWdJFZ8naYS+V19IvR+w1iNyRP8vwr8qhpjqYWtb0E2l/WmZWR5zpjZ3kQzFNWPWP5t5Q==
X-Received: by 2002:a17:906:4356:: with SMTP id z22mr2799823ejm.334.1589550946462;
        Fri, 15 May 2020 06:55:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:48c2:: with SMTP id d2ls979700ejt.11.gmail; Fri, 15
 May 2020 06:55:46 -0700 (PDT)
X-Received: by 2002:a17:906:29c4:: with SMTP id y4mr2892604eje.95.1589550945927;
        Fri, 15 May 2020 06:55:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589550945; cv=none;
        d=google.com; s=arc-20160816;
        b=s6RVjrZ2DJdEstXtPwQaNiIx5eqyr4mkALgobnVicM/F3GF+F/hPgriPSSkPtibJM5
         yFYntmb2Cvyvr0LWAPB+AEzAfBBGNXZkegxljt+0KdwAZ+Rs8IpNkfHnjWn/qQveQ7po
         W6yN7d2sSN1mM8SPsITCDeybvsmBNjT6Yj9Y0xCuB8KE/TbelPS/+EjhUnFUab+rJQhM
         USeRXgJ09Qqq1oNQFHdKU3l2NXIZd2iYrLxZuEdRNln6R0ztbz4cpJjKNe6gogGqxqje
         bFggEUHhI+3KwzkCEVBZAF2vgvFL2wZ6Eqt+qroLPYrEh9p+yXpYVHG0eKLJ7Vt8ZIOk
         cbMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=bUBTmG8G9XP6TTzlSRWn1ZRFOdCQ/M8N6fAaMBuld7Y=;
        b=kKnPm2hvhP4Sc6HL4uvLw8cSnZJH1ec7ED5cSpo+konL2Q7tR0ZmLwi+KtzIRpaR/p
         ieJDgiAel4ptL6sW7Fw65wNysyDTANcRqezozw5aqOtZp5QUXSlQrLgWbTdyqov7uBvC
         Ydk/D2YWDil6q38jLdWLn69OG2y4IPVZ/8KfBHFL+m5+RsYVWaaQPU/hTgFuucl15rnB
         UN3WZCmM5sHXKDqzkwW9ePooX47xFWdJcWRKxVks2mzJHenXs2jWF7RUG0zMLQ9ncFl3
         P72iklWL9RjIhVSSDhswb/JRouWGmU9mRNhuSKXhojnHvshYYKuN7ccsu2ZOaSwlSxS3
         2weQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [207.82.80.151])
        by gmr-mx.google.com with ESMTPS id f27si205493ejt.0.2020.05.15.06.55.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 May 2020 06:55:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) client-ip=207.82.80.151;
Received: from AcuMS.aculab.com (156.67.243.126 [156.67.243.126]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-152-DguEuvUTNmShAeVBwZOssg-1; Fri, 15 May 2020 14:55:43 +0100
X-MC-Unique: DguEuvUTNmShAeVBwZOssg-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) with Microsoft SMTP
 Server (TLS) id 15.0.1347.2; Fri, 15 May 2020 14:55:43 +0100
Received: from AcuMS.Aculab.com ([fe80::43c:695e:880f:8750]) by
 AcuMS.aculab.com ([fe80::43c:695e:880f:8750%12]) with mapi id 15.00.1347.000;
 Fri, 15 May 2020 14:55:43 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Peter Zijlstra' <peterz@infradead.org>, Marco Elver <elver@google.com>
CC: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: RE: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Thread-Topic: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Thread-Index: AQHWKfttZor7e2JWdEKPvqldyEhGwKipLI7w
Date: Fri, 15 May 2020 13:55:43 +0000
Message-ID: <26283b5bccc8402cb8c243c569676dbd@AcuMS.aculab.com>
References: <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
 <20200514142450.GC2978@hirez.programming.kicks-ass.net>
In-Reply-To: <20200514142450.GC2978@hirez.programming.kicks-ass.net>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as
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

From: Peter Zijlstra
> Sent: 14 May 2020 15:25
..
> Exact same requirements, KASAN even has the data_race() problem through
> READ_ONCE_NOCHECK(), UBSAN doesn't and might be simpler because of it.

What happens if you implement READ_ONCE_NOCHECK() with an
asm() statement containing a memory load?

Is that enough to kill all the instrumentation?

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/26283b5bccc8402cb8c243c569676dbd%40AcuMS.aculab.com.
