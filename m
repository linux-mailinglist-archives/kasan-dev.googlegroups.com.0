Return-Path: <kasan-dev+bncBAABBKMM73TQKGQEO4GVEBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B58783C939
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 12:44:58 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id x198sf3761589vke.21
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 03:44:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560249897; cv=pass;
        d=google.com; s=arc-20160816;
        b=SoKEkKVksp5ra2m5rOv2PO4njUgZwhdiygm0O7uZYS5iBkOggibaUyIESthW13Zo1A
         HUZ7/W2cTI2Hmyv0cAcWUCo+LBLLirNgz7Lvarx5OmpedKkfzHOCSK6q5ZZPa52ZjMHL
         q34GOH1IOvc9ghbPIRopTaOyixXfQfzImHx6QV4fiGzaNx/RM+3mEEJbczC+wgAipdaR
         5Y5AnbjZd9gwlWcie8rluJXGRAr6Elb0Nnv8oD5UHBRLkUEmlFHMzDHaJmXE+otc8Fqq
         4hmJZPM648JUYVjWplZWFF2BhCzo+/syVX+/ixpV0Hg67s9JuOSluovPMgBrNQUfaZfE
         r1ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=sqjXbTyDhRnNpkHzTKf7gDrV2fFKkyjt5vuGEZ1iaCY=;
        b=idaPLhihtSWXEsEhV7iEazqym6jDi+ewZy0es/p78JxY9V+rmxgUIkvKkr2YObjUHn
         Hb8NTE/TqNvYzUh9vwP3aprlqqlhHNvePud8TF88INtCKf+OnTzQVeoKIrEQqOSqFXa1
         3lclJYQ7xB0Rjs+lubuPYKSUzL37KxJCVX07db7iC3xTZjemnUg8T06LQjW6JDsexaIq
         NMOYl7wErwmJCPQfps4b10/D0EVszMl4UrAOzQPzPRyqgLWhoqmtiRGPLwUcNWG+8ToM
         OpaPpUod9OdxOgj89Z0JiihB8kkP5pAO3NklkKMkruUt4/S+r90A+/iMXCiKRGHJJlr+
         vtZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sqjXbTyDhRnNpkHzTKf7gDrV2fFKkyjt5vuGEZ1iaCY=;
        b=A3i9Mhflxhy0OX2yySVe+3I8SlwTJowNJG4ksNgo/P5ayhpThrVyeeiOrPn8Feo1+V
         kaDe38Ayz+wHT16Bp3czdVpLPsg8068s9DorTsFZ2X9dMdXqQMgdqHhSs5SpBSHTC/ic
         6oS39pnYKapjZxhQks6y8UHRy+OImtI51VLQUB+t07YB9rjy9Ldu4q+P3gb6DxMpYRAa
         tQn3ybUxe1jXD05VhHf4vqsiJbnFV8Y3shtVtnr4T2SrEkIRCzme8bPa4hQU0Xr3w+RU
         wqKFvUGPp+OXj1RGjSE/KF35Nrl7H/JJrShex36fbtxANLJLJdNO8cOf6SUUmSxXaqOK
         ffkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sqjXbTyDhRnNpkHzTKf7gDrV2fFKkyjt5vuGEZ1iaCY=;
        b=Qmv+ro+GnT1zRfOzfWALCxJoGGQg1ZHnOJ5JaNVEIKvK6AGyrVkVVF53vtGkXonJeV
         5AcGFNkn+AXHpbRYXv3gYgIF5PR3vjvZinLOfHesm/ioi/0ltAsU8JrlrypN9oIhn5Rz
         HQ6pE71nHGQXeJf2BPhnQ0hcEa8wkRdFvezgY4dmOj4fPmPV0vnOCA2QDth4elJ9lJAF
         lN6ruGdqEIkSIEb0M4sA1GrX95CjL6XwjCV6t5lYulbQElhJUvMPMJyC3wI+XUGuswSv
         f/n0aPZzLhdh2B5FcAm0IPmjDs4/fCTPGu8Z9dL0OpJdzULulTii3UT9/olF8wmUBdRN
         DRfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWweynUlloU9pDK4t4mdqVScdTU924Ugiu+RbEgzK9AKmE4MtWl
	ftioy3Fkoxc75Nz43l3gZfw=
X-Google-Smtp-Source: APXvYqzqPNsI25VhhV4coJjHMq67e9QyGRXANkjLU8USPVftgRyW/ziJIvIMh/04rbJdFhouNwHqpw==
X-Received: by 2002:ab0:698f:: with SMTP id t15mr10616035uaq.34.1560249897584;
        Tue, 11 Jun 2019 03:44:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6147:: with SMTP id w7ls1213096uan.1.gmail; Tue, 11 Jun
 2019 03:44:57 -0700 (PDT)
X-Received: by 2002:ab0:6619:: with SMTP id r25mr14938986uam.33.1560249897389;
        Tue, 11 Jun 2019 03:44:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560249897; cv=none;
        d=google.com; s=arc-20160816;
        b=IAj+byhMZ4mt3cC6rmschoIWQrszB5nKnehRrylTNaXbp4AEaj8jx3shQ2Tcd1JOBD
         zG2IfUrs7980ZxbQG1GPb1kOeOaUNqXuBQz1M6qmZBfYKgq3QVCJAlT3WcYKIbekRodO
         imUkcMF0UlSkETCqiYp5cOWg7pWoxj4ARmrlVhJXGWs1tbo3joDSUlhEf99MVIUaxDZT
         Q06SwsYT+ku0AAasrLMFe/h8soRuIk92Dw8y3+yX65camdm5IGBw0t5fIOIVwiTwvhS3
         lBuYG07qH+q3t8GRyT76IRgI5sAS5Q/L2UbVlU1jteUTpTbJX6MCHHBhEiGQQHXovRzj
         13Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=sPWSgbnNjYhV7F10nlBB1fjN0kdnLPE2A/+eob6NAdY=;
        b=XyPnETnUEn/UkXFIpr12gyocdtMLplfZ+3Dl1s0QxRvgcQFwmlZTfK+d5n4V6zVqLC
         EOBYu8vW03/lNht3WSoL9dcNTZpttnv2TRKshueZdHwH571P6UZzMhjMxMXoDX3tnak7
         p86VyREIAFmbA7AOstS7xTvDevYs8roczXfKcAuT6wKT92mL3jK0SL5FWOn0iPwN1dXy
         OOOR2+WAy2kSr7ONju4U/NZRAy3rPwQMMVvSkoSuxiQWpHAKmB4DRnDg56J/ASrDmtbn
         1f+XJmeWIUsAwAR7cry9GPxdCOcsm8eQ8KOeomvHn6DdW+0DO73J+/3Bfbnqaudx8QZX
         Cqmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id 78si587952vkm.5.2019.06.11.03.44.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 03:44:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6438f1b0b6e14368a23e04b08d3231a8-20190611
X-UUID: 6438f1b0b6e14368a23e04b08d3231a8-20190611
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1585980236; Tue, 11 Jun 2019 18:44:53 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 11 Jun 2019 18:44:51 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 11 Jun 2019 18:44:51 +0800
Message-ID: <1560249891.29153.4.camel@mtksdccf07>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A. Donenfeld" <Jason@zx2c4.com>, Miles Chen
 =?UTF-8?Q?=28=E9=99=B3=E6=B0=91=E6=A8=BA=29?= <Miles.Chen@mediatek.com>,
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Tue, 11 Jun 2019 18:44:51 +0800
In-Reply-To: <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
	 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
	 <1560151690.20384.3.camel@mtksdccf07>
	 <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
	 <1560236742.4832.34.camel@mtksdccf07>
	 <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Tue, 2019-06-11 at 10:47 +0200, Dmitry Vyukov wrote:
> On Tue, Jun 11, 2019 at 9:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Mon, 2019-06-10 at 13:46 +0200, Dmitry Vyukov wrote:
> > > On Mon, Jun 10, 2019 at 9:28 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > On Fri, 2019-06-07 at 21:18 +0800, Dmitry Vyukov wrote:
> > > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > > index b40ea104dd36..be0667225b58 100644
> > > > > > --- a/include/linux/kasan.h
> > > > > > +++ b/include/linux/kasan.h
> > > > > > @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
> > > > > >
> > > > > >  #else /* CONFIG_KASAN_GENERIC */
> > > > > >
> > > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > > > > +#else
> > > > >
> > > > > Please restructure the code so that we don't duplicate this function
> > > > > name 3 times in this header.
> > > > >
> > > > We have fixed it, Thank you for your reminder.
> > > >
> > > >
> > > > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > > > > +#endif
> > > > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > > > >
> > > > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > > > index 9950b660e62d..17a4952c5eee 100644
> > > > > > --- a/lib/Kconfig.kasan
> > > > > > +++ b/lib/Kconfig.kasan
> > > > > > @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
> > > > > >           to 3TB of RAM with KASan enabled). This options allows to force
> > > > > >           4-level paging instead.
> > > > > >
> > > > > > +config KASAN_SW_TAGS_IDENTIFY
> > > > > > +       bool "Enable memory corruption idenitfication"
> > > > >
> > > > > s/idenitfication/identification/
> > > > >
> > > > I should replace my glasses.
> > > >
> > > >
> > > > > > +       depends on KASAN_SW_TAGS
> > > > > > +       help
> > > > > > +         Now tag-based KASAN bug report always shows invalid-access error, This
> > > > > > +         options can identify it whether it is use-after-free or out-of-bound.
> > > > > > +         This will make it easier for programmers to see the memory corruption
> > > > > > +         problem.
> > > > >
> > > > > This description looks like a change description, i.e. it describes
> > > > > the current behavior and how it changes. I think code comments should
> > > > > not have such, they should describe the current state of the things.
> > > > > It should also mention the trade-off, otherwise it raises reasonable
> > > > > questions like "why it's not enabled by default?" and "why do I ever
> > > > > want to not enable it?".
> > > > > I would do something like:
> > > > >
> > > > > This option enables best-effort identification of bug type
> > > > > (use-after-free or out-of-bounds)
> > > > > at the cost of increased memory consumption for object quarantine.
> > > > >
> > > > I totally agree with your comments. Would you think we should try to add the cost?
> > > > It may be that it consumes about 1/128th of available memory at full quarantine usage rate.
> > >
> > > Hi,
> > >
> > > I don't understand the question. We should not add costs if not
> > > necessary. Or you mean why we should add _docs_ regarding the cost? Or
> > > what?
> > >
> > I mean the description of option. Should it add the description for
> > memory costs. I see KASAN_SW_TAGS and KASAN_GENERIC options to show the
> > memory costs. So We originally think it is possible to add the
> > description, if users want to enable it, maybe they want to know its
> > memory costs.
> >
> > If you think it is not necessary, we will not add it.
> 
> Full description of memory costs for normal KASAN mode and
> KASAN_SW_TAGS should probably go into
> Documentation/dev-tools/kasan.rst rather then into config description
> because it may be too lengthy.
> 
Thanks your reminder.

> I mentioned memory costs for this config because otherwise it's
> unclear why would one ever want to _not_ enable this option. If it
> would only have positive effects, then it should be enabled all the
> time and should not be a config option at all.

Sorry, I don't get your full meaning.
You think not to add the memory costs into the description of config ?
or need to add it? or make it not be a config option(default enabled)?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560249891.29153.4.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
