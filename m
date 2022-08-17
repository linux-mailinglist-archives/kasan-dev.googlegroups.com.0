Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBEG6SLQMGQEHSQU2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF77B597210
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 17:02:32 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id b10-20020a05622a020a00b003437e336ca7sf10007249qtx.16
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 08:02:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660748550; cv=pass;
        d=google.com; s=arc-20160816;
        b=c3fNPoNzggBfAGQ+W/3n92BF5mkZli1YWJByAC3pnnPd4fY3ni7PIhkEM1qLRc3Ndj
         p9/ere1S57Wl45Ruu/gkhK0W5UsqJiFSWBB54a4INpsZzqs7LShemHxJhEUSqJCtwmyQ
         bnawuFe/syizD+JAwMB+3mtCwt/vEpV7TbZKE8M3FjGmoFs0VG4wF10Lkx0GFC+zTs88
         90hgCLmHCQsZepCMF1jK8ObF+nYAYvwsNeCcauWr3rLOHgwzCe1QcbG03T7cTKAajVAZ
         ujkxfoMs2hDPivrUd0vuKStTVs0s16Plg5KLYfYECoX2p/yv0ReZ2MMO4/h+mPuWz4z/
         5yVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GDMmAoyID7rZuyrDo1WVJHjEj8let6OdGpza8RJs14A=;
        b=t6LBQAhhRMRb8O5tCrvRbUM8FurcFCogzWmh/EIARI6vQ9XKzwECO/KAWafnoRZFWi
         SMpR0KXrrPvkLrJVSY0m6hoDkTvwsOvWqXsPFc3RXjwrn8CRgKVjpVj2SLAgY3LvrIjS
         nzJ3swquLQUh1RwBYaBRKbu47SORpxsQh3v3TRdkuJmV+/fqkUnc4fZRy4cpyfjQnhmf
         B5uK3g0fNIloZwU8wMg0pMZj1YmDmt10xcMwTO4wWPtIAiiPynA9f/JJe5aHZQZ3T2V7
         wAIeuuasVq3rlyHd+nGXGOPFwesQKT6/ruu5mgXmlqW95imr2FiC2GtjenN3rh33QLwN
         xDXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jWTBJwPe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=GDMmAoyID7rZuyrDo1WVJHjEj8let6OdGpza8RJs14A=;
        b=IiFvlqu259Xj7zU7VPzwhHT4OpxblC0Mf8LWvps9hZdHzKbzWO6aPoEhpIDCVZrSRR
         JgCeTEJbE+8Y7gt6C3pAQ8UGdwA7EqzW2kS/Fhad+QtzCaJaXrTOCRRqYXhnvurhmkoA
         eaaBJ0i4K6kFRToXxMcrlT0dpk9ONedxkyChDH1uPtyX6udU1tmRuNGKYDM4B0bb3RnD
         gh/K5C+inlz9PkE3ukyXzkmZMj0zMVW2Bw4HdqVbjVI+RBZYCP6aNJzJkecXeBabHYQ4
         CxEHm4+J/BtPM9MO3a33Fg+TlZwz3ykuJd6eXMeTteKgPQVVcTsvXW9zxLsQuTZwVDCH
         6Hrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=GDMmAoyID7rZuyrDo1WVJHjEj8let6OdGpza8RJs14A=;
        b=gtFUCNJRNbzTKV3017WTLrN2BU0J38DkUcUNRsdF5seSpMytTPZBTbSf7ZoAnSimZt
         XVrL9uFk586BW04aBJCZRc5sO4yy/bYCtShgZrKg4WT4wsGSbODsi+/rQ6DEt9ABtvZy
         tahJc8kZ0sa7cPZYRf0QrmcSwzZ9HJojjXLQqQghhqJSVBT0itnGrhGRJ4V49NsTdbOn
         jmmWrkrgyS0hNlOg3S/Ci0u1VIsikwGcj/MRkP8B3ZaAu1B3/zUwJVa2wsmNdbLDjclz
         wjCCoIyNBQdWZd0ueOI708Teh4vcLr69D26P9efE5bOv40T9i7uKXNQm7ynp9XxQC//P
         S8FA==
X-Gm-Message-State: ACgBeo1R6xQPFNrsKbzNyNn0oY1zhWxF8c2vgh2UQXTB1pmwhEOJEf6M
	LtJc5W5qhb5gUSVEV4PBk1g=
X-Google-Smtp-Source: AA6agR6lLWRoC1PN5DK2wQtDQu+P/JDPk7T9lqmqxVENDQ0pXW8gcjJAsosuaZ3nqDLS2Xu4qvEPdA==
X-Received: by 2002:a05:620a:151:b0:6ba:e711:eca9 with SMTP id e17-20020a05620a015100b006bae711eca9mr16125089qkn.385.1660748548116;
        Wed, 17 Aug 2022 08:02:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:a16:b0:342:fcdc:2d4d with SMTP id
 bv22-20020a05622a0a1600b00342fcdc2d4dls1591862qtb.10.-pod-prod-gmail; Wed, 17
 Aug 2022 08:02:27 -0700 (PDT)
X-Received: by 2002:ac8:59cc:0:b0:344:6b04:26df with SMTP id f12-20020ac859cc000000b003446b0426dfmr9746205qtf.208.1660748547141;
        Wed, 17 Aug 2022 08:02:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660748547; cv=none;
        d=google.com; s=arc-20160816;
        b=szAJmRA+Js9v9/qDXDlu6Bshz3lIcryz/yt5XOukwBuYBYBonafR2cae6XQ9De3kJr
         /69S5crRMLTMQpN2FF9ivSi+lbTm2gXVGlCUxvs7K2mXSQ4QGB4rfmaSALlKWgq2u6Zm
         fpl8g+dsA9Gr+vNEVWZ/4sffS3yUgoeTValQNdEedKq9e/mUHgnsa2rk+3yO4oMMwFQ1
         fu+PftOcqEbmZBZPXWTz4BiYl01JXhIpuJGc8enGUZQj76Gys2vJ19aSFs0ZbfBWXJsB
         tbUjA1TT6z+F5vJ9yQ3cOwg4Zae0YGpDUBDjG2qpIUCRTnMmxRJmDaNKX2JlumqOaExb
         Jnag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eLT3oLqhmxP10VrqfCdF+GW76/xHK/asbI4Ej6PAVt8=;
        b=XBhsiO/mDewxeVS3clrdvtlWDk3TxuWMCk3meOBDXJ60ScN3aEsuPbAkjUP7u5bTKZ
         zPOrhIgy2KpB6mCDGq7gRuCdUC+nJ/zUgfoXoPy3cevj5HIMe6Pv8TZ7G+OLW96Ph5vA
         ukk2tIX9YU9NrSZ4s2/7bpGa880wydg6GaajUeh2wpyYUZOBgdf7MWwonozLzQLMOSE+
         mlYj4MzwUutmuvseDgluj4ARfXcIIlrB5wWoykR3obCsOgBbS07t5vY4vyAu/JsDmkvE
         eLjaJcxIXK8r9KbQvNdeoO7r4ujGg/+r/PwKwVMrR9j+eOdTmKmVaTbr8TXFq+Mxfc8a
         4jzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jWTBJwPe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id a8-20020a05620a102800b006bad5953a88si715935qkk.2.2022.08.17.08.02.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Aug 2022 08:02:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-324ec5a9e97so238230877b3.7
        for <kasan-dev@googlegroups.com>; Wed, 17 Aug 2022 08:02:27 -0700 (PDT)
X-Received: by 2002:a25:41d1:0:b0:68f:aa3f:dabd with SMTP id
 o200-20020a2541d1000000b0068faa3fdabdmr4679733yba.143.1660748546594; Wed, 17
 Aug 2022 08:02:26 -0700 (PDT)
MIME-Version: 1.0
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck> <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck> <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
 <YvyJwrCNUdKHwxeQ@kroah.com> <YvyleOsHoztisPHp@arm.com>
In-Reply-To: <YvyleOsHoztisPHp@arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Aug 2022 17:01:50 +0200
Message-ID: <CANpmjNO0mMNFA0vKdLjvOvzJo3=90ads9wUz==u84WBYnPQY3w@mail.gmail.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object search
 tree (overlaps existing) [RPi CM4]
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will@kernel.org>, Yee Lee <Yee.Lee@mediatek.com>, 
	Max Schulze <max.schulze@online.de>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"naush@raspberrypi.com" <naush@raspberrypi.com>, "glider@google.com" <glider@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jWTBJwPe;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 17 Aug 2022 at 10:23, Catalin Marinas <catalin.marinas@arm.com> wro=
te:
>
> On Wed, Aug 17, 2022 at 08:25:06AM +0200, Greg Kroah-Hartman wrote:
> > On Tue, Aug 16, 2022 at 04:39:43PM -0700, Andrew Morton wrote:
> > > On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org> wrot=
e:
> > >
> > > > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=
=BA=E8=AA=BC) wrote:
> > > > > The kfence patch(07313a2b29ed) is based on the prior changes in
> > > > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up ear=
lier in
> > > > > v5.19.
> > > > >
> > > > > @akpm
> > > > > Andrew, sorry that the short fix tag caused confusing. Can we pul=
l out the
> > > > > patch(07313a2b29e) in v5.19.x?
> > > > >
> > > > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/0=
7313a2b29ed1079eaa7722624544b97b3ead84b
> > > > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commi=
t/0c24e061196c21d53328d60f4ad0e5a2b3183343
> > > >
> > > > Hmm, so if I'm understanding correctly then:
> > > >
> > > >  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24=
e061196c2)
> > > >    but the patches apply cleanly on their own.
> > > >
> > > >  - The kmemleak change landed in the v6.0 merge window, but the kfe=
nce fix
> > > >    landed in 5.19 (and has a fixes tag)
> > > >
> > > > So it sounds like we can either:
> > > >
> > > >  1. Revert 07313a2b29ed in the stable trees which contain it and th=
en fix
> > > >     the original issue some other way.
> > >
> > > 07313a2b29ed should not be in the stable tree.  It did not have a
> > > cc:stable and we've asked the stable tree maintainers not to blindly
> > > backport everything that has a Fixes: tag.
> > >
> > > How did this happen?
> >
> > I do not see 07313a2b29ed in any stable tree or release that I can
> > find, am I missing something?
>
> I think commit 07313a2b29ed went in mainline 5.19, see this merge:
> 39c3c396f813 ("Merge tag 'mm-hotfixes-stable-2022-07-26' of
> git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm"). So there was no
> stable involvement.

I sent the revert as a PATCH for 5.19.y here:
https://lore.kernel.org/all/20220816163641.2359996-1-elver@google.com/

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNO0mMNFA0vKdLjvOvzJo3%3D90ads9wUz%3D%3Du84WBYnPQY3w%40mail.=
gmail.com.
