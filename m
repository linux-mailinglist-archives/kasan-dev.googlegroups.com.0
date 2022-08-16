Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5PQ52LQMGQEX3SJLHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 170A1595F10
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 17:32:06 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id c18-20020a2ebf12000000b0025e5168c246sf3171222ljr.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 08:32:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660663925; cv=pass;
        d=google.com; s=arc-20160816;
        b=MqKpkYL1Q1NbjlrgbUzo84m2pLYsJkp/1UGOBmsWudDAyCGO4wUKqSy+ViZYsBqJux
         EroFjDiS1LJaDzXG//2bi9KeZpu6IEztLdsIV/xi3cat58MJaB3I59A2TyIyAOPLvQ5d
         SaNXOofyE7JDzWWAPjItyHWBUESXwsMhSb7LQ+aRRgVMMX/yTGRqUxRpdjieMjU0L8lE
         p0uko540u8IpIuZ08Mb54HQLxr3B+YD9LiR6Fui8PrRCn7ir+lyyREqO2AMb04qaGtxo
         xzRlwfB5Pbm8seeHCufp8eJdUOVwMxiiU+9yNNcBqCZjyawBcaeIPVc63Kec9pq5Sd62
         e40g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0yiWf+WY7KALSefokg+L3/wyzMjnGfCOSF0b81J4gTk=;
        b=McM6cxs/s35E0eZzNCdJOFG4jN0rw903C3edqgN+4v8Kgdo/G4Z04GUbpE1OoEmfv3
         HhXEOL0/Pwy9uVFXqr/K/a18rpWMdvYw2/yOFKsi/EJLRl/DNvd5kgyyY/6X1nNAKyfs
         ISpQEMx8UiCuiyTNpzHU2VqbkjR0mdcICRNP7+qKCDFy/1IwjSfMEvZ2JdUPY+q9GsoG
         FCjME7QnhQn2wv7ACOoB8cxzX/z+yffuIlQaRQmZYOQJBiuXLlwwEjwwX7e/Z/gnyZg2
         YXwlMrRRvr55oSVjxhHRsAiDo71mrGDiPIC1HsXVfQ2lQvTrJJnSTTpv8naLWLelx+gN
         5riw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc;
        bh=0yiWf+WY7KALSefokg+L3/wyzMjnGfCOSF0b81J4gTk=;
        b=qrdLw6Dsb0lcQoHmEWosYANaPiFLtCx6T/BOEYJtSWQWqG1sBXX4PSDGQGufQF8DF0
         aa9uhDtjFfonK5eYTh7+R5ekCCWO7vNZjUbnagSD/fyLKlCulsbkTIn4xbdSSi9hEqRj
         8ScfpVOEk1UTF0d4ZBlK6HrzSv/uhOqIMGawUzbwrBgBxGopiDcq/eDLybn1xGSbRVJA
         IEJ+akhbjTQAy818SnQ66NoVGXoup0VrIQUY4PAa1KRHIWHGq7RPaZSOuGfxAdN/WOmy
         CBHyKp/6JEzE9G0cs3vtwTzHC4rcJCUSZb4hY+eJj7lAYw2mIjgvxWXvrJAupAAvox8J
         jiVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc;
        bh=0yiWf+WY7KALSefokg+L3/wyzMjnGfCOSF0b81J4gTk=;
        b=hIhMD1JirSr3YjZJAQw0RrPSUsjMWV0GUZzv8o0mH+VNCECNJGylk8eAe71yOf9yrG
         YZP18Ox0TdPiSdkpYS7GgFhLPvcyUJcH/vfJkMyPhiAmBkYV3ahWfDrgoa5p5wj4r4Zg
         1p2mpjvwA6Hue1d+96FpraX6Y8jdOb1IEzoH6qawE+bxBi47gg+BTelEVaNKDIIxCohC
         Y7TbB2zobVJWXeynpTRtkeoO8aQimsHcSJ0xzCAHy+I6UjbMIOCOzDz5jYyC1hm0SnzH
         Qu/GfovgJs3MMDXdy6RIkeZOzFnISqYgsxU1QH6aai+n4hT0ClWpKRhg/FW4EgqgmSOI
         yi4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0U/e9LY5YKWD+YPmP+krxBrtgHNlKuD93G3diYCAqnQDfj8dYL
	PzWV9Dfj+RL/HBXUGgBDGqU=
X-Google-Smtp-Source: AA6agR6dzLfOjKI4Giqia8bs4UOI8qgfYj3Os0noCKcRub0/OIhGSa7urGscjsnKvFp6NobnLxnRIQ==
X-Received: by 2002:a2e:a58f:0:b0:25e:a8a5:d1d0 with SMTP id m15-20020a2ea58f000000b0025ea8a5d1d0mr6724152ljp.74.1660663925447;
        Tue, 16 Aug 2022 08:32:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2ac4:0:b0:25e:6e15:51f2 with SMTP id q187-20020a2e2ac4000000b0025e6e1551f2ls2159765ljq.10.-pod-prod-gmail;
 Tue, 16 Aug 2022 08:32:03 -0700 (PDT)
X-Received: by 2002:a2e:9056:0:b0:25d:64c0:27b1 with SMTP id n22-20020a2e9056000000b0025d64c027b1mr6930313ljg.396.1660663923915;
        Tue, 16 Aug 2022 08:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660663923; cv=none;
        d=google.com; s=arc-20160816;
        b=CIr45asEY9p+rF3j8qqsYVoq3tpYuGe95ZX2Dc0qvBKBp0Mtika6kAX6bxVZwzx4jv
         xBZC/qZ3IHlsT55wbPXrGPchBb6HJJDv+NhwK3618uL4rq+jpp/uK4kJgXSeZMPnzL6Q
         QuQ0j5RJ0v4erBvLmaYL/3uGupvK+L8bZx2SgSpc/tBKOXRZE6XlOSYW3wGWRKHqlMq4
         XopymZq4TeI3GMJs7fnT0aoWNbONGf/s+FTIUUhMhDii2bs9bRykzoLPqyJBtDtUeB4R
         dczew6YAa+XQW1laSAu5vcIPfXytB1HBSGfUrIrL83cRCQIdQ5UvUtKU66EsmD9FqHM6
         nyAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=4BcaQ/c8s6ekOnqofcnc1th2vlCw8TVBTBY63JNWgp0=;
        b=LGlnt9VMB+z8LovpOR+XcRWm4X+TXfQYWTmSjgfy1UsWqTxi/UVYS+HJNr1ny+D1Zf
         Uo8xx4r/qt1jNZyJ2a5Zjr4mdDRRu6MxltjemM4og72n1ABLTBgPnW34GjKLwjd8w6ym
         vNrglIKXaCpDt/0dIAUKGuOvNsv0P/8vpJK3fwAlt9Hg0PGmi0fwW0G4TGcdm9U3g6Di
         uB6+74BQHFNCLc/m5of4yiSBOKL3dxmBHUoWAaX9I4V1YDktjHb2Vd7qJy9qHL2pKSbq
         qzkPy6418bV7TJL6Q9r4VDRqgwDIccxpFBgEQbD4EY31hAaQ5rvXLbDugABv4NDrOxMZ
         ZWNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id q7-20020a056512210700b0048b0f16f43dsi840662lfr.7.2022.08.16.08.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 08:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 55D66B818DF;
	Tue, 16 Aug 2022 15:32:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EFEAC433D6;
	Tue, 16 Aug 2022 15:32:00 +0000 (UTC)
Date: Tue, 16 Aug 2022 16:31:56 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>,
	Yee Lee =?utf-8?B?KOadjuW7uuiqvCk=?= <Yee.Lee@mediatek.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <Yvu4bBmykYr+0CXk@arm.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <CANpmjNMd=ODXkx37wqYNFhivf_oH-FSo+O4RDKn3wV14kCe69g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMd=ODXkx37wqYNFhivf_oH-FSo+O4RDKn3wV14kCe69g@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Aug 16, 2022 at 04:34:31PM +0200, Marco Elver wrote:
> On Tue, 16 Aug 2022 at 16:26, Will Deacon <will@kernel.org> wrote:
> > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=BA=
=E8=AA=BC) wrote:
> > > The kfence patch(07313a2b29ed) is based on the prior changes in
> > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up earlier=
 in
> > > v5.19.
> > >
> > > @akpm
> > > Andrew, sorry that the short fix tag caused confusing. Can we pull ou=
t the
> > > patch(07313a2b29e) in v5.19.x?
> > >
> > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/07313=
a2b29ed1079eaa7722624544b97b3ead84b
> > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/0c=
24e061196c21d53328d60f4ad0e5a2b3183343
> >
> > Hmm, so if I'm understanding correctly then:
> >
> >  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24e061=
196c2)
> >    but the patches apply cleanly on their own.
> >
> >  - The kmemleak change landed in the v6.0 merge window, but the kfence =
fix
> >    landed in 5.19 (and has a fixes tag)
> >
> > So it sounds like we can either:
> >
> >  1. Revert 07313a2b29ed in the stable trees which contain it and then f=
ix
> >     the original issue some other way.
> >
> > or,
> >
> >  2. Backport 0c24e061196c2 everywhere that has 07313a2b29ed. Judging so=
lely
> >     by the size of the patch, this doesn't look like a great idea.
> >
> > Is that right?

That's right. Either option should work but I think with (2) there may
be a few more commits to be added.

> Right, looks like the kfence fix didn't need to be in 5.19. In any
> case, this patch I just sent:
>=20
> https://lore.kernel.org/all/20220816142529.1919543-1-elver@google.com/
>=20
> fixes the issue for 5.19 as well, because memblock has always used
> kmemleak's kmemleak_*_phys() API and technically we should free it
> through phys as well.
>=20
> As far as I can tell, that's also the right thing to do in 6.0-rc1
> with 0c24e061196c2, because we have the slab post-alloc hooks that
> want to register kfence objects via kmemleak. Unless of course somehow
> both "ignore" and "free" works, but "ignore" just sounds wrong in this
> case. Any thoughts?

Since commit 0c24e061196c2, kmemleak has different namespaces for the
virtual and physical addresses and there is no risk of overlap. So the
comment in your proposed fix can be confusing in 6.0-rc1 (but fine in
5.19).

In general, if an object is allocated and never freed,
kmemleak_ignore*() is more appropriate, so I'm more inclined to only
send your kmemleak_free_part_phys() fix to 5.19.x rather than mainline.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Yvu4bBmykYr%2B0CXk%40arm.com.
