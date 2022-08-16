Return-Path: <kasan-dev+bncBCT4XGV33UIBBQWV6CLQMGQECT26CUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id A210D596612
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 01:39:48 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-3328a211611sf76783647b3.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 16:39:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660693187; cv=pass;
        d=google.com; s=arc-20160816;
        b=NWvh8WS7TaoBcIB25RDqst1Idx+9ebm3VVGSZ+6vyG0IxsatYmuuqI2o3cm24Co1ai
         mJEiEueWM1ZBVbLz+50R1fsilgwPSD1dkBo9xWzPprfn6gIdkEhkLCXulvDXZvOlsI8j
         CpVlAesNnuPxFp81g0gdLOi9Ozxv9ecJkboNI5ZHEto1672Wc0NOxb671XnimmZRIxf9
         hSons9q0BqvuE59zS2arJKHwmfuQesr7GjCilYgJCnMVorC1Lg0IPDfX04rCmc+OSCnT
         ls5GjPCiIH9Zg9q2+tBDqYzsFagucapT4nggEJIofLKLkrTUgJF3IDXxDmJ/O++2oWGW
         yZ0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=o5u8Y5yBO9Lc83VyKgGeE6FEufKgX1rrNJvIHQ7RkmQ=;
        b=b3c7wLLaUL4bWOHQSv2Zvr5rphApSf/6/xVoRnCRVaGrQq5es2OXUKSlbeTc8/7FNR
         So2NNchPQ1D0wz9ecentUrQh9fo9IEms7tb3POhoemjOcj5KLSYtIy1O+8dbVCoE6Tl8
         Mn9jkqX90lnLGm0tOiwR3aSZmYTZTHwkg4nf6c4ECCnIGwKrzlb5FaRemQpRfdw+T8NX
         NgQ8lfDrCJCZPasZfLr9gMaUSMP4x44+i5MKska9KyoZ1NFTKX544jYPyyxb2cSmv6U9
         FibLeFw2Kc2KoKON3KMzcTKpD+T7KeEuIqI0fBy1og+wWK3F8Q0cEyBHTdL81iiazpPy
         Nx4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=XJ79BsQQ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=o5u8Y5yBO9Lc83VyKgGeE6FEufKgX1rrNJvIHQ7RkmQ=;
        b=Wpd0qjOoHd9C/NtLEAhPM92k6vzIKXN8+KeQt8rf597Gg3HAXZn30YGY5LpM+0Vu6X
         R8hJuB2HOEWvJNVtodep0sHDvJFkm9w1zA6WsyB+awj68AllycyWHlhIDgd+TB07JLnQ
         8WfOKptNj8p74mXuoNfELfULkPXvWTHl7xufbnCRWEIICywmszRE1wTkfD7uarhTKKkv
         22MKtQ+yak2vcFn9EGct76YrRt6j9i4J/D3I2YvCUYpeORd0Z0Xd3VjA715Vi4mSjaNS
         A/Mg6cgfszuSgTDHAWNcRt9rUQTt2NoRFEbRLSgTuqrL4Q8wHj/bje60GauBhEGcsyhH
         Q0MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc;
        bh=o5u8Y5yBO9Lc83VyKgGeE6FEufKgX1rrNJvIHQ7RkmQ=;
        b=e8/kxOSE9qw+p840EUMBhqxUcl03bRT6MeTM4q5bFpFp6+M9IgDVGhne8XDW50yF6B
         a2fwiMvuHiy+DQoGAWdUfjpIPjguN5QcJIlD8hu/EytZEQxeZU/XFdayLuue46uzg54o
         Khht9UjsHs2izTwWSwbV4vCBM7T7iGyUPzIkmk2IS70dkcWXHhi5hYPF4h5dfHzvcHrM
         RARsC6r4Y3VRxY2zWb4EVPke2RkFB504jVS/GdQFU+XRgJC1AwpKbpRq7PzJZoxiOECU
         vVWb8usU4x1e9o6lg4YyIuDvqU/v/V9nqDYghxv3TUioV1R6ju/k0Vv+F9QfbmrQcJWr
         C8ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1d4aEcLrPKQLVgUCz5isLLkVSx60iDmcIZMCC3hvf8foDXzJKl
	l9NbSJR3E8c3RcdPwP5SGLk=
X-Google-Smtp-Source: AA6agR6yMVIcb1cDSw9SxMfvPwNwbr+vE6686IZHZr88WOSaXVLtK1DZ7oyyNC+c+Yigjpk+Vp2P7g==
X-Received: by 2002:a81:39d6:0:b0:328:4e6f:8484 with SMTP id g205-20020a8139d6000000b003284e6f8484mr18653783ywa.497.1660693187116;
        Tue, 16 Aug 2022 16:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a146:0:b0:683:8677:3cba with SMTP id z64-20020a25a146000000b0068386773cbals5885062ybh.8.-pod-prod-gmail;
 Tue, 16 Aug 2022 16:39:46 -0700 (PDT)
X-Received: by 2002:a25:b5c9:0:b0:67b:a397:5e24 with SMTP id d9-20020a25b5c9000000b0067ba3975e24mr16497464ybg.108.1660693186492;
        Tue, 16 Aug 2022 16:39:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660693186; cv=none;
        d=google.com; s=arc-20160816;
        b=lNjNSDsTAcGqIYIpeCm/bP9+ZsH+FWweyobeGjXzrkIgVvvMFpJtaHZ1/QOQ5aDvcJ
         GAaTvekMD62IP439VlqHg1wyWIy6JfsBdbhZeKzv5VOPEPhUCOjCXtjI3hodmKLw4WMY
         LzwKyAKNnUC1iTB7iQMW6LP/qOKZfC7Mj1DxaV0th69ltLfXcJHtp6j6Bbp5Jx/sb7WW
         NgVObhkN7wIS6TX/4yKHQ+2QZZVG0/FPkjJ5EMaPAq0zNqPAti8jgEKdb5oeeOqDl8I7
         OJcpSktpC5ba7/L9SGaSXkvU12+2p6zeeFu1J0IfObZlnYJSXUuTY+UAuvCCnvA2qlTV
         LsYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5ARKNDsizg6VLBV70UWGmKGMZR61DS3cmxD7SXkGF/o=;
        b=AGGM/ulQIszPO//h8Tg7RdwXcc4OnS0/1AFRWkYgSVB1qLl/2ayGXY99KxLd42vMuV
         KYQZNdrZFkbewiOH/CZdbGIugtVajzbkXXWnOEub+7DXjyxpUIk2uOFvVvACB3JU9Pdw
         3zNvHzCSPRTZhDYGIX5Bk4VfdkQ5pfloSykvgBQLeiBrCxNSuvD/jYwN128G590JX2sV
         hcQ0uE/BUb1UtmtycoB4vqgLjrp83wB5JCBd65hCNadEsCilyPVWDHUtqGN5b+4U+Z9o
         Y2g+RuacRRrxNLgGiepzEFf4WuXS4iUvur59YxSP4LPkEn2FQZASgg6HNBUS05AWVkS6
         Vr/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=XJ79BsQQ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h5-20020a253a05000000b006717aade33dsi73543yba.4.2022.08.16.16.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 16:39:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 014AE61336;
	Tue, 16 Aug 2022 23:39:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E4360C433D6;
	Tue, 16 Aug 2022 23:39:44 +0000 (UTC)
Date: Tue, 16 Aug 2022 16:39:43 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Will Deacon <will@kernel.org>
Cc: Yee Lee (=?UTF-8?B?5p2O5bu66Kq8?=) <Yee.Lee@mediatek.com>, Marco Elver
 <elver@google.com>, Max Schulze <max.schulze@online.de>,
 "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>, "catalin.marinas@arm.com"
 <catalin.marinas@arm.com>, "naush@raspberrypi.com" <naush@raspberrypi.com>,
 "glider@google.com" <glider@google.com>, "dvyukov@google.com"
 <dvyukov@google.com>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>, Greg Kroah-Hartman
 <gregkh@linuxfoundation.org>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-Id: <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
In-Reply-To: <20220816142628.GA11512@willie-the-truck>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
	<20220815124705.GA9950@willie-the-truck>
	<CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
	<SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
	<20220816142628.GA11512@willie-the-truck>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=XJ79BsQQ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org> wrote:

> On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=BA=E8=
=AA=BC) wrote:
> > The kfence patch(07313a2b29ed) is based on the prior changes in
> > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up earlier i=
n
> > v5.19.=20
> >=20
> > @akpm
> > Andrew, sorry that the short fix tag caused confusing. Can we pull out =
the
> > patch(07313a2b29e) in v5.19.x?
> >=20
> > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/07313a2=
b29ed1079eaa7722624544b97b3ead84b
> > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/0c24=
e061196c21d53328d60f4ad0e5a2b3183343
>=20
> Hmm, so if I'm understanding correctly then:
>=20
>  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24e06119=
6c2)
>    but the patches apply cleanly on their own.
>=20
>  - The kmemleak change landed in the v6.0 merge window, but the kfence fi=
x
>    landed in 5.19 (and has a fixes tag)
>=20
> So it sounds like we can either:
>=20
>  1. Revert 07313a2b29ed in the stable trees which contain it and then fix
>     the original issue some other way.

07313a2b29ed should not be in the stable tree.  It did not have a
cc:stable and we've asked the stable tree maintainers not to blindly
backport everything that has a Fixes: tag.

How did this happen?

> or,
>=20
>  2. Backport 0c24e061196c2 everywhere that has 07313a2b29ed. Judging sole=
ly
>     by the size of the patch, this doesn't look like a great idea.
>=20
> Is that right?
>=20
> Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220816163943.672fe3285bc391b48e431e54%40linux-foundation.org.
