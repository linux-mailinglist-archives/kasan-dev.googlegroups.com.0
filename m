Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPV66SLQMGQEYH5F4XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EA8E25974B6
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 19:02:56 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id i12-20020a056e021d0c00b002df2d676974sf9352247ila.5
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:02:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660755775; cv=pass;
        d=google.com; s=arc-20160816;
        b=TRWAuVUeiZMRiD477owtUrNRI2Lue45KTAukCagnWdp7VB7qVQQLsT0+zoX/x4OcXN
         nhIiBedCgV7Dxl+xjvlIcYIVwWanjCe3/Rj9OcgWdxyCmLX3ZfOSghXwe3uYl83z/aj6
         cGd3jNob8kdps4mU18erdh6MybbrkuCN85zQSqRe7RPQkMCRy33pMVU4yXEx50wvUzui
         huvJJo9ZfmyffNmbzAW+h/nMHma+O0ORtzjvSB/S+RE4zlNIvHypvxwQMLizwtJcyqat
         Vk4rp3hBctTTmvfA4Xs7Ym6NtEsMAAbWZ8nSAZdTT3UNaw2csS0vpb6pPa6zsy+K/iZR
         b5UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Xy6QQ1x5Ad6OphNnTGD7qJucGbecjkEjnDgdjhEnRgs=;
        b=RIQagTv+6EoCrtizB+7IVqu7pVS7cahZmE1BiMNoQwUrdhvj19YDHeh8OdiM6SdGWU
         hRFQ2xmrTIO8OqlfNMOdPUuSr/fJL9ljrQHpxt3nJEK6s2zOcDjlwI32DMpaGf8rUD4O
         HjdUVDTC/k9UIHGXFxdiOyvlrluwKIUlEx9Xl7z0ZnjB18e5lWTAqhEEld/PZgxocWGB
         3T6qnz1fxde/VCW1EebMQWGlyIAbGCvrSNgXnGHEuJncLI4OXBTiz3jpkMR6TRf5u8So
         8xNuht27xVeW6+IHPRxLp9g8VcJX4HFqNBY/UPWvCy9Qc2RI6EQywQWoyZJ8/FOJuJew
         DG1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc;
        bh=Xy6QQ1x5Ad6OphNnTGD7qJucGbecjkEjnDgdjhEnRgs=;
        b=HT1KzX5HzbDj2AmhA4MPFOSVT+UhJktYaHmhpBOzpC3y2JVbbscfZccRzzgp1QU/9t
         19PmHuadV/ug+4eQD5Tj2NcKFSp+EdYA9/L98NzrBlFYI0GiSkWtRf/C/mDfYGdizAKC
         B6F2p2zLrG23O4Vcy+fcVgCMnv85v8fSM7UJENWSeSB710waTssUDjwt5aJeq6v2YcvN
         6voOFWJiQJX/8FTmnbBMBhp/uH5mRPX3EUBQZqrfDFCZJTK3plOvRDtaT6TIwQLWXTP/
         gTVF/jG0/yUWIw/RdVKh9UJkYqHzoxrcVQDd+xRs/1sFQQDeuN/K4DBSugKF9SvZdEZs
         qHXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc;
        bh=Xy6QQ1x5Ad6OphNnTGD7qJucGbecjkEjnDgdjhEnRgs=;
        b=FBKIT1rwiRd5EITaTeC0tgeYVmpQGzXFaoLnPjw5mF2jP47t3wu40DFB2woIo41/Au
         mXBwakVeEW6VC6ssACXBeVKaFPDX8Tp/STY9tNfFQ58QzsqzZ0gGrgTKZMzyq8Laws+T
         S1SaHrTmPRIfzAt2FnECLMQ50HyN1V/RicyNKG6YOFIPmiZneWnXcI+UmLIenYtwYVtY
         UhZiWAbevmu/5M0LZN6Hhxdb/+SA8/wrIliCX2wqwtw3QDJoPno5EvUUsj5EL+M1bmUk
         50+lbi76vhSS8oroONWh+gRWSfFdKfOTkrVAZptQy8mce/LM6sjhG/a3aR51FeqRU5Xy
         MYIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2yQKbDb+XujbG0ncZsGuC1nbAoVH5T7xzXMvUiBoDHbVRD/4Jz
	W0z+rKe5ydtEgIwxRXtigyo=
X-Google-Smtp-Source: AA6agR5zbh9g6rC+EbSLSGlIsmIqpR2hT9jo06NMW5SqAS1JwihZWIHyM9+wqvzmij3B0tWLYs9Klg==
X-Received: by 2002:a05:6638:3d84:b0:346:d274:146c with SMTP id ci4-20020a0566383d8400b00346d274146cmr983465jab.155.1660755774981;
        Wed, 17 Aug 2022 10:02:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e0f:b0:2e5:9aca:e895 with SMTP id
 a15-20020a056e020e0f00b002e59acae895ls1922620ilk.11.-pod-prod-gmail; Wed, 17
 Aug 2022 10:02:54 -0700 (PDT)
X-Received: by 2002:a92:c549:0:b0:2de:7b52:ab93 with SMTP id a9-20020a92c549000000b002de7b52ab93mr12230284ilj.77.1660755774392;
        Wed, 17 Aug 2022 10:02:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660755774; cv=none;
        d=google.com; s=arc-20160816;
        b=0TI9Epz39143QukqKiMD3rVDkYyK5k294hcEQKQTtjhZCNSLbCbSpO09UwmnLnC8Ys
         XqCsxGdizUmPH9r2RwFA15BIoiQI4aa2HPRuDh524xNkfrCxnWMqJApOIVl4YvspYYpl
         Ru8CeMCTB35slTe1t3lICbHKCk4ruU/UAg1iJWDQAiavTX2BKPl9S6B+Uv0i13WqUi5W
         XeNOkqc8ZMLonAcwZQ6rI9YbuIUaj34m5+e3ZnkHnt30fiZdK/f2gTUQqJELq9JKzQEw
         s5Chd07pkUNjQ7jsBfhLiLV2lJ2yRMD4jWtCpl5Dl/WePw+dvHTWaDeXLTALnf2XpNSI
         o3IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=xGTU+7PEnkjt4L9Ei4/B6QxM5QoPm8OhG75IodRhvOc=;
        b=cSrUeabxp9/D7+1RWsfoiSyHlxN8N1/N2WmcFGAnOhLiNg/IILn4NZw5Hvd5C2GBlJ
         CyTyFqEmYP+zS2jN2LHUvvfynvgzf6lUJlRAQSxbbjFVdiY+TCFoqu1Qd/ldoCbfLO8d
         E1l6hd+trTjT4wKv8LAA11yqSYw4Ga5rtwU3+NbzJHmDxw9zM1eU6OHM2meyt7LljZ6V
         RFCSr0mjO7yceyycu/+QznpcfqlfqCWJ0ZAvCC8VDjj/Mm3iBxCnQBRV55PAfi/71UHM
         msvu01aoh7jMMmn9mVoC+Z8mz1iyQwU+x66qIO79w5mEw0ve+9pEatui1DbavRL5iCh5
         bUBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id l6-20020a922906000000b002dd5983e472si780185ilg.4.2022.08.17.10.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 10:02:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E7CBC6111F;
	Wed, 17 Aug 2022 17:02:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 29FA8C433D6;
	Wed, 17 Aug 2022 17:02:51 +0000 (UTC)
Date: Wed, 17 Aug 2022 18:02:47 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Yee Lee <Yee.Lee@mediatek.com>,
	Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <Yv0fNwX/nlqIL9ou@arm.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
 <YvyJwrCNUdKHwxeQ@kroah.com>
 <YvyleOsHoztisPHp@arm.com>
 <CANpmjNO0mMNFA0vKdLjvOvzJo3=90ads9wUz==u84WBYnPQY3w@mail.gmail.com>
 <Yv0c0+ZRxxVc4W27@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Yv0c0+ZRxxVc4W27@kroah.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
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

On Wed, Aug 17, 2022 at 06:52:35PM +0200, Greg Kroah-Hartman wrote:
> On Wed, Aug 17, 2022 at 05:01:50PM +0200, Marco Elver wrote:
> > On Wed, 17 Aug 2022 at 10:23, Catalin Marinas <catalin.marinas@arm.com>=
 wrote:
> > > On Wed, Aug 17, 2022 at 08:25:06AM +0200, Greg Kroah-Hartman wrote:
> > > > On Tue, Aug 16, 2022 at 04:39:43PM -0700, Andrew Morton wrote:
> > > > > On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org> =
wrote:
> > > > >
> > > > > > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=
=BB=BA=E8=AA=BC) wrote:
> > > > > > > The kfence patch(07313a2b29ed) is based on the prior changes =
in
> > > > > > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up=
 earlier in
> > > > > > > v5.19.
> > > > > > >
> > > > > > > @akpm
> > > > > > > Andrew, sorry that the short fix tag caused confusing. Can we=
 pull out the
> > > > > > > patch(07313a2b29e) in v5.19.x?
> > > > > > >
> > > > > > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/comm=
it/07313a2b29ed1079eaa7722624544b97b3ead84b
> > > > > > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/c=
ommit/0c24e061196c21d53328d60f4ad0e5a2b3183343
> > > > > >
> > > > > > Hmm, so if I'm understanding correctly then:
> > > > > >
> > > > > >  - The kfence fix (07313a2b29ed) depends on a kmemleak change (=
0c24e061196c2)
> > > > > >    but the patches apply cleanly on their own.
> > > > > >
> > > > > >  - The kmemleak change landed in the v6.0 merge window, but the=
 kfence fix
> > > > > >    landed in 5.19 (and has a fixes tag)
> > > > > >
> > > > > > So it sounds like we can either:
> > > > > >
> > > > > >  1. Revert 07313a2b29ed in the stable trees which contain it an=
d then fix
> > > > > >     the original issue some other way.
> > > > >
> > > > > 07313a2b29ed should not be in the stable tree.  It did not have a
> > > > > cc:stable and we've asked the stable tree maintainers not to blin=
dly
> > > > > backport everything that has a Fixes: tag.
> > > > >
> > > > > How did this happen?
> > > >
> > > > I do not see 07313a2b29ed in any stable tree or release that I can
> > > > find, am I missing something?
> > >
> > > I think commit 07313a2b29ed went in mainline 5.19, see this merge:
> > > 39c3c396f813 ("Merge tag 'mm-hotfixes-stable-2022-07-26' of
> > > git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm"). So there was=
 no
> > > stable involvement.
> >=20
> > I sent the revert as a PATCH for 5.19.y here:
> > https://lore.kernel.org/all/20220816163641.2359996-1-elver@google.com/
>=20
> Why do we need a revert here but not one for Linus's tree?

This commit was meant as a fix for 0c24e061196c21d5 ("mm: kmemleak: add
rbtree and store physical address for objects allocated with PA") which
only made it into 6.0-rc1. But it ended up in 5.19 without the commit it
was fixing.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Yv0fNwX/nlqIL9ou%40arm.com.
