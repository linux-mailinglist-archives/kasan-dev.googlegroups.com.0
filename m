Return-Path: <kasan-dev+bncBDDL3KWR4EBRB76K6KLQMGQE73X45SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA72A596B4D
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:23:28 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id q10-20020a056e020c2a00b002dedb497c7fsf8658087ilg.16
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 01:23:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660724607; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6/CjTqvF/EsZAwVLyqXe5OoUMfgIh9t9nwMW+Awr1KPbdlt7hpoQWE202dFe6CTPR
         llXSmHMud5ECZ8zT1SeoZg+NpYHUGtH+JIg+O7OGnvbn+ANK5bt4Y8CkAjzDoly4gj6G
         kFTN45/vQtJfUTabArmkFfqqOERHg6a9mWHggoX1/3JIloItneFDvz5nTKh69L2I8YNq
         CBx+arathdKtd18scMHcDbIp3p7LlDMR6AYwdwukNaCvHu4h//aidRWew04uNlvrrEVk
         UjFrI4XAAnUk60URqrdDHy7vPaAqC05rq8dsXsFHHw9PzTDGp9bLAzO6xVnnodFqds6J
         OeZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YjseKUwnOeN+KFSPgr+5MRgzqHSTheKz2jnD1FGyvIY=;
        b=Cw5qs2rWrGiJPNEYqtz81Q8z8b5JO8ltHjNi5nXKzAT6XMGkeTaPNmNNJ5EIl3J6U8
         bdZK+ya17swQgBZchxbHNpca0znpGISDj7PMX1CGejc2u1Y8QEWsUC8rCJCos37nsdYD
         KHWC0eGmD3yOIOnizr5nsXgpTyDXPxLBHhVKH+a8cbDqvfCrYrGo9/QGdGaXR5qdG3xC
         tDhazi4fmsJnwf7NyY7eUG4GOzRFOgz+sRIGcpjnjRRncHfeYBrcxHLFhWWwXslIDvQ1
         qgz9h940RzH+F8PRU0GtkSf2Z9xVAoo/SeqThcuNIrdd8WFPIKGvC2WtxlClgRA4Thei
         zFmA==
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
        bh=YjseKUwnOeN+KFSPgr+5MRgzqHSTheKz2jnD1FGyvIY=;
        b=n7RTHEx5RTOJfbmy6O/8DsubpatJEuFFhWq5io1Qt8IQFPMj2YGunKLNBMIG0bE/hF
         cW5+6qGXCtYOaRRk7U8xTuzX2aY2T+nQIWGoAS2Yz8dTy8OWg8Y8Sk4W5/EINmFRJLXt
         QanPWDYmN3w3L7sKxaUoRoa4F2KGdJHgWJq94zFT1coQHONIqDjZQECqs3OGOGpjWlhQ
         XGAKouY8EYG1yDSNOjy61b/1UhfR4ZqOk3E1gb8LVoph6QPnUCv0vDpdgwwGiC/RQH/j
         YFlmEQYxwePQmCEDr8FdM6NNpUjYGHLqjnbnyb9Qi5u99XSZe1K9HnKJ5DWG2c7mdLAc
         S5VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc;
        bh=YjseKUwnOeN+KFSPgr+5MRgzqHSTheKz2jnD1FGyvIY=;
        b=mDBD0iIN0nWeza8ZnV0P2+rcJt2roTVBfUxre5veHvWOeElrzvEpeVLSs1fPW6lMJ/
         +s81iMuxl/FhLW2qQBgXPWtJdX56DCA2f3uJvl4l5x7SyilupPnRt4pjxWv2Jhtp0Zzh
         XLqv3B8hLcQkwvRiLUbPtejGVO9V9bMl8grD/5RirV8RBlQwVwkj8Px58OkLZEAkCv1D
         R+Oa1s07je8g6Vje6y47xK1Hy3/W/jWcEbkP2ADoUvZ+mp+tf0srmjhjPL50Ch/kHCkw
         Z8o8hYKNrESF26X5wljoJNQl3AzwVWQAeb9RMwm2NvFz2fBS057bJDNHY3UQYR8L02Ug
         ngkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3ebHS1C0JxmUTs67UoH8kefaGVqSrb8rsilbMztqmFbT8zJ+Ka
	aTyuC0cVLT+GD2dIAD08szM=
X-Google-Smtp-Source: AA6agR4mxfseHEF6xd7PssW3WWnXdQBypWVFD/FQTR2rgxnrnXgl2PtM0TjPe+CJAjfRb62OKmEw/w==
X-Received: by 2002:a02:950d:0:b0:346:bef2:6496 with SMTP id y13-20020a02950d000000b00346bef26496mr1955391jah.266.1660724607580;
        Wed, 17 Aug 2022 01:23:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:371a:b0:688:ec4c:4336 with SMTP id
 bh26-20020a056602371a00b00688ec4c4336ls134425iob.1.-pod-prod-gmail; Wed, 17
 Aug 2022 01:23:27 -0700 (PDT)
X-Received: by 2002:a6b:cdcd:0:b0:67c:9b5b:2fa with SMTP id d196-20020a6bcdcd000000b0067c9b5b02famr10841523iog.195.1660724606981;
        Wed, 17 Aug 2022 01:23:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660724606; cv=none;
        d=google.com; s=arc-20160816;
        b=Th524Lh/FQ0dccyk/rK8A6fNq8B+JcUshCcM1HJCDQamEl0xaVdAxNLx8PXtkq01Ar
         bPLaFEfWhlCFTlVvMaIWmPISD6lzyr522Kc3Gp1TBZmOm10eGxJpzfobiKgvac5GfwoJ
         2w9XdHOEAg4EI1UhGyXtxGHkrP+S6aJp7QJ82AwJIEelqHdOkLgA4Jaw4khj9ay89Lhx
         yid6iJgL9zgiRPSI9OE7aSIO0PeeFgYIHK0b0S1jy71kB9/qjDIomvecIt7fZZW+chND
         drYb2nt83fio1V/vcQX1S6HpQSQSKJ9XIjr9ki96QULdjd7+Cfiekax3mBhG1R3OkQK9
         WimA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=iweQVFAJFkShAFatNk5z5hKfd+KDXq1+4imfjo5AvHA=;
        b=XShFT4DDZrSDmnenmvvujddh8ucBch2TqlUIk51DAbvOhEcn7l7eqsQR06uXmXgkLP
         VHsP9ut8d5PT2Nq6ucYyvX3S+1hqx8laZZ80r0oMfjqHPk/0wfBXO/CFrzEDjJcUS4+g
         Ed+7najY2VdfKbxtDilkxL5KWGiPT0ahX+fsTrwLFORCLMbbtad2QrGq5JPiL9YlHsvZ
         xcDNt24Gn33X7fa8W2OgbtGBDrWUn2jtu+CulGeLsTa/81J621FishDm3lgkZTv3itsP
         4aycKdjdWGCGzvnTMkSmastpvN2WXZuM8+MczeE9OD0RtxoYcZUaGrlMRs3CPIi4jqgp
         pyiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y24-20020a056638039800b003436beefc0csi564671jap.4.2022.08.17.01.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 01:23:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 97C63612D6;
	Wed, 17 Aug 2022 08:23:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DDE0BC433C1;
	Wed, 17 Aug 2022 08:23:23 +0000 (UTC)
Date: Wed, 17 Aug 2022 09:23:20 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Yee Lee <Yee.Lee@mediatek.com>,
	Marco Elver <elver@google.com>, Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <YvyleOsHoztisPHp@arm.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
 <YvyJwrCNUdKHwxeQ@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YvyJwrCNUdKHwxeQ@kroah.com>
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

On Wed, Aug 17, 2022 at 08:25:06AM +0200, Greg Kroah-Hartman wrote:
> On Tue, Aug 16, 2022 at 04:39:43PM -0700, Andrew Morton wrote:
> > On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org> wrote:
> >=20
> > > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=BA=
=E8=AA=BC) wrote:
> > > > The kfence patch(07313a2b29ed) is based on the prior changes in
> > > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up earli=
er in
> > > > v5.19.=20
> > > >=20
> > > > @akpm
> > > > Andrew, sorry that the short fix tag caused confusing. Can we pull =
out the
> > > > patch(07313a2b29e) in v5.19.x?
> > > >=20
> > > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/073=
13a2b29ed1079eaa7722624544b97b3ead84b
> > > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/=
0c24e061196c21d53328d60f4ad0e5a2b3183343
> > >=20
> > > Hmm, so if I'm understanding correctly then:
> > >=20
> > >  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24e0=
61196c2)
> > >    but the patches apply cleanly on their own.
> > >=20
> > >  - The kmemleak change landed in the v6.0 merge window, but the kfenc=
e fix
> > >    landed in 5.19 (and has a fixes tag)
> > >=20
> > > So it sounds like we can either:
> > >=20
> > >  1. Revert 07313a2b29ed in the stable trees which contain it and then=
 fix
> > >     the original issue some other way.
> >=20
> > 07313a2b29ed should not be in the stable tree.  It did not have a
> > cc:stable and we've asked the stable tree maintainers not to blindly
> > backport everything that has a Fixes: tag.
> >=20
> > How did this happen?
>=20
> I do not see 07313a2b29ed in any stable tree or release that I can
> find, am I missing something?

I think commit 07313a2b29ed went in mainline 5.19, see this merge:
39c3c396f813 ("Merge tag 'mm-hotfixes-stable-2022-07-26' of
git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm"). So there was no
stable involvement.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YvyleOsHoztisPHp%40arm.com.
