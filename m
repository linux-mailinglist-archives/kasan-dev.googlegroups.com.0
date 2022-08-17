Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBWFZ6SLQMGQEJHLSENA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CB96B597476
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 18:52:41 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id i12-20020a05610220cc00b0038a83e3bb42sf1720040vsr.10
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 09:52:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660755160; cv=pass;
        d=google.com; s=arc-20160816;
        b=TydCR4OyDy2eTtiW8vok6u5URyQVd2h9EFuzI+qnO7205ShHNiPW55wQiqyJqP9Htk
         3q3mRwI6Lm/22MWOtR30JcFTUZip6gVZ+f5TLN/8usrEvt42PUEpCTl2JwE1hnEOzaf6
         Rqtn7nSGNUDuKhpbbc8q6pxK3ENsp3YtibBzLKB5Xxb9OBaf0MMaKWTzmQ/kdJD/mxJI
         42PGmn10Dcb+b7HbEdqHNtQv1Cy7zm7MH1okbbgy/kWUmimwii4Qon9VocoHCM3AQdlH
         ndueng0hehMKhrC+fP/YRmy8uGT20OZuCNfMI8ygpz3f4qM8YRNvF2B0bmJtmgJYqxnE
         PP0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=alk4XTMBjoKSEbDoeTyYzKb1M5U6qMp3/B5XqSCWAac=;
        b=dTv2ypQSSb1QcwHWjFGFiUiDh66M9MKxmqYtK/S+JPAf97EbP+rKgBnIDRkprEIuR7
         xM1OwD5ZumMoX83hv6j0FVamZ5aW2lIWUhBH/z9k+/UNlJ+zJcgeMcNY0w2pE+FZywqU
         Az/NmKL4V0mWY6Ec3RxYXdJ3yXCMKOEiNY/+0rQ8fuN/IbLNalgHO2N/i/QndbYR1CKs
         2ZGDesAiUj5NZNKh4VR4gfd1PSE75huWUfYFUmN+jNY2op/jUQgxDTjvrxcTbsevwWtv
         OWRelmCtG3yYsoMW1qMR3XljKfI5bO969A9U8YXJwEyXNrbKzMk3EcMaW3Z5VUQ+88q6
         ev0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=xosMnAiK;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc;
        bh=alk4XTMBjoKSEbDoeTyYzKb1M5U6qMp3/B5XqSCWAac=;
        b=t2iM+ArArOE6eBW15Ro23iq+oNzfYzRRMtgfbpdrnKlwieBU/jKYFO2hbFX/alsg50
         htmaumffI1hNi+JePfvHKK6PZiRwyT60nj67YuH5/BJKheBY54vnGVt6Mz8S1CmtDjxq
         MPQTdx30T7CH57sHVxYb3ofyUvUpAcV5IdREhOe6jYR2gOXkP/0zE7/Gf65Lzr7CA4uu
         +TjBVhZPRnxzhYQrVX9OFIOWO9xymJRzN7ZqgyjyZs9sEGfQcO2L6EY/iA5lU9oiGMWl
         zNzPJ9MppZcvoQs7XysUVZ1+9Sp4yuHApZNVDSGEecpSNUTZVFvWy96WbBSzMsBfrIcy
         xySA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc;
        bh=alk4XTMBjoKSEbDoeTyYzKb1M5U6qMp3/B5XqSCWAac=;
        b=5wPWkyH6mVqAGYbvF1ZtxleEjYbshjH/8bHebRSkBmQkmVjjp8w8zvPpsi4SpQOTXe
         Fn9v2kB+Y2se7Pby9zYdBXFDSwdi3k8/vHrZkPUBzTbxdW1hTJ+Y0mSqDSfY76Vq7nSe
         U7DqTPkxcwLrKidlqtNbC/4jJPAJke4mrxvEJuzMPtEf1Edufv6P6TR6HfnWLaFmEU9q
         I2wTpJRF5Iz4HSNTs5r5dvjUcmaQTy7uSOHnEjO9wmWCWSLCh+ALA8EGPhYqJ1H4dqat
         bkmg/nIY0EENQBx32+AvkD+F1nTOjWbA79sqHJ3Jt/Agxebop6ahkMmxaTKSocSVY8XZ
         3kEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Wl0XCUITTYZn1rZw0bsJVPIlNsEoD7LU4uQjLMmeLovvYQCkk
	bdEXRf8HR+1bpTK5DdvW9uw=
X-Google-Smtp-Source: AA6agR4tNNf9jIbOcVo5dAz6d0dzQwz9fHhYREeC4nAhEQQKdTYvgsqfW6/RTmJth4f5hTc/qDBJtw==
X-Received: by 2002:a67:fa90:0:b0:38c:5568:a659 with SMTP id f16-20020a67fa90000000b0038c5568a659mr3723120vsq.63.1660755160696;
        Wed, 17 Aug 2022 09:52:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9493:0:b0:374:df2d:f6c5 with SMTP id w141-20020a1f9493000000b00374df2df6c5ls1951453vkd.4.-pod-prod-gmail;
 Wed, 17 Aug 2022 09:52:40 -0700 (PDT)
X-Received: by 2002:a05:6122:a16:b0:380:2865:5d82 with SMTP id 22-20020a0561220a1600b0038028655d82mr8067609vkn.40.1660755159990;
        Wed, 17 Aug 2022 09:52:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660755159; cv=none;
        d=google.com; s=arc-20160816;
        b=XH2ggKGUsgSBRjEquD/OEUm1tu0DanVaII7e+++FGzkdEwZ+/I2xv4fXOKX5VLIrAm
         j05ijlZnoQ0e3LR6sV4PH6RyDO4VDEODaA5QD4kMSFjJXGSGo4iIlxlMeHXTUnwXb9ZB
         lWO+B3joaKsb18YJnWBaVMZpBzxwiq6ed0sFTbqXpiECF0jROzt4zc6ltL3LXBueddNR
         F2BpnJk5fXa/hHkDYtothnFc7ByRAj3JbiWDec5xsRpGu/N/wkGHY7+nokKrNUOJUElH
         qgSzB9FpyHxSoMmHmD3s0wxM0XulBYoU26MemqyHAfksltCsGQywj2OFDIeMVOrxhq2Y
         xpvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=QGz9YIqS6Uvsfa4izNll3++66binpJ0YZx1Cg6gVu5Y=;
        b=gicpDV+Up/ZxkW0ExrzGM2Rom9hJqG7m938oXkm9ooMGLZefR868UkYDAcAhCeZdTo
         pRKqTbziiZWcPhRCjJJF4G0ihLP1X5NwQ/F1Jwk/9JeaHnVpVqMkO/hDpKbHv0LUgDt/
         ElNeOaazcA0u8qR6TpRFz3l+L8HEpZpsOtRcjCS+C2CqOVdjGpUnyXxFwN7ePWmf51S4
         sATNKRAANcE8Kxq2l8nvRTVuD0VqpmCJbqvygVhD/Yv9gMPNLgtoQXSME+l8ANZ2xy83
         QN9Ey7Y8q05mgSPkK6OX9G9odQwUHAMLkwUa25A46QbrGloS7Gg6waoSmoeuwTGEpR9L
         7h9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=xosMnAiK;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c7-20020ab06ec7000000b003875726f968si1552308uav.1.2022.08.17.09.52.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 09:52:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7881660C96;
	Wed, 17 Aug 2022 16:52:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3E038C433D6;
	Wed, 17 Aug 2022 16:52:37 +0000 (UTC)
Date: Wed, 17 Aug 2022 18:52:35 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
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
Message-ID: <Yv0c0+ZRxxVc4W27@kroah.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
 <YvyJwrCNUdKHwxeQ@kroah.com>
 <YvyleOsHoztisPHp@arm.com>
 <CANpmjNO0mMNFA0vKdLjvOvzJo3=90ads9wUz==u84WBYnPQY3w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNO0mMNFA0vKdLjvOvzJo3=90ads9wUz==u84WBYnPQY3w@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=xosMnAiK;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Wed, Aug 17, 2022 at 05:01:50PM +0200, Marco Elver wrote:
> On Wed, 17 Aug 2022 at 10:23, Catalin Marinas <catalin.marinas@arm.com> w=
rote:
> >
> > On Wed, Aug 17, 2022 at 08:25:06AM +0200, Greg Kroah-Hartman wrote:
> > > On Tue, Aug 16, 2022 at 04:39:43PM -0700, Andrew Morton wrote:
> > > > On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org> wr=
ote:
> > > >
> > > > > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=
=BB=BA=E8=AA=BC) wrote:
> > > > > > The kfence patch(07313a2b29ed) is based on the prior changes in
> > > > > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up e=
arlier in
> > > > > > v5.19.
> > > > > >
> > > > > > @akpm
> > > > > > Andrew, sorry that the short fix tag caused confusing. Can we p=
ull out the
> > > > > > patch(07313a2b29e) in v5.19.x?
> > > > > >
> > > > > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit=
/07313a2b29ed1079eaa7722624544b97b3ead84b
> > > > > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/com=
mit/0c24e061196c21d53328d60f4ad0e5a2b3183343
> > > > >
> > > > > Hmm, so if I'm understanding correctly then:
> > > > >
> > > > >  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c=
24e061196c2)
> > > > >    but the patches apply cleanly on their own.
> > > > >
> > > > >  - The kmemleak change landed in the v6.0 merge window, but the k=
fence fix
> > > > >    landed in 5.19 (and has a fixes tag)
> > > > >
> > > > > So it sounds like we can either:
> > > > >
> > > > >  1. Revert 07313a2b29ed in the stable trees which contain it and =
then fix
> > > > >     the original issue some other way.
> > > >
> > > > 07313a2b29ed should not be in the stable tree.  It did not have a
> > > > cc:stable and we've asked the stable tree maintainers not to blindl=
y
> > > > backport everything that has a Fixes: tag.
> > > >
> > > > How did this happen?
> > >
> > > I do not see 07313a2b29ed in any stable tree or release that I can
> > > find, am I missing something?
> >
> > I think commit 07313a2b29ed went in mainline 5.19, see this merge:
> > 39c3c396f813 ("Merge tag 'mm-hotfixes-stable-2022-07-26' of
> > git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm"). So there was n=
o
> > stable involvement.
>=20
> I sent the revert as a PATCH for 5.19.y here:
> https://lore.kernel.org/all/20220816163641.2359996-1-elver@google.com/

Why do we need a revert here but not one for Linus's tree?

confused,

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Yv0c0%2BZRxxVc4W27%40kroah.com.
