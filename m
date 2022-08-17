Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBAGI6SLQMGQECDVR34Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B669D5974FB
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 19:23:13 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id w17-20020ac25991000000b00492b09753c2sf111176lfn.5
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:23:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660756993; cv=pass;
        d=google.com; s=arc-20160816;
        b=hGIgR/ENbEFo+HGB6mDj9YFJucKRREPI/p8mqmjo65VGQZSYB8D7Ej4kOAi6ciwruC
         tc4Xz5tkfN0iXPvAKUQj3cHv1rqcbLuVjKMsdsWWy9sTOFQuklk4OEBXu44vaomkk5L0
         kOiaWBpQkpn7QIYJz27MBYoXw9V3j0e17W0v2wf0Yruqvna7qydVU4mBi98BJ55yEvb+
         dbKTIPg1zRiSgIYOJWm/WjAnHDQ4O7ONh9g2J6CLtDljl7qPOBUAkV4QMJz0lWpMEF/N
         sDkjhWCzbFW+bfzwrCQAI1IPUlXSfHSsZEh/J6ytjiEzmCGd7LmHhSSNwM0K7uM0KEIz
         Qy6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GllVd/wN0q0wlJfybu5Fn7CwMVAkHckV0Xq6fmgS6Cw=;
        b=IL32Y0ksXTuhhtcUhQW1QGFGOw03vxK9BDjDIe1OgCqKTXZSImdMRz5coSQ7uPUJ6M
         eovEAk85p0maX7YpMDmtsRe3wKKkWO0CnrE50qtfImU/7/Eqx/UHBN8pd659NeLGzib4
         vJyXZTvrjoAaYbKQ9tthHAL2550kk92nJY44c+p+MXUTdCknecWENDjlpXroKWS8xi+u
         i2+mKDY++7kxLpFvJyj2UAP6EKrH8PyZTtfrrA4z66jQFbOMF21Nen8vQMCI+qUe+KIg
         O3hBT4WderCzHqFfbpE6wV1k0h5yzUT+TXBoj8Z0PVjfWBQEppvIBxumKJ+AW4fGPrlH
         uYBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=WYgP5bvG;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc;
        bh=GllVd/wN0q0wlJfybu5Fn7CwMVAkHckV0Xq6fmgS6Cw=;
        b=I5i0NC0wiAn5kr7rIA/xPNos321D+zEmDiraNFVz4nfJqN1n+ZfohL8lVye1+7Q9Zp
         uf6v2ciZbLOJL4UM7tu/b1SE3g0qDXPtvnlYM2/J7uBYqW/byCOGWfrns9BawOR9bSCO
         I3Nq4ZdW9fnGWnLrtlFNZA27IHjxm63Piz7cQI9HmhQt4KgVaqSct50U7z4jrUBUS3tN
         CCWSOwaYTJnK0riGA6ybCAdEAqddiONTBNNnoIrLOmxmUbxYQ0N6GCxcEBMNImDXvPRB
         YHfwT82rMsZG4Yru+qGNqmvVnW9OYFWgAh1eNwB3qX4tQLQW3ckDv3JgYaYnY4JDJCxW
         F4GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc;
        bh=GllVd/wN0q0wlJfybu5Fn7CwMVAkHckV0Xq6fmgS6Cw=;
        b=BmfgX5wqob/QEw6wfo6iDvK2CjJnja+5B7wOulshfQovhEUEt88dLss9wY7VPlHerC
         Uef0eqelrpYCwS3+95eBUJoUDufTcIzwxAMd9Y1fHXfmKOjxbxd/MSP8nGBDjGbRbDti
         GyS+sM2FG0DDqE+ug+RKjv7QhjUbnXMuvGDiSWYtz/rA+JqCgNycbMb7wb5Y4UvDFnE7
         ZrwKW7KV3ZlIAJrlo8cu8H8vurh9Nwt1daCunsED286Bv2rWILSGmT/BG3Z+NYZiZiyB
         TgXn1UzDledvFSgPmPMwveBVFd7ZPs/sxpZ8LLR9acHxZ1EbG5JFeYJpQxF5ioQl/Mim
         FvBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1audsEP4mijIm88duGGnqKT78ZGuaIUNsFGkLZTDyvJnLDQQ8u
	gFpd2e1wFvEV0cRl2DPbg9w=
X-Google-Smtp-Source: AA6agR7DDXxsBYqzuuOAT40TjgoI0QU0G92c4uydxm2qHtT/YVdB5KFg9B4+W4e/JekjvD2BNTyVQg==
X-Received: by 2002:a05:651c:101:b0:250:896d:f870 with SMTP id a1-20020a05651c010100b00250896df870mr8594521ljb.235.1660756992885;
        Wed, 17 Aug 2022 10:23:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3148:b0:48b:2227:7787 with SMTP id
 s8-20020a056512314800b0048b22277787ls5928597lfi.3.-pod-prod-gmail; Wed, 17
 Aug 2022 10:23:11 -0700 (PDT)
X-Received: by 2002:a05:6512:12cc:b0:48c:7bdc:734a with SMTP id p12-20020a05651212cc00b0048c7bdc734amr9360908lfg.577.1660756991666;
        Wed, 17 Aug 2022 10:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660756991; cv=none;
        d=google.com; s=arc-20160816;
        b=dlUW6uwCw9a2ar9rWtslL4xmsei2qats+HZBxYx4CFzfB7OFY/ra5NpxwA3wvtixMq
         g+on7xAMklJgNKcobV34DCF2v1nzIxd0xObeKBbz55RRg/yQZ5x2M1QLHOL+jipBdSTz
         3jbq58o/osk5bN396ntazRjXblRKNhafRd4/60O1qUE/ez81yygN/enZ4SMHbugVfaxd
         pQWeRmuPxTcvPzXJzhNw0PqEUeI7bV01M1yZHxkgdYxWXf1EeSOel+er+4xMFsa4ccT2
         K82ZlJ0Hg9SUsO5gyhdHZQF/94ApCgysnhr5E9xQidSk68qdmGKCmcMsDE45PjYSzncg
         iY+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ILa+JzCF/hdYqd81SLM3fcHV2+ubi7OpWhXPurlOQOg=;
        b=0uPpwcFc+W6UUrWaU0UtqY6Obfvy7FCB5/qnS6jum9MpJBR8gvlwFNdPBuKs9AfoSJ
         bfzU0LWl1eSMqXWZ07aXkbHF1vTlazkYf0eDQPAzlZ1Vgeizy/tF0OJ1vQ8Ai/XSxENP
         oBQV6f2ZwlCq86WxcYGlRHiqoccej3P9bwS8HaQJtv9pgE4M/rcME+1wHY02ogdubxbB
         50SOTOkRMnTQ8DLtxxHkIc2l3l3QzKa+VOqMms8GOf4iP7ZykgpTdazBq5YnE2LnsMoc
         O5tlAwTc7Ge+qA7cR008SY/XV1CCW+s3fAv9/INfCF851ewkSkChteFSKc3erCq0zSwk
         v/hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=WYgP5bvG;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v5-20020a05651203a500b0048b12871da5si1057908lfp.4.2022.08.17.10.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 10:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E7768B81DA0;
	Wed, 17 Aug 2022 17:23:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43C90C433D6;
	Wed, 17 Aug 2022 17:23:09 +0000 (UTC)
Date: Wed, 17 Aug 2022 19:23:06 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Catalin Marinas <catalin.marinas@arm.com>
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
Message-ID: <Yv0j+sKaqPkTlnCz@kroah.com>
References: <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
 <YvyJwrCNUdKHwxeQ@kroah.com>
 <YvyleOsHoztisPHp@arm.com>
 <CANpmjNO0mMNFA0vKdLjvOvzJo3=90ads9wUz==u84WBYnPQY3w@mail.gmail.com>
 <Yv0c0+ZRxxVc4W27@kroah.com>
 <Yv0fNwX/nlqIL9ou@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Yv0fNwX/nlqIL9ou@arm.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=WYgP5bvG;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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

On Wed, Aug 17, 2022 at 06:02:47PM +0100, Catalin Marinas wrote:
> On Wed, Aug 17, 2022 at 06:52:35PM +0200, Greg Kroah-Hartman wrote:
> > On Wed, Aug 17, 2022 at 05:01:50PM +0200, Marco Elver wrote:
> > > On Wed, 17 Aug 2022 at 10:23, Catalin Marinas <catalin.marinas@arm.co=
m> wrote:
> > > > On Wed, Aug 17, 2022 at 08:25:06AM +0200, Greg Kroah-Hartman wrote:
> > > > > On Tue, Aug 16, 2022 at 04:39:43PM -0700, Andrew Morton wrote:
> > > > > > On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org=
> wrote:
> > > > > >
> > > > > > > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=
=E5=BB=BA=E8=AA=BC) wrote:
> > > > > > > > The kfence patch(07313a2b29ed) is based on the prior change=
s in
> > > > > > > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows =
up earlier in
> > > > > > > > v5.19.
> > > > > > > >
> > > > > > > > @akpm
> > > > > > > > Andrew, sorry that the short fix tag caused confusing. Can =
we pull out the
> > > > > > > > patch(07313a2b29e) in v5.19.x?
> > > > > > > >
> > > > > > > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/co=
mmit/07313a2b29ed1079eaa7722624544b97b3ead84b
> > > > > > > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux=
/commit/0c24e061196c21d53328d60f4ad0e5a2b3183343
> > > > > > >
> > > > > > > Hmm, so if I'm understanding correctly then:
> > > > > > >
> > > > > > >  - The kfence fix (07313a2b29ed) depends on a kmemleak change=
 (0c24e061196c2)
> > > > > > >    but the patches apply cleanly on their own.
> > > > > > >
> > > > > > >  - The kmemleak change landed in the v6.0 merge window, but t=
he kfence fix
> > > > > > >    landed in 5.19 (and has a fixes tag)
> > > > > > >
> > > > > > > So it sounds like we can either:
> > > > > > >
> > > > > > >  1. Revert 07313a2b29ed in the stable trees which contain it =
and then fix
> > > > > > >     the original issue some other way.
> > > > > >
> > > > > > 07313a2b29ed should not be in the stable tree.  It did not have=
 a
> > > > > > cc:stable and we've asked the stable tree maintainers not to bl=
indly
> > > > > > backport everything that has a Fixes: tag.
> > > > > >
> > > > > > How did this happen?
> > > > >
> > > > > I do not see 07313a2b29ed in any stable tree or release that I ca=
n
> > > > > find, am I missing something?
> > > >
> > > > I think commit 07313a2b29ed went in mainline 5.19, see this merge:
> > > > 39c3c396f813 ("Merge tag 'mm-hotfixes-stable-2022-07-26' of
> > > > git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm"). So there w=
as no
> > > > stable involvement.
> > >=20
> > > I sent the revert as a PATCH for 5.19.y here:
> > > https://lore.kernel.org/all/20220816163641.2359996-1-elver@google.com=
/
> >=20
> > Why do we need a revert here but not one for Linus's tree?
>=20
> This commit was meant as a fix for 0c24e061196c21d5 ("mm: kmemleak: add
> rbtree and store physical address for objects allocated with PA") which
> only made it into 6.0-rc1. But it ended up in 5.19 without the commit it
> was fixing.

Ah, that's why the Fixes: tag was referencing a commit in the "future".

{sigh}

I'll go queue this up now, thanks.

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Yv0j%2BsKaqPkTlnCz%40kroah.com.
