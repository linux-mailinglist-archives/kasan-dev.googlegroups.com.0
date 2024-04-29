Return-Path: <kasan-dev+bncBCSPV64IYUKBBSVLX2YQMGQECIVSHQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f58.google.com (mail-lf1-f58.google.com [209.85.167.58])
	by mail.lfdr.de (Postfix) with ESMTPS id CA7698B58C9
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 14:42:52 +0200 (CEST)
Received: by mail-lf1-f58.google.com with SMTP id 2adb3069b0e04-51acf60fd95sf3048716e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 05:42:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714394572; cv=pass;
        d=google.com; s=arc-20160816;
        b=DeUuHKh3GNbjA5ENTE/AfE630oRxe3TF5/eWsDw+garE9oUDBydhv82nHx8uViiXuF
         Ut3cWY5frlXlsa/NE9ItVFJtxGZj9ajk/FMkTOldaPt6O1l4fYVRNrAfYU1LttDOzb8y
         8Ub6ckcx0OIrHCjaXz8U3/5yzK6w11rYG50kUvOdJrg64cVkaeY1+La2Sjjj5sKwLOvz
         YD6dKdwS3PbjYr2FDieOqN4g2OioXKiyOAB5sld2Eu6ssH5vvoKeBMitYNAEj8fo9WU1
         MLmnVH6WRnw/GtTCZH74UyXqCzx+I5tq08JdNWedQoSzu+dEWfuU/4ZiJdUstlJrXQfO
         15xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=B/SB8yWSnHjyd+IdYCxBIehNAVFUE0cQhqGZn4Kbx5s=;
        fh=8nhke/dDYLTj4OmRGUUE57OWFfWghyhuFAl0q0HXaWw=;
        b=RfSEG69ytXYkFWhdUaCe1jDY63Qj0bvZ5PQNpI8sOQKy6FjDLhtX2Qn3IPL0eDhwDS
         0UXSjWdzSYoavs9Ohi3SeFYV4mUEHWGEFLAhyr6IfyqotB6VQeOalEO38ZXFmypSkIC9
         E1sDuRxU9arjxqaSZ3eIfIyYzYD+irFlMsALD0LXJ7m4ZwLlEeII7fK+BfdVjIhVCst+
         FZii6pW7uCNOGIQg9YI7MBvTuPDux5ombKynpHQ8LqW4jGXmxBm782688KyIugB8O3P2
         ju4Y0KhRINatGZROvonNcM1C4z8wuUJegM0SBCYuXXEbcRofXCFkC1y6iVD1pdUHXwdD
         fIdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=vYbycYWT;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714394572; x=1714999372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B/SB8yWSnHjyd+IdYCxBIehNAVFUE0cQhqGZn4Kbx5s=;
        b=Fw+678UVaSFBC8Xr208IfiZm44z648IslXQxzYHvWrmBJZHI9phWpl4h/NQhm8VF+e
         YK7XPuYnL2THDzUv5CkaT5dbwpeBj0YZSMhnYazKLdCzqoUSlABkGjG4M9HA248M0g4F
         OXN0hL4qHNHSutXM6e6SnMpi/c6QVlLixB/pxmHv1VHme8KJnHHR9QO13YfF+8fQ6GSA
         to6jnSS6bjlDkN8O6+afK0J00M99w8ym0WdnA+AonomWwhjs5yR5zC7NCnt1fvFEQ9Ye
         +Pz1jklClkkHhSAONPmzjlvXk6i6cavdYtMYuOwhNAsIvYryzF3mRzY3+Lun4Q/arkDc
         grkA==
X-Forwarded-Encrypted: i=2; AJvYcCWutXz887hmOacuQbKOsDeljZ3uR0NiHjm/sGYzempXyFVFcQmN163L6AYQO258c76IR93wmmOAWZm4Y3vo3CELUBzbKwfwfg==
X-Gm-Message-State: AOJu0YxOriWPo2KQGUENf1G87NqhkrlojvhBo2CQiPg+a6+Wf/wKWdZ3
	Yq+W4dyT8aMO2F4cFT4CG8rankIp+8o/W69Au7fS4CJeegDdB5PI
X-Google-Smtp-Source: AGHT+IE+dLRs0YTtuX47K6V2PXZb93V9vlDZLZpI4w5Yi/TNKqwr1T7XI+LHY1o+sCb7Z07hdLyIHw==
X-Received: by 2002:ac2:4e90:0:b0:51d:9a0b:735a with SMTP id o16-20020ac24e90000000b0051d9a0b735amr2301072lfr.53.1714394570847;
        Mon, 29 Apr 2024 05:42:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b8f:b0:51b:db14:78ff with SMTP id
 2adb3069b0e04-51c2e64ea27ls816836e87.0.-pod-prod-01-eu; Mon, 29 Apr 2024
 05:42:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXK7jp897UDxUEP1ST+S9AoFbeIOPHwIaoZa/YAx06B7njUH6hfja7bDRuVvcUXzf6xl/JGSpiDiO7GojQ2u5xKxFMDD7uzp2IVhw==
X-Received: by 2002:ac2:57db:0:b0:51b:ddfb:23d2 with SMTP id k27-20020ac257db000000b0051bddfb23d2mr4275405lfo.55.1714394568797;
        Mon, 29 Apr 2024 05:42:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714394568; cv=none;
        d=google.com; s=arc-20160816;
        b=zDVMuoK2eCFm8+NPMCuWH8ACqCd+L8wveXrjUwmTD7nuYEz7vtaAL2uCbZPSXT+NRI
         KeRsHHmDDeDSks365SBq4y63KrjkbQ2g0DxIS51l5vNi2MxV6AbG2BwioFH+qjTfTp5L
         zMCgIdr+rRIKaUT1FFxVKADlhReqhTvALUlmvik0OlpT+XX1NADkxEYKF4f6c1FzceKH
         dh/Hb8pE5fBfhIYD02U+nUOUdgmqeLEGUwkhFAx29Xb76kPAmeygWCNRwRLSwcok68cx
         1Q4/my1ha5ejQJX5nie91H2bMjNvY5bZIF8BLf/zqVWJQn4m5zHCul/4Jv/Xy9VvKx8C
         NWWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=359x1PKhAyHtMkK/vfg2dPAMOncA3H2TWjtf6Bw1En4=;
        fh=f1bCjR6GvEeKJIgL+fKn1RTGR8R19y20wfjjyDIIt9Y=;
        b=aEmHOz3/g3mM4Qz8Mf1RfFz4L5qHNmSk9dngVB/zLzEuB5vK7SdB7d/rgdVPhXuf24
         fQ+lrjpIKI0e9gb5z0dqNAA/gZ1PhDinObSqUjKdIrMMmjbhRxDCtDr56P0JYapTJpNE
         l4MihPpk/d8v4gTI1XBmIuYL4ZerpRK2pROAm4EBkRbwsXlJZTaCajyTDnDQFTmDaa0q
         7DJt2qbKk28CHmyNqUKveezQJNfPqiss34grxtB5aJ5WGt9KeycN8IfiuxVtRYcVJ1lC
         i0WlRFtWlzmzQnhlM0cvnPMG/XNeSOXLd4EQ98jj5T44XujyrTiGCaVMZI0wlXqvfjpu
         TQoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=vYbycYWT;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id m4-20020a50d7c4000000b0057048846487si1242250edj.1.2024.04.29.05.42.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Apr 2024 05:42:48 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:38466)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1s1QL7-0003AY-2P;
	Mon, 29 Apr 2024 13:42:37 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1s1QL6-0000rC-48; Mon, 29 Apr 2024 13:42:36 +0100
Date: Mon, 29 Apr 2024 13:42:35 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Boy Wu =?utf-8?B?KOWQs+WLg+iqvCk=?= <Boy.Wu@mediatek.com>
Cc: "linus.walleij@linaro.org" <linus.walleij@linaro.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Iverlin Wang =?utf-8?B?KOeOi+iLs+mclik=?= <Iverlin.Wang@mediatek.com>,
	"mark.rutland@arm.com" <mark.rutland@arm.com>,
	Light Chen =?utf-8?B?KOmZs+aYseWFiSk=?= <Light.Chen@mediatek.com>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"glider@google.com" <glider@google.com>,
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"angelogioacchino.delregno@collabora.com" <angelogioacchino.delregno@collabora.com>
Subject: Re: [PATCH v2] arm: kasan: clear stale stack poison
Message-ID: <Zi+Vu29rmNZ0MIFG@shell.armlinux.org.uk>
References: <20240410073044.23294-1-boy.wu@mediatek.com>
 <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
 <Zi5hDV6e0oMTyFfr@shell.armlinux.org.uk>
 <292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel@mediatek.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=vYbycYWT;
       spf=none (google.com: armlinux.org.uk does not designate permitted
 sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Mon, Apr 29, 2024 at 07:51:49AM +0000, Boy Wu (=E5=90=B3=E5=8B=83=E8=AA=
=BC) wrote:
> On Sun, 2024-04-28 at 15:45 +0100, Russell King (Oracle) wrote:
> >  On Fri, Apr 12, 2024 at 10:37:06AM +0200, Linus Walleij wrote:
> > > On Wed, Apr 10, 2024 at 9:31=E2=80=AFAM boy.wu <boy.wu@mediatek.com> =
wrote:
> > >=20
> > > > From: Boy Wu <boy.wu@mediatek.com>
> > > >
> > > > We found below OOB crash:
> > >=20
> > > Thanks for digging in!
> > >=20
> > > Pleas put this patch into Russell's patch tracker so he can apply
> > it:
> > > https://www.armlinux.org.uk/developer/patches/
> >=20
> > Is this a bug fix? If so, having a Fixes: tag would be nice...
> >=20
>=20
> This is a patch for cpuidle flow when KASAN enable, that is in ARM64
> but not in ARM, so add to ARM.
>=20
> The reference commits did not mention fix any commits.
> [1] commit 0d97e6d8024c ("arm64: kasan: clear stale stack poison")
> [2] commit d56a9ef84bd0 ("kasan, arm64: unpoison stack only with
> CONFIG_KASAN_STACK")

These are not suitable for use as a Fixes: tag because these commits
refer to code in another part of the tree that has nothing to do with
the BUG() dump that is contained within your commit message.

I ask again... Is this a bug fix?

Is it a regression?

Is it something that used to work that no longer works?

When did it break?

Has it always been broken?

Has it been broken since KASAN was introduced on 32-bit ARM?

I'm not applying this commit until I get *proper* answers to these
questions so that I can work out whether this needs to go in -rc
or whether it waits until the next merge window... and whether it
needs a Fixes: tag or not.

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zi%2BVu29rmNZ0MIFG%40shell.armlinux.org.uk.
