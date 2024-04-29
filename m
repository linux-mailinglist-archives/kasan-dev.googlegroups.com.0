Return-Path: <kasan-dev+bncBCSPV64IYUKBBKNZX2YQMGQEPYFGW5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-f64.google.com (mail-wr1-f64.google.com [209.85.221.64])
	by mail.lfdr.de (Postfix) with ESMTPS id A13118B5989
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 15:12:10 +0200 (CEST)
Received: by mail-wr1-f64.google.com with SMTP id ffacd0b85a97d-3455cbdea2csf2318402f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 06:12:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714396330; cv=pass;
        d=google.com; s=arc-20160816;
        b=eDv2DGcvZWQkDcFUXvB2hYtunw5ARtKQuVGrPEFOwoTNGU6mXc5eRNyRBKVO9UZiar
         pmFYkS5eoOIsfTwfE0NReQfC/jbcxUbxHIEnyQZg+rcvJkK6FL/3dOhbUVlq1jFj1M/7
         VlHgHdwpknc+EhCsIADkhD5J4Ri9Izoy9/lw9iQv8tSRq9rUGyewte0ZlSPodCocUIhW
         I3uYm/TdRvhQZEgj21pSrQzaNQE4zS7ZSuIO620+9K49iiOpVBjjGyGXEELbdA20dL5j
         0lOiDB/GMxebnsPhL5Q0au2tEetrQeUyobQNTWB73eOD1c/dIqW4r4eUrnsGbKQnxwL5
         2pjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=n8GTRgJWBbnzZCU4eR+mFAcvkvJn4taUj5Zhfqsslpg=;
        fh=uO0FHMmB65vom2jJx6FV5WJT+vH796n1Mm/5DbiCK1Y=;
        b=pCx75MlygKWnauM4DQmXeEKkI+lG2YOxuQS21fS07dPsrJfWaY3Ai3HPMI2Q+aLdiX
         yo9LKK6hpHCtCAJQW+YAPRXzCZJLZk6zm/GdKuXndaNMNDuHAinmQlXNVM5wFFu1RHh0
         UAkYh9A7kk18B2MkGK+TQhlVhPylX6HNnH+hzs8fW14kMPJ8iD9r4DmDhczav5cHRSDA
         F+D37z9IbXyb60LxEuVFTwDDXGuvn58K71qJl7bTm5ih59ItU3Dpz1WKP4gQci8BqcAF
         tYmplHtcWbu6WZJduxIXcKLyJcjHilNefp+1kKhO7xa7uc+rk8C9TOMHhMEaQHs8/E33
         2R4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=I0IvXxBC;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714396330; x=1715001130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n8GTRgJWBbnzZCU4eR+mFAcvkvJn4taUj5Zhfqsslpg=;
        b=a4rZsmnycyrIhawDgf4LFtytf1kM0p52yOUUfNuiSPVCBw5seThzZcqScW4JHblw4q
         NTxJGWoh9dAi8GfqCiptrGcb5ehngUflQniXrgIvK82zjVTTE/x/sOYlnzFtdaShq4RG
         2wNVdB6xMOl6ktboArtHexm7Ceua2C/TSIIUjtZubw2PGvy0xv7OCOMOXQqdK7+FHRay
         OGH7is7eLamb4NKHXSHiTIrCCHZL9FSxeITBOu0wVvoxwDGhczZmPzgYIEf8GrUBjAQO
         59o8nZD8ZtQDhaEWE1FrrQROhm150sfJpXPvnGAFG9yMcfofaTKBMkMY0Q4ad5iyLPKc
         ykFQ==
X-Forwarded-Encrypted: i=2; AJvYcCXg5lIfHwYwoDhkHocaPNQKwOf4embGJuCyJYp4cN5ra2B3QMny+ewaCrY6/eOUFxbddGdUmmWE1taUfwjFuHdApgphv02MiA==
X-Gm-Message-State: AOJu0YxUQ438mMjkCGNiBFLH8lo2PAR63wAA7YkE+Cuyir6cRljncN+8
	WGsxIpToC8wyBwpTXVbAL3FkBt6aZdZ6Ke6g7LcJqbbsKUNxfEwH
X-Google-Smtp-Source: AGHT+IHOm97hcJvU1R6vNWQXg7ilsvOjObwEID1NAh5jZ4GAJd7+GLwvs2Nqw6ObTan+za9kf/AgyQ==
X-Received: by 2002:adf:ef10:0:b0:34d:10a9:3a22 with SMTP id e16-20020adfef10000000b0034d10a93a22mr2629365wro.32.1714396329761;
        Mon, 29 Apr 2024 06:12:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6e81:0:b0:34c:73a2:4395 with SMTP id ffacd0b85a97d-34c73a244a8ls926229f8f.1.-pod-prod-00-eu;
 Mon, 29 Apr 2024 06:12:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1TEblMQAmRGrlLwuaCEbUXISDmcjn6xYGOYNlRXTlVeK/SaC/UxuRX6kjE2B2HlGWmnPmIFXw2T94a6nL3+K+tJqtFBEOulgIIw==
X-Received: by 2002:a05:6000:dcc:b0:34c:925d:fa7f with SMTP id dw12-20020a0560000dcc00b0034c925dfa7fmr5204288wrb.12.1714396328041;
        Mon, 29 Apr 2024 06:12:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714396328; cv=none;
        d=google.com; s=arc-20160816;
        b=oLgT47eGjXiLgm13mJao1SeQ+CDlSdT8BXxEcFsaudVPq2CWPkVrQjTMVYL6lFl+Qj
         EaIFnzFEQ0JoYUwR+2K8DSUOxhFD6nmzHuadlW5trUoTr6UJh9hR5EF+3PUz0Bc4LD5l
         ChfDfD0+2ReXciGz7O6fYSpBLDbEidIIAXmgtEt1pbLljaLWtGKSHPZFeYcLLQW6ozNI
         OH3/wviiBrooew/RxYvzeBsoguGDiiM0UU7ahKnREQFlhS5G4jNsyeYcsOw1D9ASnvWy
         rvAJheDBhAQHw4m/R7xKvCncmma/IvTpb4KCk8DQUq98Ch+6AVCBOFRRgzGMloC+Hf5X
         bZPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ox5aOTl2u3/O1HZ+ZjOWh89n2x4TqGAsSONUIygHFgI=;
        fh=W3ZwuKdaXDHBN1A1L92YXmAn06zYpSYeNTXmHwGe11U=;
        b=aHZYyNi5ouCMz2QPzVGpDMRt2GuUTkjJCYEcQxhEjUsaafX08ky0OFOwF6QKPXBdbF
         69HApGeP7LuTuaALeIqMgqkLeS2jeXocVnxkYoSyxFd4utlq3IS/X36sA/sEcFtu8ad0
         YLLAPxrEb9aNSeK5aMT5QoCLwvs3brSisJKf5GecNC+m1BGaIPx8jrYnJqHzgeOaaU1p
         qErGoLibNFU9NOd12lJ3VWXs1OYouC5ep4FRGIczXfdyTKDFIUlop3EJGxWzFBy2J7nI
         7vicELFN1N3EN1oe+etn7kiXoYCVYq/Li0z+w2Sl5UfQ0YD9E0o4iuKNe2Q+eUJ+Y0R/
         YhNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=I0IvXxBC;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id dr3-20020a5d5f83000000b0034cc1c47b8fsi112625wrb.8.2024.04.29.06.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Apr 2024 06:12:08 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:60030)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1s1QnV-0003Cq-2G;
	Mon, 29 Apr 2024 14:11:57 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1s1QnV-0000sD-57; Mon, 29 Apr 2024 14:11:57 +0100
Date: Mon, 29 Apr 2024 14:11:57 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Boy Wu =?utf-8?B?KOWQs+WLg+iqvCk=?= <Boy.Wu@mediatek.com>,
	"linus.walleij@linaro.org" <linus.walleij@linaro.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Iverlin Wang =?utf-8?B?KOeOi+iLs+mclik=?= <Iverlin.Wang@mediatek.com>,
	"mark.rutland@arm.com" <mark.rutland@arm.com>,
	Light Chen =?utf-8?B?KOmZs+aYseWFiSk=?= <Light.Chen@mediatek.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"glider@google.com" <glider@google.com>,
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"angelogioacchino.delregno@collabora.com" <angelogioacchino.delregno@collabora.com>
Subject: Re: [PATCH v2] arm: kasan: clear stale stack poison
Message-ID: <Zi+cnTPS1rgHtneN@shell.armlinux.org.uk>
References: <20240410073044.23294-1-boy.wu@mediatek.com>
 <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
 <Zi5hDV6e0oMTyFfr@shell.armlinux.org.uk>
 <292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel@mediatek.com>
 <Zi+Vu29rmNZ0MIFG@shell.armlinux.org.uk>
 <f90f5352-30ed-419f-803b-7885b4298868@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <f90f5352-30ed-419f-803b-7885b4298868@gmail.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=I0IvXxBC;
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

On Mon, Apr 29, 2024 at 02:57:35PM +0200, Andrey Ryabinin wrote:
> On 4/29/24 14:42, Russell King (Oracle) wrote:
> > On Mon, Apr 29, 2024 at 07:51:49AM +0000, Boy Wu (=E5=90=B3=E5=8B=83=E8=
=AA=BC) wrote:
> >> On Sun, 2024-04-28 at 15:45 +0100, Russell King (Oracle) wrote:
> >>>  On Fri, Apr 12, 2024 at 10:37:06AM +0200, Linus Walleij wrote:
> >>>> On Wed, Apr 10, 2024 at 9:31=E2=80=AFAM boy.wu <boy.wu@mediatek.com>=
 wrote:
> >>>>
> >>>>> From: Boy Wu <boy.wu@mediatek.com>
> >>>>>
> >>>>> We found below OOB crash:
> >>>>
> >>>> Thanks for digging in!
> >>>>
> >>>> Pleas put this patch into Russell's patch tracker so he can apply
> >>> it:
> >>>> https://www.armlinux.org.uk/developer/patches/
> >>>
> >>> Is this a bug fix? If so, having a Fixes: tag would be nice...
> >>>
> >>
> >> This is a patch for cpuidle flow when KASAN enable, that is in ARM64
> >> but not in ARM, so add to ARM.
> >>
> >> The reference commits did not mention fix any commits.
> >> [1] commit 0d97e6d8024c ("arm64: kasan: clear stale stack poison")
> >> [2] commit d56a9ef84bd0 ("kasan, arm64: unpoison stack only with
> >> CONFIG_KASAN_STACK")
> >=20
> > These are not suitable for use as a Fixes: tag because these commits
> > refer to code in another part of the tree that has nothing to do with
> > the BUG() dump that is contained within your commit message.
> >=20
> > I ask again... Is this a bug fix?
> >=20
> > Is it a regression?
> >=20
> > Is it something that used to work that no longer works?
> >=20
> > When did it break?
> >=20
> > Has it always been broken?
> >=20
> > Has it been broken since KASAN was introduced on 32-bit ARM?
> >=20
>=20
> Yes, this is a bug fix and it has been broken since KASAN was introduced =
on 32-bit ARM.
> So, I think this should be
> 	Fixes: 5615f69bc209 ("ARM: 9016/2: Initialize the mapping of KASan shado=
w memory")

Brilliant, thanks! Now merged.

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zi%2BcnTPS1rgHtneN%40shell.armlinux.org.uk.
