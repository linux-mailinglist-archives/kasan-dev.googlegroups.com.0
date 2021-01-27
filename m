Return-Path: <kasan-dev+bncBCSPV64IYUKBBKP4YSAAMGQEUX5CEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f191.google.com (mail-lj1-f191.google.com [209.85.208.191])
	by mail.lfdr.de (Postfix) with ESMTPS id F29CE305819
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 11:19:21 +0100 (CET)
Received: by mail-lj1-f191.google.com with SMTP id m25sf1011759ljj.9
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 02:19:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611742761; cv=pass;
        d=google.com; s=arc-20160816;
        b=g8U6gnOZeeuEEPug0gipGa4hVHr5d7K5cfF3cm7aTHB+9bnKiWulTuLwUaj/j/5bYF
         4mlYRc39d5Fee+sgvNFYFyGLoJ7QJdmkj8YFWr7mdIfcNxSttTE/DR8VJC6LTT+1Gk+D
         ahBF1DV/0k4A9hYlTA88sWEwa7yj2dWZwH7XGYSpD2zsifOByM7rfZQPvYCDcKkNSlDb
         xe+CoAGBSOYA7VOK/bf4Eao+qj+DcV8K50gIuFjlhGQM6hViSLuFYk7TlxGQcnhWVqKQ
         isnvXfhkgFD9RVXZKYfBH7OfMawARq91L02xLAmsRqTGjQzNVJwFuTDpLfvdGKHrPljh
         6GAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=HyIKGc/ZPtFfI1LjigNQql0kNeOXCi1JFq65/JW2JIs=;
        b=Zdb3zLdJ9AhtuqcgijXTJy3ob4wmHEKxS6Wrf/ROZ0IP97dFw/4vn+RsUjo91GPnkz
         sOnQx5iqfwLNzIDE4jIHjb7hrXplW+/KHu7/VAWVwcqWVWpSZ9IehMDCMwAJ6ZFi8xh1
         yehLovUhyuFBL3K5bHOuJKDdozvJIPlR79JMOHRMB7ov+ANsqqZDvTG2aET8+OUK7670
         Uv2vUdAMTD22pat+VjwOs+lPo8gpnr3Q6ny9HjLtviJYs4w/3LbSqvWYFpsCPqh2mRgN
         7aFDP5IQynv+dBvhaIs3XudS3tO+GLA+T6biIRN2+hfHGqNFTvs7Xrk++O177x+AWBbP
         7bZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=h0KKolQx;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HyIKGc/ZPtFfI1LjigNQql0kNeOXCi1JFq65/JW2JIs=;
        b=q0mwnX0hlukljzhBdKsEeFl3+S7WtiUOAj+H12p7WvnAS34XAfSTriXu4TUwSfmUxX
         F6f7WoUUK6dWoya/BRgpUhQhjSi5k5EGbxKisiQ9yw+Jp6BjimzG1eGymgH5t8zMsG+S
         CTGpqKxAyyKT8EoPf3taHcUcDDMu2DIBcf0Fnq0MQEojjqnacRRqs6/QJi/T+GycVmYz
         w97A9ckEBdj2x/KySw8odWlcGS0afzbpn6pZyjXJejTNezBrLivZprNDnuG/9Lo7Y3ot
         MyF7o+OR/0UEGFMSaNOiXIS0tNgFE1rztMV4g4oyB6HnBpxUgMQIzpVHftymn6iMfR7F
         BZRA==
X-Gm-Message-State: AOAM531Fsv66E7GrcKXuQ2cgI2fJ2DRB91f18HGepJsQ7SYagXEUF6zo
	NwqKKZ/po9jrP7YiHKPbQpM=
X-Google-Smtp-Source: ABdhPJzynFkek7Wivq02q3qegwZ+3aIL/1Yp3KjZPuU/FOiaTv2Ua67AWK8b0W4NOtU+IcePlCTurg==
X-Received: by 2002:a2e:1519:: with SMTP id s25mr5235284ljd.495.1611742761548;
        Wed, 27 Jan 2021 02:19:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls996626lff.1.gmail; Wed, 27
 Jan 2021 02:19:20 -0800 (PST)
X-Received: by 2002:a19:220b:: with SMTP id i11mr4792016lfi.128.1611742760553;
        Wed, 27 Jan 2021 02:19:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611742760; cv=none;
        d=google.com; s=arc-20160816;
        b=afbnzf4h4BETiGDFuwyrqNeicaoixg6SV63mS3ILG88EnjrWWGHH9zUJtF8GPHN0/C
         rZQiknGYIBkIox0B7h7ENFIUqPwn0xjjYytP7Oqj2o0WwseKEa9/C3mbMDtJseSOG5Gj
         WzysoKB8WQ3Ka0Rcg49WkOUXDWsh0fnQZkj/ob+teqdjjJe0Cea8KbOP6QWdiwaj2tK/
         5bE0DZLm2L2kXmLKBfmdAeSCRhWWBBIXi3P5nX2Fam3sHSIDymtXjvs2h+wBD7NMQidR
         PNzdH4NFXWl2e6B08SMWBHUqWzxUt3zX1xx/ZrrP1iB8J/EjyPmyqYn0l1X+tMjeUDf0
         bVNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=X71nbtO+IDAsMiCFLIMZtm4yW21O3Ez6En/15CCZRW4=;
        b=OCTda4QbrgLT6bPdMphPOG//vHsipWHmOhjImD81yjFZgKIOmD/nTuQlEwy6vTLqW8
         d+dMae7sjlUhVIEs27hxDbZynAbm4cpXNbkqs/7EV6DBewNcNM9T1hbPl/eUNHkBYoF7
         Lh+U4ClFvvEjdTQ8sMHJ07MLaGC+DhzFccGrBrIKB5Q9HpI65Ydk57KPzHazP50JqESY
         EXWvEkjArtMFA9hiDtt1YHnJG6bkn1kx8c01pDL5CM/oR050+RnDpYYBVUMOHqgxv12F
         n+LHYe9mpc1Sg+6PCR9ugfmBhJ6UHBWlZJRTTsdgLSLZlWQTNq0vxf1mLeWWYrRdgNBv
         Vb2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=h0KKolQx;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id t21si67091lfe.3.2021.01.27.02.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Jan 2021 02:19:20 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:53326)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l4hus-0005Ig-1N; Wed, 27 Jan 2021 10:19:14 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l4hup-0004jQ-CK; Wed, 27 Jan 2021 10:19:11 +0000
Date: Wed, 27 Jan 2021 10:19:11 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Arnd Bergmann <arnd@arndb.de>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210127101911.GL1551@shell.armlinux.org.uk>
References: <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk>
 <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk>
 <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk>
 <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=h0KKolQx;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
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

On Wed, Jan 27, 2021 at 09:24:06AM +0100, Linus Walleij wrote:
> On Tue, Jan 26, 2021 at 10:24 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> 
> > I've set up an arm32 instance (w/o KASAN for now), but kernel fails during boot:
> > https://groups.google.com/g/syzkaller-bugs/c/omh0Em-CPq0
> > So far arm32 testing does not progress beyond attempts to boot.
> 
> It is booting all right it seems.
> 
> Today it looks like Hillf Danton found the problem: if I understand correctly
> the code is executing arm32-on-arm64 (virtualized QEMU for ARM32
> on ARM64?) and that was not working with the vexpress QEMU model
> because not properly tested.
> 
> I don't know if I understand the problem right though :/

There is an issue with ARMv7 and the decompressor currently - see the
patch from Ard - it's 9052/1 in the patch system.

That's already known to stuff up my 32-bit ARM VMs under KVM - maybe
other QEMU models are also affected by it.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210127101911.GL1551%40shell.armlinux.org.uk.
