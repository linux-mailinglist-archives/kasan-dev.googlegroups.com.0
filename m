Return-Path: <kasan-dev+bncBCSPV64IYUKBBEPPTSAAMGQEPOX6C7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-f58.google.com (mail-wr1-f58.google.com [209.85.221.58])
	by mail.lfdr.de (Postfix) with ESMTPS id 883ED2FC044
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 20:48:33 +0100 (CET)
Received: by mail-wr1-f58.google.com with SMTP id u14sf10351906wrr.15
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:48:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611085713; cv=pass;
        d=google.com; s=arc-20160816;
        b=NjxHaNVUPXInJcOFhFnXaJqJi/EwINrRX98BDGHmwya/lWn/8VIwQGwGbPW/3hFmbF
         FZMeEGz8Wj42tTE9f5q/5DTwYU1+Iqz63AsHrCqCCjedzloF6jk6CJPnO7/07cN1j3SA
         h3nNvAWJUEVarjiFnvfN/dsOQCnqLHROuS3nESSJoAWyQHDES2A3ltUnPkmK/QOSXv4A
         xbVHx1+8wbm3FVDzkwTbfjKeEMz2YH1CZ2tf3QaHG6twmg0XXBmb/to5MBskickISoDY
         1bVTBQvEfH/ByJJT5SoFN0V/apKuhc4JUnoHIA34j8UyU4PivK08cird+7zBLVAv24HA
         GDgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=buxS+eJ4vhi2toMfpSgGEowzy5oaS5INA5lZQ/41mvg=;
        b=f6vFizjrq72dtJqLc1tE69GHdDmrO9x8/wounG3IpAmGRd0SJ3UIuLwRh/BAsMkNJ3
         sFc0WmUeu2p57eh89N7aVCQlwkTgiJGPll1DQQcFTIrdAvJIVlY7nzfV4aHgyAvYN4TB
         XllRJaOfHuDUE8spfHlRzkzvQVSyo4vfr63X+0//XDTayDsGvVtIfjlYwTQjIzMoSwLF
         sHj2kBmGrz7YlcuoHxm4TkMHxo+I6ztgjFC1nguhaXFpRre64aoBFh55/wYBQfNOvZxY
         RuBfICWfZfdM991D6nzQF8PhwvgZDciFM5BsARJLhQfuUpAll7yUfVd8iSbKwJ7Ah9iN
         Aa7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=QxraNCTC;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=buxS+eJ4vhi2toMfpSgGEowzy5oaS5INA5lZQ/41mvg=;
        b=GxSLqNKdHf2BvkijfH8Pgs1xcpe8c1J2QOM9jcN082eBCQdAAc40dkCvil4WBVQTUH
         Q5a0IY9tmOy01eBf7iYxu6WrCdSdJY5MSDdKHyK/XktTZI2ld5DmdtJbbo4sCrUHusfD
         /D6npcTO9voYaM0ZAfR+3ofOeLIyYOgm90zJTr2fpoAjFosy0exwJaQDVQehUgqrJ4F2
         0EpehhbTWDwDLzrKaFiohsUXOJ2NyI0UoHzsP1Oas57YAznb9Nphqt+n502soAykqfAh
         q1C4VoUOxkRvuIEzA+uu30ql03HYxHFVBvOMRSTooDtqUeZTGCISklt6HQJTuOe45dvg
         Ngmw==
X-Gm-Message-State: AOAM531+O/wB6do1AsGUPgvCYcVJ+C7pr3500aDae96canoxjr3Ey9Mj
	CwaxzKHT1V1fAkkwdXPfGGg=
X-Google-Smtp-Source: ABdhPJxsS3cBzW3WM6SG92tW6fKP650QenLtsaqb75RmjHwveNyiF7uFgvLkG/uNh9QLo1TyUX6qYA==
X-Received: by 2002:a5d:6a05:: with SMTP id m5mr5789760wru.96.1611085713281;
        Tue, 19 Jan 2021 11:48:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls473595wmb.2.gmail; Tue, 19 Jan
 2021 11:48:32 -0800 (PST)
X-Received: by 2002:a1c:20cb:: with SMTP id g194mr1087327wmg.51.1611085712475;
        Tue, 19 Jan 2021 11:48:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611085712; cv=none;
        d=google.com; s=arc-20160816;
        b=KBjmv+NiBf2aeCcyNydJaB5B8efI4k3BG29PpBbefbEvNMMAiZUYvGyzfHryU82ci/
         Z9+qP21Ou3cgs4uDp51hVptjo/RCF/tOPnYEXXnwK8BnVsGbLZLfqRE2Kq3X9d/H5kT+
         80dSEw5L32KfLJ/ZHSseLZC+qf226eAayG1VylXLv4uhNaiQ39r5E2r8ZW6bBEeT8TPc
         U1cBQdtY1AqS6/urYrRQs/qOYUhU1EyEnfrmykvsle1RfUBgJfsTPW/E9XVJZgClvwp/
         bNAzOap16RVmadTBaYBStJtQPC4+MojOF29WQ4OZvmt7pz9OQ+rHdaon0mvB6lvtqDGr
         Dlog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=UJ+Gl/MaDzjeCMELmpBWNOHj8O0WSEwffGTVaKOBVEQ=;
        b=bz0ReXIAxhk32efhtDRiQYYJcCKwFrd3Y5h55H6FfyiJOio5IAOezDFpBmc2Zx7YOf
         Hp1bbr9T/E/Wzl85B+DC7XrLoNhzaxL5vN7G2RF8u8yeOPii9tzGiI9QifpndAKMleD9
         EdNlhLF7pqG4abLLe8Lw8sQOKUHSdKUJ+/ogla8VVKFt9BanFsVxSLdl4L2oEo4YtKK/
         dPUfQGH/6Az4QuVAnZDCvPntVs41MDJRV+zKsHwZCZo0NdMvStVTbjle3V9eDKbgcyMP
         hu+gnVeiLR6tCDUPWt7uypY5gS0bTcC3x2j9NZKnorrmNBULmbj2Dm+rr1EkfbwKpfN8
         fLSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=QxraNCTC;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id i4si289212wml.0.2021.01.19.11.48.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Jan 2021 11:48:32 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:50094)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l1wzM-0007oe-QA; Tue, 19 Jan 2021 19:48:28 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l1wzL-0005I6-8L; Tue, 19 Jan 2021 19:48:27 +0000
Date: Tue, 19 Jan 2021 19:48:27 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119194827.GL1551@shell.armlinux.org.uk>
References: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk>
 <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk>
 <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk>
 <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=QxraNCTC;
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

On Tue, Jan 19, 2021 at 07:57:16PM +0100, Dmitry Vyukov wrote:
> Using "-kernel arch/arm/boot/zImage -dtb
> arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" fully works.

Good.

> Using just "-kernel arch/arm/boot/zImage" does not work, not output
> from qemu whatsoever (expected).

Yep.

> But using just "-kernel arch/arm/boot/zImage.dtb" gives an interesting
> effect. Kernel starts booting, I see console output up to late init
> stages, but then it can't find the root device.
> So appended dtb works... but only in half. Is names of block devices
> something that's controlled by dtb?

My knowledge about this is limited to qemu being used for KVM.

Firstly, there is are no block devices except for MTD, USB, or CF
based block devices in the Versatile Express hardware. So, the DTB
contains no block devices.

In your first case above, it is likely that QEMU modifies the passed
DTB to add PCIe devices to describe a virtio block device.

In this case, because QEMU has no visibility of the appended DTB, it
can't modify it, so the kernel only knows about devices found on the
real hardware. Hence, any of the "special" virtio devices that QEMU
use likely won't be found.

I'm not sure how QEMU adds those (you're probably in a better position
than I to boot using your first method, grab a copy of the DTB that
the booted kernel used from /sys/firmware/fdt, and use dtc to turn it
back into a dts and see what the changes are.

I suspect you'll find that there's a new PCIe controller been added
by QEMU, behind which will be a load of virtio devices for things like
network and the "vda" block device.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119194827.GL1551%40shell.armlinux.org.uk.
