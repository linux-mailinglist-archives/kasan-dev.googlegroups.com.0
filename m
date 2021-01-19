Return-Path: <kasan-dev+bncBCSPV64IYUKBB4MLTOAAMGQEZZXXAAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-f57.google.com (mail-wr1-f57.google.com [209.85.221.57])
	by mail.lfdr.de (Postfix) with ESMTPS id D333A2FB5BF
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:43:45 +0100 (CET)
Received: by mail-wr1-f57.google.com with SMTP id o17sf9764389wra.8
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 03:43:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611056625; cv=pass;
        d=google.com; s=arc-20160816;
        b=KSlnTqMBi8kRqn9yPZY3RQ/ysfpJ0dfVS8deLZNMXjAojBIkRC0Fo1zNyQplcORts8
         T8S+/067qfTwsL4rlitTvxUSLrrfk5NLL4usys2F2Jl4mYxEdYsu7Ga5JE0aXJJVszrP
         BmyZnVX9PxitKBZmPsgdyZAZpZUH6KfBnD2wgZ/d4fOXnN4vvAFDSrEsC92qMcakFYzW
         gD+3RT6wmNqtgcmHAmhPS3bqE1qLS/F98zUhknD0xX5gJs8LM55KCWl6bPOsXCJcgaYF
         61aWk3vs7QoZvobxxngp4260MlLgjWDIVBjLNtsn/CVF9XEm5uuXkMeJWV9oiBA4wQQY
         nA5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=F2bwzMTKPFUXPqx7zJ+JAJE/r3ol+GDoplqtVro2Q2A=;
        b=ls070A0w5hOPWpoJ3NnetqLU5X7DCjoQvBZspZf/JrpnKVqmaPoZgAE+a6UlXntAqM
         mk20uU79DeFcc0OngQvKxiXMN8fuaEtYY424cwCz9BhEOBG0BhIzcx/zUfoRr2fvUZTI
         YMmx8uiCWd6EuNda3BOjxvwVPDuqAqC+AVFN353qdJTRT4tDlkRgiNUMu634vhn9eOUl
         kTf3t4R7qqwOlHz5r9iN/BeT9mCRz1Ha1UB6pstkqXNADK/rXDCKZHJCY4D3FxfLDBaP
         CKnyUUwwwnkM1l/KoDwjsQzLZ/AkU/Db+FG66939ViQjsZjcjdiGRjSRjB6HDUk4bAj+
         yTeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=zXu5n6CJ;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F2bwzMTKPFUXPqx7zJ+JAJE/r3ol+GDoplqtVro2Q2A=;
        b=nfvX6Y6ydCRNSr4qncKx0R+thYYbFBr6OUyjEPwyDPU2dfiZaIbrSPNLkJB9eXMERW
         N5aKDQ2ePRvF2cvTr69liEJTyGz1UpKbVADgKromk0ZPRk+RSxg3PHFRIwe8tIPA+qwy
         41HBnGWT+B/CM7Vw4o0FvIhG7BDXTTtXpSP2yNwz0bwk5JHKZOMnNP5ynYXLe5jW/qWX
         TMZT9gL8SohEu9E+WyXiSHMh//tVd0z1tWGXkG/lUfD62cjOpNydf2/ARUwcRcuAC8q7
         kP9t8/KuIKdsP49gZoR1Aw5mfiUYRuSZTTaaAv4EY8HL2Unqxv2Aug3ohPyqOngYhLxk
         oyUw==
X-Gm-Message-State: AOAM533vWTVGXP19I/V4ctwjaxrnNk6iyClDpGPkrkA6Pou9GbzrinS3
	lvGFKLrOlVWS449M3Z8QfdQ=
X-Google-Smtp-Source: ABdhPJz0Mk3288CprJckDx5WsaVJQsDA7ySAytgWqBcJKaMnCHbqpvcDzl9Z4dG+biVtXnAE/wmTHg==
X-Received: by 2002:a1c:24c4:: with SMTP id k187mr3826404wmk.14.1611056625600;
        Tue, 19 Jan 2021 03:43:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c191:: with SMTP id y17ls3960069wmi.3.canary-gmail; Tue,
 19 Jan 2021 03:43:44 -0800 (PST)
X-Received: by 2002:a05:600c:255:: with SMTP id 21mr3664076wmj.69.1611056624800;
        Tue, 19 Jan 2021 03:43:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611056624; cv=none;
        d=google.com; s=arc-20160816;
        b=nxXwPcbyj1NTcwVPNS75qUNMR+xGH72+qa5LkXd0xHdQaFmTnBFgrxKQxJFndVlMK5
         Tc3Xu+srpJlszIHmnCcWBNkzBdSsL1F1taH8429LngGVqlOjEuqZMmVkFpQiMEpdDgWy
         leoylCroL6RNiByjbH/q4XQB/ubCdzBsoBDv50zehEju8IIs4QT2HmB00ZkwnUGAcp3o
         DsWb1J7f3D7PICUiDZWrXiOmX5gFUJ9WkgYmOL8hFOOpNl2fAU0pq5vzu6m4VFLhnlmS
         m8MhENlB2OeaSvs3VjIkfRTrL9JoKqQ0Axp2nmskU5KlUbl7Jqq3PEI3Nd228xOzCJGn
         X2VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wfa5HkXGhmSraClnejxdxh1CPG1ZunD0LmRA0qG/zE4=;
        b=umS3F6LSjQkOw/NBk1ZicZxwSaIz5KpRr/JuOW4qSdJVKTC2BKpR/nRQm6KXaIPsKv
         +mgv/PC5smNCEGOYvqts/FJ3vr/qCcjzWfnwjM4hQWGscu70X/XZc8JPycrCtqWcZb4S
         MaVrFoHexUVlwPbeGyJ/srQIjCqkR+ftlzKn3Fl2wMuqLBLeqq1+ahWkfUSmxvJj/4rI
         R1qLniREbwxEcfVrhnfYFHFEYk2N0mdqMu/2rnPf54kLo/uNbD0qcsCrLk5X8huQDRna
         R78EgwTTmZDay1JUHyWRCucoNVFhmmhXpgtUGgUoi73eod8WKHx+yIIc9l96Hk+ibjIY
         b0ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=zXu5n6CJ;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id s74si136124wme.0.2021.01.19.03.43.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Jan 2021 03:43:44 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:49946)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l1pQE-0007KJ-MZ; Tue, 19 Jan 2021 11:43:43 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l1pQD-0004zW-5L; Tue, 19 Jan 2021 11:43:41 +0000
Date: Tue, 19 Jan 2021 11:43:41 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzkaller <syzkaller@googlegroups.com>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119114341.GI1551@shell.armlinux.org.uk>
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk>
 <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=zXu5n6CJ;
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

On Tue, Jan 19, 2021 at 12:17:37PM +0100, Dmitry Vyukov wrote:
> On Tue, Jan 19, 2021 at 12:13 PM Russell King - ARM Linux admin
> <linux@armlinux.org.uk> wrote:
> >
> > On Tue, Jan 19, 2021 at 12:05:01PM +0100, Dmitry Vyukov wrote:
> > > But I also spied this in your makefile:
> > >
> > > config-earlydebug: config-base
> > > $(CURDIR)/scripts/config --file $(config_file) \
> > > --enable DEBUG_LL \
> > > --enable EARLY_PRINTK \
> > > --enable DEBUG_VEXPRESS_UART0_RS1 \
> > >
> > > With these configs, qemu prints something more useful:
> > >
> > > pulseaudio: set_sink_input_volume() failed
> > > pulseaudio: Reason: Invalid argument
> > > pulseaudio: set_sink_input_mute() failed
> > > pulseaudio: Reason: Invalid argument
> > > Error: invalid dtb and unrecognized/unsupported machine ID
> > >   r1=0x000008e0, r2=0x00000000
> > > Available machine support:
> > > ID (hex) NAME
> > > ffffffff Generic DT based system
> > > ffffffff Samsung Exynos (Flattened Device Tree)
> > > ffffffff Hisilicon Hi3620 (Flattened Device Tree)
> > > ffffffff ARM-Versatile Express
> > > Please check your kernel config and/or bootloader.
> > >
> > >
> > > What does this mean? And is this affected by KASAN?... I do specify
> > > the ARM-Versatile Express machine...
> > >
> > > Can it be too large kernel size which is not supported/properly
> > > diagnosed by qemu/kernel?
> >
> > It means that your kernel only supports DT platforms, but there was
> > no DT passed to the kernel (r2 is the pointer to DT). Consequently
> > the kernel has no idea what hardware it is running on.
> >
> > I don't use qemu very much, so I can't suggest anything.
> 
> I do pass DT and it boots fine w/o KASAN, so it seems to be poor
> diagnostics of something else.

It is the best we can do at that time. Consider yourself lucky that you
can even get _that_ message since the kernel has no clue what hardware
is available, and there is no standardised hardware.

All that the kernel knows at this point is that (1) the machine ID in
r1 does not match anything the kernel knows about (which are all DT
platforms), and r2 is NULL, meaning no DT was passed to the
decompressed kernel.

There is no further information that the kernel knows. I suppose we
could hexdump random bits of memory space through the serial port or
whatever, but that would be very random.

I'm not sure what else you think the kernel could do at this point.

> It seems to be due to kernel size. I enabled CONFIG_KASAN_OUTLINE=y
> and CONFIG_CC_OPTIMIZE_FOR_SIZE=y and now it boots...

So, likely the DT was obliterated. How are you passing the DT? If
you are passing it via qemu, then qemu's placement of DT is too close
to the kernel.

> ------------[ cut here ]------------
> WARNING: CPU: 0 PID: 0 at kernel/printk/printk.c:2790
> register_console+0x2f4/0x3c4 kernel/printk/printk.c:2790
> console 'earlycon0' already registered

Two "earlycons" or whatever the early console kernel parameter is?

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119114341.GI1551%40shell.armlinux.org.uk.
