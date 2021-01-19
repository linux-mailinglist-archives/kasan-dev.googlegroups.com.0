Return-Path: <kasan-dev+bncBCMIZB7QWENRBA4WTOAAMGQETYR65IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B9B42FB5F6
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 13:05:25 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 24sf15475207pgt.4
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 04:05:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611057923; cv=pass;
        d=google.com; s=arc-20160816;
        b=uK/K/SPUdXk7j2nhCrkPLMyG5w2M5ZBkrnppDrdmvogN28sdu6hr8AhZ7vYKZIKPvZ
         QM6eNIyeO93TkGoWldPyesl0QyoZ4V0KTPStHA9jZTs+8WPiZ/N2SGdoVoFKKXuSWvPN
         2Jo5MgJjVvZnR1PZrs2jmN5hcb2MhmV5Zub+Nhdun3vs9UE7Md2tbXacv1b89HkoGaxY
         4zwqqKEU5nryl7JvJYf+Tai8eyhxTwrvM9Cit05l++Cd1hhcM/xwATUBf45oGKpo12uS
         JuKdeANtljGd9oRhD9DxUBVajnK7dARcLT8T72iDpOA5OjLSPA5aFxYU7hyP2cPrva+Q
         /FPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E98X34ZvJQWvgvwCyDU0doxmOUyhxmNc4Ibrlp3KGxk=;
        b=E63VdFeFhgX7Eqlmx8aa0kGDiUAamYD6iWr0ITPvwAZ429Sl5ygW1IaXs9KKVA87DY
         xK7iQB57xvI7jsZgXm7UkWXi5i5RTbzcVS+WstCIOwZyJ8bGPiyGVvi9+3uTmhUk7G6J
         hlAlOsfrXvU8o+/1Fp3Q2oDJL6TqjqIu1dVG7NFH+wbHARtD7mitueO9qS22p1ysfSGC
         /Fgic+TaOnkGH5Cvva50zK74QIc1dCpydXfvd5iomTZ4OUN25SGEob894K2ElNNNe/5u
         qZzyc/zL0T11xFnFjhrlQdzPNjuIVvUOxrQQ4I8haDl/hyPYwjWNtiBaTFTJtSrnbTie
         BZtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bW/ez/2y";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E98X34ZvJQWvgvwCyDU0doxmOUyhxmNc4Ibrlp3KGxk=;
        b=jDQN46BJKrU/8Dv5F/AFlWP10ONmOg47Rg9tBXQNIcJt++Gae6OfB1B9jKNH+LWpes
         E6hCjxWp3CX3gw5V5yjn+eVaCRpmJodQnna92WJ16JriZOQsvbpR1ImPSJpRayWLWagU
         Y5PwEIJ5V3Vkuwv/+DL+orPpd/YGRmMnPl7lY+BzJgHvikbK/tj/6rEMPQeIX/ML8a5J
         X6uRn4h7mVGJRFnieO/bEJE/WKcPXpEe03wWgzeOtOIu2pRWOh3nvVwkPnBpyLO0sEjq
         Sf8a7tOoXGR/jH3Ik8Fcbfd2g485o6I93C7E1Px6f4/nSQ34hm+9D+1F2NazAsxWqBmR
         4u+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E98X34ZvJQWvgvwCyDU0doxmOUyhxmNc4Ibrlp3KGxk=;
        b=a9/KvwBnhxzP/h8/l+2nwOM6syk8xc40fhAjv16x8Chtr/Qla2K9/6V7OP2oAwKu8E
         jGlpFQ+lo8DFrDLPhM1n5nAHzjPI1W0VK0TOhZAkOLb+cnCQ0JaF2PvV5cjP24v9a9wH
         Qixmv/B34TN+NhxKkcIgg/8/y28bCt3sRAGYw3gRNeh8TmxQsteIhkFwoqaoBJrOrrgd
         d1x7Udqt0RcAC6C0YRSeB+6TWEVL1VfOqzd3SOuUCWuRH2Z6EQuH1qJ5Bla+G5MO5OjX
         oNf2enunBvtB9w+WZmLFifwssMyqIebbjhWeg0/Ji5Y681jfNOiYzcEWl/0/NZ8IPclj
         /W6g==
X-Gm-Message-State: AOAM532saez7YMdoyFqu9w/q5DZ/rdT06GD/DUZcUo1ks7r110cgWIeZ
	cr8S752iqEIczg7l2LVKqE8=
X-Google-Smtp-Source: ABdhPJxBQWIweBF/kx3GX8P4GiXQ1q3CXAd0TTiOumBA6eFeUPkGHjs/7llAdc9qZDMQU7A19T+f5w==
X-Received: by 2002:a17:903:1cc:b029:de:98bb:d46d with SMTP id e12-20020a17090301ccb02900de98bbd46dmr4399905plh.54.1611057923808;
        Tue, 19 Jan 2021 04:05:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9309:: with SMTP id 9ls885893pfj.0.gmail; Tue, 19 Jan
 2021 04:05:23 -0800 (PST)
X-Received: by 2002:a63:78ca:: with SMTP id t193mr4153067pgc.391.1611057923256;
        Tue, 19 Jan 2021 04:05:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611057923; cv=none;
        d=google.com; s=arc-20160816;
        b=Sx7pM6fMF5ZVDaMBKf5ENl1s/xeilEOVr4VS+C1mBqvujpOV/xNP6O29Y5FKYVLGau
         khtjUqiMiu4GcMmoWJGQinjqgAdfUr1YMTKu9aYOnfvoeZtroZ56VVNIDv99shf/lRJh
         xbDZMd7gncdCsoA32oMi789bAW+NJi8DXRVtMhmnOnWHGTNbTcObj4unSM5DlClv9FBP
         Y54J7swyXyeVfTpBxpFtg1qe5wcyfDmMIN6iHfI7iM3QlTi1yaVtdEM/HkDszA6klfnX
         ZxfcxeGsGrybOEGz41fedpdR3Je5i+Y6TQUR0kHgaNVIBucnhh9GE/aMhZxSz9LQU4ed
         gGFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EwRFX+ldhkHZmh5XCDl2LHzDgFKhdapMxkHfbbE+hNk=;
        b=guId5ZSM/td7b3MKRqpLOOvD65443Y8DqGW4dUSEGgG7UWJn/ByElCR0ij4HWXoHtT
         Ektva1a5bLnxcH0ze7jgcjDZi3CCRADxC0xKmvYsOE/adM4ksTMltpH1RePcyzZGOUTE
         jI1jmcTQdHV/vasr+kPWavp/thC6gzbbrxXwEX4ijp9/dEFS3aGztvh/XiDCvw23ZwlM
         bhCMCRYRja1/xDQaOHqRlnWq9Zvi/bVEymMwysQhtBBrnttF/RAwhjKLGll2plUAdpPh
         RkiJU4lnDztQC4cyp9MIlnc+eViYTMp8iT2BTl7nE1egpMihkGRDohoef6xlbkoVeH3K
         803w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bW/ez/2y";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id o14si279619pjt.0.2021.01.19.04.05.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 04:05:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id 143so21470442qke.10
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 04:05:23 -0800 (PST)
X-Received: by 2002:a37:9a97:: with SMTP id c145mr3889452qke.350.1611057922584;
 Tue, 19 Jan 2021 04:05:22 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk>
In-Reply-To: <20210119114341.GI1551@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 13:05:11 +0100
Message-ID: <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="bW/ez/2y";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jan 19, 2021 at 12:43 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Tue, Jan 19, 2021 at 12:17:37PM +0100, Dmitry Vyukov wrote:
> > On Tue, Jan 19, 2021 at 12:13 PM Russell King - ARM Linux admin
> > <linux@armlinux.org.uk> wrote:
> > >
> > > On Tue, Jan 19, 2021 at 12:05:01PM +0100, Dmitry Vyukov wrote:
> > > > But I also spied this in your makefile:
> > > >
> > > > config-earlydebug: config-base
> > > > $(CURDIR)/scripts/config --file $(config_file) \
> > > > --enable DEBUG_LL \
> > > > --enable EARLY_PRINTK \
> > > > --enable DEBUG_VEXPRESS_UART0_RS1 \
> > > >
> > > > With these configs, qemu prints something more useful:
> > > >
> > > > pulseaudio: set_sink_input_volume() failed
> > > > pulseaudio: Reason: Invalid argument
> > > > pulseaudio: set_sink_input_mute() failed
> > > > pulseaudio: Reason: Invalid argument
> > > > Error: invalid dtb and unrecognized/unsupported machine ID
> > > >   r1=0x000008e0, r2=0x00000000
> > > > Available machine support:
> > > > ID (hex) NAME
> > > > ffffffff Generic DT based system
> > > > ffffffff Samsung Exynos (Flattened Device Tree)
> > > > ffffffff Hisilicon Hi3620 (Flattened Device Tree)
> > > > ffffffff ARM-Versatile Express
> > > > Please check your kernel config and/or bootloader.
> > > >
> > > >
> > > > What does this mean? And is this affected by KASAN?... I do specify
> > > > the ARM-Versatile Express machine...
> > > >
> > > > Can it be too large kernel size which is not supported/properly
> > > > diagnosed by qemu/kernel?
> > >
> > > It means that your kernel only supports DT platforms, but there was
> > > no DT passed to the kernel (r2 is the pointer to DT). Consequently
> > > the kernel has no idea what hardware it is running on.
> > >
> > > I don't use qemu very much, so I can't suggest anything.
> >
> > I do pass DT and it boots fine w/o KASAN, so it seems to be poor
> > diagnostics of something else.
>
> It is the best we can do at that time. Consider yourself lucky that you
> can even get _that_ message since the kernel has no clue what hardware
> is available, and there is no standardised hardware.
>
> All that the kernel knows at this point is that (1) the machine ID in
> r1 does not match anything the kernel knows about (which are all DT
> platforms), and r2 is NULL, meaning no DT was passed to the
> decompressed kernel.
>
> There is no further information that the kernel knows. I suppose we
> could hexdump random bits of memory space through the serial port or
> whatever, but that would be very random.
>
> I'm not sure what else you think the kernel could do at this point.
>
> > It seems to be due to kernel size. I enabled CONFIG_KASAN_OUTLINE=y
> > and CONFIG_CC_OPTIMIZE_FOR_SIZE=y and now it boots...
>
> So, likely the DT was obliterated. How are you passing the DT? If
> you are passing it via qemu, then qemu's placement of DT is too close
> to the kernel.

Yes, I used the qemu -dtb flag.

I tried to use CONFIG_ARM_APPENDED_DTB because it looks like a very
nice option. However, I couldn't make it work.
I enabled:
CONFIG_ARM_APPENDED_DTB=y
CONFIG_ARM_ATAG_DTB_COMPAT=y
# CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_FROM_BOOTLOADER is not set
CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_EXTEND=y
and removed qemu -dtb flag and I see:

Error: invalid dtb and unrecognized/unsupported machine ID
  r1=0x000008e0, r2=0x80000100
  r2[]=05 00 00 00 01 00 41 54 01 00 00 00 00 10 00 00
Available machine support:

ID (hex) NAME
ffffffff Generic DT based system
ffffffff Samsung Exynos (Flattened Device Tree)
ffffffff Hisilicon Hi3620 (Flattened Device Tree)
ffffffff ARM-Versatile Express

Please check your kernel config and/or bootloader.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba1NnA_m3A1-%3DsAbimTneh8V8jRwd8KG9H1D%2B8uGrbOzw%40mail.gmail.com.
