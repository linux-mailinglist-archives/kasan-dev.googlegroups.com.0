Return-Path: <kasan-dev+bncBDE6RCFOWIARBKX236CAMGQETGJBHFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 98465377739
	for <lists+kasan-dev@lfdr.de>; Sun,  9 May 2021 17:18:03 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id b44-20020a05651c0b2cb02900ec3242ba00sf266075ljr.17
        for <lists+kasan-dev@lfdr.de>; Sun, 09 May 2021 08:18:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620573483; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUzN5ZWvBNfBEI76gqGlB6NpvG6bJoTBSb4NIcQXJ+b3U952NflFXFSGH9L0El/QJs
         VHS82HY/KWEccrZxbPotutiUhR0eKg7LE6FUcBrpJDhI8ODzGQ+nybIGIO+p6Wl3S5SH
         clmFWKDjPgpre9sn0RmK6Y6fTFOyEsWJBmCT9BP35joOm18Ch9hINeDdeAfcqaM1IUhd
         K82x+Nkv7avkpM7Vo6ItcZpqfouYIXEDKwA6LqJ6919uh3WJcbFusVc3zvREh9dbsfZ4
         1CtbNUaf1yBxt5iOHTJgAcazHwswK0liKDwQJuV+4DazTguBDyr3Puncbkv7vAceqct3
         IbrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=NDopkT8ZeGT7t4eiJ1qhUIf7Bgxpt3EKz5JnZc0ddBA=;
        b=f2wbRUh2aQwIBrA3HTyOJ4Z1Wlduo81fYfAXvPTeuGDD2zoiPKiW3LvHmIazuib5gc
         V26rNNDG/EC6kMvuOoD2nByz5eVYdzcBY8hc0yT3CbwPXvPzJp+EaVDKMymPMaek3ZXW
         zqkTxs3K9KjgWh0v8A0E1z++zHQckx+OtmO0pxVyYgCyrIQ/OvQxcjMP+TqZtAmrpA6j
         L+NmBgTLDEBOE15IQpkWSPOCMso6k1aVsbTOZBUtdfBe9B4UYZnDoHnfAEzL43R4vMGW
         7H9w97pNsOeqh48SHYojXD6l1HD3+1SpQddAnL4hjavVhpF0hZAjczspdwKJMUpfg3PN
         hi2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=gHXnKu7A;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDopkT8ZeGT7t4eiJ1qhUIf7Bgxpt3EKz5JnZc0ddBA=;
        b=Mm3PGtMq+gJmNrwkgzZTxy82G1PYsfK5WcF2yIltwVWymhQXpgoXvpc+17STduaOqZ
         qR6sJlCttvfung0Sqv01MK61ioxDs+Q1UcuxgOCvmZnikNKFRF8hWR6YReM1HHSWxx5c
         ZZowyvGT/NomLBvIiPBWxCliN6//AKTSvpav/Ivx9GuzEF+B6Ye13fFQtSAo3Xblhq2s
         ImJ2iL+JXqT0sYFIYSJE/o0AO4aLONMLow4mLgXNiP371D5YHzFtISMHnRN/vNxqp0eV
         XfoLouoUhOkXd4967er+t6qVQFHq3AnhcgcH6N38mfFVUyCTWHiQuCSvc5ZgA4cCl7L9
         jfNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDopkT8ZeGT7t4eiJ1qhUIf7Bgxpt3EKz5JnZc0ddBA=;
        b=fPXm2ZOV9w5QXyv2b8ADR+8U0ldxLIKAJwJzlnsCuQftubf6gy6g1AwM6O7Kai2xiD
         7AAhAjcpgbHNjl6bXgA69IqnTWpSI5ZYC6CQtSd0qlBNOxVT82ecJIiSO6/Gmhd8J0JC
         xDfu257v9+X0U5xyRv9eIeTqLTgbI7J4Ly0OxUbtJWdDCT+gJ+Lzvjepo772GrK7bz4F
         faJMpirnT07tee785QeoPVirJFctmGSM0roRWj9f4MDC9k3J2x8b5P0Fz2GTLyEyBwn2
         lk9lEWMY6rdqifUdZhBU0h6g4JohEU5e1744dd96hKOatXQgy2Nn/XYveyH7QwqOUaS8
         8W5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oAhWRk9dZPJZbgRgdPp70wY2do3S8DEHV3bALFqcvfgzZ6ufR
	KkUurE4t7nQU2sNiuJfKphM=
X-Google-Smtp-Source: ABdhPJyO3iiKt1JlHyNEh1vezi6yAEDPUxZp21Sj4PmsHDQFKrv0wCjoE4ZxIMfwciAN6+S45QvZCw==
X-Received: by 2002:a05:6512:224c:: with SMTP id i12mr13296890lfu.643.1620573483158;
        Sun, 09 May 2021 08:18:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6c0b:: with SMTP id h11ls2465831ljc.3.gmail; Sun, 09 May
 2021 08:18:01 -0700 (PDT)
X-Received: by 2002:a2e:b055:: with SMTP id d21mr16817825ljl.27.1620573481828;
        Sun, 09 May 2021 08:18:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620573481; cv=none;
        d=google.com; s=arc-20160816;
        b=GTW8BZEiWY9V0H/ywJ9AoozyaCnz9iMPu3qIORgDqMnavqzdsBaqmJu4+Zao4Ue4iC
         9AYm1b8Ghs5CibTNL6xK8yu5V5yTBUw+GPQAlfoKR6tQGFKzloAonSNVG4li2LrYWGYk
         idLpuIdvsdiWr64Xb+M18D5CCrBomVB7vhcgs22sSwGNOtC1wolPEb47k9MAO5Vn/CpG
         9XAv5RXw86oJFfxj+yisoPCtTu9GnDyUXS6k21/Iv78M3qhUNfgZEdMK7qHUHILjvVCR
         S60fm2gKRFfKjH1O2TKfMoSpV0Arpa8wNV24gL1d+ZAsXmSpDgz+rTqxntfxE3jA8WZA
         NldA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T2n/1WwJTS3CsHkemEMlwQOIwzDpqt4PBSfYeUOZJbs=;
        b=CiROZS6Sre9CRYro5IRrvz1x2tUArsVMWa5ZtSUCaiAilYHU+vUN2MhdYghDztr5Qa
         BWYmJ5UjK3RztGRYt3sK3S5VarcGNWkZgmmmxMnopxduWE2eF3/q998dIP9Cc1nNzs9Z
         x1BYPvemWwNYHqTss7RBhT4pJPkhR9TE21dwTapPkw2fJKVXL1vXy1jFqDiRP6p1OWae
         dE54ygR9MhdmzR6zfHyjMLdrlhFEQBSv28IK0dKx/vpnAoJjZY3CsKTj9Sds+u8kMniE
         jDRQOWPHASYqFBVwEQ9tGKfIUf+L6waH+Tyr8+g1iFeXbUA13AE2JaGUCrz6Cf+2i4yF
         Dmww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=gHXnKu7A;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id b2si470464ljf.0.2021.05.09.08.18.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 May 2021 08:18:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id z13so19710219lft.1
        for <kasan-dev@googlegroups.com>; Sun, 09 May 2021 08:18:01 -0700 (PDT)
X-Received: by 2002:a19:6755:: with SMTP id e21mr14308817lfj.29.1620573481273;
 Sun, 09 May 2021 08:18:01 -0700 (PDT)
MIME-Version: 1.0
References: <202105091112.F5rmd4By-lkp@intel.com> <20210509122227.GH1336@shell.armlinux.org.uk>
In-Reply-To: <20210509122227.GH1336@shell.armlinux.org.uk>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sun, 9 May 2021 17:17:49 +0200
Message-ID: <CACRpkdaNVg9zgaDN0JG+Z8dMMk+0fdpYHwGMHS-FKUG9MZAb4w@mail.gmail.com>
Subject: Re: arch/arm/boot/compressed/decompress.c:50: warning: "memmove" redefined
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Abbott Liu <liuwenliang@huawei.com>, 
	Florian Fainelli <f.fainelli@gmail.com>, kernel test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	linux-kernel <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=gHXnKu7A;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

OK, paging in the KSan mailing list and key people.

Certainly this problem must be the same on all platforms
using an XZ-compressed kernel and not just Arm?

What I wonder is why the other platforms that use
XZ compression don't redefine memmove and
memcpy in their decompress.c clause for XZ?

Can we just delete these two lines?
#define memmove memmove
#define memcpy memcpy

Imre?

I can test some platforms without these defines later
tonight and see what happens.

Yours,
Linus Walleij

On Sun, May 9, 2021 at 2:22 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> Maybe the KASan folk can look into this, it isn't obvious how to fix
> this, since XZ needs memcpy/memmove #defined to avoid using its own
> version. Having KASan override these with a #define is all very well,
> but it makes the behaviour of lib/decompress_unxz.c indeterminant if
> we get rid of the definitions the XZ support added.
>
> On Sun, May 09, 2021 at 11:32:17AM +0800, kernel test robot wrote:
> > tree:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git master
> > head:   b741596468b010af2846b75f5e75a842ce344a6e
> > commit: 421015713b306e47af95d4d61cdfbd96d462e4cb ARM: 9017/2: Enable KASan for ARM
> > date:   6 months ago
> > config: arm-randconfig-r015-20210509 (attached as .config)
> > compiler: arm-linux-gnueabi-gcc (GCC) 9.3.0
> > reproduce (this is a W=1 build):
> >         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
> >         chmod +x ~/bin/make.cross
> >         # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=421015713b306e47af95d4d61cdfbd96d462e4cb
> >         git remote add linus https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
> >         git fetch --no-tags linus master
> >         git checkout 421015713b306e47af95d4d61cdfbd96d462e4cb
> >         # save the attached .config to linux build tree
> >         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-9.3.0 make.cross W=1 ARCH=arm
> >
> > If you fix the issue, kindly add following tag as appropriate
> > Reported-by: kernel test robot <lkp@intel.com>
> >
> > All warnings (new ones prefixed by >>):
> >
> > >> arch/arm/boot/compressed/decompress.c:50: warning: "memmove" redefined
> >       50 | #define memmove memmove
> >          |
> >    In file included from arch/arm/boot/compressed/decompress.c:8:
> >    arch/arm/include/asm/string.h:59: note: this is the location of the previous definition
> >       59 | #define memmove(dst, src, len) __memmove(dst, src, len)
> >          |
> >    arch/arm/boot/compressed/decompress.c:51: warning: "memcpy" redefined
> >       51 | #define memcpy memcpy
> >          |
> >    In file included from arch/arm/boot/compressed/decompress.c:8:
> >    arch/arm/include/asm/string.h:58: note: this is the location of the previous definition
> >       58 | #define memcpy(dst, src, len) __memcpy(dst, src, len)
> >          |
> >    arch/arm/boot/compressed/decompress.c:59:5: warning: no previous prototype for 'do_decompress' [-Wmissing-prototypes]
> >       59 | int do_decompress(u8 *input, int len, u8 *output, void (*error)(char *x))
> >          |     ^~~~~~~~~~~~~
> >
> >
> > vim +/memmove +50 arch/arm/boot/compressed/decompress.c
> >
> > 6e8699f7d68589 Albin Tonnerre 2010-04-03  48
> > a7f464f3db93ae Imre Kaloz     2012-01-26  49  #ifdef CONFIG_KERNEL_XZ
> > a7f464f3db93ae Imre Kaloz     2012-01-26 @50  #define memmove memmove
> > a7f464f3db93ae Imre Kaloz     2012-01-26  51  #define memcpy memcpy
> > a7f464f3db93ae Imre Kaloz     2012-01-26  52  #include "../../../../lib/decompress_unxz.c"
> > a7f464f3db93ae Imre Kaloz     2012-01-26  53  #endif
> > a7f464f3db93ae Imre Kaloz     2012-01-26  54
> >
> > :::::: The code at line 50 was first introduced by commit
> > :::::: a7f464f3db93ae5492bee6f6e48939fd8a45fa99 ARM: 7001/2: Wire up support for the XZ decompressor
> >
> > :::::: TO: Imre Kaloz <kaloz@openwrt.org>
> > :::::: CC: Russell King <rmk+kernel@arm.linux.org.uk>
> >
> > ---
> > 0-DAY CI Kernel Test Service, Intel Corporation
> > https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
>
>
>
> --
> RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
> FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdaNVg9zgaDN0JG%2BZ8dMMk%2B0fdpYHwGMHS-FKUG9MZAb4w%40mail.gmail.com.
