Return-Path: <kasan-dev+bncBCSPV64IYUKBB5EZ4CCAMGQEXJGTWPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-f61.google.com (mail-ej1-f61.google.com [209.85.218.61])
	by mail.lfdr.de (Postfix) with ESMTPS id 53454377790
	for <lists+kasan-dev@lfdr.de>; Sun,  9 May 2021 18:25:25 +0200 (CEST)
Received: by mail-ej1-f61.google.com with SMTP id nd10-20020a170907628ab02903a324b229bfsf4114083ejc.7
        for <lists+kasan-dev@lfdr.de>; Sun, 09 May 2021 09:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620577525; cv=pass;
        d=google.com; s=arc-20160816;
        b=L5lYDs9Okg3dv92DEQnEvIcE2IPKva50UXyY3VpAUXWP2bgs4/66if9o3zm8D+WNke
         xwtvu/YLrGOq+RdNHbgIu6x5RUvi+cczaOrWV51kzsRq37vb95EvNic2xdUhn0ZU2HAp
         mZa+auV+4r3cGU2hsGyAQxqijqekooBO8aOtkA7y3TcEr010ocNItysitqf+QIz7/hR+
         nPQpMhMNzTtucx4iMAZS6/TBqxLuJLHSNZ9daI6f0vZPOwWSL2cgdJYr3SjPqHsJbO7a
         ILCS3Vxi33uvYyhe1869kXqjd0Xbeq8WadFSJ/FOSph2P+MRRxxL8LotcLohSVuxR8m2
         6Giw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=RN//S99S5CDdyWrFgSt03Xeff63/6g0Tll2X+8M2GD8=;
        b=wElzp/NqmQebya6aFr9FBFbsRIPn614GMsrF5/6ts/k8EH/yEe7poFiEXeKSiwjqJ5
         7B0dz33PZUPywDZDiTLX+JoA9yfRryRHADSJc/hAa+serRwPBNmP5XLiGW8Pn8aVLMEL
         YQ7T1uY9BUm/FMIMDDc5PxhCd50cLKXc8Q1a5VqjGIzfkodZl6Vwm5cBpvjvW6NS8kCl
         BHvOQ+hv0QahjfQWd1ChMGu8mPBRUER4oOvI/9LytZ+rbylpuvP0Wk3Sib9DH73RCRmC
         JapwhZwIgRSR9RlFilF9K2ijDo2sCwId0bFZYLMckQxUc8AoqmI9kKm2jKZPlZwPeNFd
         hxqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=imv9hB2T;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RN//S99S5CDdyWrFgSt03Xeff63/6g0Tll2X+8M2GD8=;
        b=F7TO6oBJpLyvgLofTFhFnXy1uKjv30DEiTnRmoYIndrZRln05+58HyvzKc7QLTWr7y
         PFzy3W+gaKyW+f4zlNNY2W0xa8f0wBeXFzqc1twS85kxx+mta74xtjp1T7rf6kp0tjF0
         qhl5n9XKVAi5BxOScVqarZS38gdxB61QIM2uV9Z5QlK4kSJPyaaTZW4Rl9bB776W3xwf
         cUWPl47qLYwoZQh8ayFWcyh7gWqvnF5Mpkgie+VROMJ1bvgVbJEzo058vbyrNFrTogh0
         MGL4PZDzYitzMjxY/hZG9bbiiqvXYDlaMRveiLSZBH5ITxpdfg11oS+6upbbDuSOo/Te
         0F/g==
X-Gm-Message-State: AOAM531+EqNfn8cIyEcmMNq0aaV8Q84iOrUBnfPeABrTxEVqg4KhsapE
	v6TmWA8agNGAADUOoBdL0Cs=
X-Google-Smtp-Source: ABdhPJylK3n1utjv50UjOdPg9hZW95jpYsWZUVa86oyYQAfaQugupZlbV6JxHreTEn1Fa413T44ptQ==
X-Received: by 2002:a17:906:3153:: with SMTP id e19mr21752218eje.351.1620577525088;
        Sun, 09 May 2021 09:25:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fa90:: with SMTP id w16ls3805361edr.1.gmail; Sun, 09 May
 2021 09:25:24 -0700 (PDT)
X-Received: by 2002:a05:6402:84b:: with SMTP id b11mr24780508edz.289.1620577524217;
        Sun, 09 May 2021 09:25:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620577524; cv=none;
        d=google.com; s=arc-20160816;
        b=FjFyvgQ7T6omyuuU7nCf3a4QWwQKMMgEiQ0ChRVH3oh0jW0mURSE//DrZuVWIWqFrs
         rTGi2ekQKR6z74RsRSWDqVteez3mglCIKHuIki+CkHx/0swMx1DczfKF9aFbU3Odf4ax
         O2E3tULAwxShPlyWEU+xsUo85PDXnvmwzLYhFCks7xWeU0fHXqa8bR61KBAxpSgG7bGt
         qdoCXpzY71qza4SDWEB3nlaMkklSMBX8OHjfqAePbV0fit177xMbWBJgVg6a6Cli8xDy
         5sA1zmICHJE4kaxfB2X6gzgr4hmYWhvJRSRK8Dwn4qHFx0EjfSS6cmIZM2EHVsRZp6wF
         6B3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=KRn3B1NtIl+yLDWbQMHjQsRz0WhuDJp2AzBSzKYNPXs=;
        b=nMR1IfXmrV+XTOzuT/X7alyXgcISa0wIr1g5eUClqYoH9F7D+WyO2mcGhApLqKKj28
         rcpYb+rTxt5+co6lzvjRx56ZXVHCa0abhKbbmPP9n8ZYQz53fLYQVEqkbaHs8EyXbU64
         FZCFEkIbI801rSz5Ef/b05ZqpIKGHOgGAERmxBP3Jynr7Dehlo4PyS7x+KNk/O5IFQcp
         DiFhLNasUq67iqkjGwmEJ6fkANsEcEN7Ovr8S5wuhFtpJOMtwaL0tvaK86epEjvp3EQB
         Ohhsq/thXbBT+1+BOgC5UE2wmf+P7NDehBkNw6MoVpqC7rUpYk/8vigwZ10/JyLET3AH
         vO0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=imv9hB2T;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id g7si518305edm.3.2021.05.09.09.25.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 May 2021 09:25:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:43816)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1lfmF0-0007R1-3t; Sun, 09 May 2021 17:25:14 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1lfmEn-0007ky-JK; Sun, 09 May 2021 17:25:01 +0100
Date: Sun, 9 May 2021 17:25:01 +0100
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Abbott Liu <liuwenliang@huawei.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	kernel test robot <lkp@intel.com>, kbuild-all@lists.01.org,
	linux-kernel <linux-kernel@vger.kernel.org>
Subject: Re: arch/arm/boot/compressed/decompress.c:50: warning: "memmove"
 redefined
Message-ID: <20210509162501.GJ1336@shell.armlinux.org.uk>
References: <202105091112.F5rmd4By-lkp@intel.com>
 <20210509122227.GH1336@shell.armlinux.org.uk>
 <CACRpkdaNVg9zgaDN0JG+Z8dMMk+0fdpYHwGMHS-FKUG9MZAb4w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdaNVg9zgaDN0JG+Z8dMMk+0fdpYHwGMHS-FKUG9MZAb4w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=imv9hB2T;
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

On Sun, May 09, 2021 at 05:17:49PM +0200, Linus Walleij wrote:
> OK, paging in the KSan mailing list and key people.
> 
> Certainly this problem must be the same on all platforms
> using an XZ-compressed kernel and not just Arm?
> 
> What I wonder is why the other platforms that use
> XZ compression don't redefine memmove and
> memcpy in their decompress.c clause for XZ?
> 
> Can we just delete these two lines?
> #define memmove memmove
> #define memcpy memcpy

We can't. XZ has:

#ifndef memmove
/* Not static to avoid a conflict with the prototype in the Linux
 * headers. */
void *memmove(void *dest, const void *src, size_t size)
{
...
}
#endif

So, if memmove is not defined in the preprocessor, the code will create
its own implementation. memmove() is also defined in
arch/arm/boot/compressed/string.c for use with other decompressors, so
the local version in lib/decompress_unxz.c will conflict and cause a
link time error.

The addition of KASan added this to arch/arm/include/asm/string.h:

#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
#define memcpy(dst, src, len) __memcpy(dst, src, len)
#define memmove(dst, src, len) __memmove(dst, src, len)
#define memset(s, c, n) __memset(s, c, n)

#ifndef __NO_FORTIFY
#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
#endif

#endif

created a conditional definition of memmove in the preprocessor, which
ultimately caused this problem. lib/decompress_unxz.c wants it defined
in the preprocessor _if_ one has a local implementation (we do.)

Given that KASan should be disabled in the decompressor, maybe the
conditional added by KASan to asm/string.h is insufficient? The
makefile has:

KASAN_SANITIZE          := n

So really we should not be playing _any_ KASan games in the
decompressor code.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210509162501.GJ1336%40shell.armlinux.org.uk.
