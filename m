Return-Path: <kasan-dev+bncBCSPV64IYUKBBQORSX6QKGQEDU5CV3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f60.google.com (mail-lf1-f60.google.com [209.85.167.60])
	by mail.lfdr.de (Postfix) with ESMTPS id 8384A2A9858
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 16:16:18 +0100 (CET)
Received: by mail-lf1-f60.google.com with SMTP id w79sf641065lff.8
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 07:16:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604675778; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPxzhM+kFE2qxRXwz7+z/c2LWlV2f9dRJbbfcCu6u+Z+w2LZaxTReFapSdvn9kHmY0
         iJ3FbC5bthA9tpgA56sG11Cob59fg0gVF+SDVhyUXbKF0FsKoyOYtk98fURod4Wrblrv
         MhU1WbUpmpIEjQu8j8+xXFdUOC7RkJLobiQ8Hd7K1pa4cHilRzY/+VrJOeL2YjtBc8h3
         FGjndLDTnS/ePOHF/1LV82nPB//eZCpGebtXBmAwRtuZnuYbh8QilemdXtwbmqu0Pzof
         EKFdG74zupBqP57dS9igaNbbzvEdOti59CmTAe/ZgHqcdB8yaNJ9aHqxbOdsMia2PH1K
         N+2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=pO5KJDDaJnHmFFzzAK0De8Opc6ukeRmUyZXTdaM5r+8=;
        b=GKZF6ye93okEPOlU3GTcVB1PTGrypkQlEIRrI32J6QkkRkDY0uSvCnuKHSYualQ38x
         K5ulpADuPKapVpP/7mAF/jOUvj2+Skl9Buau4wVIvCG+k55ycaIBpfIh4s0FTBJi2lgf
         qgwLYkV20W0qTaC8cD+EaMReOgxzWf7W3uwMddShfUnxjiNDP2H5lYTq/UZ6HqE1vOvr
         EFLgE91MpIndBKc7mJ6BzPLHLoevLgIrDud4Vh1N74c310xISZGJ0B78nP5BsnOAXWz0
         2crNCQTa5EzhQ8IawYv7J6nP1PolLvk6Ewpw6AHtsXOiKTPknmFtUEMA0JodZ0ZJMACj
         vxdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b="AxiQ/QXc";
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pO5KJDDaJnHmFFzzAK0De8Opc6ukeRmUyZXTdaM5r+8=;
        b=bCmNwc2DSidl3xTC7GnB3B8KRVPrMmk9Ao7P1hnncO/GH3eJ2T4klbvxwbQu9pUT9P
         Rtylt2NVgMJLsJ6+6mG59W4fTyL8L28CjP8hG6xGx7klYysaU9nnmYP3hc990/j2JUDz
         wThSkw+5Kp0AKRH2+CLISfL6Y4emceK1yWhsl+OQMAwj/SpeXjhkqmv6C1aMLXWHLDgx
         vZ743deSa7qYqyGQ3ZDSgGgVHUc1CNXmlGatNL3NCERB0hbHgSeoG9BZI1jn6kc2tLb/
         wzfGWhWrTn0fvL4hKi72juU0VUXMZndu/fZCzUUelj3rdFHzNTDl4vETb6gKd2loj6B0
         +qQw==
X-Gm-Message-State: AOAM532TATSDlXa8rpgzdiEEXRUN0/bNX8KGYLVvd/Zl2ZmTt2kG1gto
	TJDZjsPQO3nYhku2FYkuccY=
X-Google-Smtp-Source: ABdhPJxImh+4+hMZhedyAaPWvtfNtpKLlnwrR3FIqp6iN4d2L+SIzB7/zoCPtmoDTcDIYzdHfn6ZpA==
X-Received: by 2002:a2e:87c9:: with SMTP id v9mr990317ljj.368.1604675778074;
        Fri, 06 Nov 2020 07:16:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls1283929lfn.0.gmail; Fri, 06 Nov
 2020 07:16:15 -0800 (PST)
X-Received: by 2002:a05:6512:1103:: with SMTP id l3mr1180923lfg.113.1604675775587;
        Fri, 06 Nov 2020 07:16:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604675775; cv=none;
        d=google.com; s=arc-20160816;
        b=UtXzV1EafAidPB6akvZulW4UTVXH/OiH++R2PfYwHEzTUBRyYS/j3AJqAqBDMf6JBX
         4WuhXDJsazfAQQZ+lQQXHT336BEVumdb8RVZSPyBpApADF1+syofa8zXQrw876+f/DTd
         9BaQOi6e4MFAz0A0sDiw/tO8/rbsb9M/lVa4b7apE22bu8gXmLY51s6Jxmlg5GcmSpRd
         BCd5i8m1bZQ+Hi0DMgVqX8z2ZByeOsEMKGqJqcIxgHUoridit22pjna20/lpdRS/6BZG
         sWcSBp/VoX2kAei1QUJMA28hJkDR6uBXSVWkmzyYU5+/QXBFio2V7hrFNTbb/HoiDNor
         KBlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4+WYl4Y99KMcpnDUmq0xOppvJ/gI1EBjcZfq0apHMtk=;
        b=TcFg9CuzjPD7fUisRdoo00rFjctj/IK2AWuUeR5r7g/lJl04Bzx4TAvLs0ZHuuJiJQ
         KHB0T+q/h1YbB4Vy+clzNe9/CCdDxmvceUZZF6xKb7Fv7D9Zrp7aTseG0uA/mLaCGGdf
         t+Oby4KTAYTqzeqcq2btBp5VRuS88A+Yc1aIA16KoJitjG4/EWwT3g1qm01Ug8LmzkJ+
         y9u7WHsA62hzpj3sfZjar8P5+0M7wE/cm2giN0uSmDVWe3dh8YI9xE6/xTR6chfF5g9o
         GoajcZGGyzAHuoBYAsSMZUIDQwIRLTMevMHx+KakbiZBzVqrJe4/b7MpGFj8Nz1JhOAB
         OJkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b="AxiQ/QXc";
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id y84si43539lfa.6.2020.11.06.07.16.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Nov 2020 07:16:15 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:55826)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1kb3T6-0005zp-J7; Fri, 06 Nov 2020 15:16:00 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1kb3T0-0005vX-OG; Fri, 06 Nov 2020 15:15:54 +0000
Date: Fri, 6 Nov 2020 15:15:54 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Nathan Chancellor <natechancellor@gmail.com>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Arnd Bergmann <arnd@arndb.de>, Abbott Liu <liuwenliang@huawei.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Linux-Next Mailing List <linux-next@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
Message-ID: <20201106151554.GU1551@shell.armlinux.org.uk>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org>
 <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86>
 <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b="AxiQ/QXc";
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

On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> On Fri, Nov 6, 2020 at 10:44 AM Nathan Chancellor
> <natechancellor@gmail.com> wrote:
> > On Fri, Nov 06, 2020 at 09:28:09AM +0100, Ard Biesheuvel wrote:
> 
> > > AFAIK there is an incompatible change in -next to change the
> > > definition of the __alias() macro
> >
> > Indeed. The following diff needs to be applied as a fixup to
> > treewide-remove-stringification-from-__alias-macro-definition.patch in
> > mmotm.
> >
> > Cheers,
> > Nathan
> >
> > diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
> > index 8c0fa276d994..cc6198f8a348 100644
> > --- a/arch/arm/boot/compressed/string.c
> > +++ b/arch/arm/boot/compressed/string.c
> > @@ -21,9 +21,9 @@
> >  #undef memcpy
> >  #undef memmove
> >  #undef memset
> > -void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> > -void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
> > -void *__memset(void *s, int c, size_t count) __alias(memset);
> > +void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias("memcpy");
> > +void *__memmove(void *__dest, __const void *__src, size_t count) __alias("memmove");
> > +void *__memset(void *s, int c, size_t count) __alias("memset");
> >  #endif
> >
> >  void *memcpy(void *__dest, __const void *__src, size_t __n)
> 
> Aha. So shall we submit this to Russell? I figure that his git will not
> build *without* the changes from mmotm?
> 
> That tree isn't using git either is it?
> 
> Is this one of those cases where we should ask Stephen R
> to carry this patch on top of -next until the merge window?

Another solution would be to drop 9017/2 ("Enable KASan for ARM")
until the following merge window, and queue up the non-conflicing
ARM KASan fixes in my "misc" branch along with the rest of KASan,
and the conflicting patches along with 9017/2 in the following
merge window.

That means delaying KASan enablement another three months or so,
but should result in less headaches about how to avoid build
breakage with different bits going through different trees.

Comments?

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106151554.GU1551%40shell.armlinux.org.uk.
