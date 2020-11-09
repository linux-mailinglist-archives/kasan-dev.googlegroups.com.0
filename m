Return-Path: <kasan-dev+bncBCSPV64IYUKBBJ6SUX6QKGQED2SBPPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f188.google.com (mail-lj1-f188.google.com [209.85.208.188])
	by mail.lfdr.de (Postfix) with ESMTPS id AAE142AC07C
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 17:07:03 +0100 (CET)
Received: by mail-lj1-f188.google.com with SMTP id s22sf3526580ljs.10
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Nov 2020 08:07:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604938023; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaVWFjihSijTjb50dMmmt6L6ORBEj+AK9yky0+ImeIB7h+pFMs7d7Y40AouXHUdL01
         G0BChgg0PL5kPWAJTxLogiyeNwF/QSORp7PKfp9MEec2pgSAD1U1Tdlg9902LBMiUIt9
         yAs0Xd7sefnGraBA71kk+L4bBibKVZtm3yV7RyLhISVJi2XQ0Yx/MBB42xkNhLTGRAhJ
         Yqu6oMUjksg271XEPqDgfidVRy3YQPsK6G5Xjra8/Jl44OyJ0idZvU9AVRIWfla1rU64
         6epQUAOYH8DbIEuXQg1R8/kW357mPLN8+T/dYuckWAbaazUe8TGoPV/uAzxbFeVI+OhE
         wbHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=5Wp4CV/hVwoIsS+CvD9kKJ3rXJwtwTnWKnvo8KD7E4E=;
        b=ZL1+kyB5hkEhUlxKvW265UkyUzuYHnaEJ9xtwJQ4aZK3Vh+wQiDHVLzMN1ixxK0ciy
         GdtsxYMmE6CfI60IpSAyb2v/FTfMT4pNCTRfr9CmLbjME0Sq1NqgLNLXluOUE/+dWQ4h
         PyHqzvXKGoBSts470R3jUAYX//f1j9Jz/eRT+yY/q5jeQMT4XAGqhE1NrFIOBiKefU/4
         s2pllZcYQ2d8HfXLSWjmOdIKD+hoRPj/KBEu5xgckl/IJmSnhpl5EoLfzf83HqyeMqej
         yOfepJk5x6fewGX2Xcy9au3sA7akaKioAxP/L/SRj+ZjkURlWMgnYmMgICNkiFt0c39s
         hWzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=WQ8Lp+Ht;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5Wp4CV/hVwoIsS+CvD9kKJ3rXJwtwTnWKnvo8KD7E4E=;
        b=SUoaYLI1DJ00zxxZobdVnD/djF/lSwxYEnpXa9TYfuOtyKaL6sDGcvZ0SB9e/otsjS
         bEZzjWJTQD2H+FDHnSZC96frAgqRiKw3hohbKg+zNvU8xOemD7PGw1KA/M1LCBXUaIWI
         UidDhYUtOKSrOU7o5QYO2c7EbXYi2luBHE/SgiyRFBo4YddKyzoGXZmqkBGoMsRkh6NX
         flFWH7+6mcmXmyEFD7Owi3dlz606t6Pzn8shuOAsQjemC5Z0LT1wGgQdcqHVfpdmv4rF
         sHdPK4RHc8MbsNmr1h3UNDtmqiDnj+Vj0qxn2aaP32j53aGRBQihoMEQ7N0eypNdqC3B
         dgXw==
X-Gm-Message-State: AOAM532OI6CJLw6JT498q2UamKoKYK5e1u7yGF/JZ6Ae8Fjdrx4qs855
	IVtq+5k7OtZwBVFFjYwumxE=
X-Google-Smtp-Source: ABdhPJyHE9N0tVrqONbHybIUfQowuCCC7/OjwP1t3C6eNSJnrk8oNeNRqiRHbeOa4AaXpPwJrY7ocw==
X-Received: by 2002:a05:651c:1391:: with SMTP id k17mr1343077ljb.277.1604938023216;
        Mon, 09 Nov 2020 08:07:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90b:: with SMTP id 11ls616744ljj.0.gmail; Mon, 09 Nov
 2020 08:07:02 -0800 (PST)
X-Received: by 2002:a2e:8905:: with SMTP id d5mr6257615lji.144.1604938022214;
        Mon, 09 Nov 2020 08:07:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604938022; cv=none;
        d=google.com; s=arc-20160816;
        b=wXxz9flwwoX6D5edEu4tDbeEEntp2ZLd/GTaYrWiEK3YJXmtFCnUJPW+f9l+rBhJhC
         LHJEdXCgk9mA0eeFPbu+QyOjKf4iW+igGLAx6eRHWdil0npGrazO3V5T2ttcc8uE9Rr9
         jlzS6/k6S8g19u0aAncZxraqXuA//joNsrRSarCUX28GiJtWPgIP6/KKBIyMCItvWYBY
         a3b4xDvcOjTH2sZH4dGEJUuCETsjR/mUOiYRFqDHCf18zMdkFNNoYLiPAY27Eznh8ePR
         JBAHbKt6dAiMoDXUyuBB1wLIluvNZ0ylnBmx2oTIHkpaO89LUwTTue0duAT+c6+1TiwY
         gvrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=sCgAeIe4xj+YSbbSBnoftllYArFeB2ell1ztf8OUr8Q=;
        b=X3gR0JH+nJwzoYMvlcSn8KhbT6ZaqMZbGbUhwUwq29vSyYYlUTn1LN6GMLHPVMRwh9
         gWCUMcXi+p5BiYmhW8VZqyRHiOh+l3ej3BICpyzQ+OQ7ZAGN4ru3HCE1oVf1Ox2ao+dh
         u90guF/D8cZUSB6yiJedyMgBnrkhSNhK/C3FPe65k9VQx5cqC+JNcgTlIvIdjnU6UGPp
         kIuC0/fOtW0a0BQutQns4eGKf7nELkgzzwAd89/4b0hhFrAJhY3IsktlntVBjry6PWM1
         leD4ID5QvHDyGdXpF4RYr7lLohx6nKrvHaV4idwmXcH+S12xX7r9eIpoEJdj0yiQ2xXx
         KRXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=WQ8Lp+Ht;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id m18si242730lfr.11.2020.11.09.08.07.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Nov 2020 08:07:01 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:57588)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1kc9gv-0008Rm-7B; Mon, 09 Nov 2020 16:06:49 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1kc9gp-0000Yy-ND; Mon, 09 Nov 2020 16:06:43 +0000
Date: Mon, 9 Nov 2020 16:06:43 +0000
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
Message-ID: <20201109160643.GY1551@shell.armlinux.org.uk>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org>
 <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86>
 <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk>
 <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=WQ8Lp+Ht;
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

On Mon, Nov 09, 2020 at 05:02:09PM +0100, Linus Walleij wrote:
> On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
> <linux@armlinux.org.uk> wrote:
> > On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> 
> > > Aha. So shall we submit this to Russell? I figure that his git will not
> > > build *without* the changes from mmotm?
> > >
> > > That tree isn't using git either is it?
> > >
> > > Is this one of those cases where we should ask Stephen R
> > > to carry this patch on top of -next until the merge window?
> >
> > Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> > until the following merge window, and queue up the non-conflicing
> > ARM KASan fixes in my "misc" branch along with the rest of KASan,
> > and the conflicting patches along with 9017/2 in the following
> > merge window.
> >
> > That means delaying KASan enablement another three months or so,
> > but should result in less headaches about how to avoid build
> > breakage with different bits going through different trees.
> >
> > Comments?
> 
> I suppose I would survive deferring it. Or we could merge the
> smaller enablement patch towards the end of the merge
> window once the MM changes are in.
> 
> If it is just *one* patch in the MM tree I suppose we could also
> just apply that one patch also to the ARM tree, and then this
> fixup on top. It does look a bit convoluted in the git history with
> two hashes and the same patch twice, but it's what I've done
> at times when there was no other choice that doing that or
> deferring development. It works as long as the patches are
> textually identical: git will cope.

I thought there was a problem that if I applied the fix then my tree
no longer builds without the changes in -mm?

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201109160643.GY1551%40shell.armlinux.org.uk.
