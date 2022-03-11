Return-Path: <kasan-dev+bncBCSPV64IYUKBB2GMVSIQMGQEOWISO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-f191.google.com (mail-yw1-f191.google.com [209.85.128.191])
	by mail.lfdr.de (Postfix) with ESMTPS id AC5D94D5FC6
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 11:37:29 +0100 (CET)
Received: by mail-yw1-f191.google.com with SMTP id 00721157ae682-2dbda4f6331sf65457827b3.11
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 02:37:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646995048; cv=pass;
        d=google.com; s=arc-20160816;
        b=LY07VcNY2z6FNMOoEO3sbJaGVS4E3eb8R/l/HgSEXAQMydeCfhRnxWthI/pCuAQaqS
         G9yHJ3adyBlP78zDj6m1kk3CMYavxMlQmMhfAkotY9C0Ngk2kbnI2HacDYEpNBPhTmZm
         mCCYuQxoGwWUnuXmQkYeBZRYCOOHUqwvWQwsCyAjVLpfHIUuye7jKPANShIE3p4n6Wac
         PunrYPcQ1gHFaQ4QF1Uyst5sfS0aFmnGw08Tt2Tyco2GVMx458tTfgZ+gk+XAK29D088
         0+i9GMaDwBnd73i+6qUjO3cCV9V036Qe1d+KX93zCwizwuJ9n5P/Kx+DMo490k/S6y1c
         MV/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=avxBvpeEW6+JkYUukrR6/vffdtc0Ughrtnqsg7nHKmQ=;
        b=qYMP6Ssvfqm1Fh8usdEUPrToj4zhA3lfu40I+0IccRhEdrJKVSnGfux8Lgo7bI4r7r
         7U6xAVg0yQwnP+an9GFvrSyvlzny72YNXFgLAAe0zsQ+i99mtMRZEq/YNjvEli/3vcme
         Li8XTdcSVJCQM7zBeO15OVfZxbaYcuSiOIpAI7vVGe1KtCzuCroKNi5hm76erXaHS1Lc
         3OOe7/xaRMYjqErhZNXd2axxsuOnibhtXvYtuXlslZoQXtOUZ2mctXXCYqD+POmqW7n7
         Q3k8NXE1M1GkqeuSkkG1mFperm+pkPLYJrmG7NZ+IZN5SXoWTRXkgPSo3l1ok+IuAnWQ
         WO1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=pbKdbcjp;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=avxBvpeEW6+JkYUukrR6/vffdtc0Ughrtnqsg7nHKmQ=;
        b=GKBO5S7pkY7bASTyQrmawu6w83tXP+ymNsfqSdLHbpiJ3lHPf2pttk5wlx8b5VnE3M
         Mn5YXPyCUQGajuVxr1umW9QVgbHWw/mC6T3JeWabDM+9uadI8k08FAiiTswuT7Ga1tqo
         e79PREomIwBgbfbY1ywnbl/M4fxj0+B5XFRK9g3VGcS/2/Ll2xLoHjBaaLdrb1oyGfQh
         C/9F2AL18t4nc60KLXL1PWlW4L85wf8xNcu9H+5kDfPjJSO4JdTH4OMlT9Z8o3ay7Bsv
         tTz6qE5FhH17h9Ptd9DdTF7ihPmKqIYL0qlt6haT4vq8X5VpBL0dTfLMIz7uyr8mQaEd
         oFCg==
X-Gm-Message-State: AOAM532nX3ApcMIONZWpr/+u3s2RVDuiQg1YnAzqOuM6xR1ssOBX1Dyn
	FniPJsWf4dHtDM8mbTtpgCk=
X-Google-Smtp-Source: ABdhPJyhzDOLeLcPbpkavsnUqsui0npA1MpK7Zr5NxP8dIO2lAHxvblO8exxa6614Ft+MNH6+H1F6A==
X-Received: by 2002:a81:a882:0:b0:2ca:287c:6bc4 with SMTP id f124-20020a81a882000000b002ca287c6bc4mr7866415ywh.105.1646995048650;
        Fri, 11 Mar 2022 02:37:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1505:b0:629:5586:f64f with SMTP id
 q5-20020a056902150500b006295586f64fls527229ybu.0.gmail; Fri, 11 Mar 2022
 02:37:28 -0800 (PST)
X-Received: by 2002:a25:8e88:0:b0:628:bc08:7aa with SMTP id q8-20020a258e88000000b00628bc0807aamr7547155ybl.303.1646995048212;
        Fri, 11 Mar 2022 02:37:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646995048; cv=none;
        d=google.com; s=arc-20160816;
        b=EcTd/YGpoBP0tmucGyPKtIj4/RNSSjRL0hM/oUQXwZ+Vc6rJjkLCltsjas7mv/OtUV
         HdW2Qnq3kymUxKK3L8PgJ9C0MVwo5wIA37boicmKT0YxhWeK6e0E3P2e83QbOweEgkJx
         MCaCnBBSQuacuyVjwLcJpmvbmbgW37S8af5dDVplsi+HF+r+NY4zEWPw2fwR+GJaj5ec
         Wx+Xb9+bGE476Se2C0sUYsWUs1DI6YHeVQwHqlP3Cb5SQyaRnnPHL37s3GYyzW0s1zTd
         xCbi1+m6125/QJ8Ap/heFFzcTGqdzluX3NvBD8VOXuaF3QS5fJ4DJmqrx+zMeSQkAaBk
         EZ0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fAl9Fpwe3hBpzZjYhYE3T3tApQIlsu2mrNCudRtI24A=;
        b=QoeMOomjKWCkfQEt1W1+dFLEXdr4+t/kRKeJaeEB4mBPoZRp9ahF63fH5sKXp0yWqJ
         9KNliqXsO9tVb6eqFqNQNt8Z61clWu2ptlZNFEvdz/Sb6Y78Uw4VJh5cvFyM88siaE8W
         i7KUTAoYgeWasg2pODeu5ine+Qr+SleYcGR4kvr8FSUfn4/tu9mVrgkvFstbgSmqrq4o
         0W/jpebcZ8jEKOETu9yAhPNoCmVmQavFd4p6JMiwV6y0wlG5My5Fv4jQURDWj+WrNh+N
         RMEJmLd9IbIRv8yRfZAlATFL6n0G7vcxlHM2xKznobHYunLSNfKiM90oSFZvluHlK6g6
         J21w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=pbKdbcjp;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id r8-20020a255d08000000b006289d424b2fsi579680ybb.1.2022.03.11.02.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Mar 2022 02:37:28 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:57788)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.94.2)
	(envelope-from <linux@armlinux.org.uk>)
	id 1nSce6-0002RB-51; Fri, 11 Mar 2022 10:37:18 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1nSce4-0001Wp-LD; Fri, 11 Mar 2022 10:37:16 +0000
Date: Fri, 11 Mar 2022 10:37:16 +0000
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Lecopzer Chen <lecopzer.chen@mediatek.com>,
	Arnd Bergmann <arnd@arndb.de>, linux-kernel@vger.kernel.org,
	andreyknvl@gmail.com, anshuman.khandual@arm.com, ardb@kernel.org,
	dvyukov@google.com, geert+renesas@glider.be, glider@google.com,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	lukas.bulwahn@gmail.com, mark.rutland@arm.com, masahiroy@kernel.org,
	matthias.bgg@gmail.com, ryabinin.a.a@gmail.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v3 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Message-ID: <YismXDtUZ2cPtVnN@shell.armlinux.org.uk>
References: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
 <CACRpkdasAGFDth-=eKgUFo+4c-638uo2RMbaUap6ent5mmBXbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdasAGFDth-=eKgUFo+4c-638uo2RMbaUap6ent5mmBXbw@mail.gmail.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=pbKdbcjp;
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

On Fri, Mar 11, 2022 at 12:08:52AM +0100, Linus Walleij wrote:
> On Sun, Feb 27, 2022 at 2:48 PM Lecopzer Chen
> <lecopzer.chen@mediatek.com> wrote:
> 
> > Since the framework of KASAN_VMALLOC is well-developed,
> > It's easy to support for ARM that simply not to map shadow of VMALLOC
> > area on kasan_init.
> >
> > Since the virtual address of vmalloc for Arm is also between
> > MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> > address has already included between KASAN_SHADOW_START and
> > KASAN_SHADOW_END.
> > Thus we need to change nothing for memory map of Arm.
> >
> > This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> > and provide the first step to support CONFIG_VMAP_STACK with Arm.
> >
> >
> > Test on
> > 1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
> > 2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
> > 3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.
> >
> > v3:
> >     rebase on 5.17-rc5.
> >     Add simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
> >     Tweak commit message.
> 
> Ater testing this with my kernel-in-vmalloc patches and some hacks, I got
> the kernel booting in the VMALLOC area with KASan enabled!
> See:
> https://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git/log/?h=kernel-in-vmalloc-v5.17-rc1
> 
> That's a pretty serious stress test. So:
> Tested-by: Linus Walleij <linus.walleij@linaro.org>
> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
> for the series.
> 
> I suppose you could put this into Russell's patch tracker, it's gonna be
> for kernel v5.19 by now but why stress. It seems I can fix up
> kernel-in-vmalloc on top and submit that for v5.19 as well.

Ard's series already adds vmap stack support (which we've been doing
some last minute panic-debugging on to get it ready for this merge
window), but the above description makes it sound like this series is
a pre-requisit for that.

Is it? Will Ard's work cause further regressions because this series
isn't merged.

Please clarify - and urgently, there is not much time left before the
merge window opens.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YismXDtUZ2cPtVnN%40shell.armlinux.org.uk.
