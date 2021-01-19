Return-Path: <kasan-dev+bncBCSPV64IYUKBBWH5TKAAMGQEJONWCQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f55.google.com (mail-lf1-f55.google.com [209.85.167.55])
	by mail.lfdr.de (Postfix) with ESMTPS id 956A62FB595
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:13:29 +0100 (CET)
Received: by mail-lf1-f55.google.com with SMTP id 25sf7912396lft.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 03:13:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611054809; cv=pass;
        d=google.com; s=arc-20160816;
        b=CMjlygkDBBMURVL+bcttq4463eYASSQQc9HQEhXnVaWTFfVECVGji4o6ADUYfJRadb
         wzTYavpBxCqQb1PcYhJ13vJfYiZP1DwWgffyv7OW/y/K741HTRjoDuhDiw0mL5ILG2X0
         s+rMSKMhFB6TK4gUCvI4wz8q0nQMYjuZRwS598G/sUXqnbACoVQquW4Zy0kQo6x9fe3c
         obuz0OMOIM3NHuv0s0F1pc2HxKBlqABDjHRyT2pSnl0UjwUnZMqX5BkmhxoqUI0rFPW9
         bvjPuxma5ATBwBoSVPIW1TFFmEd0jAClwdxBGDvhNbOXEqVA0hNFsDkg3LhMf5al5bF2
         LgVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=IqpWKdHHIV2wYawEkSJeuFFnUN06E+nZEObQhf6zZLg=;
        b=MijMc7gxorAzJCuMMoMtiY1eWmb6ItTDqute4tqQR4QxlaNoyOFLdwINP2fVurm86T
         nJ/Vz0W3IYe63yKE/7iISvC7klLYISS4Rym2J9EDArXgTHILnhnxKZa9AMVvtzMdJyZy
         VHNA/No3wQgwc3yoJ1cs+jC0j4Thuuc5+YE2/i+LnrMK7KfB5psUC77X1GGRDj+LJmOc
         3eIQeG3LmJoN1wReX4XoL6en1c4yZr9T/Ewr/mzNoYrfqnTK6t2qVpvDw07pB/j90iGf
         UFPp7VtJUKvH00XOxYIQEfT7InhPv5m5Ypc1Z+vmmTRu/5pfDjdL87CnP4PF5egpWDuu
         pbhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=T99wTiy4;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IqpWKdHHIV2wYawEkSJeuFFnUN06E+nZEObQhf6zZLg=;
        b=d+KGl5hGZ+HXtOnIWlotGc7KdeMca7GkNWoC0tFSG+11nWQc8M/Hx5veMc7DVZIyeZ
         r8j6HelUF5SVNlGVFI+CgOV9p7rJAgEYo+xihqE7z5De2yUyrrwkcpffjOfDf6uCampb
         p4+VyIE3ord4krufgXftuIHWCClwhc8mKfRRkuGTZC/8VJfEglJME4U2uvYat+zySf0U
         t2HoEYeSOmgYJa6uVo45TKyn9IgjcZXkf6fhLP3CXCsJy1HnHX762SrejYkblfiatCKp
         z0DfhByArUpZXJDaDvN52qh6V8bE0EDJOXB8RnZ2Z2CrnN08M/h+k48Tk3inxlObGamY
         eNIA==
X-Gm-Message-State: AOAM5314+U/n2b1CPLpQZQ1QOT/s/DM8INwL5q5SEL8R/cb5/wZnx7kT
	6rBB6nYhAbWzduY1RQ3Ka0Q=
X-Google-Smtp-Source: ABdhPJwvpcguosPP7ws58t1vKGfzxKnATw/2rFm4SPyV2IcsF3RgXz7rKWskSeircPeprPUPjtJGTw==
X-Received: by 2002:a2e:810c:: with SMTP id d12mr1641002ljg.400.1611054809133;
        Tue, 19 Jan 2021 03:13:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6145:: with SMTP id m5ls1600252lfk.2.gmail; Tue, 19 Jan
 2021 03:13:27 -0800 (PST)
X-Received: by 2002:ac2:58f2:: with SMTP id v18mr1644709lfo.623.1611054807860;
        Tue, 19 Jan 2021 03:13:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611054807; cv=none;
        d=google.com; s=arc-20160816;
        b=bxQR6jNtJxn4fxWZa7kZ74c3bsyflR8totlByhTCpUDIMq9KQ/Fiv9aPbs1GgjAbaw
         AJ/7P48til0JmPFBJ5uCknI8S1VD62juxpGyf0QLwhfo+/9alpy1oPQnSKbpGyJEf34R
         rgFdsV+r0TszsNPpOvazQwo9RjRBihfFsMVO/5elRI1Uqp24kvQzlaPP7Z8pUbP0XaLr
         VA3KckZ2SA5Xe84OB158TUHN5H1e0/EReoQ+2NhBNfrwDVZIv08lYD8suNY3YALjXuoY
         z4HtOMjYRQIIwWZ/eyWz2L35ovdVZ5SRHzGr/HB1vUWOOhGGPSwj07x/XgZpWoeIHMvh
         PJTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wlXDkJX+fPtaApZ26r5joJDCpQdFFrbacT56p5xxO/8=;
        b=c0xCeZplwsw6eryYhYkHVn4DWDbMur5OX1UrGi9/sYuYAvKs07zWG+DZTryQoWbzmG
         C/yxrrWMmeAgnJ7zzGMDu3GyXNlOzN6HJiIlw4vdAz0niTnHwxtCL7wZXai1NN4TArQa
         hMvuQf7UuuyM+2RKjPvqBlL0snbtNCSE5bN5s37fWzV5WnGcZRsoKDb160fYK/JNKpT3
         tB0JUG0q/VsZLXJSO7pOWsowNLEoigKoOHAsCPYvI9JjVqRpHzw9gQaezEuzur6gzDsM
         0IQBslcS5ZLVrsnRvT6MeELERaFM6soaDVR9ek64sC/7QziT+v7Uk7gUVli06Z+nNfdZ
         gudQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=T99wTiy4;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id y6si4483ljn.3.2021.01.19.03.13.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Jan 2021 03:13:27 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:49936)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l1owp-0007J1-UC; Tue, 19 Jan 2021 11:13:19 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l1owp-0004yL-3z; Tue, 19 Jan 2021 11:13:19 +0000
Date: Tue, 19 Jan 2021 11:13:19 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Linus Walleij <linus.walleij@linaro.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzkaller <syzkaller@googlegroups.com>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119111319.GH1551@shell.armlinux.org.uk>
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=T99wTiy4;
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

On Tue, Jan 19, 2021 at 12:05:01PM +0100, Dmitry Vyukov wrote:
> But I also spied this in your makefile:
> 
> config-earlydebug: config-base
> $(CURDIR)/scripts/config --file $(config_file) \
> --enable DEBUG_LL \
> --enable EARLY_PRINTK \
> --enable DEBUG_VEXPRESS_UART0_RS1 \
> 
> With these configs, qemu prints something more useful:
> 
> pulseaudio: set_sink_input_volume() failed
> pulseaudio: Reason: Invalid argument
> pulseaudio: set_sink_input_mute() failed
> pulseaudio: Reason: Invalid argument
> Error: invalid dtb and unrecognized/unsupported machine ID
>   r1=0x000008e0, r2=0x00000000
> Available machine support:
> ID (hex) NAME
> ffffffff Generic DT based system
> ffffffff Samsung Exynos (Flattened Device Tree)
> ffffffff Hisilicon Hi3620 (Flattened Device Tree)
> ffffffff ARM-Versatile Express
> Please check your kernel config and/or bootloader.
> 
> 
> What does this mean? And is this affected by KASAN?... I do specify
> the ARM-Versatile Express machine...
> 
> Can it be too large kernel size which is not supported/properly
> diagnosed by qemu/kernel?

It means that your kernel only supports DT platforms, but there was
no DT passed to the kernel (r2 is the pointer to DT). Consequently
the kernel has no idea what hardware it is running on.

I don't use qemu very much, so I can't suggest anything.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119111319.GH1551%40shell.armlinux.org.uk.
