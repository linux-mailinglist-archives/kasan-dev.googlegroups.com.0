Return-Path: <kasan-dev+bncBAABBLE7XLXAKGQEMRMSFJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AE6D5FDC75
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 12:44:44 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id g13sf5527769wme.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 03:44:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573818284; cv=pass;
        d=google.com; s=arc-20160816;
        b=YVxnkV3zp9Cr9VMa7u+11Cx7GFsLR2mWZsjHARzViEe71zdbiGL0HPtg343K/kXtnS
         Ov8G+L7t0qzy/Lsvc/dKGXPFcc4U4pHBd0Vu87dlSRoGrdU5BIWrHby9jdxol2pAk6H+
         R9Uu1ySkzVQ4ksrVdmPxAZCPn08wzLQvOr3pexUooxAGhKIRJSY1fbnozqJonK73vGZK
         r9/f9MPHCT5AvUDwl3rX0gl4Pwm0P4tsBN+BlKZKrVc5DuXV8YJgeAzQWigfyKRB9g9I
         S7LBs97Nsh1vlBzYDT8oamg/U/230QDaTCCjo0XeanYqGjJSmN6TzSGyOroIJcFxzcZd
         VS1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=MDIFgV/tOKjhoz7dIkcA01Z+JtmnnX7x6U1qwFxuVT4=;
        b=WRYS6RtvqKJCMUXOL5TnbCb+u4kpiISkjF5TXiWDVFJUaqKWd/+BBBFEI9KqiJY2F6
         QYaTpuqZq7/dSVPb0IbvR3j6tLgQqDb1FqwYf3F+0hOL1Z+HeisQ/EKGd3hrAggm/SjX
         +kSEzdu7Xxeo3fZGNN1h+PaPul5odgnW2NzeY6ItdvEy80WceRoqUCD3xo1qSSi6ZX5O
         dBLhYvNU4dbrRpJ6IIAcuuw5W1V3iAxO58IR2RtquBXsPa/yN9jD3b17hlN1wfMuYkYc
         XOioiCKFC1E9XMFTMIM6y9y9FDqNXwPb2AdmaalXvC4HWd/0w0TKAArsUfa8rQ7apmjo
         prvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MDIFgV/tOKjhoz7dIkcA01Z+JtmnnX7x6U1qwFxuVT4=;
        b=aTmKO+P9XK3TQ8E/TmjeC/amlxz53qddu6vgfLWzOy0hCU1LWodTGjNQN1uLPU89M9
         7n95kgl7oT8rSTL7cPfYdi6zw1ZIVaZBaeWzAWOr7pwA7MpSPwWB3hBxWhy5Dux7Pw1K
         l8LXvHi0XaVgL7/stP1GmCofMIiTq3zMVpjSin+AeWJ+DJkdppYYXZlHuL0Ze4iA4jC3
         U3qtszf4RnebaLacO9T8W3V7mkKa9ZkNHFELQ9NbWera2vsdnDeYuHXPT08XdDaWLTKB
         vXvHn1Wf/mJbj6VPIfAuTwPv1aM3yAdl5SElExapcF0o3qI5Z+8BpgHAChTw+l+ojcm2
         WWoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MDIFgV/tOKjhoz7dIkcA01Z+JtmnnX7x6U1qwFxuVT4=;
        b=PeS25FXWFtwQpPTGhKEgv8uINMl8iyZINVem11rhgaozikEvlPYbTpvlclgSFXyMVw
         QrpDjQBPlymMS1tn1Ps+ZbjS66YaQdwfcECOMYcn8C1265GmWrWAdLY4LJ/y2xK1Is30
         ueNOXulHjtTKtY3hZ99q6vh/m5lOi6jtkIgyuwmrmK3cDkSELh74LGXdjU9Qhey9o/yi
         1t/9SyxYz4v93tChqdlZkx1UHpsW4k5X0wB9RdidYcdou3uC9wKePMdV8x8w8iDmpevX
         2I0dZ8uxhDJGHEj55x+n2CuUNz66uqEdsT01zYfNxd0wmZAnhbx2L3Le1S1RGxefykhG
         VWKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV64kYUP8IN2x6xOTqg/uLyA2XDi9CkHcyVaYqxB1eKexHGrGtZ
	7nRJp3kWAl10xfA7lyysrN8=
X-Google-Smtp-Source: APXvYqw9yhgcyE6mzZlajVjrwOGBSeVHoUDc1j30rUZn9ku/AS85R7enm9gknrW1zZSGXWEVKRmiVg==
X-Received: by 2002:a5d:48c8:: with SMTP id p8mr15551714wrs.318.1573818284295;
        Fri, 15 Nov 2019 03:44:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:387:: with SMTP id 129ls15344218wmd.3.canary-gmail; Fri,
 15 Nov 2019 03:44:43 -0800 (PST)
X-Received: by 2002:a7b:c632:: with SMTP id p18mr14234663wmk.73.1573818283950;
        Fri, 15 Nov 2019 03:44:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573818283; cv=none;
        d=google.com; s=arc-20160816;
        b=LUi2crQ2cqIcCR4XPPkd+ftDGsge8zPGI1F6TtmveBW2tNPScMMGujlQvFwfiENCCK
         pjhTkkbCvcaC/JkXrTbAHSMc2d/m2WXN0gNghGqa4iuQShUbfULwx3CvIp0pms76HrOg
         3hnfen7e5YPy/dfzqmTtVkd8FnVdyuo/dZW8ijxUfBqMFWRtSrE+Y6dFcfgAZvv1Kdyc
         C6ITf/iF9EDBK9C8UbQOYzbeerBQqEfxaVIBK0k0Gci44D43pX2pXA8Zlvv1uQkPyo3U
         pS2d1E0R5355w/nkVZ22nawu1/UDItwWKmKzLotHNw+qrl1tpfYAiWnxSWAyp7ZLrnNi
         mKLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=vQ5lcC3H4qOgke9+oJRcyPaE03+uFexHlMr3n5xn+Xk=;
        b=b2WfRbHTn+3WPe8dkSqLF6rlfSPgjYjQPG2lOK6mfvTwPVn3jbIyD+GySDCA+2n9Jo
         KDLkC0QG1ZTlt+xLT7BIRC/i62Pyf0Od3fOi3VrDfoVycATjHrwB7LJWYez0Pl+ZXvir
         zRuq1g+KW+07n2wJO9BVJcStU1eHYqVBubPQd2mO4gCT18fA/aGdXHO/bzx9lcrNwmtl
         Hbt0bcYB+3WiLOuOShmb9ng0cp3S+jNXSuQTCshMVaWfqS69l/VdUdbd/xkQjwQzX0WM
         GrooPKwcS3V/g2xYv0Gghdu8DEOvuBNCvoWfZMnPhKQJ6oEJHP/LXul1/GnRZ/kQELyd
         io9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id x2si468425wrv.1.2019.11.15.03.44.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Nov 2019 03:44:43 -0800 (PST)
Received-SPF: pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from pty.hi.pengutronix.de ([2001:67c:670:100:1d::c5])
	by metis.ext.pengutronix.de with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <mfe@pengutronix.de>)
	id 1iVa1Z-0007QU-T6; Fri, 15 Nov 2019 12:44:25 +0100
Received: from mfe by pty.hi.pengutronix.de with local (Exim 4.89)
	(envelope-from <mfe@pengutronix.de>)
	id 1iVa1Q-0008K2-Ab; Fri, 15 Nov 2019 12:44:16 +0100
Date: Fri, 15 Nov 2019 12:44:16 +0100
From: Marco Felsch <m.felsch@pengutronix.de>
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: mark.rutland@arm.com, alexandre.belloni@bootlin.com, mhocko@suse.com,
	julien.thierry@arm.com, catalin.marinas@arm.com,
	christoffer.dall@arm.com, dhowells@redhat.com,
	yamada.masahiro@socionext.com, ryabinin.a.a@gmail.com,
	glider@google.com, kvmarm@lists.cs.columbia.edu, corbet@lwn.net,
	liuwenliang@huawei.com, daniel.lezcano@linaro.org,
	linux@armlinux.org.uk, kasan-dev@googlegroups.com,
	geert@linux-m68k.org, dvyukov@google.com,
	bcm-kernel-feedback-list@broadcom.com, drjones@redhat.com,
	vladimir.murzin@arm.com, keescook@chromium.org, arnd@arndb.de,
	marc.zyngier@arm.com, andre.przywara@arm.com, pombredanne@nexb.com,
	jinb.park7@gmail.com, tglx@linutronix.de, kernel@pengutronix.de,
	linux-arm-kernel@lists.infradead.org, nico@fluxnic.net,
	gregkh@linuxfoundation.org, ard.biesheuvel@linaro.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	rob@landley.net, philip@cog.systems, akpm@linux-foundation.org,
	thgarnie@google.com, kirill.shutemov@linux.intel.com
Subject: Re: [PATCH v6 0/6] KASan for arm
Message-ID: <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
 <20191115070842.2x7psp243nfo76co@pengutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191115070842.2x7psp243nfo76co@pengutronix.de>
X-Sent-From: Pengutronix Hildesheim
X-URL: http://www.pengutronix.de/
X-IRC: #ptxdist @freenode
X-Accept-Language: de,en
X-Accept-Content-Type: text/plain
X-Uptime: 12:28:52 up  2:47, 19 users,  load average: 0.00, 0.04, 0.03
User-Agent: NeoMutt/20170113 (1.7.2)
X-SA-Exim-Connect-IP: 2001:67c:670:100:1d::c5
X-SA-Exim-Mail-From: mfe@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: m.felsch@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
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

Hi Florian,

On 19-11-15 08:08, Marco Felsch wrote:
> Hi Florian,
> 
> On 19-11-14 15:01, Florian Fainelli wrote:
> > Hello Marco,
> > 
> > On 11/14/19 10:12 AM, Marco Felsch wrote:
> > > Hi Florian,
> > > 
> > > first of all, many thanks for your work on this series =) I picked your
> > > and Arnd patches to make it compilable. Now it's compiling but my imx6q
> > > board didn't boot anymore. I debugged the code and found that the branch
> > > to 'start_kernel' won't be reached
> > > 
> > > 8<------- arch/arm/kernel/head-common.S -------
> > > ....
> > > 
> > > #ifdef CONFIG_KASAN
> > >         bl      kasan_early_init
> > > #endif
> > > 	mov     lr, #0
> > > 	b       start_kernel
> > > ENDPROC(__mmap_switched)
> > > 
> > > ....
> > > 8<----------------------------------------------
> > > 
> > > Now, I found also that 'KASAN_SHADOW_OFFSET' isn't set due to missing
> > > 'CONFIG_KASAN_SHADOW_OFFSET' and so no '-fasan-shadow-offset=xxxxx' is
> > > added. Can that be the reason why my board isn't booted anymore?
> > 
> > The latest that I have is here, though not yet submitted since I needed
> > to solve one issue on a specific platform with a lot of memory:
> > 
> > https://github.com/ffainelli/linux/pull/new/kasan-v7
> 
> Thanks for that hint, I will try this series too :) I read that you
> wanna prepare a v7 but didn't found it ^^
> 
> > Can you share your branch as well? I did not pick all of Arnd's patches
> > since some appeared to be seemingly independent from KASan on ARM. This
> > is the KASAN related options that are set in my configuration:
> 
> Of course I will push it to github and inform you shortly.

Here comes the link:
https://github.com/medude/linux/tree/v5.4/topic/kasan-arm.v7

I just applied Arnds Patche which you didn't added into your v7.

> > grep KASAN build/linux-custom/.config
> > CONFIG_HAVE_ARCH_KASAN=y
> > CONFIG_CC_HAS_KASAN_GENERIC=y
> > CONFIG_KASAN=y
> > CONFIG_KASAN_GENERIC=y
> > CONFIG_KASAN_OUTLINE=y
> > # CONFIG_KASAN_INLINE is not set
> > CONFIG_KASAN_STACK=1
> > CONFIG_TEST_KASAN=m
> 
> My config is:
> 
> CONFIG_HAVE_ARCH_KASAN=y
> CONFIG_CC_HAS_KASAN_GENERIC=y
> CONFIG_KASAN=y
> CONFIG_KASAN_GENERIC=y
> CONFIG_KASAN_OUTLINE=y
> # CONFIG_KASAN_INLINE is not set
> CONFIG_KASAN_STACK=1
> # CONFIG_TEST_KASAN is not set
> 
> > are you using something different by any chance?
> 
> Unfortunately not.

With your v7 it is working on my imx6 but unfortunately I can't run my
gstreamer testcase. My CPU load goes to 100% after starting gstreamer
and nothing happens.. But the test_kasan module works =) So I decided to
check a imx6quadplus but this target did not boot.. I used another
toolchain for the imx6quadplus gcc-9 instead of gcc-8. So it seems that
something went wrong during compilation. Because you didn't changed
something within the logic.

I wonder why we must not define the CONFIG_KASAN_SHADOW_OFFSET for arm.

Regards,
  Marco

> Regards,
>   Marco
> 
> > -- 
> > Florian
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115114416.ba6lmwb7q4gmepzc%40pengutronix.de.
