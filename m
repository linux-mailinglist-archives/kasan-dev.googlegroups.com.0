Return-Path: <kasan-dev+bncBAABBLE6XHXAKGQEYE2VRDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B4456FD6C1
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 08:09:33 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id d16sf1294421ljo.11
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 23:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573801773; cv=pass;
        d=google.com; s=arc-20160816;
        b=diSdaD7h6DKqNynPS3lnNN7ZK+oa8GVdjMi6X5pMhe3Df+k/SvkD7608ZC+irBCE+1
         J39OdhZ74Dp9LA6+LpCLsYVUfJEPAuoPGouplMwsTQUnP/AZvJA74x4pXb74RhthGJvV
         +MaGYbZ7adTKimjrKCtK8wBHEhI/f7Hnh1DNWvKaJBhFAOjSFiio/WEiAoXx01vl/9XN
         DlJJJHalofSFDzyZDS9oPZ2Dxhp389gmgAkhdW8PbwEjzhi3lEyQN3NT4yjJrAcJVPrk
         TyFMibApYuLG9ggBfOzn95hj8KufEu+FMq71xtJ1dizhY6LS2QKDquRKm66prIhTRtnQ
         QnCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2qUCPrvzWwZrvH8swYQ9wkDzi43xyECGgwSBOMifHhY=;
        b=S/n1uSLViKTnSsFgjYZdMInoj7ZapiX5aaBiH7Ik4W986GlYhVyYkZ053wAFihHeu6
         VWiZ/TN1ba2Y/S5kcx9QZM/ZFdGNlw+bUMvZUH8O5PHmK+f113CICnjdzeSOyK41De2r
         4u9BNy7Kkk35BcFbNo2tik+3hRdlrzvYqFF/qSIlClg50BiH/ZkTl3Iy3DrFCMaP1g9y
         THN+hZyHUph7Tf1wzDpWX+6Ma1ZkQ8SrzKnhXxPl0N5q8z916MIcIKvDSxH+749kvfUt
         x+iZaoG+k5ngEVWkq4L0kYF3AixG4zfaJi75f8aG5w8v8KvRAuNYkfdOOk2sIDQ8hmWF
         oJxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2qUCPrvzWwZrvH8swYQ9wkDzi43xyECGgwSBOMifHhY=;
        b=RNAAqap4xKZNSi3ZD6RKd3EQAoCKEWRK9HFnXBuQE6AOGVJLNX8wi9+K4F8mHWJ437
         7nQf2KBAr4EMHMJrOEWk8g0tMbtMlqqHFJYmYgCglfidSO9dSj8L69+Mk+bKsUtHuScZ
         Gyk785w94n+wMUH5SoET619GtdZcteBXK3LLCpT47a2d79stsNcsDUTc6bH5BNVfgeL/
         YwhZHYpcO2gb+IJRukAmo74d4k0pkpZpGkV3tJuz3Lb9GtYYgmeLwZrEXW4SjTAYDzK9
         ftV7dFvzxqSavCIviK8Gzs9CMSMyRdz0DdiPDdy22HOUAo0qNUplnEjrxsyPVPV2fjnC
         Mf+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2qUCPrvzWwZrvH8swYQ9wkDzi43xyECGgwSBOMifHhY=;
        b=IDZycMYAshBfRfWwxH8gM0OtQQd8o2Fo6kJ47TxANRS9bl+Dh2fpCbBIJhzXxYS4J1
         n+eWTmgflE8Fx/hbYhVob44hGmBn43DbU+zri5CTbXI70qpG9dNaH6Rq1ny2EbAVX+uO
         +8p5WQlSQucYbzfOFtKYzh07dIEp9+1xHIgXxEm38LgkNwXT1nYTLZNN/yGPeLyAN5H3
         n4WKYZiCBOOpXidzCyQU7dfUlNksySGk2oL3nuTZRSZxukt66x5MVI/IqCsOcJGsl5uX
         DYBpfVo7pngW8fvubveBRsE2Mwbk+xM47mEVR0qRmZGaQGSW93j3kQcmmuw3cPC0EPar
         yeaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVPiddN83qSxKjf8Npo/rKLAz5EI68PuZX/9ajDlP8ybSPQxHsM
	HT8YztMbUUuRPe7N3vOcnAA=
X-Google-Smtp-Source: APXvYqwKsO2tbky350iMj5K704hiMuPVKOLXkvpotB87jwpQUmj/j+YVTseXriRnPYYp6KqcNw2lpw==
X-Received: by 2002:ac2:46d7:: with SMTP id p23mr9973901lfo.104.1573801773163;
        Thu, 14 Nov 2019 23:09:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8584:: with SMTP id b4ls2048720lji.14.gmail; Thu, 14 Nov
 2019 23:09:32 -0800 (PST)
X-Received: by 2002:a2e:300d:: with SMTP id w13mr10189882ljw.117.1573801772680;
        Thu, 14 Nov 2019 23:09:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573801772; cv=none;
        d=google.com; s=arc-20160816;
        b=hAbHD5nXJcm7KIHx+jCFGGYYZWXnJaV2MFyKUFk9Z5zuXJyj47fEcZ5tFj0b1w8+kz
         hyQckhgqjGvXJBg9yeLWYvtbY6D/dO3f1PFzPwT/Eh9DPkWUADUG0Kjn2HFyKBb9U/Mf
         texp1M4dwdiGUhrAAtxJdE4Lr90mdRCx1O4CS5ZcVqK5GwIyVnXaf4PlFya2vvyRfnlb
         /UCf55cJmr2un4i98zyrWiBbpnVZ4NMndGgBeUiM91N7LsL9tSGExaIreIuIIZ+/EQ1b
         ltusZIC70IoneUq6d7F33wnvearQ4yTmS5bEocJZGpuamtb/qu+ZxC093Vsvj7gUOWYM
         Alig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=si7doS+8+HaqDyRJyxAQRRxZLilJCzb4wG4YUdbal9c=;
        b=yiUcv/vAZWR9YDiqaD0DCE8C1BXEe/ujmXHm3EyegJnk2QSiKX2CMacdYPfdJtMMDf
         TuQQbMbsEeEUq3vPuziyGweTKi3aIJhy+y55xhyO5unYevJ9OwQS2qCFSftt6mxnfkCr
         wiVsRA3xoHRkaaAzMPUgc29DJeAZ3qngIeryALqqRu4iI35qrzFPmTlRUEqReMBHanfl
         RhHCGbRkHbkcGfz8xQRPQKmmWak8GKXYri5g+HDW/UY2B8TPNKCYg+nDJTVZ3xaiQhKy
         VLwIC72Eabp4awS9tX9fbuNj19qQnrhffg0aMVniinEvjco81v5LgURH3lYwx8GzLwDG
         Tumg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id j14si538507lfm.2.2019.11.14.23.09.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Nov 2019 23:09:32 -0800 (PST)
Received-SPF: pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from pty.hi.pengutronix.de ([2001:67c:670:100:1d::c5])
	by metis.ext.pengutronix.de with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <mfe@pengutronix.de>)
	id 1iVViy-0003Na-GI; Fri, 15 Nov 2019 08:08:56 +0100
Received: from mfe by pty.hi.pengutronix.de with local (Exim 4.89)
	(envelope-from <mfe@pengutronix.de>)
	id 1iVVik-0008Gw-CK; Fri, 15 Nov 2019 08:08:42 +0100
Date: Fri, 15 Nov 2019 08:08:42 +0100
From: Marco Felsch <m.felsch@pengutronix.de>
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: linux-arm-kernel@lists.infradead.org, mark.rutland@arm.com,
	alexandre.belloni@bootlin.com, mhocko@suse.com,
	julien.thierry@arm.com, catalin.marinas@arm.com,
	linux-kernel@vger.kernel.org, dhowells@redhat.com,
	yamada.masahiro@socionext.com, ryabinin.a.a@gmail.com,
	glider@google.com, kvmarm@lists.cs.columbia.edu, corbet@lwn.net,
	liuwenliang@huawei.com, daniel.lezcano@linaro.org,
	linux@armlinux.org.uk, kasan-dev@googlegroups.com,
	bcm-kernel-feedback-list@broadcom.com, geert@linux-m68k.org,
	drjones@redhat.com, vladimir.murzin@arm.com, keescook@chromium.org,
	arnd@arndb.de, marc.zyngier@arm.com, andre.przywara@arm.com,
	philip@cog.systems, jinb.park7@gmail.com, tglx@linutronix.de,
	dvyukov@google.com, nico@fluxnic.net, gregkh@linuxfoundation.org,
	ard.biesheuvel@linaro.org, linux-doc@vger.kernel.org,
	christoffer.dall@arm.com, rob@landley.net, pombredanne@nexb.com,
	akpm@linux-foundation.org, thgarnie@google.com,
	kirill.shutemov@linux.intel.com, kernel@pengutronix.de
Subject: Re: [PATCH v6 0/6] KASan for arm
Message-ID: <20191115070842.2x7psp243nfo76co@pengutronix.de>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
X-Sent-From: Pengutronix Hildesheim
X-URL: http://www.pengutronix.de/
X-IRC: #ptxdist @freenode
X-Accept-Language: de,en
X-Accept-Content-Type: text/plain
X-Uptime: 07:52:54 up 181 days, 13:11, 128 users,  load average: 0.02, 0.03,
 0.00
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

On 19-11-14 15:01, Florian Fainelli wrote:
> Hello Marco,
> 
> On 11/14/19 10:12 AM, Marco Felsch wrote:
> > Hi Florian,
> > 
> > first of all, many thanks for your work on this series =) I picked your
> > and Arnd patches to make it compilable. Now it's compiling but my imx6q
> > board didn't boot anymore. I debugged the code and found that the branch
> > to 'start_kernel' won't be reached
> > 
> > 8<------- arch/arm/kernel/head-common.S -------
> > ....
> > 
> > #ifdef CONFIG_KASAN
> >         bl      kasan_early_init
> > #endif
> > 	mov     lr, #0
> > 	b       start_kernel
> > ENDPROC(__mmap_switched)
> > 
> > ....
> > 8<----------------------------------------------
> > 
> > Now, I found also that 'KASAN_SHADOW_OFFSET' isn't set due to missing
> > 'CONFIG_KASAN_SHADOW_OFFSET' and so no '-fasan-shadow-offset=xxxxx' is
> > added. Can that be the reason why my board isn't booted anymore?
> 
> The latest that I have is here, though not yet submitted since I needed
> to solve one issue on a specific platform with a lot of memory:
> 
> https://github.com/ffainelli/linux/pull/new/kasan-v7

Thanks for that hint, I will try this series too :) I read that you
wanna prepare a v7 but didn't found it ^^

> Can you share your branch as well? I did not pick all of Arnd's patches
> since some appeared to be seemingly independent from KASan on ARM. This
> is the KASAN related options that are set in my configuration:

Of course I will push it to github and inform you shortly.

> grep KASAN build/linux-custom/.config
> CONFIG_HAVE_ARCH_KASAN=y
> CONFIG_CC_HAS_KASAN_GENERIC=y
> CONFIG_KASAN=y
> CONFIG_KASAN_GENERIC=y
> CONFIG_KASAN_OUTLINE=y
> # CONFIG_KASAN_INLINE is not set
> CONFIG_KASAN_STACK=1
> CONFIG_TEST_KASAN=m

My config is:

CONFIG_HAVE_ARCH_KASAN=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=1
# CONFIG_TEST_KASAN is not set

> are you using something different by any chance?

Unfortunately not.

Regards,
  Marco

> -- 
> Florian
> 

-- 
Pengutronix e.K.                           |                             |
Steuerwalder Str. 21                       | http://www.pengutronix.de/  |
31137 Hildesheim, Germany                  | Phone: +49-5121-206917-0    |
Amtsgericht Hildesheim, HRA 2686           | Fax:   +49-5121-206917-5555 |

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115070842.2x7psp243nfo76co%40pengutronix.de.
