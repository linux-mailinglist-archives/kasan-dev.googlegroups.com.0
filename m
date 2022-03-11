Return-Path: <kasan-dev+bncBCSPV64IYUKBBV6LVSIQMGQEGYMKNLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-f186.google.com (mail-yw1-f186.google.com [209.85.128.186])
	by mail.lfdr.de (Postfix) with ESMTPS id 873F24D5FAB
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 11:35:04 +0100 (CET)
Received: by mail-yw1-f186.google.com with SMTP id 00721157ae682-2d07ae11462sf65720067b3.8
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 02:35:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646994903; cv=pass;
        d=google.com; s=arc-20160816;
        b=RtQGMivIpQKfZ4WddY5jg24xNO1YPaqfcqqOq8ctVpmLSE+e/vFkeV0JZVnLiqbsaG
         gaBlH0sDggPg7GoX8V2DNTT3LcFalSipTnBI3CDF68mq36pCp8jSP6BOpNaKvVth92uG
         gy+dtGPmq5bI9cagAYoP43RfUyGr9YmeqxfMXV5B2X4EKjeEnf7s5DPdMUQj/hP5O9qx
         XDi/CWs3dm9HdBWbPaCwzstNvJogAtxocGnKtah7BuqvdnBBTFkWoHK1lU1jWJIqFsk+
         OQ5dFEnj5MeNDPd1iVP2RxKSjF+p+huUnNy2kPiTS9L9YBGGmEVcyN8v7sCzN5Ce61qT
         JzIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=f3B1211BsgL1rZ2EpGKPy7A5UtELWHNdg3iKp+1txNM=;
        b=Rp669I8lPOO6wudaO4N+6xU0PQtVThfUUUxRmqMWEOze3V1OnD/YD4nIocKPeBhuTF
         KDHcfLrd78D5AwNsWkhLRjqHVynM5kvfJo1Gi+KrksqEbjwOZSGcFJ7KsH1OAqVCBC62
         dGSfFaYXxnr7rztiJOV+Iga/RZ8v/vF8Cs8B7lWr746Vrj9481wstW7IPXpe/FhEnqXQ
         c0FX/HIlzk+RuKKGSCeoGxJqzZndz7vcWhQF3NWMkQIYzPT3ZWv8/vhiGA0IjT5iPYK2
         gMbR6hM3hv12VetPyze2Q8KviBap8U9QPBQlbRFqflrC5cWiSWsqqQqfecFuigmv5ssM
         amrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=GNpys08J;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f3B1211BsgL1rZ2EpGKPy7A5UtELWHNdg3iKp+1txNM=;
        b=VS+pBn57KzzxVyQt/8Gsn/oRxtQYjhYBIQ/l7qbaQIiatXNYuNMIyAoEh8aCUeHAnw
         sL/hGfnZTq7kdtZss3l9VxNx3/2JiItskjvJX3NlEc9eP7VaSWoD6DGiQJLk5O+yeecP
         S6UHzIL4ryIkDMv5FAR33u/yLwvRlo/MjuMtXhnjTyC0rvZQckNpIsDFN71TXeUMEgg+
         RJXpaz5XPh0Du6hpAaZouKezANRI6z4GxnlaInR3LweQ7Qzk3NgB4MLbuyBtJu7MntoD
         yGUwA/wBv8fJ92EDsMnHyRYnd4LUtLNIMVsxVpS3mwU9z2cDU57cGPbX5TijrsbTpvHn
         2PUA==
X-Gm-Message-State: AOAM530WtZhQ2JSIv/NEiapBJyMTZcqHvS8PUpBk9D10SAfricMBBe9I
	giv9sL3QimCeeUh2FtaJgko=
X-Google-Smtp-Source: ABdhPJzESbkfOIHA8sJwuX1e3rLu/B8WoAc9ZptQeIWn0aTfrtHgd/PmK8ELWtl8yQVlLpdvjVNRBA==
X-Received: by 2002:a25:8a0b:0:b0:61e:1688:f684 with SMTP id g11-20020a258a0b000000b0061e1688f684mr7476783ybl.323.1646994903221;
        Fri, 11 Mar 2022 02:35:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:f786:0:b0:2dc:2dd3:6ebd with SMTP id h128-20020a0df786000000b002dc2dd36ebdls356845ywf.10.gmail;
 Fri, 11 Mar 2022 02:35:02 -0800 (PST)
X-Received: by 2002:a81:4a08:0:b0:2d1:19d7:1902 with SMTP id x8-20020a814a08000000b002d119d71902mr7533967ywa.337.1646994902683;
        Fri, 11 Mar 2022 02:35:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646994902; cv=none;
        d=google.com; s=arc-20160816;
        b=IwI3X7d7XkyfUlbzDazsle9qqgc1WTOoc7hUthS68M7HFMOnZbomMMa5i58dpDFnJj
         ze255nNsdX/Sb5dBVv/hEMgB97xjpWZhp6wrrObN8gBdRZfNakXg9sTJ/mGCDnMze2tQ
         CddEk1NtRsrnIxLjcufGwNENbFB/Z44bO4HnzVi7XywKoYJWX4+xDNSiRUoLVlDvqgGv
         nHIZXRRg6DGRlidxq8UY6d43KW/CNbH/+nOAyppSGlte07LWw3P/uVNs2eDb6CCq0/JH
         41+QLxwn76ZZZBXix3UqH9oZlIPJ23Rjr1a3ubbUP5f8MWhy+md1oaWAFBxiownYDrqY
         mDXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uyaT3+EVPViBMT6fbeRdikl9gpqbHKai7w6iSnQ9lMw=;
        b=gxqPIvQg/1N6T3rj9mEIe50lpjvTI2WpGRwwmINn2ZkSq7MchJn0AWyEjOboh0T8wM
         B/5Xx2tGrXOWdIVQnjPWWs0M5RW+c5+lGEywu3/+V5rHg37BhBjXQpcDl62NkblsRb/X
         NORSsk8V5o43xeKPxGbD/s/V6Xdy3/iHhKoYoOKF/1rpOrjnoGaUIrFTxBUbItU2BUsc
         D2Qwivg2Q1WdQVMVFkwE9E9Ic7leub0TGUFQ/CjhK0RMzBznXCTa+XvmW/b4Oq2fkvNU
         G6TOYPvYTJOFlVriYEPPiH2nSYmh2zYYk7ruH8SKtiSToToTajYS/ZcNs8mNN3up9NDI
         PrQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=GNpys08J;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id v8-20020a056902108800b00628aa3cadadsi411316ybu.3.2022.03.11.02.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Mar 2022 02:35:02 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:57786)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.94.2)
	(envelope-from <linux@armlinux.org.uk>)
	id 1nScba-0002Qe-Qz; Fri, 11 Mar 2022 10:34:43 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1nScbX-0001Wi-Bk; Fri, 11 Mar 2022 10:34:39 +0000
Date: Fri, 11 Mar 2022 10:34:39 +0000
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: linus.walleij@linaro.org, linux-kernel@vger.kernel.org,
	andreyknvl@gmail.com, anshuman.khandual@arm.com, ardb@kernel.org,
	arnd@arndb.de, dvyukov@google.com, geert+renesas@glider.be,
	glider@google.com, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, lukas.bulwahn@gmail.com,
	mark.rutland@arm.com, masahiroy@kernel.org, matthias.bgg@gmail.com,
	ryabinin.a.a@gmail.com, yj.chiang@mediatek.com
Subject: Re: [PATCH v3 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Message-ID: <YislvzIg3Tvwj2+J@shell.armlinux.org.uk>
References: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
 <20220227134726.27584-2-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220227134726.27584-2-lecopzer.chen@mediatek.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=GNpys08J;
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

On Sun, Feb 27, 2022 at 09:47:25PM +0800, Lecopzer Chen wrote:
> Simply make shadow of vmalloc area mapped on demand.
> 
> Since the virtual address of vmalloc for Arm is also between
> MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> address has already included between KASAN_SHADOW_START and
> KASAN_SHADOW_END.
> Thus we need to change nothing for memory map of Arm.
> 
> This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> and provide the first step to support CONFIG_VMAP_STACK with Arm.
> 
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm/Kconfig                 |  1 +
>  arch/arm/include/asm/kasan_def.h | 11 ++++++++++-
>  arch/arm/mm/kasan_init.c         |  6 +++++-
>  3 files changed, 16 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
> index 4c97cb40eebb..78250e246cc6 100644
> --- a/arch/arm/Kconfig
> +++ b/arch/arm/Kconfig
> @@ -72,6 +72,7 @@ config ARM
>  	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
>  	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
>  	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
> +	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
>  	select HAVE_ARCH_MMAP_RND_BITS if MMU
>  	select HAVE_ARCH_PFN_VALID
>  	select HAVE_ARCH_SECCOMP
> diff --git a/arch/arm/include/asm/kasan_def.h b/arch/arm/include/asm/kasan_def.h
> index 5739605aa7cf..96fd1d3b5a0c 100644
> --- a/arch/arm/include/asm/kasan_def.h
> +++ b/arch/arm/include/asm/kasan_def.h
> @@ -19,7 +19,16 @@
>   * space to use as shadow memory for KASan as follows:
>   *
>   * +----+ 0xffffffff
> - * |    |							\
> + * |    |\
> + * |    | |-> ZONE_HIGHMEM for vmalloc virtual address space.
> + * |    | |   Such as vmalloc(), GFP_HIGHUSER (__GFP__HIGHMEM),
> + * |    | |   module address using ARM_MODULE_PLTS, etc.
> + * |    | |
> + * |    | |   If CONFIG_KASAN_VMALLOC=y, this area would populate
> + * |    | |   shadow address on demand.
> + * |    |/

This diagram is incorrect. We already have the memory layout in
Documentation/arm/memory.rst, so we don't need another set of
documentation that is misleading.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YislvzIg3Tvwj2%2BJ%40shell.armlinux.org.uk.
