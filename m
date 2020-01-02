Return-Path: <kasan-dev+bncBDVIHK4E4ILBB657W3YAKGQEM3NBQEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F17F912E361
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jan 2020 08:47:07 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id i9sf4975979wru.1
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2020 23:47:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577951227; cv=pass;
        d=google.com; s=arc-20160816;
        b=U8HUUaOy1bTasNixDgye+NvdZeXwFxvhAkIUpgdJLKXRrTfj91R5kP42KfepWEhnOR
         k8b8eJsq3RfpxwiDsQATDWzks4Omh600dAJMmJBZ7rc99ToeG76nfiI9CvSu/WkNFj/m
         RluVnKkrB1V2D1yiO4FmKRPfXFa76Sq53suwLj/dE2lCC/V72BIeig3V3yw+1NuTfmSB
         QGq6ClrQewL89LzLjj4PLvyA+Glxh2ESZ2wLmoMdMn6evHQlZelRsyNWMrmtJHOLGokO
         YXlJlQNq/u/C8o4CD0MwPnM1wixUGQjpYEGAoLb0rxJ7Tn8AyH4nBcAuo5syi+MdtnuQ
         WFjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XulU/s1jjCwM6MfmomqI8lkvSWuJhlfPBuT2XheHi2I=;
        b=obEqHfP2kpDOCE9l807OI9dNZS5KMsYrhFAE4joiB66zdoET5IUUS8aKz3XCbzJCAF
         TiBsp0M9G7whlBLy/SYZwQsbIPXnaR9Ck7/WZA9t+B3YUX6shL+WjhbwbPm29FZpobdp
         AQCGAGMgHeH/vFTOIliRONxqy50r6DzjhBJ8+MBgA/+461+Z3VR++AQCwkwhbCw0vCDp
         9ch0YwIxpTi/bmERtKCrRXwJjsuOXglCx+sh6/V4iBIUJm5Vlzs3Y3hgA9gSEjn13So7
         /WoSXSe2dldcr773Zs+gVz0p5SpFiU+28GXLxLBL1J0Mi0wYxma8sobeMoLeL0wGrz9J
         XPWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=OXFQiSuv;
       spf=neutral (google.com: 2a00:1450:4864:20::242 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XulU/s1jjCwM6MfmomqI8lkvSWuJhlfPBuT2XheHi2I=;
        b=pLpT0gUfjLQ8rtHeMvMK/Ght0a7AkQVTv83GWe6XdYdNeXGu1k0maEjxegRKgSUo4D
         Z5gZjAZqS/sroOhUQaR48R1pgIpN9qsaM/oe9/YxIcJIe2bHxQ/wnIf6JCSD8eOWv+iO
         ODnvfzrLkSHtCWMmKXU1G+syrPvKIxBKcYdzEeFgkMvfb3TaRpuaQxSrZ12+WDBvb0/Z
         w2UyBevQUfZvLAia0kUT/rvJtdoZ6Gtv+3aKFk5ITmVjSAs63lEpr1u3fvzS4V7BrHif
         ngek6kBLn7Y+VeUmr2v0aT5fdNhXix+2D8UqTwLLpK/2VKARphBl8NrYIguLcaVxE0zi
         Xy1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XulU/s1jjCwM6MfmomqI8lkvSWuJhlfPBuT2XheHi2I=;
        b=pQlTbISfiGxO/KZTX0QZ4C2Y5jwA3Jt58Ln00o0vHFtHtpUm0R0/+QJK3sPgk5m6Ym
         WHKRMXEonhzbmVMU+mzFE3FuVkBuns8RLCmT2890DDtGDln2ZvOSem/sz5SSFGCfKoAC
         WR4hsKd27Ugd5qfYFJqJkKplX4VvSUT9IIxzF5Beht7lS5RW88Vq5JwfwkMesRWJlinU
         3Q/Ke/MqwZbfsWWKxqhyLg4iOTSSW8oLC9UXj8IWj/asOzDCyGDkbaFksbEPGBxCybpR
         gkOC4VsJCejim8/+oRqx6mCMsASUqfSFUwa7chC+FXOded/0WRZSrRDJd9cMIC25ZSFU
         nm9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXds4KeC8/hqFCuZm1eCmdUfZE2EM6rTzKU/hnEO00EkX1gpXfs
	34U43Z/tgWBQlDYhk3FNVQw=
X-Google-Smtp-Source: APXvYqzPnNB/3LhQfVu8ml0C3nyzGvi8//6bs3BqHfXaquF3lOs42AzWYEOTK9XuCJpfcD0cjVdkyw==
X-Received: by 2002:adf:df0e:: with SMTP id y14mr15530671wrl.377.1577951227652;
        Wed, 01 Jan 2020 23:47:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6303:: with SMTP id i3ls9972930wru.13.gmail; Wed, 01 Jan
 2020 23:47:07 -0800 (PST)
X-Received: by 2002:a5d:5491:: with SMTP id h17mr83672406wrv.374.1577951227115;
        Wed, 01 Jan 2020 23:47:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577951227; cv=none;
        d=google.com; s=arc-20160816;
        b=uozLV+QwoKO07d4nrI+7z0pvM1i1B2fQzPRO+Q5lIR+pz6GLtFcBUNieH6vP/yc/PH
         g7U9W62iElqA+JQ1aBMaeOalhvawrfrqPKCv04Ub57nHSZVkNN1oS0UySpxRlb3oqus7
         19hnS2rLoKOcvCJfoOPcyCaVb1AcLYrnBbXbSHG1u2juVhzoCS9Qb6+5hVgPFco3sI0m
         fYVIFCOQEzmPl23aHJe4NUjiN2uzSYqdcubCjAfwcnJg3ubPsIVsZKnn0CvL9/vY/gCW
         8wSZLs9u9LVhL/bIKOonG3vQnsTpwMicFF29GllZTyn0h1oTbS+siMIqM2E8LiZ6w2JF
         0amg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UMsZF9sy1sW5J3kVgI/fUJy6gl0uFtVuKYIkDGAzFWk=;
        b=xQrCM8XE9LcztW1zanUpOmXCBsaom1TEqmNUNui0qoAliYy7BznIYh/JN8EeaMvyqM
         DBBBJ4xqW8vJGZvdYrDOaCj8dn21tIi0CM7VVbauDFgT/Uh5a2gS78qSKjl0UJ+4mUx5
         c1YpEers3EibfoAEatArHrX57kE53Rl42Q5I6jRdgSplmzPhy07jNqTCR6jgxYRWeN3f
         L2IDTkLRRr5eJreiRqhuaV4JpQBBfubv0vtYg4O2Zgq5ygb1aE9voI0oMDRCRBOj4G9/
         SexxjeD2EMCQRBOUtdz5Avvi1+u1vIvtCwwngcuACVSIMzTIXfIlGifcuaivAbfRgT+c
         T2+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=OXFQiSuv;
       spf=neutral (google.com: 2a00:1450:4864:20::242 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id t131si236950wmb.1.2020.01.01.23.47.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jan 2020 23:47:07 -0800 (PST)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::242 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id j26so39839609ljc.12
        for <kasan-dev@googlegroups.com>; Wed, 01 Jan 2020 23:47:06 -0800 (PST)
X-Received: by 2002:a2e:8651:: with SMTP id i17mr38826910ljj.121.1577951226498;
        Wed, 01 Jan 2020 23:47:06 -0800 (PST)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id u16sm22081579ljo.22.2020.01.01.23.47.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jan 2020 23:47:05 -0800 (PST)
Received: by box.localdomain (Postfix, from userid 1000)
	id D26CE100528; Thu,  2 Jan 2020 10:47:05 +0300 (+03)
Date: Thu, 2 Jan 2020 10:47:05 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v7 1/4] x86/insn-eval: Add support for 64-bit kernel mode
Message-ID: <20200102074705.n6cnvxrcojhlxqr5@box.shutemov.name>
References: <20191218231150.12139-1-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191218231150.12139-1-jannh@google.com>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=OXFQiSuv;       spf=neutral (google.com: 2a00:1450:4864:20::242 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Thu, Dec 19, 2019 at 12:11:47AM +0100, Jann Horn wrote:
> To support evaluating 64-bit kernel mode instructions:
> 
> Replace existing checks for user_64bit_mode() with a new helper that
> checks whether code is being executed in either 64-bit kernel mode or
> 64-bit user mode.
> 
> Select the GS base depending on whether the instruction is being
> evaluated in kernel mode.
> 
> Signed-off-by: Jann Horn <jannh@google.com>

In most cases you have struct insn around (or can easily pass it down to
the place). Why not use insn->x86_64?

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200102074705.n6cnvxrcojhlxqr5%40box.shutemov.name.
