Return-Path: <kasan-dev+bncBDE6RCFOWIARBEEKVKIQMGQEH24ADPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B13EF4D550C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 00:09:05 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id g11-20020a056602072b00b00645cc0735d7sf5036601iox.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 15:09:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646953744; cv=pass;
        d=google.com; s=arc-20160816;
        b=d8IpwoMBr/8jJYvnurLbunYC83ujdfdYcKzH6gRwRpPLlozyjiE7GJxDmcYW2nwYFX
         UxviA2yAZGWho276cbkh0uzo1TPDMIwVWN+vfCCuM0JKsV3JGqqfnpu4IRcAGpvehB59
         rKzyIVaHu45RkkMdxYomdBW/0zX9yWU8CyuVftmxVJaRoJUhUZtyKXAypceJCYUG12uP
         gHd3586r/jF0rQOem8BeFiXpeuqJbCh0zTN3Pi9LsKBAjKkREV84EF8NiK+2FA+jATrH
         752WbloAyBx5aaUAB9pBIr0HLs0SZ4JpNPwe62HtruYVvpd3gTOA2X1md3zwhsm35EJm
         bDBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=LFK4fa5GhavpKJpzGBu4l9PE90a2Eb61FK3nRTxMCvw=;
        b=PhQGAtT8d6NruJ09lVoiOhYagwVcLtOkB89HAIEAg/latGRhebsXzip6L7zqaKJ1rT
         m1MmIA1jDaLOd3VeakGU3W/pI6Yvx3O5bHF0uPMXOSRR++Nr6x4//otNm8jbhVTcrs9o
         d4X+mxjNlBXRKcfrCBLOqIEKE6WidJqBEua9B+VP2lqCmTE4UuVWJrWGwwX2ydKZ/9pB
         zzbvegxIqGATWMBodg0LbWt+JpFJVT0D3TsDVJFKp+vBrfiZHExZnBzUehPVvJy2CfcT
         hj1Ns1hgxAT5C6ZaTSNKGIDfyuJXzcZF3aHLcoIToocflxA+WoCoE3hzTqyJ3bLSVVrc
         KBqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=gEB1gLA0;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LFK4fa5GhavpKJpzGBu4l9PE90a2Eb61FK3nRTxMCvw=;
        b=aDGXybAHAf20NPTCUZi4N2gbS4IntluL0PuZmKImLXgw3wARMjyGWz7uztEON5J/2q
         Yzr6mRJECrtZwHEXVnQbZe/FmS0qTgIN7c/TlPiL/3xNlrKKwL/RUbcZ1Idbjq/pDNZ+
         xUjzayCZMmpLSy09ofrY5ZS8PKOVLzVUB/XaSil6o+1lHY/8LZ2v9cqQ54U/w5KQthzS
         TWWNIF1qR1wNvewDu3xVBus1z0W32ALbcw7YL6sIRQgLMaC6uKgLiOWhh50LhLV4sa7Z
         dWnHvb8mpadG37nFt5HDeGFnX7iK7ipCcVLGy02TmrNNXQkAHNSmhLuPfL5ZF0Z3Xbnu
         4/Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LFK4fa5GhavpKJpzGBu4l9PE90a2Eb61FK3nRTxMCvw=;
        b=iON/3lNgNbye/H79VlNxvpIrnQ5K8YNrhVFBRtjxbWvn2Oxt0y7X/mXpXE9DYjHDJL
         dQP7omkCswt2qveP1lfZ6wxvqupBvSPhk1dYp/HrbrrOHOYzxf0j+e8R0r/e5AKo2/7l
         2oEwd7syhYmpKUEK47xuLPATsAqKQdzZ1frcbx5eyMHEOlkICcvVfpCv4piuMRINZybT
         13Pkr0wVq0iOuh8SrrMVh7hM1pRV+3d0aeoJIA/4Flnp2o5vLnhic1vJTcZrrlOgmCbH
         /GN1XWw8zs3PgOY2PaUPbYN7CIF3o9VX2dWws5G9/2+nxLf0+RxS92BDWEX1RfSODTmC
         5IQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321ZyoTEwOUZZBEgnaf7bb1bg/rglqoBsa8pvUtsh9yjxYVW8IW
	cVQR1smQI8to7ciNr2rIQ3Y=
X-Google-Smtp-Source: ABdhPJy3hNyc5Hh0S4095W2Vxp7ebQwHPaJ8HYlmZ7KYaeVlzW0Xk6QynxSX3mIg7vcwDPRd5trA7Q==
X-Received: by 2002:a05:6638:d8f:b0:319:ac03:7386 with SMTP id l15-20020a0566380d8f00b00319ac037386mr6230430jaj.296.1646953744525;
        Thu, 10 Mar 2022 15:09:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3010:b0:319:c97e:f47d with SMTP id
 r16-20020a056638301000b00319c97ef47dls240614jak.1.gmail; Thu, 10 Mar 2022
 15:09:04 -0800 (PST)
X-Received: by 2002:a05:6638:dca:b0:317:c2e0:180f with SMTP id m10-20020a0566380dca00b00317c2e0180fmr5951770jaj.161.1646953744136;
        Thu, 10 Mar 2022 15:09:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646953744; cv=none;
        d=google.com; s=arc-20160816;
        b=jjKnHAWPiM90fUbWd6wKp2VfYQMcH41O+XSLhfLuiWCBypHq+aPWgiYnkT1Sxz6tLm
         Vox/A6VeZF0JrWVig12vphOl3m4AnQoBGWTvoKEfrrV0ktLULx4tpaWZjpufF5IlWS6q
         RClWEU99kFzc+pHcu0vNnVfeb+itZK7ok/PZh72aBfSWjdworzxk1o0FflzJHrAxy2Yw
         8394e5aD+r1bgRvYV1X7n+s7x+HiDYRLbYqAKDm1i0TtRYKRAjlGm6DKIsj+0LJBDfe6
         e5Ot5Q+ZIRFyDhssoyObgK1dev8LnZfNMpyTKogbNVOoqurG2tfJs6ECNtTrycdUCEgC
         6e/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A3ve4hF4svjPt8CakjTgSzf8dJz57xeyB2FGYpaeJb0=;
        b=Hx9IdPO/fQd+jNwgE16o8OYyGAYp6JOK0akmQJuy3o5icUeC4STFnH9WkhBbEfIqzg
         SQRSjK351PZNzboSssRSWvBSU4vPtwj/j73gGgJXCFvHlM+6YH2OaGDNecpD5BBV0uhh
         dvF3rRfGQxKg7nZtNiAm5vDZgcZyVU9oJ81q5OWLHHI/JOm4kCU2LFFHxGo76lnxV2up
         4iR0uHlPFhF5/iLIZho5qeIE//TT27Fca1+2Y6S8wIdJXhunY2dAXgBEhNSEPla5Zrux
         wL0QB1toEoGpjnnquv7Ywf7KpBz6F4fV+b0341ps82NJj57GvzfVme9082HuyZ5KZgE8
         P6gA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=gEB1gLA0;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id u25-20020a5d8199000000b0064066eda410si697429ion.2.2022.03.10.15.09.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Mar 2022 15:09:04 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-2db569555d6so75571967b3.12
        for <kasan-dev@googlegroups.com>; Thu, 10 Mar 2022 15:09:04 -0800 (PST)
X-Received: by 2002:a0d:db15:0:b0:2dc:b6e4:cd2f with SMTP id
 d21-20020a0ddb15000000b002dcb6e4cd2fmr6420087ywe.118.1646953743812; Thu, 10
 Mar 2022 15:09:03 -0800 (PST)
MIME-Version: 1.0
References: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
In-Reply-To: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 11 Mar 2022 00:08:52 +0100
Message-ID: <CACRpkdasAGFDth-=eKgUFo+4c-638uo2RMbaUap6ent5mmBXbw@mail.gmail.com>
Subject: Re: [PATCH v3 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer.chen@mediatek.com>, Arnd Bergmann <arnd@arndb.de>
Cc: linux-kernel@vger.kernel.org, andreyknvl@gmail.com, 
	anshuman.khandual@arm.com, ardb@kernel.org, dvyukov@google.com, 
	geert+renesas@glider.be, glider@google.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux@armlinux.org.uk, 
	lukas.bulwahn@gmail.com, mark.rutland@arm.com, masahiroy@kernel.org, 
	matthias.bgg@gmail.com, rmk+kernel@armlinux.org.uk, ryabinin.a.a@gmail.com, 
	yj.chiang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=gEB1gLA0;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Sun, Feb 27, 2022 at 2:48 PM Lecopzer Chen
<lecopzer.chen@mediatek.com> wrote:

> Since the framework of KASAN_VMALLOC is well-developed,
> It's easy to support for ARM that simply not to map shadow of VMALLOC
> area on kasan_init.
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
>
> Test on
> 1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
> 2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
> 3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.
>
> v3:
>     rebase on 5.17-rc5.
>     Add simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
>     Tweak commit message.

Ater testing this with my kernel-in-vmalloc patches and some hacks, I got
the kernel booting in the VMALLOC area with KASan enabled!
See:
https://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git/log/?h=kernel-in-vmalloc-v5.17-rc1

That's a pretty serious stress test. So:
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
for the series.

I suppose you could put this into Russell's patch tracker, it's gonna be
for kernel v5.19 by now but why stress. It seems I can fix up
kernel-in-vmalloc on top and submit that for v5.19 as well.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdasAGFDth-%3DeKgUFo%2B4c-638uo2RMbaUap6ent5mmBXbw%40mail.gmail.com.
