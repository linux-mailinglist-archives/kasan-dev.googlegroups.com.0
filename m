Return-Path: <kasan-dev+bncBCN7B3VUS4CRBZ6TVSIQMGQE3WRLAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 480524D6024
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 11:52:25 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id lt6-20020a17090b354600b001bf5a121802sf5108240pjb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 02:52:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646995944; cv=pass;
        d=google.com; s=arc-20160816;
        b=KNhzJ/fzhaJb+EYdTD/YL/yk9a0yyj98zq1P15DGQmvMHZMPClGTcf6lElTu/Qnj2C
         vR5tJ5lLZsXkdjH3xnDoNtwTbm6xForUCWqTJhsyiGPyH06kIytzk+vSxU4nCTRAsLXn
         FN7eshfQQqLwNoVsQMrZY1NhqhRtwuqoidiFgJ27aHaeodVh+gSim48liNCar5v7FQZ2
         tJlElNb/CpRe+v3j0mF3wQgEwaZsp9fIRvmVEoSldpdgxdrN4jmHkgTo7OcWKUMy2Yfu
         GxM91fCTEEOKyiirM54Wr5wwmq+3aavd8BAHfKxWgUhl2+Wu5Iktg85ygRPEwvcWIYf4
         RAwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=FPYF0XiD+AkXaH6Coh+EEGgPm5dTi46XhXEiNmK9Zlg=;
        b=DTJcSSHTOytx6Ukz4p6HTICbslmxTB+CguvkZWWNCOJfdX8h2v8bBLp8vJQdHWD83A
         HOx1nItAajqCCxkxHxOiln9QcehrwgtYuZwAxcqvHRZtlydMYHOw8cmoApzUhIv+3nNs
         a/k+OBHJo8AM5jYEl4BLUTrsWrOz+HrkyfUdCCRF42rpkGMYTIane3tiaPFVSo18cAZZ
         ziuBKCsdSjyvnU+vyQE0QrtstyyzNDlHOSbd/OIVkG2GjKERhMx3trb6wzNLVZrEmHFD
         Yde0HW7GJFm7pLCxa9lvSgtc7Yh4bJLNp2L8yY4c9TsnrFVTPoWesARqTcqRExSAFI7n
         lp3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FPYF0XiD+AkXaH6Coh+EEGgPm5dTi46XhXEiNmK9Zlg=;
        b=EraIts5qTiV2JUru9XT/SBiFQ4A7fyOde5zn90MtkI7kqaJRZBepFr/mq52YGpoWWd
         J4ON20uAyr5KHiUONSIA/ykmNqyEuiKCK/dcTbOZBWqNZ+n3WKB5otbZGmfGSHJTejiO
         SYqBweI6dcJQrogPQMMcMdW0JwbqY0+Fb7X6vCILxZ5p6kT5+uctPVA5EFNsh3pcFLbs
         MyWWhP8uKBL1PXEHrOaHQYTSrsfN6g5jwqrLx82wsdxUjHOq0v1sUUUWEEUIUsl2tLRm
         q+Mlk5jR6zkGwHssbAEhEBKoFR5cidwen7vqAOg+QsIlzhrykYN3SFjgzR+ggWzj6Cls
         0WXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FPYF0XiD+AkXaH6Coh+EEGgPm5dTi46XhXEiNmK9Zlg=;
        b=yrA3DEn1wlh1n9JfRQ/nHKaWd9VH49bs1y1eRBMr6NB1OaeNUen5y+dNKL7TsX2kVM
         sR06Wq4kwJtVnYewmUKANxxNRdB3aC/0IQkU2j4wpqkbnvFuepIA6QHfFGJUsa/Icw01
         /TOdhS6/+m0JngZQdekxrwbL+iZ6a0KPhet4ZyPu+ADn7zAx3rSbFIGfCMlfuOvYuhzG
         KPu7zGGyQIUm3DxG7Iv7z5EIIuayV6ni0NCWN4wGLGEH9Ybe2b1EBt4xeZZ7//V5LKJx
         eEXd99CFsyMAWvM0kNJe2Fxy12NzzOhfYBkvXCA2gts/otKzYxHEm2qcKnKPOP6CV4ep
         hFrA==
X-Gm-Message-State: AOAM530CcP2wh5amcceB27lxMvm4ssZZPEt7RH/92E2c3LXP6hINOXc5
	uHVKrioiSpFQV9LME8YLF80=
X-Google-Smtp-Source: ABdhPJxBLWaR7x1l6gZD5OenXbiOgJJj3oi+0BJS7iW7CYB0ux0CXjoQFu9CVoVLC5VSppTgNsZztg==
X-Received: by 2002:a17:903:1205:b0:151:8ae9:93ea with SMTP id l5-20020a170903120500b001518ae993eamr9588660plh.37.1646995943918;
        Fri, 11 Mar 2022 02:52:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fd0e:0:b0:380:5398:a9ad with SMTP id d14-20020a63fd0e000000b003805398a9adls477514pgh.7.gmail;
 Fri, 11 Mar 2022 02:52:23 -0800 (PST)
X-Received: by 2002:a63:c61:0:b0:370:592b:3ad1 with SMTP id 33-20020a630c61000000b00370592b3ad1mr7938741pgm.240.1646995943219;
        Fri, 11 Mar 2022 02:52:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646995943; cv=none;
        d=google.com; s=arc-20160816;
        b=aIu/UWy/U7HTmPaXVEWlpI+pTqKfntDL/lsCCkBdb7YKzwkat30zGHRy4wkUs7Lejn
         mzQlPLwA6F6EqX36Ql3zWhXm4MmAdyi09SRn3brNkN5dHDS3iSE+aohbUsTXyc2/DB0p
         R5tuM6eewUaz3uAnUVua9PmC1NYhlpfiJqJsCYWvCWyEmkSOlbsdebRpZCInYXAHFO1H
         1QlAUvqXADAtN4FTdmLAMj5QiUN49Z9JyDqsPi71kMqhjIVSy2bDOBreDsXmkPVJivCL
         CnvR9nxKeQ41jDgObM+4fPukF7HLgBfCymLULcrty0TSmbt0QOftQH1g69qBV2dwvgiR
         je1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=v04e9ym2zXrE7nR8R9CxfdNKPcIar87Egq5qeDOvY0w=;
        b=FQqhVeg9rRxJerey7fvji8hl9HRiQI8096AFO4wW8LoF9Kp2TKrzmRV4fc427CcsRQ
         /wy3Plw6XWRI58JvLleNR0IVmfSadx3Mh8p7NCl9Y/cdjO28AxEpLH9oJec0K+uA46I6
         pPWd9I/T1vjbgHNpfl8Pn8klenqUmEsLAi+GFZ4VA/MHB8ZSDslff8ZBmeBOlbtDXfYJ
         5MKeclqcmOhpfCwlRnHZPF7UWyLmdyVK96tJI4aeFAR9D99jH2GxuQsI1vj9al04QUlJ
         o3XtVWzfSFJmJ0VpyoPpLasJw+agf79AlpOfyIHe3Mey4wRAVtKvXP0KxtLgYaqRHIZq
         lrvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id k12-20020a170902760c00b001515fbf5905si453673pll.1.2022.03.11.02.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Mar 2022 02:52:23 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 133bdabe412341dd9d880869907dd98f-20220311
X-UUID: 133bdabe412341dd9d880869907dd98f-20220311
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1442557884; Fri, 11 Mar 2022 18:52:17 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 11 Mar 2022 18:52:15 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 11 Mar 2022 18:52:15 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux@armlinux.org.uk>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linus.walleij@linaro.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>, <masahiroy@kernel.org>,
	<matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH v3 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Fri, 11 Mar 2022 18:52:15 +0800
Message-ID: <20220311105215.5408-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <YismXDtUZ2cPtVnN@shell.armlinux.org.uk>
References: <YismXDtUZ2cPtVnN@shell.armlinux.org.uk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

> On Fri, Mar 11, 2022 at 12:08:52AM +0100, Linus Walleij wrote:
> > On Sun, Feb 27, 2022 at 2:48 PM Lecopzer Chen
> > <lecopzer.chen@mediatek.com> wrote:
> > 
> > > Since the framework of KASAN_VMALLOC is well-developed,
> > > It's easy to support for ARM that simply not to map shadow of VMALLOC
> > > area on kasan_init.
> > >
> > > Since the virtual address of vmalloc for Arm is also between
> > > MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> > > address has already included between KASAN_SHADOW_START and
> > > KASAN_SHADOW_END.
> > > Thus we need to change nothing for memory map of Arm.
> > >
> > > This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> > > and provide the first step to support CONFIG_VMAP_STACK with Arm.
> > >
> > >
> > > Test on
> > > 1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
> > > 2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
> > > 3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.
> > >
> > > v3:
> > >     rebase on 5.17-rc5.
> > >     Add simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
> > >     Tweak commit message.
> > 
> > Ater testing this with my kernel-in-vmalloc patches and some hacks, I got
> > the kernel booting in the VMALLOC area with KASan enabled!
> > See:
> > https://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git/log/?h=kernel-in-vmalloc-v5.17-rc1
> > 
> > That's a pretty serious stress test. So:
> > Tested-by: Linus Walleij <linus.walleij@linaro.org>
> > Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
> > for the series.
> > 
> > I suppose you could put this into Russell's patch tracker, it's gonna be
> > for kernel v5.19 by now but why stress. It seems I can fix up
> > kernel-in-vmalloc on top and submit that for v5.19 as well.
> 
> Ard's series already adds vmap stack support (which we've been doing
> some last minute panic-debugging on to get it ready for this merge
> window), but the above description makes it sound like this series is
> a pre-requisit for that.
> 
> Is it? Will Ard's work cause further regressions because this series
> isn't merged.
> 
> Please clarify - and urgently, there is not much time left before the
> merge window opens.
> 

Sorry I didn't describe it clearly,

config VMAP_STACK
  default y
  bool "Use a virtually-mapped stack"
  depends on HAVE_ARCH_VMAP_STACK
  depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC

This means KASAN can support with VMAP_STACK=y



BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220311105215.5408-1-lecopzer.chen%40mediatek.com.
