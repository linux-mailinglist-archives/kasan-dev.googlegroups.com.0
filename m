Return-Path: <kasan-dev+bncBCN7B3VUS4CRBJ6ZUSIAMGQEWKL7XKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB2AB4B3C36
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Feb 2022 17:07:04 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id y6-20020a929506000000b002beffccab3bsf2952435ilh.22
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Feb 2022 08:07:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644768423; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nf7a1On8xbGuDSfAPy8fDGRPCanho1IO8N4W1cMiWWyGSzS13g+a42C4dPVAIPuQ9O
         pvvnazbPZe/EYY+Fkir/bwT/uXMeMU4UxNNujMVnTU6hQkF/xzQks8mfxALKN5RkHMAg
         xcsSQnHPth6h+mBPuDwGd+Os8VOndLu9iV+tdgG8Tfp2g2T9/x5LbCf+iOtr1it+icX0
         0RtUugw6Nn42/uaVCyM843XgrobzulljfnXfxtuPJs2TclTnz5V4kRdMg+Ev+UDiG+NA
         0FgboUkrhtnCJe0dXrn93T6VWww/p+wts2GcVIp31l+pqNprzRU+SqTNnPpYf108WTFY
         fRsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DwvLjlYdnojpxoGpAhZwNQPlMRHNEY1WeLeqAVZvIjA=;
        b=nXJwPAe7uouJgN54ef7uNt9XufzAf6BZfpEsfP5AuPE2X1Cu4E71QwY8TE3JBFCWwm
         iOIdUvHUSbzyiW8myGJtFLgBmEoMaAWCetyYwnDpdPBmPYi40kG6+gq6jTty5yU9pP+w
         6vnrwDgtlRal0CEKMsl+8JtN25SJCKp6gvo5/sqsOUIdVHBXipdKa9MhEhmrV3Tm7J+j
         gEKVHEjYAuQ79mMRBdvGkrU5QVe22ty4FXo6DvYhtUcQmMLClXiAN1glDVa8qPO4fPGX
         lbCViZocxqpX1G6xkaBRVlo6l6Ud8GuNMgAsnHMHYQAtf+sHq/+Uvp5K95ZITz0uYB5J
         Wa2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DwvLjlYdnojpxoGpAhZwNQPlMRHNEY1WeLeqAVZvIjA=;
        b=myCIkNHHc525Dcf4W4GoO/n3YAqAxvOP4JFgWub7MjbLiYKr4+YCOtPP+lsjmPHORU
         JGyoGGrCGDNXmBeAmn4VCozdfjCizvkZYXdnwydPp9/6qbs+rIeN/fhdgptiAhQLsMP0
         9nyw4epcBDCrYO+WvCMu1Qfp2ztlRbVb/P7rQDtqUGns5jGHRrgb0CyaudRZBGncxT7M
         avBwklYijSlb7uGcFYWOKssrUqWLKlm1DZStrIiOHP4MeLJUEwmGDz5COu5wQDJZ4dO7
         ZGYCDx6L/qj9AFQC4pTZfqsJvskT6LCnwqgSRrBXHM53JTIaSvNt1QiWEtd/p2A2m4A9
         whRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DwvLjlYdnojpxoGpAhZwNQPlMRHNEY1WeLeqAVZvIjA=;
        b=WQlBe7ACQpGHo5NTvkbW3DXsF4hO86UN2V9ZfdgF6v/J20HTBhQowMX65j11R96kRU
         KNnjRc9PZIeogDv/Zi3KXyX/H6IaivaC1CXr7HvrTkY+3JDRd2EjpegALdYn+AszDiAn
         LqgHEOAAfGcODnw8tlfyokXCQ5yftnH1E5Zun2YCXgY9NX7UqY/x9sObAaCpPgXDwZY0
         BL9fqt0BRoWSrsPHL9NY/e4rj7NelOYrTTIQTMhfNe+SYVG5XlSKag1MAGRDmwdKn1Re
         +VcErqq2+gvte92YELGGL03sVkyZ+W//8+l1o+BfuWIDjSOQBbJR9Dp+7uTfm1JQLLHR
         qfig==
X-Gm-Message-State: AOAM533ddRwh1P4yNOaCjIZGrlpPcYmLenHrwdblU/IdDzfHag0oszS+
	2FySt0Xdb+Oxsv4J7Zj8gQE=
X-Google-Smtp-Source: ABdhPJyOhOGQwcLFCC9O4FqPgln+1gGE9IDPLYgnSgbU2EPHYtFyQ1gfVHUjKFuDmpTNEXYIFQNAQg==
X-Received: by 2002:a05:6638:260b:: with SMTP id m11mr5705231jat.55.1644768423220;
        Sun, 13 Feb 2022 08:07:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1808:: with SMTP id a8ls2303318ilv.11.gmail; Sun,
 13 Feb 2022 08:07:02 -0800 (PST)
X-Received: by 2002:a05:6e02:20ca:: with SMTP id 10mr5470240ilq.225.1644768422763;
        Sun, 13 Feb 2022 08:07:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644768422; cv=none;
        d=google.com; s=arc-20160816;
        b=yLC4ZZGXbJIg7xlPIrouLl/nGU5bIQAKnOqJDV/iyn+1ZJarYijRzir1FQD1ArI9Et
         Zw4z4AMfpS5wl3XzJH6tuJpT3ohhKQ+PX9NBGOz3J8nbNwCLpCrNiV/iXI3vEeAtAlLA
         420lpM3kgat9thXPz0W4Lg3a4E9N1BqtcNu/FOvM9x/960joG9uvY/fggIGD8Xku28/S
         5xg1JYXxbo8c+S0FbjzE/UwGLcFUL5t2/pK5cTqprdkhPKwsVwj1fJHOI5Mlvy0kwoxd
         0TN36Qf2B6XQQtcCc8kDl0yKjBIeIXvsogjgResDwfVeG7pVU4cT1meuWv5o1bntU2Z5
         HSpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=qICD7DWwu4VWEKDc8nUuBGGQ6cKdxNztGfxOOEeoSYE=;
        b=iMW/t0xfZByuJC3HiRyWD9udyoj1rnj/f7fIeZep4Lo+lghGlayCgaRR7JfwLiJOnv
         jxOO/oJ6kbWkjVv8m9tehrRQVxUGETnXClWpEoYO2ZsHO+SJ/sNInq+By//dhF3Nvg1u
         C10xCIef+EHlykA3NZqkD+Eexvi77NRZ6LW24DGYluJwZtv0b8dMbd8LF+f61C/J+DYE
         R+yGnsuyM6yAAtogC5F7xYJJGuRVT+64g7tFspes3fVdRcIJZvfH9B2UHp4IFCQXDnO2
         P92oCUhL679IoHcGVycmzdgH0bQ/6HIy127P62b5baVOSwKlDwg1AewyHLO5WPyR1mDW
         uzPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id h18si4141046iow.2.2022.02.13.08.07.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 13 Feb 2022 08:07:02 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 7c26e1c48cb240c78db72cdf8cb77316-20220214
X-UUID: 7c26e1c48cb240c78db72cdf8cb77316-20220214
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 757746491; Mon, 14 Feb 2022 00:06:57 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Mon, 14 Feb 2022 00:06:56 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Mon, 14 Feb
 2022 00:06:56 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 14 Feb 2022 00:06:56 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux@armlinux.org.uk>,
	<lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>, <masahiroy@kernel.org>,
	<matthias.bgg@gmail.com>, <rmk+kernel@armlinux.org.uk>,
	<ryabinin.a.a@gmail.com>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH v2 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Mon, 14 Feb 2022 00:06:56 +0800
Message-ID: <20220213160656.17605-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CACRpkdYDg3saLpfHg=R1kYpnC_BBNgBbe7un-B4e8bgDYPq1Fg@mail.gmail.com>
References: <CACRpkdYDg3saLpfHg=R1kYpnC_BBNgBbe7un-B4e8bgDYPq1Fg@mail.gmail.com>
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

Hi Linus
 
Thanks for your review.
 
> > -       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> > +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
> > +               kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> > +                                           kasan_mem_to_shadow((void *)VMALLOC_END));
> > +
> > +       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
> >                                     kasan_mem_to_shadow((void *)-1UL) + 1);
> 
> Where is this actually mapped?
> 
> Can you print out where
> kasan_mem_to_shadow((void *)VMALLOC_START)
> kasan_mem_to_shadow((void *)VMALLOC_END)
> as well as KASAN_SHADOW_START and KASAN_SHADOW_END
> points?
> 
> When I looked into this getting the shadow memory between
> KASAN_SHADOW_START and KASAN_SHADOW_END
> seemed like the big problem since this is static, so how is Kasan
> solving this now?

For quick answer:
As I knwon, the definition of KASAN_SHADOW_START and END

(@arch/arm/include/asm/kasan_def.h)
* 1) KASAN_SHADOW_START
 *   This value begins with the MODULE_VADDR's shadow address. It is the
 *   start of kernel virtual space....
 *
 * 2) KASAN_SHADOW_END
 *   This value is the 0x100000000's shadow address: the mapping that would
 *   be after the end of the kernel memory at 0xffffffff....

and the virt address of vmalloc for ARM32 is also between MODULE_VADDR and
0x100000000 (ZONE_HIGHMEM), so nothing needs to do.

If there is any cases may break this assumption, please correct me, thanks.

> 
> Please patch the picture in
> include/asm/kasan_def.h
> and the info in
> Documentation/arm/memory.rst
> so it clearly reflects where VMALLOC is shadowed.

Thanks for suggestion, Yes, we really do need to update doc for memory layout.
I'll study how to add it and provide in v3.




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220213160656.17605-1-lecopzer.chen%40mediatek.com.
