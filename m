Return-Path: <kasan-dev+bncBCN7B3VUS4CRBKUYTKHQMGQELAQCMTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 44C37492304
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 10:45:15 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id r2-20020a0562140c4200b00418e57a7b35sf17885952qvj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 01:45:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642499114; cv=pass;
        d=google.com; s=arc-20160816;
        b=bYAguE1amCO04yJDt+wFgwF24brVayBlj3YTm9Zx6LBCAO+8xcRdIHc6HrRz9FoWCE
         iIiT4BGJBNf4X2TgeTB1iqvs6b2e6zwIYtSjocZOeASQjfls7f3dh0/l9alPhYUmm38R
         uIqCPV5WSrL7rU31tJwTfTak2298WxMzU25V9jaisl1Er4sioBsTDLOwqnxKwk2u0yvU
         VFKTGuuM5anRi8r7w3XSaasnZackKgSalh4lyxHtwsBVP1FK/smmbM26HtOEjrGrlor1
         i9Ogg+sZB2VMKrqho+snS6bpZJG9Q6zw5/e/lGBH9HT64wtDoVYo7/g9rNGGs1riaoHi
         zIog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3DXe2JDyNf2SFlMVkW/FFV/NzD+w49PzTO0+mDvs1Bk=;
        b=OYuG3qyoDwS4X4kpvqFHcrXnnnQmB75jgCwV0kMyt9c2dXlfw/SjONHTRcmiFyUisn
         P7ZgX/4y4fgyxXIephufwvxrvsGG+q+mLMYJYzW2qK1Zg+rew9MCPnVZvt3DRp4SUdCz
         FHdLEQxxBVdVSlnH6o7NWHT4ZiMLNPiTiUZup7SF8lZa+bopiUN6cbYLJtnl4mZcvBLY
         SYRg7iDG7Lqxhw0/qFxqiuySapj8UHCiDTyB16aEk5pHVM2ldj6Bf61oo63G/BKubRgN
         9bVq04csuBNeEAUeobnYDnCY066ND6jJVr65F1E27yKqWdl+QUD9x5R5/ithnqL4eZJr
         McDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3DXe2JDyNf2SFlMVkW/FFV/NzD+w49PzTO0+mDvs1Bk=;
        b=LKSxgwRb9S7ba/za6WlFWNfdu1IEwU0870MB8VEfIJmztyPoyaJ7Y3ZT0h9MGuJ02Q
         sDJjpIolhiVougBTwdDt6GLx25TAZPW1qo9fJdJdOrrUBBn4idb0vJ9zrjJjxJunXe3p
         9HoSIZ5wODMVQ5P//ymTqUqC9dqeQbYILxv+6obDIVMOWuOB5AuDf09FuJ6RX8rdCnEQ
         Rv0Xp0QiT1nN28OvBCq/x8txbQ9YP+NaZBth/xzppZGzl+Im/PMIn35u19qbRaZy3C8f
         2b4ABf+OD78O+OFTuLA6zHIhZm0hOdrab7v+ttlJbjXo/cAAuSggRsbr8pf7OyrbN8IP
         nX2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3DXe2JDyNf2SFlMVkW/FFV/NzD+w49PzTO0+mDvs1Bk=;
        b=3YY1TbuJ1Fhb9s2SON5r5wnNTTbZ6deSZrh8VkwkXBTfb+C5C/LIMT59Gm0UOLSSmi
         xoIyHa0fyFLTnN4KcPOCso8yVcDrr5WQfLm9TsjHKiIyVIIx+Oc7mM/X7xmAy4cuSWYZ
         D+g2RP/QpYqGHCq6AxYJqSDtkW+4781fhgDCIZJmbMDwLV2GbYdSligtLIpUFYaqSQQX
         nbUZ9wFiHyk+lCfTBGYPcnl65bb8hOd916uU8G/wpRjfNqk1j3vbSHWW8wqLeruUQcV2
         dL/rwQ9AC83kuKXLKEUu2fzskRXXBa6CeRuWBS5xjDlOrI4KQX6tBFTVgfJxynPg/4kN
         k+XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hjxJ+UnYZ2hJkDTWhXEKLkfIkDhuu5EBfVonKXiJKWsqUjs4o
	9947odpdtIureWBrI3LIcsM=
X-Google-Smtp-Source: ABdhPJyTt59KULloY3CkpXxxYyjc+TnDdDkzcILr6EinEPiG0HD4S6vqws1TiZ+jzr7g1sFKrkhVsQ==
X-Received: by 2002:a05:6214:3003:: with SMTP id ke3mr18617169qvb.54.1642499114106;
        Tue, 18 Jan 2022 01:45:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aed:: with SMTP id c13ls7281569qvh.6.gmail; Tue, 18 Jan
 2022 01:45:13 -0800 (PST)
X-Received: by 2002:ad4:5aad:: with SMTP id u13mr21721605qvg.123.1642499113707;
        Tue, 18 Jan 2022 01:45:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642499113; cv=none;
        d=google.com; s=arc-20160816;
        b=WChZmt47Cg/KVb8beeqdJTYnG0UIhyLMY0APvgq6nJIAbBP48xn0YHGxT4AducGy9y
         BIO46M+Q5pX/OK6QAxn+xwFV6aYvGqspC9RhKt2gcpHVkgTKOb+a5AVFFZWMW8MIsvku
         jSNQt60j7L3+bQPJj+bG4+DzlkyQCHdv7LFht/TR7II9AV148bVMP4+acjZPWtG+TjV/
         0s72NLIF+YsiK9jrxQeNEh0L9u+KOzZwxdG+kSFlsv9TE5XwbUhu+L06MhB+XVFNqw8u
         SgyMYBbLPuFpPQbJ7XBo+kbbQKokgGV6AVDlg7ntibBVnU3dU3Pw7JLx5j948oYTcMOd
         aqow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=GJG6tni3mfiPA2jUjcABvLdD5XT7MKYGvyjuvJTyDXo=;
        b=VoQ7jOhVZclIfhG2CrhhuDWj+5OB5sSHihRWfFwQoXCAqAU6i+Qxidbj1QWBWHroYU
         GxdqkLbOm1iE8RoEMjCdZ682MWAd38nBCG05E2LJjQhdxLm3trm7ihlZOqYJ8bzGSKB1
         6j/hYHpP6Y7RmZklB6ID3KJLHxNvwLpps85nSZex2QtLU1uM0SPwg+GOMPDBlKSrdEio
         J6gwpn0mRO8se1RyHaG2UBhOUNnNB1YqA7EPwEs49q9heiC8zDFqzxhWEmNdL+N9hJQv
         2VuU3gXncXbomzuZQUn6+g62WyoOt9AdJXEElCQ74xYdG2HMuQ881zi7+hWys2BYd5Sj
         50KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id f23si2862136qkg.1.2022.01.18.01.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jan 2022 01:45:13 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 173ced852dfb4436b434d8522dc5dc95-20220118
X-UUID: 173ced852dfb4436b434d8522dc5dc95-20220118
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2103710147; Tue, 18 Jan 2022 17:45:09 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Tue, 18 Jan 2022 17:45:08 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Tue, 18 Jan
 2022 17:45:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 18 Jan 2022 17:45:07 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>
CC: Russell King <linux@armlinux.org.uk>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
	Linus Walleij <linus.walleij@linaro.org>, <rmk+kernel@armlinux.org.uk>,
	"Geert Uytterhoeven" <geert+renesas@glider.be>, Ard Biesheuvel
	<ardb@kernel.org>, Mark Rutland <mark.rutland@arm.com>, Anshuman Khandual
	<anshuman.khandual@arm.com>, Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
	<yj.chiang@mediatek.com>, Lecopzer Chen <lecopzer@gmail.com>
Subject: [PATCH 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Tue, 18 Jan 2022 17:44:48 +0800
Message-ID: <20220118094450.7730-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

From: Lecopzer Chen <lecopzer@gmail.com>

Since the framework of KASAN_VMALLOC is well-developed,
It's easy to support for ARM that simply not to map shadow of VMALLOC
area on kasan_init.

This can fix ARM_MODULE_PLTS with KASAN and provide first step
to support CONFIG_VMAP_STACK in ARM.
    

Patch base on v5.16

Test on
1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.


Lecopzer Chen (2):
  arm: kasan: support CONFIG_KASAN_VMALLOC
  arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC

 arch/arm/Kconfig         | 2 ++
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 7 insertions(+), 1 deletion(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220118094450.7730-1-lecopzer.chen%40mediatek.com.
