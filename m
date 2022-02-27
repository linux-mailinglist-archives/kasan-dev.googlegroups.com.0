Return-Path: <kasan-dev+bncBCN7B3VUS4CRBGUC52IAMGQEL4YYANY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 090284C5B62
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 14:48:14 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id 199-20020a3703d0000000b005f17c5b0356sf9236847qkd.16
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 05:48:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645969691; cv=pass;
        d=google.com; s=arc-20160816;
        b=GXcpSSCKoX2xEJQc83II8BbVl5OBkBTvdMccqzqCcJq0Qvjzh/T9uDwRxDUZ5a+FMj
         o8HpXmR8UhNC973cJ0GTXGLr1pKAHa6fwwmTLjIMKI/10BHzBCuFfGW91NZOQdQG5eWW
         QUOYN5TFezY31Sdg9UCbXTaoEWUgV/w1O5BEu9QNLrXRgUaGq+FzTk8bhOF7kVDYoP+7
         9zSsNwuR3M4XuzsClcT/nVKH8NX/Fx++/cKOoYiYRcCmr4T0pZYQ1skJDYimeq3D8j6f
         8GZfJAZNpFPfQQwd5tn7F1rswkURewTY5C4tRmXQOpT0u7hGvT/7EKAkF4CJfWddWS/S
         wBfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=P8KRjOZqjytJxVkwLYM1GkJURnQV1asCGfk9WSSIYek=;
        b=UoY65I2rg49DPt0dMc584GLn46Eb0e4KbuEahmqnMYgfXP0ZYK9nns7pmbLe6NHhUu
         9jGGfq/TgexdOChh641um993Oa/+RJze/u0yn9HvrzZJH+tJ8i67YcgNU1j6pTC0VDzj
         jDaE7HyJtvqPirb4Rk8zIueVUMI+N/kkRJ7KSiiUdTl5XpXroZkkOkdFt4fW/E+j80OB
         svDjkjNKWLipwSquNfD2lMtqGwfDwY2V4oB6/wmD0tuDZF1W88ji+kQIeyAs4TJJHKC+
         OvMdS2zZW476i9xxx/A0nrymIPgQukP63kS9nGsXXyscHpjTHeWJImLXWQF5dscvCIff
         tKFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=P8KRjOZqjytJxVkwLYM1GkJURnQV1asCGfk9WSSIYek=;
        b=JMmYFsbbOVEs0A1PKdG9GN3LukwR4svNG4VCpP1FrGfx2euI8rt9DEtm23BKPc6aG8
         E+7mOqPcp/t8lyblXsxIRGhS9v/CwKnbsD9cpbtfepDtPnZ/dTfaJaIbfxgDDZzwz31E
         NBTHOUW61wrM9MyQW+/QkmotSy9euNE7R2Iix3e3KblI32xnf4e8SsBS//5f7vFYb8Ne
         D/G/9sdjj4XuZMIugdMKzK1Hsr0SF6mpHxyoWapS9HPT6oxw8lWC3+YL7tss97eWTOS1
         fFnfzoxcXrVdNYM6f3EGHYttUeTs16RBHq3MW6Qpgz25yhqZy1u1FBqsA7fQVMGlPiwE
         I2ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=P8KRjOZqjytJxVkwLYM1GkJURnQV1asCGfk9WSSIYek=;
        b=We2S1r50hMpEsjZY8wE265/3cfnVO5GlLkB2vo4OVvorv+4RFpaTxgsyp4DpufAiF7
         j25OnAakjKYzuEeUTOvt1U2c8y/O5RFUmRhpMiptVMzcSVHJ4WIEwKO+hgjxTbqfABJd
         H9sS3cRuLpcLAtNNOpOzHjRThY/sGk6jtZGcklMV2vuREB0uSudDkZuiDPPECXhS9dAu
         FAWf7mTo8t5Quolf3hq8VuttacXscG0V+p5hcqvhTTCyQWEENYObOOfdDAhUIWQWOeoy
         PWevWrinUmbG5r577ptLOed50EyOwRWacx7CV0SQun3blspc1nFn54UcpkurGOTsbRRw
         ooIw==
X-Gm-Message-State: AOAM532dBhz1mAsA0ZPH4iQXUKwEPNvLH9YIOwsYnpJBDHIdy0hh/cQ1
	H8vgHHPQvhAT7uWvc/1WcJI=
X-Google-Smtp-Source: ABdhPJxnYkGNBv/mMbGgvygys0RoHIRz+/9efftRHVciAdvY+JJwkCd1WrmabBB6uCexp5knKBMnDw==
X-Received: by 2002:a05:622a:87:b0:2df:f424:a6ab with SMTP id o7-20020a05622a008700b002dff424a6abmr5784270qtw.81.1645969690726;
        Sun, 27 Feb 2022 05:48:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9107:0:b0:47d:b38f:ba1b with SMTP id t7-20020a379107000000b0047db38fba1bls5967002qkd.7.gmail;
 Sun, 27 Feb 2022 05:48:10 -0800 (PST)
X-Received: by 2002:a37:b982:0:b0:662:69d4:f05e with SMTP id j124-20020a37b982000000b0066269d4f05emr5829128qkf.11.1645969690210;
        Sun, 27 Feb 2022 05:48:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645969690; cv=none;
        d=google.com; s=arc-20160816;
        b=me5qz5/Z9ahzGsqpPIb2A1+hvJyVrJ83Q3urHpVkjwGI4fOnY4lKT3cvxPuG1mrfUj
         NVXbiurblP1pNBmBoFvoCiii62hykRSDWh97hT1AcXUNn7PgaitezxPy2OWjR4oqXQyt
         4wzMr7mGJDgiEpsXlLbVvCoG6sO3hBOBe/lPAZDBgsCV2CWMPggqfoGGb0+GRIOEindO
         Xjy6J1J0MaK7sQV9N0+MjF9kaMF192/NKdK8p4tcapGWKPVEbvIETxdhTKFYWUTrgFCh
         f5BZN/BFBlSqXJPcMroCmoBb/zcB4GBbc3gO8Qj5iqkhk3y9n1ESzPZ9VmnSUkFMicJq
         XZhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=xWT204ZhpNV/+oPI0hRnuUCyOqKA3Ec9UtXyRUX+ixk=;
        b=DR2+QMDo02y/E7f0P9If4BqPYGC9pKdJFoKvb+8emwIJvJUk674EZ14vIW/9PH5ePM
         q+Ix2z7kiRyRoy2iVhhG3qz/o819TgIAuq7htLodgzrZKFzcdvLclW32X2yEeGBE3SYa
         TsBl5B7bl6f0+CpMuBK0+b4hyXKPkzDPmyNHaOF36zorV0Ec6PdQr57cJsrcmV5Jw4E5
         YvRk2N21Btn8mRam5Tg3VvyxjKfiaNmDQgNhC+bjC4XoNZGRPIESOKM+EFIXcTwmK9B1
         f4fMz+B4lYiOXqIwC2egZ0c3p0N2kB3O7lGhAaztDfrqZKosEtcijsFmZRD/vmlyg5zO
         p0Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id x17-20020a05620a099100b0060dead337e7si535195qkx.3.2022.02.27.05.48.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Feb 2022 05:48:09 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 1b39c2a6e4e84b62879c77927a8e5592-20220227
X-UUID: 1b39c2a6e4e84b62879c77927a8e5592-20220227
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 344440268; Sun, 27 Feb 2022 21:48:01 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Sun, 27 Feb 2022 21:48:00 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 27 Feb 2022 21:48:00 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>, <linux-kernel@vger.kernel.org>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux@armlinux.org.uk>, <lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>,
	<masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v3 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Sun, 27 Feb 2022 21:47:24 +0800
Message-ID: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
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

Since the framework of KASAN_VMALLOC is well-developed,
It's easy to support for ARM that simply not to map shadow of VMALLOC
area on kasan_init.

Since the virtual address of vmalloc for Arm is also between
MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
address has already included between KASAN_SHADOW_START and
KASAN_SHADOW_END.
Thus we need to change nothing for memory map of Arm.

This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
and provide the first step to support CONFIG_VMAP_STACK with Arm.
    

Test on
1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.

v3:
    rebase on 5.17-rc5.
    Add simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
    Tweak commit message.

v2:
    rebase on 5.17-rc3


Lecopzer Chen (2):
  arm: kasan: support CONFIG_KASAN_VMALLOC
  arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC

 arch/arm/Kconfig                 |  2 ++
 arch/arm/include/asm/kasan_def.h | 11 ++++++++++-
 arch/arm/mm/kasan_init.c         |  6 +++++-
 3 files changed, 17 insertions(+), 2 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220227134726.27584-1-lecopzer.chen%40mediatek.com.
