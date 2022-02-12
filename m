Return-Path: <kasan-dev+bncBCN7B3VUS4CRBLWMTWIAMGQEIYAFBPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C82504B33A2
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Feb 2022 08:47:59 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id y124-20020a6bc882000000b0060fbfe14d03sf7973691iof.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 23:47:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644652078; cv=pass;
        d=google.com; s=arc-20160816;
        b=LwpEcd2SyFvSkCVoy9BGQQnsXRrWeUQg0KNqgHjz+VRc0aZhzCHm9GtFqqw+6ElXGx
         eGKDSiFWU2mLOnPBOKA58hCIm50tvhE+VhBmXt1x+jOb7vW9RbykD1V6vF4fMNrJO1LA
         GHlMdU/Ii7W9BMqFOT4z6yDK0AsLRsPsVVflyZH+A+Gu3LKmHjwcqD7nwGznhndGsonM
         aF7UxObnV1NuUu4Gf1KJACnV71Zp61Wfqim3h2MDx+H5ZmQfLfvt5UNWwFIDCiUJ4Hmh
         u9c9rONk66mmdw5SgmseZzdMlOISAAq5a/jmU3QbaBShOp4Bl+tU8nxtttxfLtW4KBob
         XUsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=8hNRA5HefRN0Wy0xmu4bHxWFv2gGRSiWKIUfgthf4uE=;
        b=C1VuykFDeirJUzGaH43hpI3EcxRHg5KgrAU8oVMz75FzLSqCHaQY4W/ICpukA96dYt
         4WVUDcdsrI47SeMTzPdR7L3hPGkqAzSn5gvyTYaxyxoqYZk1GOZ0sjmE+aHCDsdxXoaz
         zxyIS7skHQqA0jl4ibfcPo0YUFvf6awEacRL4NA2d/lctlhyMEyr43Vf4HpP77sYepZ+
         0aFzVeSz6cogWbi6IKKM0aGWZPvO9jRvRL+VVYGAG56O79FFW+4A2fvz2v+GKibxGe2f
         Y1WQKoz1XlU5uioKho3h+cDPYPRlos5hGfWMGni603G596aCAhahjT+PqELEns3zGNqJ
         ykww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8hNRA5HefRN0Wy0xmu4bHxWFv2gGRSiWKIUfgthf4uE=;
        b=ckxofr3rEIyp0XsPtxIz6NYVb3Ak4VoRphU4+gynoFer27DBzPo4CWERy1zDmfdJ9I
         rfMutj7Ryiyqy74AKyyak83yLwZ/GQq91l2dIa0J1DVKTB657EtD/8AhRFZffVudd4u0
         tOhVCLFkNdbSvIF4Y+5EAtm89AbK/w6jr0MD7ZRV7PJ3qhgg+EtXSa2F10f7FruGRQpC
         C/Nt8zetFS0x0BlmqtesvfNNtazJB+y7eHnvtQD4jVClslc7lET8Wa+S1Qz93q7QPhFk
         7Es6gLnb4NsiYbnSlHQhzbAhM9ybsrnbV4zk7/knaxUHE4w9zsz3h4GfzhGTMVkWeXvG
         xaRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8hNRA5HefRN0Wy0xmu4bHxWFv2gGRSiWKIUfgthf4uE=;
        b=twwUaXoyL4+tuTobmnrEGN3n1eOAaef6iAyDBa4NpAC0BfZpc4pTe50AQAnG6RldGh
         2Qh1fniAUfv92MJd81iyEfJ14U+ca2HtiptFeR48zVrxARvNKp0WF9zqFAeAeOgTyDz4
         6LWp/MMbM6+Z26XO8Ek/+nb+uhm2iz0+POFmFeX9VIqZjcitRvqe6g5HTw1XZkgJ58uz
         s9VpxmxRPpy00hTClrarCyBj+kfah6RewtCiAm1hdUO1Ezc5UKrlOy4QEUmqbLaZi/oK
         wzXP0aV2WyOSTa17Xv53Hnz1QrXjHMEw77MTSVAjKcqlU90jdpwldQZzmNumj8VK+YuC
         gjIQ==
X-Gm-Message-State: AOAM530YaEv3f3JPzz4KzRMZ8/4VJXp4qbibxfRt/Tw383AI9izfXHKt
	NLh5Of8Y1UbwrErSp2AVUsQ=
X-Google-Smtp-Source: ABdhPJxgw+fyeuJyoufWCk/cB8v/IEUf1fbXq3ghaNki0zCg+IseY3NDYUwi8O6peQJx6I9+GVsIXA==
X-Received: by 2002:a05:6638:22ce:: with SMTP id j14mr2955698jat.225.1644652078585;
        Fri, 11 Feb 2022 23:47:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1447:: with SMTP id l7ls1997720jad.8.gmail; Fri, 11
 Feb 2022 23:47:58 -0800 (PST)
X-Received: by 2002:a02:93c2:: with SMTP id z60mr2813058jah.211.1644652078123;
        Fri, 11 Feb 2022 23:47:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644652078; cv=none;
        d=google.com; s=arc-20160816;
        b=1EKsaRehB/5vPBaWcivXpgccXEijNCbdON9gxiN7+xdqq/TQeUa0qrwdfv7b8enroo
         QuL5p+2JzzUn3xM/IBGD0VeWDG7A5RDxF8vCx9RdpzNpPaxKryL+g6USlivJHS97o7yA
         czVD5MDGnRQOiUjJGLm6RlkSwkdOecWys3alPxkulzhBAL7sQIa8uWZiSOtt+nBmJ7AB
         rFc1D2OtMnmLaNIJ/s8BZ7hb+++iXJPikxY6HgmqAzlqC2bYrb4/GR0q74OxUbQK8eY4
         E2UO6DZ6H67WiG4WgCGV2JGg9hX8ep5bLjMk3+pjxpTfydskNFDGJbdDulhBdmYJICYR
         2IkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=9AKIjLaKw6pxo7GO69IhHuC3pHcFDLcw+MZC6ypb8Xw=;
        b=KafI9CfVPbQ7AbL9xW6NHkRMrOu3gqWw9MQFEefnTniAHSz6dIsCnc931fmv3STVJt
         tLEi+D5N9QklgzgjulMQTQpi9KLj8tKD/ioctCfwjyu/jeOx+Ng1nl9jDrwMXlLMzgyr
         Qy0cxgMpsZ0hdUgN6xP/w3x6SxGkdGPSEr4bvh4A24jNBiHjJ3FOa9i+e+gNb5/7GObD
         ZSFvyeImoNLQsg/PSfThXq8CihKMOYjhI1KqsOlcaUAJmX9TxZZQiw+e5gdS//UfGn3j
         8lXd+848Im72OeK4bDwsrM0jEcRDi+JUsgzx7kyfeoV2v32tdL/UdME+dE3UB6Uz62u3
         ewiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id q17si970662ilj.3.2022.02.11.23.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Feb 2022 23:47:56 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 32076c34da7549a7a2be3e1cbf29f30d-20220212
X-UUID: 32076c34da7549a7a2be3e1cbf29f30d-20220212
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 319208344; Sat, 12 Feb 2022 15:47:51 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Sat, 12 Feb 2022 15:47:50 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 12 Feb 2022 15:47:50 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linus.walleij@linaro.org>,
	<linux@armlinux.org.uk>, <lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>,
	<masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v2 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Sat, 12 Feb 2022 15:47:45 +0800
Message-ID: <20220212074747.10849-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
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

This can fix ARM_MODULE_PLTS with KASAN and provide first step
to support CONFIG_VMAP_STACK in ARM.
    

Patch base on v5.16

Test on
1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.


v2:
    rebase on 5.17-rc3


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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220212074747.10849-1-lecopzer.chen%40mediatek.com.
