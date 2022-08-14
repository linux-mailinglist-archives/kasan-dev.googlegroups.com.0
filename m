Return-Path: <kasan-dev+bncBC5JXFXXVEGRBC5L4SLQMGQEPQN4IRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C0E195920F2
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 17:32:31 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id q11-20020a170902dacb00b0016efd6984c3sf3488102plx.17
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 08:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660491150; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zvs+OIMlm82sMf4P7vPp8a+thymSLaSnGAbGhuRzCgpPDVYrO6Z8lMmXNWzu7CimiK
         V8BAr7ED/Eex7ayCqCmVWncLw3D9a7YzVZSz7FEsFpfE+7R1uHNiCHkFi8+Oo4IJXp2X
         NXx0ORyxv8Pp2EzkBjU21sv5Jf7daBHcgCsnw0VFNX0973bAV4pbnybNFNog33VNYpnc
         XvMmG8AVHtEMRz/rzEigAzEDc8e3+HEXtXhuj1jjXXfRgL4YUbd/6/9wNLNIsGgB0Uoq
         Opp4hXC/Trnt1iub03SCi8J464DYq7NVRGoqta7yOOPRdEMy9Dl5ZUu5AGomljX7/xQu
         ii8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jdRzt/Ji5e9mhOICf9vS4CFYhtQcVIlzRMU84DEw6/U=;
        b=zYbD/AQbsbz3TmOKMT4s757g5pV/gKolCkGrdrv5LSMNJkFPHa3N869PlXUdNwjnp5
         w6DJAHAY3mneXPUiHIyaVJVmxRKgISOCuZitccH2LBxNCIR8Z4VHL10JI18md/BcP5MI
         BBg1ThQ9+pMaWkClyATWQqIAmJA4kzU3OfUlQsXZrgQ7iuyR2CgW1UORbG7YFrq3X4OD
         eqaH7QsDb6ufCqp4kgjzhyDPUi63dXs0/C16NkBsCTJT4dK43AbJiOOtztRPbnVRksRz
         UvUBBGAZ8NGZnTCtHnBDxQuV0hrq1gSRN9V16LmcUrT1N6nxddAZIC/uWrrEArb6Xqn+
         tXrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PWWhl7jI;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=jdRzt/Ji5e9mhOICf9vS4CFYhtQcVIlzRMU84DEw6/U=;
        b=AceB7dUngdFbAXOvoA6u3QrUCOpp2JYycBk2rZFDhC5wmz7IF+8mE9MBz9utZJ4ilM
         MjbwgZ40tF7DjZhdolCzuDZp1htFRGGjub2jV8xtDTuI6a/RO/ldFBuSwnOWeeZW6CWl
         HxQAqvELLs6PofqkYPb2/v0NnT3J82MAHcYHel9WIa2vfqC8xTs7zr06kwVS7E5fdl25
         m05/fSb7+qMUnaLWViGEAHXUd7PcNnNLm1mWQEZkqVwHeLe6YgifHPKUvfxm9ucQSIa/
         aiXWHWlkrP07M1F9uwGjclRlXylYtGjyan2CKtKZVSpq+KtNJ+kU0KwyBrcqxEsrn/01
         5Y3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=jdRzt/Ji5e9mhOICf9vS4CFYhtQcVIlzRMU84DEw6/U=;
        b=XGX4a52Xm4nCeVpCY+zNjoeTpLaZIYByuAaRIVuhKm/M1clp+/ntkH7Zr3npRdEBVp
         s/Bfr8cuo2WxZuFgR9Rw8EeRLIasivQio2xigmQHQ1S22M/Za+ozQU06xdWVEXBJCRcu
         RB5olqPq5UaYWWTLQ6JoIllaP8tvhMnm6eupdyTbWoSsiZv06zSCHGl1nLIewG5dgyPe
         tHte1RrbQubQ8JBrDS1aX6WjDNO1B27K9suvMRGroge/gS4spmc6j7A1fBDWr1bIIsed
         E3NerVWWycZQpsGM3pWLeQG1jNlMcRZMP3/+d6vmyoQIlKDC8p6YBIZVf3c1jCIUqg75
         8GRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2c1o0cMY98up0tIiXfpcB7HFUJyesz711nq/llpOBTRmBpLS4E
	/mvv2dz/XDx9gZfOWgijZH8=
X-Google-Smtp-Source: AA6agR5QEygLIT054ENMSZImX2BnbaUX8tE4L0e5kf8+FISTU5rg0b7QX+g7h3g1wMKSTpuRkI7HEg==
X-Received: by 2002:a17:90a:4805:b0:1f5:39ab:29a9 with SMTP id a5-20020a17090a480500b001f539ab29a9mr13783742pjh.202.1660491148077;
        Sun, 14 Aug 2022 08:32:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:83c8:0:b0:41a:1c22:f9e9 with SMTP id h191-20020a6383c8000000b0041a1c22f9e9ls1351622pge.6.-pod-prod-gmail;
 Sun, 14 Aug 2022 08:32:27 -0700 (PDT)
X-Received: by 2002:a05:6a02:49:b0:41e:27a7:7252 with SMTP id az9-20020a056a02004900b0041e27a77252mr10362225pgb.209.1660491147162;
        Sun, 14 Aug 2022 08:32:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660491147; cv=none;
        d=google.com; s=arc-20160816;
        b=ORnnkmP+JYUPu5oaolaCWza0rL92nycs5YonXt22YvkiMSFdRJH+5TMVB23LGteieq
         CvVq8+KtT5Hwm4dbwxRO1UEtZHqtDcD1nXvP8Ejmu2I2w+e5YNHnxfkXJ86qSASP/y/s
         8qTV6rjQH2PXKeuAnKKDeoXyL3TD6wRJNc1GQ87mY6jDJgiQAc+kmc6Okfq6YhM2PqB8
         hPkTcUYo4VGWzhOwD7IKOcaHxiaY6j0F7KzStne5ZfHE2Yl6YLcRZ5mzTuQKRf2n1Fk2
         W8mU3E6in5ttQFj0iupx8gxa7Cub6v4XHUr4Wsv/CQmT4ykUXiTrIiG5T/F8iD1fiIOF
         qdxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ETP860wXTMKHlk6ZOm+ImoFiI2FT7H2V4Z5/7irXvPI=;
        b=ub4vnEr85pKxi4VW/lI6j5jJYyts/uqx0kA9Dlm7ciRfWc31mXj48tPDTy4VSffvZI
         SRVXB02Hi6zm4zIzs98uKcIFMSSo84gFee2Acf5c64ByDjpcZxHx4VIUNGaKPTvwyO4H
         MflU6onWznzPlKpAb8kXJahvu2NXyZ2xTevsUqTB/OdPf8OBkhin6lcPjdy7GOEcm8Fu
         4udWs0OZGvwfZN4SNfEaRyIVhLMVY4P9eiCjHbfRL0b3VVuop3kLoS2PJlP4cnaauLoh
         b2XLxGJId4zrhLNEsHeSVq+1LRKj8SsWK/o82FqupoD/ac9m+AVMD+7SVXqa22Op273L
         VZVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PWWhl7jI;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k80-20020a628453000000b0052d5f21fa66si317335pfd.1.2022.08.14.08.32.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Aug 2022 08:32:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AC37960BC9;
	Sun, 14 Aug 2022 15:32:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6CBA7C433D6;
	Sun, 14 Aug 2022 15:32:24 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Lecopzer Chen <lecopzer.chen@mediatek.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	Russell King <rmk+kernel@armlinux.org.uk>,
	Sasha Levin <sashal@kernel.org>,
	linux@armlinux.org.uk,
	ryabinin.a.a@gmail.com,
	matthias.bgg@gmail.com,
	arnd@arndb.de,
	ardb@kernel.org,
	rostedt@goodmis.org,
	nick.hawkins@hpe.com,
	john@phrozen.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org
Subject: [PATCH AUTOSEL 5.18 46/56] ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC
Date: Sun, 14 Aug 2022 11:30:16 -0400
Message-Id: <20220814153026.2377377-46-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220814153026.2377377-1-sashal@kernel.org>
References: <20220814153026.2377377-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PWWhl7jI;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Lecopzer Chen <lecopzer.chen@mediatek.com>

[ Upstream commit 565cbaad83d83e288927b96565211109bc984007 ]

Simply make shadow of vmalloc area mapped on demand.

Since the virtual address of vmalloc for Arm is also between
MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
address has already included between KASAN_SHADOW_START and
KASAN_SHADOW_END.
Thus we need to change nothing for memory map of Arm.

This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
and support CONFIG_VMAP_STACK with KASan.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Russell King (Oracle) <rmk+kernel@armlinux.org.uk>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/arm/Kconfig         | 1 +
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 2e8091e2d8a8..f440cf59cea1 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -75,6 +75,7 @@ config ARM
 	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c56d56..29caee9c79ce 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -236,7 +236,11 @@ void __init kasan_init(void)
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
-	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+					    kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
 				    kasan_mem_to_shadow((void *)-1UL) + 1);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220814153026.2377377-46-sashal%40kernel.org.
