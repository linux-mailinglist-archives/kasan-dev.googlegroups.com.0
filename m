Return-Path: <kasan-dev+bncBC5JXFXXVEGRB6VJ4SLQMGQE54YDC6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 268E05920B8
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 17:30:04 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id j29-20020a4a92dd000000b0044aa3238852sf1570198ooh.14
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 08:30:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660491002; cv=pass;
        d=google.com; s=arc-20160816;
        b=jvfjkTCZ9VpIsce/nIHkppV1RXY+CMkkNHtfvg2cz5/uMayVj3LMJBLNOp3Ytgc5Km
         LTC3clXiLKzRJ8iR5L4XUbk4UQwyRJ6XaBLgEH3p0Fq1dBwNeWU0TOUBxgpJn42RQFos
         4w85lhMfpwZKNocybFmImT822/DF2wGQ+vGxB0Dzybxmc+alUIh4sgqIGy2RM14WwyzN
         WElDlT9y6zLxLoTgy0H45Hm6fxtmkiMrXSb5pMSAc2W5nt4YV/dihhCNNnRMCLZCn0d6
         JbSk8pvG71Eet1CK4k55wZU9Bu3CYkJeI3Uq8uICECumRsCAfcY6bnq+nd5ws05nJa2u
         R3RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DpPgHoYmt1iO8iEArX+WQbbJah34XbOzAQNzuuJFQlo=;
        b=eMjt96G6ZiLM9Cf11OgehMytzGKHsPO9bucuowBCIz8SxYvsRdB3YXqOMHp9LbH+tk
         Kd5oVetnBFMYkfAVGsJQOo1O2H/e/kgCAvLawTb+rFBR+jq5tt7TaeoYwfh5E1JwxT6i
         OEylOtBVTwY9Wp38HThqRaGUNqMW1SLbllBsl9LBaYNA2o+tmknsAgbPwZj54fjy+g6x
         76orslVfNn8W5BD2HEPcQ9WKOogGtORUtb/mDueUDUU9PRSS+qNjzEbGY6M0aSMwJU2Q
         kSiqsQAhAhmSts1g9sT4LLQp8SvqlIpaYL2b48C6pTa0Z79JNi8wY3KH6ble1G1yYv7W
         VdYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GtAorFRN;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=DpPgHoYmt1iO8iEArX+WQbbJah34XbOzAQNzuuJFQlo=;
        b=uBvv8FGWxlG/yPdAgGVnuqDOaB/sM9squTjg/DPjWgDqRzjkex6JQLdKwdZmYa2I7f
         FfO/CNVoPItpKrQKRAe71P8SRXW+ZyojAxfKWeeRmKlqHoh2j3vifh0M/zKNIoq/Ku3o
         3y1Um1o7qFn98QuFzEIXfkJ7GPxEldhuKbG6AFPd7IOAaO3UUpOhYUOt/yWvK+D1y8lM
         7io1qqwRyTCOMx7g15rWydN6SfqHlbfv75H531XG4nj7WoEdfobHqQDzXXaIA8b9nLyI
         TtGbd/N92cQkK8BRaWbMd4ue6hZ2RW6SVXNdbikF/4fpP09pBghS65hePJimzjWVf1JC
         jMVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=DpPgHoYmt1iO8iEArX+WQbbJah34XbOzAQNzuuJFQlo=;
        b=AUa/zhGdtvvZ8u52Vd3/0wND81+r4gQO79Ftx1/QeLkFljVQ2dESQELoEh75KpfxSm
         39v2RAd+nYfnZ2v/xKCDyB+soyqy2crAoCUTTAz1LtJi5JYz5Rjkfl2a26zxhmOmdE1m
         ChCaIOIxup9IqasnfAHdhLaJWSegWCgiD5f6fp6rTykQRpMOYFpz2S4oSYgWC41Aowf7
         J2ShlbT4ta2v1TvzCr6bjeogGthOf+VS0nHV1bHNioZTZAqRoEffHH36CBKmRY3Gl4ob
         l+Ibkpg0pVXtLeAXrwxi0sCAmSlsgAvZRohS3gOaQ5siTZ3NlqB1FdNG1wGpeX9KO4PY
         +d1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3T6o96GTnTOrN2+mE3A+FYpcRCzt8ESjVWEFWysKU2TsqLtvCN
	SRClDipGsVvVtqiJgdWwuKI=
X-Google-Smtp-Source: AA6agR4eKsVCAqPsP7Ojhy30efjyDC5gKT0hBOIJRYmBFBHyaF4FyNEnKmdVdf0TVPfb6KIS9q/cng==
X-Received: by 2002:a54:4719:0:b0:343:31bf:66bd with SMTP id k25-20020a544719000000b0034331bf66bdmr8524356oik.15.1660491002529;
        Sun, 14 Aug 2022 08:30:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a604:b0:10e:69ab:4435 with SMTP id
 e4-20020a056870a60400b0010e69ab4435ls2260845oam.4.-pod-prod-gmail; Sun, 14
 Aug 2022 08:30:02 -0700 (PDT)
X-Received: by 2002:a05:6870:818e:b0:113:82da:24 with SMTP id k14-20020a056870818e00b0011382da0024mr8657887oae.103.1660491001962;
        Sun, 14 Aug 2022 08:30:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660491001; cv=none;
        d=google.com; s=arc-20160816;
        b=tgg1FyHcypHRb8y7nB59DSix0zB9RhNYbhkkRGIvlBNypQK0XDyeEofSFm4D5jZ8rS
         Ilujpnsn0zodhJkSLMlVuJUT2D3fZ63XcjZHNGGQEIPrTR/RoEmE/1Qgm5bDJtrAi5B5
         b42NfRg0t1KqcGMsLNOTTcPWj7lcHNyrWBAFlMaYkXOwBmIgRvO7cK1QmCZF+MLobf94
         SynKhaQqkQpJag5QQuz8ei2dW/enpCTRY5j4dbS5LvHVU2ofsqPQzxqk28RNTi0H67na
         3hQROh2SXYTCMOwjVWjYpSj6nvgZ7zBpS6FKX7gR6VobQcRu91khOzUQGAaN5LD/n5CL
         1N4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s2djNZABbvmH2AvUX+S2K4U66TjxzdyJZ6lYmrkXhvM=;
        b=KE3BbIOght7pg3YXB2FAW3ptLPwXh+Ekf3b+YmDHE1XYTg+ailOUeZ9hlJFEZ/2Fw8
         Me48w/BBpm+At6ECMhF63TS3nRf9Fg4rn+G/CcNsfCUymUiW8aqqC7BAN1ZTnmygYCbr
         Qnx9VJ16nnT/zMkYTdZ8/e2PGTFA4O4FZIcWKgUCOT9YJVm9SPKVTruNUdH9UzoTcbdW
         WhX5Ng6PwIslCt1Bkxpo1UH+CwTVM3ysIdfkDiIqR8+P3u2BbCVUo4nHskVNUxwHZG4v
         elr6MOe/AilOLM0w0SP209YkM7MZqbaTo+9ZJxaAdM2p4rphrKCiq3riVbp3dLDfoCLX
         1cmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GtAorFRN;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id p4-20020a056870830400b000e217d47668si461633oae.5.2022.08.14.08.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Aug 2022 08:30:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B7F2160C40;
	Sun, 14 Aug 2022 15:30:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6A8DBC433C1;
	Sun, 14 Aug 2022 15:29:59 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.19 54/64] ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC
Date: Sun, 14 Aug 2022 11:24:27 -0400
Message-Id: <20220814152437.2374207-54-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220814152437.2374207-1-sashal@kernel.org>
References: <20220814152437.2374207-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GtAorFRN;       spf=pass
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
index 7630ba9cb6cc..545d2d4a492b 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220814152437.2374207-54-sashal%40kernel.org.
