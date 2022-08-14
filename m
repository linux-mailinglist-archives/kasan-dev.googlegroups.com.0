Return-Path: <kasan-dev+bncBC5JXFXXVEGRB5NL4SLQMGQE3O6QQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32517592122
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 17:34:15 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id q4-20020a0568080ec400b00342b973d2e3sf1098600oiv.11
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 08:34:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660491253; cv=pass;
        d=google.com; s=arc-20160816;
        b=uAOtNF512VL43j7dvpY1X14eehxDKrzokTynFWmK8ErAfMk5H0ZRuFl3/ebUSd6Ur1
         wpOW4YzrIXIkUROun6FFK+6K7guHy48uz+Drj9PE8wePdzfGvUQN4AEwGuLy1zJisK7L
         zezZvTNMGU5igF41LosXXRMzCdage1f4P/CxGb2OI8qwupCgoCuVP2qWtIlaXNcstg80
         ur2bbrBcZR28SMljx/xr2ACblxV/6zEGKFzZV+81ImO3ec5QbDivLs3BjF79DxcDzZKk
         S7um8UgbdJs6T5HYGg848Qpirc/706B9BfKmpwDt1TA+GbLy30DfOyXG1wcKmfkLU2b5
         ezog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xJSZCdQsU5NoaG71DaJWFsqByEF/Wz9F4j6pvmzjHH0=;
        b=eR/KzjsAPbe25gSSAD9QKYi7789eSFecnoJb13P7GxvqMmhBZExaCRbhVJugpLSxeU
         vdFoP/bPmiCj0XfEkILQ8h+RHb4kSEFly8J0Ah6E7y8mFh6b5+kETOXxm7qCINCLLPlt
         N3R0cB4Q1+DGo52+cd4qxN/m/1QFKclUZZ/eb8f2cP1bJJXFI8uizA5ZJrqzVqhT0Des
         R7avlWTzk3OjpQNShGBQqQpqX+zGAXg9mPW2N/5LP2n5+Xam/qHDwR3pEZcXcvgrhNMK
         yLgAAtAb5psXJh6o53cOSJxXtdk7X/lEhHhvi+BjzCnDilSdQuVpUSDdl3YKtIXm4tF0
         c9Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VdcMjWcX;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=xJSZCdQsU5NoaG71DaJWFsqByEF/Wz9F4j6pvmzjHH0=;
        b=N/1GfGUpXhH9UZjjJgs/Pu6YX4lecv/aJaA7o+K5EGE7wQT7lX/rdX33MvWfCqrr1a
         ggcgLNG5M7MT5JSs1dd6jqT9kBVFUUwKbJom+kksP56P+0842KjIy8MTXW47p9r0CFmf
         urz+IB0HgB+qfxh++nqY3kzvEF8osvWBdyeAGQEJJb4KPkl6sYzq8TUiYPkd+PQOIKi1
         y5Kx1b9jGfrgferHX/lujNsT0FYQCulQhC3tFpDh7Fcs6WXqVDJxqSZdHh8YDl4ySylP
         5l8uJVVvVWjxRiZAs5be3xoyM+Y1jpyTTqJ/+YURftPvy/OCru2xlMHsfLkfVSOX2h4b
         VEIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=xJSZCdQsU5NoaG71DaJWFsqByEF/Wz9F4j6pvmzjHH0=;
        b=EP+YE0ZNLMtHUtN41FLySkRbkC06vRlqt+fA4qDW4uqtPTIoBcfiWNAwiJBnVIsEvT
         ABA/8qlNXQzck0C0IlIWF0ELUWRzGMWvrXSwaNYsi++tVwilZGAE5e0VijBMGm0nA0jc
         p8Z7UjOAJRIG/GtHPSCZhUTh9aKD9ulq2SDT+p3FS3jgwg+E0Jei2tj4SJA8liSd7E88
         /895Y7TyC/ZBxgEz6EgxCnSXW8gXvHwfgt6nBmmwArEBVAqZtcHCXhAcQ65Zu91J/B9k
         wGVEheooJWIAf2s4M4EBTuaXjwp1sYWGOoGR821iRcUFC+XSwanj5XXwYGNP/DXP2xaQ
         7j6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1bKIJeBWFhswhGtMKnU5JOOuDeQepZTzToRs2vctKvJhK1vThr
	tD0kl3TH7GbSrVI4Nkm19kE=
X-Google-Smtp-Source: AA6agR4rQ4SRMGywwawUIGzFUbS/WljP7BhySZ1qmOajsme3fDE38qKJsSN9MXvHE/miRhoGQnlL1g==
X-Received: by 2002:a05:6871:10d:b0:111:9e8d:59a6 with SMTP id y13-20020a056871010d00b001119e8d59a6mr9823811oab.24.1660491253635;
        Sun, 14 Aug 2022 08:34:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4e06:0:b0:342:6547:bf34 with SMTP id a6-20020a544e06000000b003426547bf34ls1864622oiy.2.-pod-prod-gmail;
 Sun, 14 Aug 2022 08:34:13 -0700 (PDT)
X-Received: by 2002:a05:6808:9a6:b0:344:b7a5:424 with SMTP id e6-20020a05680809a600b00344b7a50424mr187562oig.147.1660491253111;
        Sun, 14 Aug 2022 08:34:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660491253; cv=none;
        d=google.com; s=arc-20160816;
        b=TltQqAa0XXAGQudUDkl8qaEsTdvFBTS7us3pTIznrQUXnuiaV1dXvIerO/1MEPTGxP
         ve3tsYrtn698nlpB3BN7Z9ROYCaFEOeGc7weB8niZuosVVs092FkEY3SvmWM8tQTNaTl
         /pBXqkpLo0syGzbEFlhS7SD6Xyjga25UZXwEVqk3RAFQBPnn87Kru3GZNsg2dAVGh00o
         re0FJtEtdn3cicHx49xVvgydGbeFxbHdvxvqaDMPna1co05Z4ArSiGlqqLbqT5x3vJac
         NAsVThFFz77z2tY3e+1oHmjIGXhdRsZ5feYKlFw2UBIdieecbFKbYiS2uLepSvzEaJ75
         YPHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9BufiCKQq70iP4kpmLVl7bD6nkPJELy1R8RlOhVI4RY=;
        b=xkEky17MFUXevvKiBDb9LBvCZ/fmxkcdnlA3dR/LGU0NSkbEFcp2kjmDfpGD4+JK0u
         OyLZ0lneGjPnu842DrO8DxH+/vnUVAbWIU09MAiEIQYn2vM6icobCWtFcI1536SF/RZq
         KCD6h/XQKw6erdtdo0A59P6QqBKsofBK+tWsODmgs7ZYnjvtUoAwRdB7wRaAwhGOWA3W
         +PpqK9uBo9v2tz95BuW/XXDtwh+mvXSJIGOuIYbzBJScN1koin2Rs3BkLjS+mJi+oZKL
         TRemY7P7zyELn+1ifpFbNdcRkxUeWxrVefSi2MA+/+dy3B6lHH8iVozcgA4n1Lng8Zh8
         7/5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VdcMjWcX;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id j4-20020acab904000000b0033a351b0b4asi436998oif.3.2022.08.14.08.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Aug 2022 08:34:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DBFE960DBC;
	Sun, 14 Aug 2022 15:34:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0B189C433D6;
	Sun, 14 Aug 2022 15:34:10 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.15 38/46] ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC
Date: Sun, 14 Aug 2022 11:32:39 -0400
Message-Id: <20220814153247.2378312-38-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220814153247.2378312-1-sashal@kernel.org>
References: <20220814153247.2378312-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VdcMjWcX;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
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
index 4ebd512043be..44f328fa5996 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -71,6 +71,7 @@ config ARM
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 4b1619584b23..040346cc4a3a 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220814153247.2378312-38-sashal%40kernel.org.
