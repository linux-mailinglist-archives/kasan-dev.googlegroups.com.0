Return-Path: <kasan-dev+bncBCN7B3VUS4CRBL6MTWIAMGQEHEOHEWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 69CBD4B33A4
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Feb 2022 08:48:01 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id 204-20020a6214d5000000b004e0003cee84sf7880213pfu.17
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 23:48:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644652080; cv=pass;
        d=google.com; s=arc-20160816;
        b=oTZt52yG67/v5rlTqYzeeGzkKgN/pthVl5Q9gfgvwY15lLP3xRaPDcIDhTsuIaTTyL
         Onst3kdcZQQDGcYEV+xUzAKW1IKK6YDl/Wj1Mmpp3L0NPQ6UtbOmM/4sf7bJgcSTzQ+H
         vjkSQU/qxr0aqVkO7kkHm511ZV5tN9S3xMtjj+DD0pjeWbGLBH2UK14zXpOocrWRto0Q
         ytWbX4wbTBEpvHFPV8KXYLgGOiNNUUEJlSzHEWCXF3qopJihR+GS0JUma76OIfC7cFHl
         ctUEDrcwXrs+R4+G09QQbiMP7z8cOaVVMx2oAKzxiAOj34KV3CGg1Q6P2V4Ryryc+Q8g
         n+lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=KcEEK5+lSaLErEErybympcMz3JAkN1NkMwrI3Jfh99E=;
        b=lWinGMXTrk2/b0n/f2LAPFCIvkdyCFVQ9DkNHWPiI0XdL29M0KZG4nDPOgb8XOLMJw
         2gO8GfKExHwJ47fr7bVlbi4jRk2fPT1ifCwCiwxG3yDIHiDfxe+RSmnGqBsFFapzVWRk
         ew9QULf/j9Ssq27bgPIQd55wC2jbkLEptn6UMIezz9S27+3g+yGM6o6W7+xMPwcPi1V8
         LCmvjthZcCba+z5pW6AaZ1Q33GejOVk1IzCA8F3WSxlo5y7XfEnCu6CSqE6kN/wAmgk/
         pETzlEFat3Jo/l5v2/hPqq3rO5bmwiYZpcdT07zJe3mL3SKoP1Chn7YKfszBXFWeJ20O
         SvFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KcEEK5+lSaLErEErybympcMz3JAkN1NkMwrI3Jfh99E=;
        b=XchD7WUy06N+hnNtyhDJY2Rqei70FTYi5U0Mt/dA7JKs894fSDnF3GOAC1yCgn9fWm
         GcYFes1yvdy9qGhvkxOGCLhnpXvvSzs2WNnEg1cABw4jM+ioUsEwrVJpoa7f7JKE+S6g
         S11kOK8IBOe2Gpl25yHy7LDqYCx2xzKax9hr78KJs6Ij15xn+zDdrLM+sA8rVGPVnG6j
         y1+DcTp4do4ChSytU+O0GRG9zpEdaglB9Wo/VeBNfFyumtymOBybOeaWi/Pjm27xPt/n
         DiT86JCX9HRHWkqBJfIS999R0AFYxufqIv0+/kcXKJTDZasItUXu9AJoVb/XRTZrD5l1
         C6rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KcEEK5+lSaLErEErybympcMz3JAkN1NkMwrI3Jfh99E=;
        b=RBM0MatdsGHYrIK2DRVFY3NxGAxn3JguUnevwosIWmHmh1g4u/blTWJcpaMbEqirwL
         aYjpFKyanbY/peRA9yErq60ZP4d1KmKsm0Reux31guAY295l2oaZIYUanK3B/qTr1T22
         hpHFvK/Nxjz2SY8eebZWC8RiuUzm4wYI7OWFm8FGdjNkR3lKW0dtMZ+r0svqhrfmofVC
         O/y5fbS8V5dQyJ7/c6/LIbH17/EhRqzD0AULc6z0L2PsbsUWu/Ag4qO0AquKTc/ioyRh
         2jeFJwM+732ptC5rA34T1d13ly6YkV+6lTTeBkflgF3DyD9pf4LBBNpsyK8FGSupzHSg
         zBWw==
X-Gm-Message-State: AOAM5316h0rAZ6SXmlX0+Cb4uKmIoWP/MRY0W/oahIXAwjGdjfk9sO/Q
	wQxiLpghkxk+1IULHF18pw8=
X-Google-Smtp-Source: ABdhPJzCss9Zhhy29ZsVQQbvF5I9Y2CuVOgwzGYgT4VKAovpy6m5ksEJqUl8ASPkJq+HbrJfQSvGbw==
X-Received: by 2002:a63:6c01:: with SMTP id h1mr4331550pgc.118.1644652079707;
        Fri, 11 Feb 2022 23:47:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a409:: with SMTP id p9ls7427505plq.3.gmail; Fri, 11
 Feb 2022 23:47:59 -0800 (PST)
X-Received: by 2002:a17:903:41ce:: with SMTP id u14mr4906633ple.49.1644652079056;
        Fri, 11 Feb 2022 23:47:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644652079; cv=none;
        d=google.com; s=arc-20160816;
        b=iU/CYCsYo6COe3rjrux5pUzZaO4m37IU48vGbR6DG8UleIQ7ywpfWYEwbH73jMlTtT
         feZQgbmegG5l223kI8fsB1XHn5HZbultrCDKCiZn41GAAtD3Hg3+aMBx9O5/ZVZ0cm8t
         sEmpfjA/IcTuG/QIDKHKD8xMtV/ks33H3Ue1d5oLpXVgD4E8AP7xXKbeFMY4OHqG6QPF
         540XAjgtwgexsHr6yCC+BzvI3kpJUSPUq9RREPbyJ1dPzDoJ09HOXt0jRy+Crb5HvJ4g
         CP0YbFRBvSn8ZNsbXDdSM5HV0NyYJ9apxk0Um12yy/7xR6qQUjta7HOoHfQtz594s9pg
         dEjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=18gRPS1BDdtJ8Vdbc5lpaHk5iz5usrYUWIsO/gKYl10=;
        b=0gUM62QocA3Bf30s/I+w/h6yPZmnw5F5uFjjUaP3QzUznYi1HLcimZwknsqATCA4dp
         LzvEddq4emTEAdPWLcR+rZVIig48bBQeHXqXV6rHUzoUTtjzPPpC+fwgH48xIzvjn7IR
         Ly6G+kq/L3VmwdyZcNViExvmli2Y4yN0Uj7u2DUZKTgPY2ngY5hZXaqQlRuTtCfLtoSx
         sGED4GwNklmN9Iqsg4NO6fljG24pCupEiRMW620gy4SPEbZu19mukrtLKA805+JJ4PwA
         zjTXJzCRaoKyVTTTfgGR6z80E0R+O58iYoPYvQ1s0+80QiFJvIX4ZfqyKR7GZnExGNyP
         LsoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id p12si844808pgk.2.2022.02.11.23.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Feb 2022 23:47:59 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 21ae44ea32604625b45640a4808bc4dd-20220212
X-UUID: 21ae44ea32604625b45640a4808bc4dd-20220212
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1333138036; Sat, 12 Feb 2022 15:47:53 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 12 Feb 2022 15:47:52 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 12 Feb 2022 15:47:52 +0800
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
Subject: [PATCH v2 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Sat, 12 Feb 2022 15:47:46 +0800
Message-ID: <20220212074747.10849-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220212074747.10849-1-lecopzer.chen@mediatek.com>
References: <20220212074747.10849-1-lecopzer.chen@mediatek.com>
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

Simply make shadow of vmalloc area mapped on demand.

This can fix ARM_MODULE_PLTS with KASAN and provide first step
to support CONFIG_VMAP_STACK in ARM.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm/Kconfig         | 1 +
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 4c97cb40eebb..78250e246cc6 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -72,6 +72,7 @@ config ARM
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
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220212074747.10849-2-lecopzer.chen%40mediatek.com.
