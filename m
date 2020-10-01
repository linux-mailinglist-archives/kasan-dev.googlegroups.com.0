Return-Path: <kasan-dev+bncBDE6RCFOWIARBU7I275QKGQEVWHF6BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id CEA4828028B
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 17:22:59 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id q19sf1271635ljp.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 08:22:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601565779; cv=pass;
        d=google.com; s=arc-20160816;
        b=WsfLcBIRAtCDA7n++KuVNASRenqgamK1IbjC67MHa7LYn1rEqz2Ew8QcVSnQY6UkDc
         NOX/ZzMM24Hh2CoZijRWgty5d9V+aAvJIbI/Fj03CvhTu0cycOUZipxHaPwK4U/E/c+f
         Yd+YhFh3CBzzzmhrZ0FVYuUe7nvXsJsiMeqnjHLJIJvhQFWwLgOlPKEpLmlZhStFhHoW
         2ZnKqogGms5jK9WA01f32NSdsV7w+GRSK/IkLaSNhj24+8+duilugD7rrOTPKkmuDTPh
         VnC1KEFb5CadCRAalFc+EbA+E1bKTK5XhxVMjnbKN36mr9Mu39XYZy23GZGvUyvI4cFx
         Zqkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GPo8Rc2RKMyOQsqIXXqxnjwMuVNg9yYDDCDF6JQHmMs=;
        b=kR0a08p2GBJqMWbXJGVftndW0kTmW1S/FFBBqXXNqzzavvCi4UwzlPIsCXSYpejexK
         u/mlaAwdBTiDjFQFaexbgkCq/astkRG6351kb28lQIDH6eORMt4+549KDhTfCaM6XGWb
         W3M1B6q3+WD28AQIPAzqViavB2Cseg/tpHrPqBM+bTJoUduKfVFwfc2OJ76E8GaVnBKF
         CVRyzITZ84654sKXwfhuZ5cIqIWGtFaGGhb9OzsscLjVQGc2McbZCPbEGYXmkNtt7XYL
         UELg705IiRJORawcoVcn16veCwbjq3qiQfVT7DctqO4eXjHYd7XG04TRpMIwjJSSXZw3
         qakQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mik3e1qJ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GPo8Rc2RKMyOQsqIXXqxnjwMuVNg9yYDDCDF6JQHmMs=;
        b=iStAM1QM4WTDXV1MovMPEKxn0xInzDEk921Vc6uzapR3wWnqTPN0SoizRUDjm7WgsB
         2oM+64q/P+lWoyxSByh7VxNiZNWEaMHC70Ve9FRuqpaqlCh1T1ynx60gSVmh7oM2uNVS
         eUVzp1UwW7flC4jw9fNplT2BlBP8JfT9Hmdo7UOoAQAJrSgbViqsEZkE+CPhKO59dg8y
         b/wZ6SpzxqYAMD6/BbE4d97tfdMAE+HQKgpKtGRUpCWoaM2T7cFVKlSF8200HHyoj5uN
         nla/Zui+4epxxH4VJ3nUeV2fxXa6x1dNKpHN8ZcvYzEaTv04VEZJv0V94DjlFkGwMmGP
         Rm1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GPo8Rc2RKMyOQsqIXXqxnjwMuVNg9yYDDCDF6JQHmMs=;
        b=jVxtWHFlWmMg7G3ShL0dIx7yN7EG6vOInxwiIarw+VSPYoO+5MJBvpcjmEyI0Tzise
         ZuHaqxl7xE5syzN15ZQRpQaByLJYnkQ8vk/49ElgDV8I3JKvDjSdlj4ucjJqTjaxy5iq
         bEwRGrsWXMoOEyo/dVRizrs8YgFfZra7PIt4zHvWhxIMPiQBvxhOeEO1NPV2cG7A+hKr
         xTbCKwvnMVJfDi1jQ9zox6IlNwmsx4tTHmtz0osqqCVkcQvfIj3LdhkN6cv1LCfMBS5v
         GDfftDlt7eaQwRrXlLLBExFVLJRZ75d0G0uRbcHW5hS4OQmG4PUmkrByCSV/x3o0WxBM
         4KWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OvWSjEwM5Xwwy14gIx1XCpFw2h8HHUdPMs3iGqwiuaFx8kYTM
	UH1nI/jtoUKtjaamFcVvndk=
X-Google-Smtp-Source: ABdhPJwTTxpOqOmuiAwfhQ/1lyyCJmOVB5b9jbENddSusv86/IXK8sHpPe4uxD+QFJjJLRK3HjAvSA==
X-Received: by 2002:ac2:5594:: with SMTP id v20mr3054199lfg.344.1601565779362;
        Thu, 01 Oct 2020 08:22:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls909404ljc.6.gmail; Thu, 01 Oct
 2020 08:22:58 -0700 (PDT)
X-Received: by 2002:a2e:9d83:: with SMTP id c3mr2699249ljj.385.1601565778230;
        Thu, 01 Oct 2020 08:22:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601565778; cv=none;
        d=google.com; s=arc-20160816;
        b=dVzfUL4rvF14dB00lCqggFTUoHINNrXq2kD5g9Jlxuo9aPDx2RzcEv7y2ZsASCgE1I
         0/JA91WLaEv9DtGwrWQlmZdXu3UNCmQIjttqcP80X6sCecDskOe/3o/459iykmBRObLv
         +KxOpKm+VEYGxLSaDifnUxettzXKEt5G6Cgv267mYsxIkf743cDl+3sSZG4oKgJeUd7W
         V9VwSNMmwjUsjVfDvZ+QGr6edL1QtHTy2zWj68axsY1TX20OEDdKYer5EX3EpTgc05vt
         XeiZuk3f2BHSMKSp39RNCUKwcOp8okQd3iH76NkFjFAKbrNFPThDETpw4L5FisswCZPE
         PJBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=S+7lwer1MnIu2awMYj5Jn+sfVKRlLjP1q7T9qbp7QkM=;
        b=mLu0c9x2rblG3auG9eeTkIwbqe/42IT2/wJU/Ktp6bsXojgZkP8GSjG3QRpLFG4t7V
         jmMbyOCEEtzKn7YNDLPhzSijCHVRmQN6U6baKsQEVkOqI85u5nG8Oib+QlyGfBnzBrSI
         kzzu14fgWT3UFg/yxaZnT/jK8aRlondJldtakm3N18Jw3WaZ3X8QurADwcn7xMatHMc7
         T38mpAoOABhofZ5t5GLrVZc2jfawLluwiEXyAjJ6ejYsvdDLDSgxaQozQvEm1E9rBddK
         C7MOFRz8UD7Z2BKCuiwM7Xwgunt5XTFvw5AsjTzR+rM7v3xlGBpOPYWh+6Xcre3pFdej
         itaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mik3e1qJ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id j75si183781lfj.5.2020.10.01.08.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 08:22:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id m5so7072687lfp.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 08:22:58 -0700 (PDT)
X-Received: by 2002:a19:f513:: with SMTP id j19mr2565422lfb.174.1601565777933;
        Thu, 01 Oct 2020 08:22:57 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id v18sm587578lfa.238.2020.10.01.08.22.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 08:22:56 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 6/6 v14] ARM: Enable KASan for ARM
Date: Thu,  1 Oct 2020 17:22:32 +0200
Message-Id: <20201001152232.274367-7-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201001152232.274367-1-linus.walleij@linaro.org>
References: <20201001152232.274367-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=mik3e1qJ;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

From: Andrey Ryabinin <ryabinin@virtuozzo.com>

This patch enables the kernel address sanitizer for ARM. XIP_KERNEL
has not been tested and is therefore not allowed for now.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v13->v14:
- Resend with the other patches.
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
ChangeLog v9->v10:
- Rebase on v5.8-rc1
ChangeLog v8->v9:
- Fix the arch feature matrix for Arm to include KASan.
- Collect Ard's tags.
ChangeLog v7->v8:
- Moved the hacks to __ADDRESS_SANITIZE__ to the patch
  replacing the memory access functions.
- Moved the definition of KASAN_OFFSET out of this patch
  and to the patch that defines the virtual memory used by
  KASan.
---
 Documentation/dev-tools/kasan.rst                   | 4 ++--
 Documentation/features/debug/KASAN/arch-support.txt | 2 +-
 arch/arm/Kconfig                                    | 1 +
 3 files changed, 4 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..050dcd346144 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -18,8 +18,8 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
+and riscv architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Documentation/features/debug/KASAN/arch-support.txt
index c3fe9b266e7b..b2288dc14b72 100644
--- a/Documentation/features/debug/KASAN/arch-support.txt
+++ b/Documentation/features/debug/KASAN/arch-support.txt
@@ -8,7 +8,7 @@
     -----------------------
     |       alpha: | TODO |
     |         arc: | TODO |
-    |         arm: | TODO |
+    |         arm: |  ok  |
     |       arm64: |  ok  |
     |         c6x: | TODO |
     |        csky: | TODO |
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 0489b8d07172..873bd26f5d43 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -66,6 +66,7 @@ config ARM
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001152232.274367-7-linus.walleij%40linaro.org.
