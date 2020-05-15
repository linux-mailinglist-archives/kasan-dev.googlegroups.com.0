Return-Path: <kasan-dev+bncBDE6RCFOWIARBRX77H2QKGQEB3XIK4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE321D4CCE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 13:40:54 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id q8sf769833lfp.23
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 04:40:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589542854; cv=pass;
        d=google.com; s=arc-20160816;
        b=i1ELqpxTI8/3vSMVixLbTwO0yAHZJSLjAUlO8ioRLQ26oCngY1x8EAdp7KO4X9BPh2
         PHSDGGk/AmTz/74bIhrc+E0NvByfO2DFJGl4Ux+6fcLSoEP7nV/TRY6EthfJI/5Qc2la
         jnUyBcIhyss1c/96FzFS7RT2dQ9Sg18NPWHKIPEIAxVvYDGDqTEjmCXz12T6uGR6XEHc
         FdLv3L3LfoQ13Ef2fjHqCbOjf+Z2MAOSUN8Xa95zNg2FrJ/rj9QUwwPnwHxJ4++m3JA0
         bqkIAkeif2xFIsY04rWKMBrCF3F66m6v03xfP2pEalfUQJ4lbyQGU/KE+Asc7pv2PSO+
         9lrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MgySuTT3Ns4YcWEIkoJTeus4NhAKwBrcBXPkzJ7PPtY=;
        b=MqxFVLOPsDiuF312bvSHGE/6ysK3beJzBaA/YAj09oJG9Sp55XMrsRVPYX+/ql6jza
         XgaQ9ZQdFDqob1ksIz4x5eOv7NgmSogtTWf7NHub3bo3/kC02GuKJZyxzuuludzkw76C
         r8J3vE6/iWFCuDNlnAA5x2m9AfagCx7oFleHDZTrz5kwb7tNbCJMB3spMt4YxR2yjjvP
         YhiITAatKJPAqlD0q2LnvBMnkQa9iCFbV6zvy3OggM689d8v692xfUNL2W1PswRWaV1E
         /vxXt9d841kX6J4iHbI66jrhan0SDUDmVcuHYvt7V6OPumavL55jKZ0XNIX4clg9nmvs
         Kn9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=JWuuM1dg;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MgySuTT3Ns4YcWEIkoJTeus4NhAKwBrcBXPkzJ7PPtY=;
        b=WQtkYtL0BtuZeTFW7Yh8Cu9WnOp70nDAAw/ZVdtwTIYcibJyd8r6aRsmpSO/Kle/V4
         mZkHeOVmxOmDdXLTZtWYSST9IhqpcISn0N0ABrifKOG1upNenJDag8WmnmDREyXIh0mE
         W8KzDVtubFdTxEJj4Nm9NDeIHukW4MmKRU5Yv427tMwVvzqqcFhYmqJGO9MJetBMBmBy
         xbuIVdsE+RRINaeSzoXRT5spOFhQFUjF8fxwly8yzqUNxnECiOKyp5uHi2JPkqLDVpQq
         xZzalh9N5gAreGlvV4k9gLMKU7k/YBAY/tTLl2SQk4QuwTxmxLmDzDHcd2u4nnvy2m+x
         LNRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MgySuTT3Ns4YcWEIkoJTeus4NhAKwBrcBXPkzJ7PPtY=;
        b=cOK2+xJbLLHQvHdB4kxU1nWBwAksc4TodQFliQCRRc88Fa+HCUZ27XhcjuuDIb1Vhh
         n2r9DYmIj/KaBhVgVFE4tr/7CWGqoZOSUsp+Bn79MWxBBIYP3VxjkAzeUsJ/denu5uZ6
         oD5RJxAW2HxVaBk/l5jQUN759E6fWV//waCnulStNs5nY6wSMF57YxTF7vX37Wf9owWH
         Gw03hNEmvPdDNMtA2d+qPhJgq2YhTEDKkwSvVV86QJgZb6bzr4VvYaJxp8zd3klg2BqF
         HKRkXMoRKmyadwdxZ6L3G1eDKrvzKJipmwZWpci1L1+GOzwqPmJHLj4XsicM7AhjCvdr
         enXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iod6gPXdlqxyFvcHIF5w634kw/NLPwKr36vt8ezf4mcoLR/ac
	IcVp/M54tEnvha/bM3a7IT4=
X-Google-Smtp-Source: ABdhPJxUnKY2dKeYA1z3FYLK0zm6ZCrZAfbxwkzR7x0WgTgyFu5RmyGJXXTZG7B5FXQAYkAvq9GHDA==
X-Received: by 2002:a2e:6a08:: with SMTP id f8mr2185691ljc.8.1589542854440;
        Fri, 15 May 2020 04:40:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1121:: with SMTP id e1ls328290ljo.2.gmail; Fri, 15
 May 2020 04:40:53 -0700 (PDT)
X-Received: by 2002:a05:651c:2c3:: with SMTP id f3mr1269638ljo.172.1589542853508;
        Fri, 15 May 2020 04:40:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589542853; cv=none;
        d=google.com; s=arc-20160816;
        b=mFPMSBw4x1hd51r9fdex5HXz21NDkmP/8ixvPouRdnXrAZl5+4zrNCkUJjy8U+MrEN
         zd+BSwqw72mRd/2rf7IHYgVBbRF7N/Paq1//KeyjidadHKftqmUNkwJKA9eG7QL9acNo
         KdavmIP3RS2L0VMHYuXUANOoamwmB0QmELtHt8Fjat2oQNHKUd7Z2/sWyClnf9Kl0Lsa
         xhTrSIezR/agFoUyx9wZGmbmhiz0YN076orC+erRcoaF7AkOzAaW0e4m308MpV/ancxq
         prraS+KPsvUYCKl6ukZVk12CS5IP8lCb74FkX7O6hYXrjjJzTiRXZZJcD2YkQMMXlu37
         nw1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KLuWrligKNn1WjBKyBQuwxe6r/5e6Gs1d25GaKttivE=;
        b=ZT5lpfeN8Qcmtq84Se47UyLCryi+mHKXEJ7q1rkLYZ8QEdi8xYRDJ0ZMz6ctqmPbBf
         Jf316ghhwI++pg6WBN6a6V73l8hs1nlXOEvadyf1LeX2WUkuOmiulPEoN8z1+lniUa7c
         r0G6Vo14bI69MYjSqZmAXPYazQysKQu0invQUzL/EoTt9GDkp5AjfU3/4t8xSYgSu0MK
         15Zx/hCgXHOXLCK4/UtpEJANWuTzMvq2DlbJWKD9XyvsY6OU6G++a0lEzUgX4hIm1Meg
         aP88bVkFrzVzPZYjBNgvUgvlra2E0HPf3BIEhZlbGTwBj5OgNFmWU9zXzL3POReSxEo9
         c9Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=JWuuM1dg;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id q9si107607lfo.4.2020.05.15.04.40.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 04:40:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id l19so1864361lje.10
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 04:40:53 -0700 (PDT)
X-Received: by 2002:a2e:9cc1:: with SMTP id g1mr2056865ljj.261.1589542853237;
        Fri, 15 May 2020 04:40:53 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id 130sm1218445lfl.37.2020.05.15.04.40.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 May 2020 04:40:51 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 5/5 v9] ARM: Enable KASan for ARM
Date: Fri, 15 May 2020 13:40:28 +0200
Message-Id: <20200515114028.135674-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200515114028.135674-1-linus.walleij@linaro.org>
References: <20200515114028.135674-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=JWuuM1dg;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
index c652d740735d..0962365e1405 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -21,8 +21,8 @@ global variables yet.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
+and riscv architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Documentation/features/debug/KASAN/arch-support.txt
index 304dcd461795..8f6283604028 100644
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
index f6f2d3b202f5..f5d26cbe2f42 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -64,6 +64,7 @@ config ARM
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
-- 
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515114028.135674-6-linus.walleij%40linaro.org.
