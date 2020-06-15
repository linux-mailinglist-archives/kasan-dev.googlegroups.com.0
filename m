Return-Path: <kasan-dev+bncBDE6RCFOWIARBP7TTT3QKGQEOHZRZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 207AD1F92A8
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:05:04 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id g24sf2419934ljn.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 02:05:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592211903; cv=pass;
        d=google.com; s=arc-20160816;
        b=YH/Y6DmC/XvDpVoxrgAYvbnQWZcD2EHjepOR2NmsF97zO9dvbl8eCw2VtUVIVecKd/
         IeUnpuZ+czm79iM+MGNk6v0jtDL4S4/wZi0gTFbVqKNxvdnJO+WJkvfKl1Oa5mvq1Rh0
         cG/f8+2Z6ekvGX3dfJwFiz3a7OCL20Cvl6Okm5f2wqspN22fTRq8lqGUDncl8J+Adf+I
         jnWCOoaeoY7/rMYK8CXAW0uRri2kR7r6ZmzIeql/BSO2uwnaVEzn6EQnvJFkcThN0AYk
         eUIg9/iGq6ZmoIofBsgF4xkXjtCql8geZ8G0/wuCDB6/dkOnpN0RQUXEk81/66Cz0sG7
         dXLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OcqX/IIPJGA/FIzIuZRV0oMVA3qrMVi5VumQItQDL0w=;
        b=kD1DJUbTX7MvaCulZ4Ik6N9ncT7rF3dWW1Yqk+QPjxwxBRuzIx0lYvaAbyHquWKx4p
         Dbq+uPkL7iZeOiSGH3fDuFD1PiUWPTICew1aw9b6EidAXfaS4W8D8zL6YtTAggjS0oXA
         rAwn9je9ZK6vNFbiMbre8txWm2Rzy1zoKRnztsOXVEK9VDar9IgJURL08HRcR6Of4s/m
         JXn1PXU3GLfAhAOivxufwnFoNn9BiVLck5jZYAEbZ2dMO2uyPN1+N4GlO8oF8J7tuTek
         GHBi/GNPQ+PT32UGTmazDk+ad8BTGgAVZz1uKHmh6/LbGVpfbm1O0P3D0NgWTevBOdYW
         j0dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=BeYxegor;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OcqX/IIPJGA/FIzIuZRV0oMVA3qrMVi5VumQItQDL0w=;
        b=qKcZ0yskxGDsW4avSsR0V3FNtlKmkJOfodMAxJqWpWEJuuiNYrIeMPPv4GG4DYL7BH
         wRtw2i7Iw461/+TJS4aJGzjZlqWLQUSSTljnUAqiyOiKAbTQ+498pBW1ZnGZrlAvqxqM
         7TVwLiWC7kG0Z2Cu9qHtZ99+/2yJC1q9dTdWf0QgpwfF/n5QL0WDb0nLNmtrWsMp7Uq3
         C3xTNTpirlklai2rCU3Am0CoLkdannUOphGORHgRzdlfw79yYLQsk+INylqDj32//YfG
         i0PZOX4VMGDMyvjBLMyieMNrDB7Knj5XjlkwRgEXYVWFTDOXzmQSGoRDgf4IBjLeOfAE
         M0qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OcqX/IIPJGA/FIzIuZRV0oMVA3qrMVi5VumQItQDL0w=;
        b=Qxbba3/s69CShCsMGQKFBpJ0a63XzHrE8Dy2ir8/G77gAyRF3b++AZJhntIpOoEEZJ
         OGi3BHSEiU+rI/YtLg8fwZWOSOKSumD4YlWh+lzL90AfxIuPOvS0EJY5OM4NIPBPug8R
         +mlfsCUDupA6Q0+rG+1Df+j4zZ9A5u5OFwriVTYivZ6oXdHzgkOkB+AK0k1x+eWbk7Vu
         jeJe2hphPxGi8tk8dUadqK1odMveB/FMnuatI+Ln6mG2Kk3806slkSiEg6Gx8dK833CI
         XrNNTRKUTxF5U2H0BBVb5DILnHoZJElNaerOfKzVaBYG92OFC+0j3qRoRoJmjCvyg3W4
         rf5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530F1gfgavifKssu59QhR76jak4rMQ+3ssB/jlyNulKXpy6C2UKg
	CfdJpv3n/QUIcQ+FT5wkI10=
X-Google-Smtp-Source: ABdhPJxzO0WbNl0bydfe7vFc/0IhbjZkZtb5WQqu9vZwnHU7jRqdvmIynujLqvvSYpy1S8iz2wmKAQ==
X-Received: by 2002:a05:651c:324:: with SMTP id b4mr8920555ljp.271.1592211903661;
        Mon, 15 Jun 2020 02:05:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8843:: with SMTP id z3ls2449774ljj.11.gmail; Mon, 15 Jun
 2020 02:05:03 -0700 (PDT)
X-Received: by 2002:a2e:9187:: with SMTP id f7mr12939207ljg.450.1592211903116;
        Mon, 15 Jun 2020 02:05:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592211903; cv=none;
        d=google.com; s=arc-20160816;
        b=V32jzBMg/EhqsTq6cKe2rRykhgTBKE0XAXMoSya2TUkxImhV7FeKpHoPU3iVGb69iL
         MWvOxS1XdGbhlcgxljQBVK4D/j8CxRvDMGDsv9itQw9yUxQSwtAOwRQyC0jtz+GxKsao
         4l6KAQAruN2OsIv3tJHHUSCk1y3heblcBVwRUS7HOx0kJZH5YV1d/JlNrfCkucyrX3kj
         t2rP73jN9qx1f/1ONhBPZFG0wEw+FZtrfDRi9AS+3hX6SuF6DfhyJW8//4BD7j6ObSgl
         HNr8Lf79E9bMk7fX6KMtVGMZ/XSg/S/AlOGWJvvqL8iEuqWQeLG5+7uXMpntopt6Y7ME
         O2kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nchE55nRntl3oCk4FdQW9onBhZ1ErhGUuqk3T1bdYUU=;
        b=MOfaod5Bkvl59RHv27EkVSE8HNYHcvH/960QBLQm3DYCyuQisnuPaEZVu7zUlFdBuS
         fcZEz1YEVS7hGiYKf/yotSvDVL1AJvguSWdzbvHFBnQ/XVWezxMR6yZA5RpA4qWWgpK1
         0AgthdyNrU7QrzVmvp0SJWtqa8TiwIVfRWWd9Zat6NDPUasxuy0f0gmw24yr2VZb3AWp
         y7Y4Ho1MuX0Lm9/jiDhjEaFyiag9rR3k9ugg+8Tmedd8LvAG3VJNCAtSazDDGB8oB1RD
         7UsJUO7C2QdQ8CKffoWb7CHlNzbyOcFyF5wpuLp8+mt+cbpTEC80E3KJkjWpBZGiYhGs
         esxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=BeYxegor;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id v16si589743ljg.4.2020.06.15.02.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 02:05:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id u25so2578638lfm.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 02:05:03 -0700 (PDT)
X-Received: by 2002:a05:6512:488:: with SMTP id v8mr13266432lfq.205.1592211902846;
        Mon, 15 Jun 2020 02:05:02 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id c78sm5284434lfd.63.2020.06.15.02.05.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 02:05:02 -0700 (PDT)
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
Subject: [PATCH 5/5 v10] ARM: Enable KASan for ARM
Date: Mon, 15 Jun 2020 11:02:47 +0200
Message-Id: <20200615090247.5218-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200615090247.5218-1-linus.walleij@linaro.org>
References: <20200615090247.5218-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=BeYxegor;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
index 6ff38548923e..a73c55fb76e6 100644
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
index d291cdb84c9d..6a6059f8bab9 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -65,6 +65,7 @@ config ARM
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615090247.5218-6-linus.walleij%40linaro.org.
