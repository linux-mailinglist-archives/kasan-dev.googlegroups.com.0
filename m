Return-Path: <kasan-dev+bncBDE6RCFOWIARBTWM7X5AKGQEPXXKWCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 286FE268B61
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:47:11 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id w7sf6896727wrp.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:47:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600087631; cv=pass;
        d=google.com; s=arc-20160816;
        b=e4TWGpg9DMRubTqxrsY1bPJJNBXDAUm3MJ9y1ZcrfRmByu07Z6C+//yM/Od4MmEy9c
         AJXjuv3JC7z8fal30M9k5TeRn3KHQorCcQxsyYzK8vpk99BZqSZR68AsC5qm6+ZomESy
         Z/S4BPXOzDrcHBXFR2JmJOzS0hboW++alAHQ56viwe/pbn/lVoNRgXS/MZ+DYQgU01Ip
         mdBKdRsqU1u6O4JDwiYF7esfyKwKg6P1C2Vso+OtGuhC3qTxA3DsbrT78LW25n4E+2+V
         DE6eKH/JNSnxzavu6wmtt/SWa9b/bzoiuTiVCD40PbahPQl/CsTkMc8lsyd+EeRKmg1j
         meJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SxUTROXpWCA+Ca2KjuL8H1pPH6knqOlekwntvxlnvYI=;
        b=cKfSoUEw55WJqi+en/G9wRSu8Va4gv8TOsrDNFMjd7O8u7mCzkm9opBnviRM99MXHm
         26irz6ljtC7gHe9kBOJjq6t1FqVL43nS5RQbVZfOx0RWPfAf4Ddm6964FqA4Tvx+6kc0
         I7q2l3CQjxe3++cjQlPTLz2FM++kClBPy3w/AK3QIk6u/lIlFB784wm3NPEJh+7qjKad
         VAxcYvG1ymGC1QyPz6xkKRaWGrhw4zOdFaBPmIezZZvkkTe05E+NyMZ4/yd4Qkz5lClP
         oD0dF6xC9HzasoGZoG9NkFD9iaC/CrFXGcSfSqLl/GrszB0gJvNSW8snkP9vUYqPZpGO
         hbYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=HLM1s5T0;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SxUTROXpWCA+Ca2KjuL8H1pPH6knqOlekwntvxlnvYI=;
        b=cAvVV5qMOYd7/qt1hn5xf4cS9uBTp51/uRz4A0kqpCITrt4dRL/mgAQ5eihfwECkkD
         5JOVB0rkvztOKeKhI1OdIA6VqFJDl83O/K+WzLzLvcGnS6lTzdOUMAMz2JiJEQSB34Zi
         vx0hNEeBnEVC2C0aXVLNOX0QLPUZ2Ldcixz1xvM4u4Y44lbwazIqqgjHfN/CBA6DarnN
         VVIPAiGKDc4+Ecge96f7xfniLYE+EtUg1m7o0FkmA+x+MZa5w9uUup4mPqWUYc0FUPX8
         az1IhwdOpjYNlCe6QkZHek2KmpD6mXcCARYPzI6dTpUWJbo3m0u8i5fhDNHnNjMZvOr+
         Jlag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SxUTROXpWCA+Ca2KjuL8H1pPH6knqOlekwntvxlnvYI=;
        b=c6CSfuVyRxz6/xxDTmbsSuqFHze9bFkx24z11SffYmp/6Yqmi0uyysh9EEsMztLXSM
         QNLHvBmNQO/ZcPAIpy7cJxWCZS9Y3aXMcleil3q9d2lA6gQBE5t0FA4hfFNfo9b1E2A9
         cC8VIVACesq2rK1DOKnXeMO3VBXj/dX+1MldcFznKoeNfJRIijY9OBlMTjz0Qci3r5F4
         pFdLqpPjMG6FdoPCXu/CIDE0afKCYzbws0SOXZXTyDelsRRlro/FzeP5YeTM9kLyZynQ
         GZBYtVG7fjbDH2CqlErdtM9w9IZ2vwxejSfGOZfrDkmoxN35wHvKFBbhRdX6fqLo8T8k
         PeAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hxncC4FW3WFACodLVSTl3EFLx0pNMrkJdLnZDDzNx0Osr98D2
	vX3a3I67ib+FKoX4ymUf1tU=
X-Google-Smtp-Source: ABdhPJxb/mlrmOUn0uqycWWtv5VovKYueZbG7702E1Te6eLptUins8JDfATGGurAROhKgO9247Ktlw==
X-Received: by 2002:adf:f203:: with SMTP id p3mr16067518wro.339.1600087630798;
        Mon, 14 Sep 2020 05:47:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls7817429wrm.1.gmail; Mon, 14 Sep
 2020 05:47:10 -0700 (PDT)
X-Received: by 2002:adf:ec4d:: with SMTP id w13mr16309900wrn.334.1600087629844;
        Mon, 14 Sep 2020 05:47:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600087629; cv=none;
        d=google.com; s=arc-20160816;
        b=PhXcoNMJQiC0uDp13VVG4P+gVo5ySrmGF7QF/7l4rM5heeQPp14CiWwcJyUrN2jdPN
         r8XvSg3JJ+2af/Wt04s5XwXA/pSp1vj3iYM8MdyN3oMyQS1BUlVLNeIyezjIZsiXRgqs
         Uf5kqCjHxIahBo8n9zHSGdICK6qqm9U/8M74qQdfs+as4YdKXo1ZI7TtTZRFYK0j6XVY
         ucHt6MqlxIw8YY5BrqoboQDE3k3sg0wv6tFSOFUQOPaPyD1yYUfOLrJQ6qLm84U7c27x
         Mn3HXdEJPXKL7z7vbxgbJ2ORXLokfnIo35FHdiFhOMT+guefsOtFUjd7oeAGoY89LMb5
         MbkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f3LaHau4pywVsgw8aKJRGJpwtETd/TjzhlH8i8Fv+JE=;
        b=tJQkOBWplpbRxdqyWR67AYScq1NOIgtbZmd9kgpx7sZT7ngGGbD3DmyOZ06Up5HyF+
         js3+fKvDuQ+Aj8gQ7dRuvFCAU1Hu+8R9eRGK44G28hY+LC5BU4sJs+AToBP62Tl+GJ6x
         de+A40vfU/N+nAM9X2cAlacHgX8MljdLLg3qzp+XCikzFqQohWaIFJn3xWgSX/fKNoNg
         mSHb/peSbwpHzCmG7CEGBKNkTHhX4sNcElAVOlIu7jDnMwxf5kGYZHfLLN7BX5LFsbSb
         eUCq+sPHtt6d2w9LfIpTPbk9vif7qOvjlTDaZ/oyf8HGPAyAgmkDLefwAg8y576AsM7+
         T30A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=HLM1s5T0;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id n1si140573wmn.1.2020.09.14.05.47.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 05:47:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id z17so13240102lfi.12
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 05:47:09 -0700 (PDT)
X-Received: by 2002:a05:6512:338e:: with SMTP id h14mr3978317lfg.422.1600087629311;
        Mon, 14 Sep 2020 05:47:09 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id e17sm4050173ljn.18.2020.09.14.05.47.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Sep 2020 05:47:08 -0700 (PDT)
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
Subject: [PATCH 5/5 v13] ARM: Enable KASan for ARM
Date: Mon, 14 Sep 2020 14:43:24 +0200
Message-Id: <20200914124324.107114-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200914124324.107114-1-linus.walleij@linaro.org>
References: <20200914124324.107114-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=HLM1s5T0;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200914124324.107114-6-linus.walleij%40linaro.org.
