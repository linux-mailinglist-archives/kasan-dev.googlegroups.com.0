Return-Path: <kasan-dev+bncBDE6RCFOWIARBWFCWX6AKGQEJLAUSWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC0CB2923D1
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:42:00 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id o15sf2968179wmh.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 01:42:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603096920; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQUt2an9P4RJ4IzS4iCNOBxA0ewMys9Ik38cgzDJ73TJ93ki214ejKbRAL6yp+2oSE
         RVnZ5yBZSNP9hxcT7mk1I+AO4ebqHdF+xDm3risr7WFYTnmpXHI/2FMqseto592DYE4X
         ZjqYJH12PHfvCyzbyV0B1bn3NkovfLgJVvLkGYVJBupsLVlnWdT2IIDoCQVPpkSUFQYs
         Ga7C97qATc0mWII5Qoy9pXHf98pxRVy+Xe1hv5pABKiezSDpE1dNOOQ8xCizc7oGyKCF
         xtqPPpT3MUbTlgMvMt0zNg4WTXshhpPHIr9Wya3GeiGTKN7epw0NiRJjxKJGMeLFD7X6
         H5wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m8knMLMO28LKDiC5uelT0DdIikJtmzqzrFgIqoZ+oFI=;
        b=atdeOM3WOIAEUf1pvBEi5qTh0IG6wyS8cusBNNMn3PNNnRHAHmnY+7tGyMuVxbhGJ4
         0aZXxObKHQKS1qgfCoRL4iEXY9a2G84/gBw+Tq1xKdhFLpaTbg2eaDbApIn00CtVKr7j
         sQOLDo5FHZbb/R1mAJbDL8edVPueR0yg9SY6nogbm5NO378vDE2/YdXbLqPHbSI6eORU
         6FhQGEm7GA52NmOI3L2jXjGIjDFiBdlK/MiuX6daZQuPW/yCV19Rve2bHXb0onMLWu7j
         mhkP7bXRyv0lr5DSCqEWHDAq93dpV0lxIQlqMEB42nUa6TqF8wcndzXM1eVmoBGXcSRa
         8rBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=NwlA3RLQ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m8knMLMO28LKDiC5uelT0DdIikJtmzqzrFgIqoZ+oFI=;
        b=ksg/goYKam6eL0wjnPzMHfU9qOLJGpDv4mg1bjxpnicmvsYEFGQtCzdDsAnwzuPKZO
         dXpExj0r/AttMsXtC6kL9pAGSw/IuPu2MmTMBRP4jvEmoPXM/zcUBv5rd2QYA9tVi28G
         SqpZTaDf0TcECsFi8U7GnITFHNkqegnFe7Di6L7SXwlceBqFfdrMJg3UAB4kKry7ln8X
         1aY4T0oLccEu4yhswOvHTkpMNmMHz0WSA/1Hd15aXVsLh2flh8WJZWQ6OVz7Zzuu3XeZ
         pE5k4W+PPHHdhDJc3wR+1ZKyr31C2ZmHsRx1wU302OnIls0LK41AvLfqAwg+hKN2OfMJ
         75lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m8knMLMO28LKDiC5uelT0DdIikJtmzqzrFgIqoZ+oFI=;
        b=L5WH9sCgsn2viYCV/omGSeuBQGdQC3GkzuI5FOroa8HaU8mRo9fcK0KPDfMbXtsmqa
         EBM7Q/YUODahLzNcGSC1/o22QwOOpZmnlj7i3zKbJeZVJqlH1/E9nug/cCiKhdV2eVXI
         jnMqY9v6KuIyzhVZtBJak5xXyft3GTWU7vh2CVgNwygX8LepK2DY+dn21mP6ns3ls44Z
         k5UXhS0IXceGrzi41oxc5cWtGVNUHg5nUKXsDqEEkgaaFuoG+emiobXxOYqH/EE0/fO6
         tWhCURguvmmcnaSk3lXay9xUCuIWQ1iGy9H1jfMc+wUUnvMDltDbw04cUDxVNWl/aeY3
         zscQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hLyrmJy5EETLUgMxqXiPTDE4ZU/Nt148FUwBygHGyq66jf4/e
	GBB7Ej4lwZIm9zJDUqb+3x4=
X-Google-Smtp-Source: ABdhPJwmU75h6dk7dNQISHO0ek7IlkDy4WsQYvsZTvRKT1RawtaCnfKjPFtAwAEmMx3EzKyDjzoefA==
X-Received: by 2002:a5d:5612:: with SMTP id l18mr10478356wrv.372.1603096920586;
        Mon, 19 Oct 2020 01:42:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7d02:: with SMTP id y2ls4366325wmc.2.canary-gmail; Mon,
 19 Oct 2020 01:41:59 -0700 (PDT)
X-Received: by 2002:a1c:bbc6:: with SMTP id l189mr17316330wmf.52.1603096919729;
        Mon, 19 Oct 2020 01:41:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603096919; cv=none;
        d=google.com; s=arc-20160816;
        b=PVFqrtJo5V+uuaj4Pt145oCxkNyWD76/xd8pZ2blAKtQlXD+II31MKGiyTBBxvFTmx
         JZAKAXCyfJbxx8y5qWaT9Br4Wmvkj6K3yo4j59s3SoVENQxjlnkC3iwyhQOYG7BA6Cr5
         L63QvV5Z+RdRFpxEDekmDi3cy4nxdREZ9VJ73y0iKXM04adI/v/wlucxsfrWIZQgdTH0
         hKXhudy1jdBXxrakrYQrrGD3PCboEI8oYVmJd9oy7p2vNf2/N/dnb4BHctgMzL1/hh1k
         C3LZ6QIGxctSk1ZhXakUUIzOiT/1N6TmF6GpEDBnVGnfPmHCziN2/F2zip7vTAqkn8d+
         qY1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hvW5D1tB1h62vzTkANn+LuUgiNyjCx5HCXo2cpf/5sw=;
        b=jU0AdNWMno1yItqEgSmIfINh2f+rNYv9WF2A5ine17QlNJM093Qv3neKTATgH43Q4H
         g1UHRvQ9Xu1WvhWXoZvIertGplv8TdHJHGdQqM8lKiTpNLFfvSNjsjQB754SeNWYF4uJ
         l8IMiupF6aLIbb4UWMm8Ha3MWWrCP+ljrnhUVT771cCajcSCan4UqwQOmWODcY3G4RZ8
         xD5Nisusz6ZqggPm8Cqa3ocSCKxy4qQ+urZeSgE1MAbXfonjMNf0YzY2w6TipcflSFOS
         kFgYWEH8v52+6h2Myn8Dy1/mjb4PwI7b1Bfjbl3PR+oz4uRGG14dLciyCuw9EDSVR8Z4
         Mb7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=NwlA3RLQ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id w6si328862wma.2.2020.10.19.01.41.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 01:41:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id r127so13116196lff.12
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 01:41:59 -0700 (PDT)
X-Received: by 2002:a19:7719:: with SMTP id s25mr5025636lfc.521.1603096919130;
        Mon, 19 Oct 2020 01:41:59 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id b18sm3174795lfp.89.2020.10.19.01.41.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Oct 2020 01:41:58 -0700 (PDT)
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
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 5/5 v16] ARM: Enable KASan for ARM
Date: Mon, 19 Oct 2020 10:41:40 +0200
Message-Id: <20201019084140.4532-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201019084140.4532-1-linus.walleij@linaro.org>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=NwlA3RLQ;       spf=pass
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
Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v15->v16:
- Collect Florian's Tested-by
- Resend with the other patches
ChangeLog v14->v15:
- Resend with the other patches
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201019084140.4532-6-linus.walleij%40linaro.org.
