Return-Path: <kasan-dev+bncBDE6RCFOWIARBMNRRT4AKGQEJZVFUCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 20442215733
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 14:27:30 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id s1sf5861354ljo.17
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 05:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594038449; cv=pass;
        d=google.com; s=arc-20160816;
        b=PAlli17sfdSFGlUKiuYyn7Oeglp/wuYntdC2iX/Gwu4jDIHOc+s4DdXDEkwNisZRdt
         cBVY2mH6W/MKk3hxQzEk8YWieIjv4CIlGeJFRXXsG/P9d4WAHGAHx8D26hSQvD772Hvw
         F7ZEf2jtJO6o6K5IKWpZ/yPenZq0Ag6DNBAcTPiQfFWUN95iQcg8dDDgj6E/femTxQ4Q
         tJB+w9sZZuumjVQh2+34yijWpaRGRR1BRXybGEStsu9wF6Eyl+RveVs9rpjyUEFKceKR
         kpd2GzKm2cGezxaPoPGREv7pJaqIvlipVMQm9yMIhK/+1mzSBA0eTBFSPfqWLDmWAUyX
         PE4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6x2YZgbH9NIh1kkkIAXOnFFooXlz40IctTk6Jprxq7Q=;
        b=nax+yn7AxWpEHFjyB4KUSgaNFyYKHqGbNSBYLQVhNS1x9OAWNQxsh1mnRlgbNO8sMm
         jdMc/RKsVM4qxnIldoFPWh6iY2VkvuW7NDgy7yxdBo/9xHU6FzLi/OkQouVALmamr/hX
         MrxhwdvQ8HOH+nK19YqGTuNqUbPhqEiGRlchzLrvT9Op3nJIUSuAo+TKSyecI1SGhn5d
         PBHUux2ohBNepojKmb3dSagmgTDFpxbzY+Do5iXv5RaNGPNw16vaj00ECkdZuz87rbi/
         sPdBtfy47BIsnZu5ek2d31IdzOzcD6PtUsuPxZi2qixmg8DaCUimeGuCGbMs+oH4qC1N
         PKsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=U8cmE1A7;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6x2YZgbH9NIh1kkkIAXOnFFooXlz40IctTk6Jprxq7Q=;
        b=R7F0SovPQzT8xjFcpnt/1oO+bxMwjvK+DEI1hv9RN9fstg/BRYzwPk+2JpnJpElj6Y
         4BYh2gPKr8CDa5Lf0dPLNsO/YertMYsCbZsTyl3P/q9s3T6aXnn25pzqDhQN6KE3u3ga
         73Hf6HWMs+vVMxYGQuEazr/FBU4uC8IyYrzM6GgNwr3iXJbyeSbSXO1vPGHwRq9jXWmr
         Ep7JsEaRjVURRK7O6UAGcTuA8AFoNsNYDLtk787Oq1/I2ae1ljBs+/UnkcJJqKkNkB1J
         pBORe3+WEXoo6N4zGbfGjNyqdLQ0Wtzmi0DAigthD11aEUT6n8vEsd6MBULiLVTeX3b6
         KPVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6x2YZgbH9NIh1kkkIAXOnFFooXlz40IctTk6Jprxq7Q=;
        b=f5nW8b1b4VABDsHA+8QL9JHSG7CsWi/bnRqJybj4RTHg6rsvMOUtAooi6Aw69pAgOf
         pG58DU4COWb/l7nxYT7XIoPpfyfSnx+x+qK/hQQ1alol5AYYpcReylGo6wsX4NKe2CNN
         WIiKmDO/2iC4Jsb0v94wPHe7rhkrsB6ia20Q2UOXQJZUIzLxjDOe7a3FmhefBhAGGSgb
         OKoM2fO63bQL/Ioc2cAGDU9+tE9egMcHaTt2+FskYX+4zijCJjEzBKCNT2mBQG+RtCtg
         ywIueEVXJSaAZc/HfuQmaslZi9EN9dJ+xf+4lPKlIEz5L3ywyn7SKwKQiOVh2+SxdwSr
         0piA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333BkSK37MoUdiH8pQ3VEwy78QAyG1VRvQAsf8qXHNz4dtpvdrR
	YpuBAbYz3YkqDKt1eBwFcQw=
X-Google-Smtp-Source: ABdhPJx9Q9oCQ+C/4V4Aygco2DOJDfxVQdQsHr+LEdatmNMU/VmO+h3R4d6rY0YoomLio8igABHf3g==
X-Received: by 2002:a2e:9acc:: with SMTP id p12mr4166163ljj.363.1594038449561;
        Mon, 06 Jul 2020 05:27:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9809:: with SMTP id a9ls1192501ljj.2.gmail; Mon, 06 Jul
 2020 05:27:29 -0700 (PDT)
X-Received: by 2002:a2e:9857:: with SMTP id e23mr24138078ljj.411.1594038448979;
        Mon, 06 Jul 2020 05:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594038448; cv=none;
        d=google.com; s=arc-20160816;
        b=hXvYA1cBHG/Cnr/DeFxY+wwnwiAlPVKOo7RSf8nh67iHUt+RaG1Ram31VnXSuMVIbs
         yYDxi+skJnGLhi/pqSt5nu8d5+9IyRhiQtF/7ic1wea1PGlrNOPbxx6F8/gDcEEK8YIz
         dOXaAz+lWMsBIKzl7OQB2ztwB6LLPe8HqaBD6WSTay5U29ZWNkhG+1g66Kq3hxzVlbW4
         s6fSAJy41s5NV4WlAoQVuPCDIa30PyRYOiVAUMK+iSyI45919qf7Xfn8I75O0ER55Ylq
         M33xD7pqYFsnLIHoow2s0iPS2re3xWb2UGI4zQlHQIOjUhWqDK4H4mvvBNQlScH6ZwHh
         ElWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zrZeijvKclD0LoRMeuFsiIbPHQb2TJSstZW6Stmx2xg=;
        b=bSfr7PXBzhWNmtGl+WJ2yT0i94LpSUaP/hBkdIrUX5tKLMNy/99ZuDP/e/vHMvnav3
         OCGGtGG9ydj50YhltpHVymK2QWgJpT1aJqi8ryHMJeFSR3zOeJhbir9tff90VbeAdmmO
         LuQpzFEAeVirquodZUvg0+6RX6/Ouem2Q+R1JEIg9u7WXNnbVLqkJDxovUIzil06bclz
         s4pXpCiLO1dHwqT5XBvWbq/VuvKJUpsnzfpoRulejiCMwRKNLrGkiv7itNbX7tOdz2QI
         Hlln2Zwp5h2luK2gTomHW5j56eFm3jfgkNY+3zsaNckNpJnuFGiGFzFw0bxyZImmog6w
         QCjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=U8cmE1A7;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id z3si996809lfe.5.2020.07.06.05.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Jul 2020 05:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id k17so9670761lfg.3
        for <kasan-dev@googlegroups.com>; Mon, 06 Jul 2020 05:27:28 -0700 (PDT)
X-Received: by 2002:a19:7407:: with SMTP id v7mr28396547lfe.4.1594038448737;
        Mon, 06 Jul 2020 05:27:28 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id v20sm8534223lfr.74.2020.07.06.05.27.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Jul 2020 05:27:28 -0700 (PDT)
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
Subject: [PATCH 5/5 v12] ARM: Enable KASan for ARM
Date: Mon,  6 Jul 2020 14:24:47 +0200
Message-Id: <20200706122447.696786-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200706122447.696786-1-linus.walleij@linaro.org>
References: <20200706122447.696786-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=U8cmE1A7;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706122447.696786-6-linus.walleij%40linaro.org.
