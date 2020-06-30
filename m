Return-Path: <kasan-dev+bncBDE6RCFOWIARBMEB5X3QKGQECWVFRYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id DA11720F5E9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 15:40:00 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 64sf16922780edf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 06:40:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593524400; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQVTFcY8saC7EZgoMMLIRigPD2P/q4GyKkUhWcnbewbXHgVqFfu+KH6Y7q79oril7+
         uZvgGw9TNaEhmfZqvW8b/8uWuqbeHqFp506LZk99uhU0UfqqFlvZ9vDr1eozk5kgU+Cl
         UnAG4UNmxEEr535dZuQT7EX2JxMQYeqJj0NerAHHFrZRpoXlpD41s8VeAEL0E1YhFPXD
         zDh3/TXkuhI1Z1pl/QhoyRtl0uMVWjneGGFJv23Dt4dnH91R3eagP0dVwhDpI/iFvgUm
         33nU/JwJWylWdpVvtYO2xzFWNSPwdsWsWDA9tOM9wRks+M7IWsl/7kyzOcrunFaS8A6W
         WBHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JrUJAzr/UP4Ac3K8WY0AZOgO+pmrFj0ipCduAWlg/3g=;
        b=roTDoRFywwxnLTBdBBJoesnokw/eah1PgIiBTK7TCNKUywIx+1T1BWCSGKkjK1bJqv
         60Dkd9stcX2Y8Q7GvZQRkogV9o4gxskKKc4K7D0AcG60S46gdkbxHFcG8DlLh4PTQn7e
         pWi0XiY10LLFsE/2gpdsQyRr52TjBDRPrxoUzFibiX1WjvPQVzsvz7mj824b8J+PQNYO
         W8cHU1M2aEoV/hiOsZ/y5Pqj9V4DydRitih9q2/EplBQYl0VK2BhMRL2nBSY4wv8/ugA
         MQWnl+FO8v3TeOryh/yw3esLyJgtDCa6yYQILEyF/Pus5SMW/rQDEZ9hizLJplm9cQgq
         6KvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=GNazyTG+;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JrUJAzr/UP4Ac3K8WY0AZOgO+pmrFj0ipCduAWlg/3g=;
        b=sSYb1bKA89Dn9etLQbR8PZXk5ncV7TMOodu4tyV3ZV17sNQCU4GSL2GKx1lfzLvvpv
         GariTNGMe29KO73IwNb0JrRSGi3e9+d2ClAlTZtsZ8rcFHJUeeepzejFViKFtGDj1AMY
         Z22Hv5Bw1NLdrGk1wfPsM29pOXHkyu4zlPQXnXutOv0z1nUIm1ts1hMBgBXI1+hyj64+
         T+ghdQ9MZQRVnNYetY6LINTsknSkeua8xuG/7uUSHFGYgOyUNA6wzMyef8nycSXs6sSH
         jBBdZ15WF1K/dtbHc/v5OEGUP6but50G1DLBxnOFfL1ybi0E0mrYR483n9kaY+WXDwCg
         P9Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JrUJAzr/UP4Ac3K8WY0AZOgO+pmrFj0ipCduAWlg/3g=;
        b=PgoXOSffE1DGO8AKycyv2FewyOMrhZHfk2OeCwxBBR0j8Km1K5HOTFgxP5DpSUGk/m
         3gcwqzV+nsMD4xezYowylNzEYV4EKalWWwxSHpU6iiyYXJFOHKZdEfXSp/1LlF9EJZUX
         3qs8dXb6R0qEgBouPEUAxfTGTjFoixdmT0rb0vfpq3iuboxzNCmpLYDeKO/GlM9T//VH
         CFp8CDXAzsOI/S4SyBKfRhrKZJ2GGNW+eC+6zy5G35aMF99NczU+tbJVAzQ8ZQdUBl5C
         6maDnn3k31B72l7JnXfl6/Ox/wU9Fl0fE8/K1QFgGi7Pi34nUeHMhKBz6GiO+5MwUhlO
         WXFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xgedUUCH6hAX/bR+xcmHATqkjKnOJYkDKO3I90Hud27j9iQpE
	B6uBpvgC3oVSQtIAsQepd5g=
X-Google-Smtp-Source: ABdhPJysmOzMk5FMnGc2oJFXytP23D5ryJOQJDd37+E5MJJ/PLM34TWWxfL/EwxqBF5ZO7eEl18+hA==
X-Received: by 2002:a05:6402:1a54:: with SMTP id bf20mr22153368edb.69.1593524400679;
        Tue, 30 Jun 2020 06:40:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:ed8e:: with SMTP id h14ls3242030edr.2.gmail; Tue, 30 Jun
 2020 06:40:00 -0700 (PDT)
X-Received: by 2002:a50:ab52:: with SMTP id t18mr23554633edc.195.1593524400259;
        Tue, 30 Jun 2020 06:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593524400; cv=none;
        d=google.com; s=arc-20160816;
        b=VMfkR/0EAFkgfhdQaM/H2sF5aaigq3D5zPO5/7EODsqEYQgcFHC3GPSLoxq/6wks3Z
         xLxVcNsDrT9n8aariHRG1lw5mQhnyI8bnrgczsQ+ICxZ58+Qi0h3DvA3WZy1K0772a7C
         q+w4euWn1gvdG9PbNhfvlV7sXmEnvLQzOBJLZa2gcDZsIT69v51Lmt2C9NN0SFkOh3fQ
         hjsxRcnGaWpK4ZxsTDytrIZvXaATpVF7CAHmQljWmjEfo/T9+zQer1ytz8ptnElvWU0G
         RaEE6fCVUsAjMTLvIxFk+bRlMkvFV6MAiJxRVXh/G5R+ZYTBcjt98xaYxRN9LKYIGrRp
         qmxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LVOKV6YAweIQtdd0AenNdnzUPaOgbv3y0Z2q3n4aE9s=;
        b=0XHGd84mT4wG0uiDd5CnnR90YKVD3w+QnpavgzJhe7UIUxJnuyiEwuIb/VPVu9HNUm
         KfzkcnajM4xIj+6P9Phyr8RzBpswIRxbmlxwZWtRBgXtU6XvZnSullJfZhiWqDjb021S
         7ySpUYYv4t92aTTDjV8MUecqjfwJusmLXGK7xpJXmYAvnNkdblamf+T+whsvdly2Ciuw
         eXR/PhVfqZjxjLSeiiOfl/CaebfzmRysaH6gb8vjfDxPaRsHQU8LrA8ezdQxa1gDDE35
         1hu55b+3HTpTSGmIp1TwI1amnHiht5Mi10swtpahJz7AgpZme1ZMrvcF151nG7YWlmIK
         N54A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=GNazyTG+;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id q9si192787ejj.1.2020.06.30.06.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jun 2020 06:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id h19so22564046ljg.13
        for <kasan-dev@googlegroups.com>; Tue, 30 Jun 2020 06:40:00 -0700 (PDT)
X-Received: by 2002:a05:651c:54e:: with SMTP id q14mr9501732ljp.279.1593524399694;
        Tue, 30 Jun 2020 06:39:59 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id a15sm737819ljn.105.2020.06.30.06.39.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jun 2020 06:39:58 -0700 (PDT)
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
Subject: [PATCH 5/5 v11] ARM: Enable KASan for ARM
Date: Tue, 30 Jun 2020 15:37:36 +0200
Message-Id: <20200630133736.231220-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200630133736.231220-1-linus.walleij@linaro.org>
References: <20200630133736.231220-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=GNazyTG+;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200630133736.231220-6-linus.walleij%40linaro.org.
