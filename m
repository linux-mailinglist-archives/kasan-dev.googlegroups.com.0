Return-Path: <kasan-dev+bncBDE6RCFOWIARBAEH2D2QKGQEAMMYMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ADE01C8B49
	for <lists+kasan-dev@lfdr.de>; Thu,  7 May 2020 14:48:00 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id n127sf2464303wme.4
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 05:48:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588855680; cv=pass;
        d=google.com; s=arc-20160816;
        b=lASF6V6rmn8tBUBRX5pDl4bVJUJN1wb8TkfyBwrKNPTieEhQrOV9HLVBj8v/Cv41RZ
         LjHM2ofeAigK5mE87eMKGBp3rkYgbURezYnrFChayMCiWBCOHZK7Vpednhohhmt08BdQ
         Tb9PIaaEgdNHlq0E7nodVlRAAprGXxa8EQFugQYgomeFzSQPeN/Hu2Y3MWK9M1TO/Z5N
         M9Duy7e3s8aV6ocsLRH9kWCdDZyOmg31YouvM40OxVfst1eUHJiMkmBPmAqiurSQ7YRZ
         GVnI8Lohl7/C8owjZu2ITuuV3zhUVs204xNTj+z5+DyqtFXE19pha59jWhWYK8xj4nx3
         G6Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=A9qIw743x3KcCs+88whfXznMJ+LGR3zlr4sIy4epi+w=;
        b=Ol0FwViCyvYSeGhimdNe58U+BXMsaXScvWx80m5t05TChmEWQD0gvqnzD1ufVKRqzs
         jWFiMybOk5w95T9X8TV70+z7aHDepcWCtazAHSTEfLnw3uhoJMyCK45nyz9lGzwV1oS0
         EyCyitr//N1jZEULIP/yDPtlko0krUMSxNFkG3vt8OF7+VWCJr0iGK+xkVQlNB5ZO8Qz
         bd3BpBQzKeO5e7UZeRDO7DlPzRPiEeqf+v0L5oo+vLXUtBXiao3vb8CATe73K5OvZ48S
         BEzmG+o2ayFV1Esl7kwClKuvfbmA9mi8j1Xw/v52FLd03Uk55MA5cJBtE5zCM6XuUoaN
         ZGxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=tV8Y9hHU;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9qIw743x3KcCs+88whfXznMJ+LGR3zlr4sIy4epi+w=;
        b=P4VZSozW5ICAMD+gASV4KLDNKo/5fVc7VJfjRUmQPPvxy1VBdTTlb7gerQoupu5VMA
         u3WZ88CokiRGYatJP451cXR3jJcUGbzknvsDvW9J/n0A6KDrQph8WlP52djSpemMsr39
         9NhkPtRw0Y46FWD/iVCO2BdAkjsmyvMBChe3QWvXSne2c2pWSUsj9ENINDONzgwGXBKj
         gSuvh8E0HL3MjuaOKpFiQ8UOITm5fZeP4IUwydwN6az9ChVQ9BOL+qyzOlNVlJJGpkgV
         TQX6k6A/QmuW62HGxIGFPyGiUV+NKhTW2Di+H4kwhG7YjFC38kGNcX+IWuqNDB9xobEM
         Fz+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9qIw743x3KcCs+88whfXznMJ+LGR3zlr4sIy4epi+w=;
        b=ThJQqvtqIvIGtN8D1amWTO7ZmtZ2tlHWPL8mxGw+JC9Wu2rhBOFjeyR1dOFKq0CSVF
         BYzewj1W+4JqfpiI6Iaf5YoDHeTzayyxkiNacvydjXqj6W+KkyKLV5jOw4674RDKRD/1
         uXIlfmsfVblpHWSqjYxL72HG1VB5oG7XqGuvhcfa4Bqdo2PD7JiXbzAP6gluDdfAiW5/
         k9WMBUp+RKEmxFNBVHd9wrmkgjRS4+Ape5/tGtROKTid//cE16n8eDCqcHOHue7lEDsM
         KE27x01f/RKx4VDuKt2IcfOdsQV86IO5dEvDuwIqUSlxVZkjBGDjiVyJnL8m5iOoFoiO
         hxrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubZPeDDUcZ2LaIFZa1HK+eDlWB66yDSBQ/xSHlPnREeU7xLeKIC
	BefUJoH4VcJ2sA3XB9inH0c=
X-Google-Smtp-Source: APiQypJedJyshjZLqu8rNR9D+IwxyhuOn3s7rsB7vSzDQTcSsPKKOPppII7NC1SOu/5StDuTG1tuNA==
X-Received: by 2002:a5d:4dca:: with SMTP id f10mr5274184wru.347.1588855680062;
        Thu, 07 May 2020 05:48:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:668b:: with SMTP id l11ls6099103wru.0.gmail; Thu, 07 May
 2020 05:47:59 -0700 (PDT)
X-Received: by 2002:adf:8b45:: with SMTP id v5mr16815796wra.175.1588855679633;
        Thu, 07 May 2020 05:47:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588855679; cv=none;
        d=google.com; s=arc-20160816;
        b=vsU1C2Isfi/S8tusVXYj4C7qhVmwidR6o6zusoPaXlq7vO7XQMm/DPDq4n11pxlP0H
         6J6gr/6s9HpA5TKObPYUApfTHpVNHsFsokr34k/o4PO68A6jcf5LGJ2B8740QgWxoAJy
         TVar4zCWEUjE6vYzZ0c/UONbKwauRY1cfgPx/Yw/9pnfJ2QYPm4EdpSoHf8T6cdyodzK
         x7qekH0CKLvfcGpIJAmfRV6T5Hzz8fks5EycArvAL+irWoWgCye74pR5FNi73t1RLA1/
         yavrO6sjb7E3kYmAwq83MSeS1/oBA0nc4F/Vd9mfMi9Q9dd5FLau+xmmi3sG4hlEPeLB
         E7xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nM7TzUBJiuB8tbDUVVmcxE6+YeyITN8sIcQWGY4GUzQ=;
        b=zBvdm2NIGvEZp9WJZa8YGb36PaOksJnFSGAkytZJDJ4a4IU66GkqCeAxaRS0yrl0iP
         03BjrqXx39YBmuRq8jam/UbiNUhh/O33lkowOKQIqtb6ZeyXONDyqPRxQ/RMSpCv20I3
         YRjWSH2HDTF6RimH1F7pDHPAzBmexE+fAeiipciF8WvVkIdqijkhBBitmmy3bRLQa7iW
         Ve9k0SiRGWQKoumWWUSE0Ndrul92GIQr3Ac3T99iYDwlaTQhCsKO4j4aZc0Uxf4WLBMW
         ohkNGACKGKJDvwBkx8LsrB6CzXvkIYhuL3ZmzODMJrbxZ02tgeoq0RaOah/daXr4BFCN
         DB7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=tV8Y9hHU;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id x11si235337wmi.1.2020.05.07.05.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 May 2020 05:47:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id f18so6115618lja.13
        for <kasan-dev@googlegroups.com>; Thu, 07 May 2020 05:47:59 -0700 (PDT)
X-Received: by 2002:a2e:8753:: with SMTP id q19mr8466814ljj.6.1588855679326;
        Thu, 07 May 2020 05:47:59 -0700 (PDT)
Received: from localhost.localdomain (c-f3d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.243])
        by smtp.gmail.com with ESMTPSA id b4sm3730126lfo.33.2020.05.07.05.47.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 May 2020 05:47:58 -0700 (PDT)
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
Subject: [PATCH 5/5 v8] ARM: Enable KASan for ARM
Date: Thu,  7 May 2020 14:45:22 +0200
Message-Id: <20200507124522.171323-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200507124522.171323-1-linus.walleij@linaro.org>
References: <20200507124522.171323-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=tV8Y9hHU;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v7->v8:
- Moved the hacks to __ADDRESS_SANITIZE__ to the patch
  replacing the memory access functions.
- Moved the definition of KASAN_OFFSET out of this patch
  and to the patch that defines the virtual memory used by
  KASan.
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 arch/arm/Kconfig                  | 1 +
 2 files changed, 3 insertions(+), 2 deletions(-)

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200507124522.171323-6-linus.walleij%40linaro.org.
