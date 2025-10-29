Return-Path: <kasan-dev+bncBAABBRGLRHEAMGQEGGJWAGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 33A75C1CE61
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:07:00 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-592ef198363sf68963e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:07:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764805; cv=pass;
        d=google.com; s=arc-20240605;
        b=E/BYrLZY5jAgnKO9uehguGdUrck5B0nzgZG1Cj6kfvPz8hdizVJ50UsBo9c8tCAwVu
         J5vBLE5d+Iw9ghxeM5rMS6xWrLjayBK6Rfm2AXmfVViT0uYKoZfezRYxRHlwbxY0KmvA
         CP1eaWePS/NqaItqFYrarlVAPpoG3bbPLaWiznMnaPq4ML9BSocdmsktyoEoO5NJ1wX8
         jtnLYQVjvQ/APqWVXhrEi2yJL6MvMXLswB5YRIK4eHYnJhW81p3cyuVgfXSxTFGYEnSS
         b5EH0BVGDILK6K97KhGolTNEbsgkFUL2fy6+mVnoPmgKWkSJ7PqYRXRZdGGiTshwLknJ
         8aTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=FjkoKUSlte8R6PdDUwNMLqL2wM7DHVj2RJT3yUkJpmI=;
        fh=JaOEPP/0cXbqoot9LOoS+AJNnKgVG+AJU8Gqp5Yd/xU=;
        b=Uw1O3Ir1/9ItNtYTzEnmRUtgkQ4MFDoVpDWrO9d8j5TUOfhRmgnvD22W7aBraTt48+
         eoCaBkKTdiVhgP0NOOkUY30VU3BIQdQ0AqdUMTJwxcZFvtQdPXxpyxc2A8oY5MXBylKl
         iX93uLHKQyheZEneKnYDXzmtdNnIM0luJFN+AFgP6yxbUJArb+xfb7hUBkHpSczNmBEb
         wsncPgQ60uW5LmRaRYCtsW1lh/rVYl7n6YyUu8Llfwa1h/AVaVlSHfTWVx38ZPuXnF8v
         0ewV40eVLajEI/TffVu6z8Ooa9L/Oz9zMryNWkUllZc3nDcENP32mV0ibcM6P+fhCEA9
         uFog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="pGVXX/VY";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764805; x=1762369605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=FjkoKUSlte8R6PdDUwNMLqL2wM7DHVj2RJT3yUkJpmI=;
        b=XU1LAEtK9pSq2Ha5OKOnbYrnox/JMMR8XcANJlq603zrijk6lMj2DxzQ7PibPAh6YE
         +qPbovYZZhdMeopKuZXg4Sr0wDUVqQiRxutQ3YAuIy/kRcXazMDNps5nvvFJ7c2ZMhMl
         +VzYP6ujZ7efSbB9YcovRag9XFwIzsU3MF8v8Nknc4N/ONaMW+xb0vYf4YdzFVVg8VJn
         qnyx70A4xQue7q2whH3Un/KS6vq1U3gaZWHE7cKsxIbTlKZfSpHasRqpNDRtT9y4JauG
         eRNiCmMbEPOLjRTUdB4ovXa+SozzYvPXYjGeobcOs5kJ+f/XSmSONLZkbd5BmBYFP+9h
         vTNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764805; x=1762369605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FjkoKUSlte8R6PdDUwNMLqL2wM7DHVj2RJT3yUkJpmI=;
        b=GB1sl6KikoVyMDZLGs9daoiVQ6PqECD9qUN7eR6hysiu8mIJejTVOO9v6AESyI7Q5b
         WDfXAt/yqwXsjajA/d+xD5+CPtdUIKQt84PETdqDVN9Q4NVTiN/55BnYiHQOTOy6dlU3
         RObQW1lqU6wwJsSvBiFXlKFMSHG0SoJaq9FIl8lwLVS2riQjK2OHI8VCqQvn1tGzWDTh
         uGWULgWkjQm/vJACbEzCvdoW882KCq77FsBisvmmldzwvvhBDUN1LsuG+V5qB+9ICf+P
         t4Z+Qm7gbXDo+l5y7eSyhEesJqhjc92L7ueYO9G4AhFZNX3FoDwMUPFmnug8idwwUf1t
         LvhQ==
X-Forwarded-Encrypted: i=2; AJvYcCViQSe6BUYg2x1cV/tqPDhQpBsG7VO7+44wgrKVc8lCpuYbYFVSOFCIdq2U0oNC8WtPvGevqg==@lfdr.de
X-Gm-Message-State: AOJu0Yw2jAjj+1W1XUSCqMrKdyu6XSDpm5R/xWGaur8X5AYqJ9/UpElR
	SPmx+i9ckKm8/tteyOQKqR5D9hYRrYuPyjCJF0xy0Eggkrc+iddo18qI
X-Google-Smtp-Source: AGHT+IFn3xVsfa4zQUXtrlTsy6b2xaYiStGkudxNlupqDQYcJTZcCZ8N/RHh1Ee2i7paGB6RXR73Zg==
X-Received: by 2002:a05:6512:3f06:b0:592:fff6:b21e with SMTP id 2adb3069b0e04-59412886e4bmr1560529e87.20.1761764804910;
        Wed, 29 Oct 2025 12:06:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+awTBXwyxJ/ZNef3sKJyroPTmj+2i38EOq29UzXkCCIOw=="
Received: by 2002:a05:6512:401b:b0:592:f626:e02e with SMTP id
 2adb3069b0e04-59417643f08ls25925e87.1.-pod-prod-04-eu; Wed, 29 Oct 2025
 12:06:42 -0700 (PDT)
X-Received: by 2002:a05:6512:b11:b0:591:c53f:3b6f with SMTP id 2adb3069b0e04-594128ddc73mr1459430e87.52.1761764802611;
        Wed, 29 Oct 2025 12:06:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764802; cv=none;
        d=google.com; s=arc-20240605;
        b=ao86+TQkL6ahYAHl5zlXsCBrZ6fO68rznXidYJZ7ChICQyCV42J4gqTTyb1C3NC3xQ
         IY1X1CikPGSivTJGQnIcliDMEF+ay7qnApu/KKxU9XUkgb9gBLq4CSzjF5L6yya689yR
         OtENIUM0ksR86B9kdSUYuIpiu3JyFmDB74s7bB7sRk5yEcfUHmXJiPBydmLPPrzTgRG4
         zESMNVfiNOGoNsXa0iftwVKBVRWqVCO0IdlGV+aq+19BxNuumaSetnaaQCYt7P57GvQT
         kNBiymiNrmArbP8eMhHHjXZSu/bk+QSJTOowPqn97s1r5MXJkTlu/OQes9RMb31OP8JC
         0idw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=RT/zPmq8dzuzMSpg5XGcznppBgYR4y/21vyg9rTeyzk=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=YRHaVMc7bG0ieTcfzb5ejRCxCwYFCO/xr6RvFUaAJpJV9gqPE3MKZfqDo4Ef0mnMMi
         nak0m7adAp+0rvIYcZB5b67Ss7AXvykrmHNEQzGq4bTSeLMkLD7UVZbiejYLZAmtrK4p
         g48u2V3XPUk2DfizgQboGiiNsk/OQl/pzDplmP1jDvARIqwrl1XwsBMBZlYQa8IDscZS
         lTI+6NszRgpr9V8WBEE4eTD4S51ohKCq6NZfOkFcPpywg/IOlZ+0vqyQBLx2NW+jCm6x
         8VmuHgXbO3V6LvgZrprSs30E0Vr6pL2ap7DCO1FGhDshEgFQrI5CASlJv9cpiSJh2axN
         ZGoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="pGVXX/VY";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-593028932c2si244979e87.3.2025.10.29.12.06.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:06:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Wed, 29 Oct 2025 19:06:33 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 04/18] kasan: sw_tags: Support tag widths less than 8 bits
Message-ID: <8319582016f3e433bf7cd1c88ce7858c4a3c60fa.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5f5d346b6b1d7504801ff3b4ec51dbe636e94b26
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="pGVXX/VY";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Samuel Holland <samuel.holland@sifive.com>

Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
pointer tags. For consistency, move the arm64 MTE definition of
KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
RISC-V's equivalent extension is expected to support 7-bit hardware
memory tags.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/arm64/include/asm/kasan.h   |  6 ++++--
 arch/arm64/include/asm/uaccess.h |  1 +
 include/linux/kasan-tags.h       | 13 ++++++++-----
 3 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index e1b57c13f8a4..4ab419df8b93 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,8 +6,10 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
-#include <asm/mte-kasan.h>
-#include <asm/pgtable-types.h>
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
+#endif
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 1aa4ecb73429..8f700a7dd2cd 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -22,6 +22,7 @@
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index 4f85f562512c..e07c896f95d3 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,13 +2,16 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
+#include <asm/kasan.h>
+
+#ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-#define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
-#define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
+#endif
+
+#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
+#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
-#else
+#ifndef KASAN_TAG_MIN
 #define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
 #endif
 
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8319582016f3e433bf7cd1c88ce7858c4a3c60fa.1761763681.git.m.wieczorretman%40pm.me.
