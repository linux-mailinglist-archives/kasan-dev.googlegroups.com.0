Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOET3P4QKGQELAYWVJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1457D244DD5
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:25 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id t21sf2177474lff.5
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426104; cv=pass;
        d=google.com; s=arc-20160816;
        b=pualERGua3yax6OTtA1NWFmFDbfK5FmiD31UivabJjri6RLTuXfundPxV6Y1bCKXRl
         pZM1IrO3YuSurjTJEM2fHKod6eqeYfBCtCzs8Q9z4vbmunbIqOOd0RCZp2jHRUqsXYvk
         xONswBNXAS1LUifElG+amzsdkIvJ4DEKuknEHdg4gQz7O9TohdzmhDVouwA5zxZLWnGq
         BNXHExGi9MPVG1onWXIek/43h1dZO50+zUQ9Owz30LikzMEMONDglBpI3JGnQDrDvN9I
         VFRtNeuiSVPHBfnnEoJ+QkIKkdUnm4n6nB3dfyD7hD3qJpIWXPL4Cl3Wbg90+TJoiwE4
         U69w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=hKzciX/EdjQa4A/z2tEEH2qrS/77mWsyKuU2dOsboPA=;
        b=oOxL0U8tFVUnS1b0PWkngfK1LVaIPg8QS/Dwrv+lnFViRKNOB2LNbaocGQPApYhD69
         Bbcdn1XxvIzG51OKxXV/gxzwJYMZIqDGjKZ/Qsu9+WzsF29oABKNo1MZIWKQIVjvIGZQ
         2bNEHzkszC4cdDnaFp67J2NqZpa8UcK0lyI+ROsEB5UB7nshGodgWh6vsSs4vYiSgN2j
         kCOeq7AADf+UTLyHAaQdxQbm0y69U1ydHo2ZW+D7/+JCWmA3JGRBcmS597crjEtnK9iq
         toMPH1U3Bk7TxG8vVkGzCIIlxKk0dGnLzM4Hw1sNIRpwiOdNuqnm0sy2GyouRc1NaRME
         AmXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iN00ACnX;
       spf=pass (google.com: domain of 3t8k2xwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3t8k2XwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hKzciX/EdjQa4A/z2tEEH2qrS/77mWsyKuU2dOsboPA=;
        b=adRbqXW9EMw86w0SWBnD6FvRqkZ0jLwm9jRXvFehs+QMn0rscR+/lhIAFUpImDGd12
         I0+XwSuPSf4OL1843Xerv3BCYcLeRueqZXU6GyROFOvJckcnJIwFFsa2TiTj4uhWSq0l
         YqgKBcADZj3qatxxxYPboEOHivGaI0M+HvoclxenNNLKU6aHONA6YeF38EOYpY2GzO0e
         0ydQdIXEado/Q+Bb4xF5Z0NsL6YGM/aIBuFyB9p+qcUc1YppH/DybS4VIhHOvOaxdyvM
         dPmMgQrTyQQ55SHFY2vIYa1g/9QYxVKvCTXewxnJKX2ibJUHC9bUG8+vHMvV0RRNeYc3
         fT/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hKzciX/EdjQa4A/z2tEEH2qrS/77mWsyKuU2dOsboPA=;
        b=jwQLhadJV0eHtxzU5yj3yt909Y1orsQLiyyQfaQWiPGJ8hsMIcG0g75Tw4YOg5MaSV
         scjIJeDkQE7aBjBmzQsCy4g7LhzJWgOvgD0VSuQHhnhBHbiwQl74jz1FfaZXAAe1sXTY
         KNdzVS14LP3Ou0BZAanLoUuc3dUqvYVVPzhSogZbXh4ILEMS1y81vTVOhCcmnQnT+7P1
         hDozWMwud7i4Iotkb/x0wk68ndDY6bIJP4Sk6AzWBqTC2+UtdbvxXd1jcJutm2nNnHaQ
         0sUJyc+fG7mYKg4ZIgHmsj1kkY2oYf/1ga7gGn35yMXf3YUN8tIurl2yBDmzyoEc+0ip
         gm/w==
X-Gm-Message-State: AOAM533O6heS3NT2X5vlBX3mNjMgdgQRfo/SwIVRXXcYTm5QOJqzvLzH
	13Gkv0iStRIU4+gdvlK6kIQ=
X-Google-Smtp-Source: ABdhPJyUt1LSTbGftljsT2GaGzrxhQirGMDSSd0bsJHhCxtrWOGETrs/8aeDfs9utG+cCJs+WZ+SEw==
X-Received: by 2002:a05:6512:36cf:: with SMTP id e15mr1721105lfs.149.1597426104573;
        Fri, 14 Aug 2020 10:28:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b48:: with SMTP id o8ls171443ljj.11.gmail; Fri, 14 Aug
 2020 10:28:24 -0700 (PDT)
X-Received: by 2002:a2e:808f:: with SMTP id i15mr1869944ljg.151.1597426104023;
        Fri, 14 Aug 2020 10:28:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426104; cv=none;
        d=google.com; s=arc-20160816;
        b=IY9kiB3jidaKgVsevRnskAEPIgbjlHGtIwIzr5y8+vWPTnjGcmIRrJf3LzNkzNdZ1y
         kIIKnaXEVxp9Rz2Kim8ikgoyETB5Ni9jFvX/U0duicFfd+EDBxeQMDpsbt65/BE6TkyX
         C6qZzmuZVsjDxEhcsEVisMQkLWJ91pY/OUDpRWn6lmaFORjGFVj84kJjrRM9eMT/m7Lp
         jYdUehnSdki/Cuz4j5jpT2Wgnyr7blwLMnwSjiLWeyRgOmRUZ66nezr1/xf0Q2Yqs2yE
         mn0jp9vqAH/TSCbc8iS/TT+zsfpzf3k6Mdphn6cHwCfR3fK51HmCpfgtErCjrLbygDVz
         Ea3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=G1m+mBc5DHN9N1yWiSk6nb4X2zq+d5nDMgJyTLNPPRc=;
        b=KuPJNb0yzaK9tShYDXIwJB6vAIqmsI8SSyQ9rdu4DYSHoVxUchEzTl+FSk5miVmGBb
         R86NG4URNk3ydQMyZs/FydggpPAWpbcy+d7cndTVfP8v0yw5fcot8oKjFU92d4bRIKg4
         jrT6TMwfd+6OC/f6OMsgfFfSnSs6XgwsfUf8yYKZP51ODnrEuMpa/vOJm9pKRtAlo/MA
         Le4R0js0k+duTqCNOQg0vbpv7WGdpIrWHJgZ+zgLF0/XNLzpri8S4zDRWZ1GsVUp2jDc
         cgjw8X0/SsCG2T5kjGBkza97sTjyJl0MeE5QF1NePPTYbSRPpxNay29/PyI7qn8LSbJa
         qMQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iN00ACnX;
       spf=pass (google.com: domain of 3t8k2xwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3t8k2XwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 141si477616lfh.4.2020.08.14.10.28.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t8k2xwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id b18so3603543wrn.6
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:23 -0700 (PDT)
X-Received: by 2002:a1c:32c3:: with SMTP id y186mr3400306wmy.15.1597426103272;
 Fri, 14 Aug 2020 10:28:23 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:07 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <8a499341bbe4767a4ee1d3b8acb8bd83420ce3a5.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 25/35] kasan: introduce CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iN00ACnX;       spf=pass
 (google.com: domain of 3t8k2xwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3t8k2XwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch adds a configuration option for a new KASAN mode called
hardware tag-based KASAN. This mode uses the memory tagging approach
like the software tag-based mode, but relies on arm64 Memory Tagging
Extension feature for tag management and access checking.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 46 ++++++++++++++++++++++++++++++++--------------
 1 file changed, 32 insertions(+), 14 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index e500c18cbe79..0d4160ce5ee8 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
 config HAVE_ARCH_KASAN_SW_TAGS
 	bool
 
-config	HAVE_ARCH_KASAN_VMALLOC
+config HAVE_ARCH_KASAN_HW_TAGS
+	bool
+
+config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
 config CC_HAS_KASAN_GENERIC
@@ -20,10 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 
 menuconfig KASAN
 	bool "KASAN: runtime memory debugger"
-	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
-		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
+	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
+		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
+		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
+		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
@@ -38,13 +42,18 @@ choice
 	prompt "KASAN mode"
 	default KASAN_GENERIC
 	help
-	  KASAN has two modes: generic KASAN (similar to userspace ASan,
-	  x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
-	  software tag-based KASAN (a version based on software memory
-	  tagging, arm64 only, similar to userspace HWASan, enabled with
-	  CONFIG_KASAN_SW_TAGS).
+	  KASAN has three modes:
+	  1. generic KASAN (similar to userspace ASan,
+	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
+	  2. software tag-based KASAN (arm64 only, based on software
+	     memory tagging (similar to userspace HWASan), enabled with
+	     CONFIG_KASAN_SW_TAGS), and
+	  3. hardware tag-based KASAN (arm64-only, based hardware
+	     memory tagging (MTE), enabled with CONFIG_KASAN_HW_TAGS).
+
+	  All KASAN modes are strictly debugging features.
 
-	  Both generic and tag-based KASAN are strictly debugging features.
+	  For better error detection enable CONFIG_STACKTRACE.
 
 config KASAN_GENERIC
 	bool "Generic mode"
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -83,15 +90,25 @@ config KASAN_SW_TAGS
 	  casting and comparison, as it embeds tags into the top byte of each
 	  pointer.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
+config KASAN_HW_TAGS
+	bool "Hardware tag-based mode"
+	depends on HAVE_ARCH_KASAN_HW_TAGS
+	depends on SLUB
+	help
+	  Enables hardware tag-based KASAN mode.
+
+	  This mode requires both Memory Tagging Extension and Top Byte Ignore
+	  support by the CPU and therefore is only supported for modern arm64
+	  CPUs (MTE added in ARMv8.5 ISA).
+
 endchoice
 
 choice
 	prompt "Instrumentation type"
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -115,6 +132,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8a499341bbe4767a4ee1d3b8acb8bd83420ce3a5.1597425745.git.andreyknvl%40google.com.
