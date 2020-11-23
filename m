Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4NN6D6QKGQEZTSZNEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 271872C1550
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:22 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id f4sf6234714wru.21
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162162; cv=pass;
        d=google.com; s=arc-20160816;
        b=RLKs8Ld8ztoXsFZ/HhlzXXj3PRDC0amF4RG5zRJ/HpSU5Yl1D4rMgD+VISgskzPm79
         N67j5B0EjiPJsqcz4CfVvBJJ8qBfv43wIQ5U6gYsiKJb4O8zAIzyDrZq98qU7JsvHVaY
         E2Eww2/SknJFvFBnzaQbf18Vt5xUwPj+G+pLOAw3uYh745A6VWwN51LZ8+Czu1Gjan7T
         GwKT+1taWYoLPRsq/sVXaNnhLWZq7woUhHRCHyTAerdWmk4gLeAdiXht2R493J2xGfeD
         MDv4SNQHcoJWX/TtUOn+tH2icOpihPktlSraltY00HNdGqTiwNr+E8M5BOsB4+AETrzU
         2yew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LatOF8k14OjMg2As/vTuorVB6c9zkTYGfxx8QJx7DBE=;
        b=bH+fmIIy7h8jQjMtq67RTQaOr/MqLxTVRRDoIYlyb5xxhLXne2UwqEEGVrDRY4294S
         lCF6OQ3BIAnHAOFsuKVmSgN8caTMC3TnAhuqojuphaR8bBxhl3EH1GD6KUBRU42xnil1
         Phwl58ogPufNqdx1plC2FkTKZQdW4re2tDcCMUjIduVyzpM9oyquBfXtR57khRwCPw11
         LHrEC8XXnKjIf6poG54wNPIN6OT9DWIF+kFuZmAjEVOsBZZuMBovlBDfHqkYeZAh0O8D
         VmZcI5yNHQ4XQRcyHCfmRXa2Q6CMxnZsXwXO4Unf/+EMCUTTo6padJcXSoNn0+/qV/xw
         sf+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DoB1+tIa;
       spf=pass (google.com: domain of 38ba8xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=38Ba8XwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LatOF8k14OjMg2As/vTuorVB6c9zkTYGfxx8QJx7DBE=;
        b=MOQZxATp6eaVig2fdJLdC3mF++x4z4rEecimcufPbanuI0O90D1dOubOGxVcMIq4oU
         hLQZoL1cJh5Iu6Me81sCFolaGy6ox2G8WjFWclY6zp/rvzJeJxOpVujXKj2aYirlSwQi
         hNlL+ZjbgUq1z5HN0GSXQqCuoMs3EMOwf7v5Hlm1WQSbbaJBx6UY1ySvjXlMDe/OW1xN
         /OCVERWotYq+2Rq+eLxF4AjhquJ15sbFzNHj1kRACrBsMqqfIHvanre45P17eBH4TVSb
         WHQBM7+Fs5biFbI0Qd4GuHmse7SP/tyfUXGaRslvsj7qiEwoAWoJ+no1orD8rQ+7O9rT
         ialA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LatOF8k14OjMg2As/vTuorVB6c9zkTYGfxx8QJx7DBE=;
        b=M8luNQ5UsHX3JxpjI8JoXRjCEMMDkTxhFbEevLzc6FDQeB2m0QESQRZ8eu6IKsmFy/
         2CR/0t7eCWJQzJlQiQAV1LMb/LHLRGU+psJB0yms4s13fCDZAuZljk/vMjsp21CRRpPj
         fVnP1EnP1TL18pNn3qdOIcyz4VkdP35MuQgzNvC3/MbWo0+k37Jwbocyr0/6K0Drxuhi
         nF+Pdzmde+awB63D60CBnDeiCFnRtlCsS0mUtF+JByTHXq37PTzMYGwEwC61QagB/g3v
         ZwnObUCvVlBv0Ad4xyaVMgK1Gs+u5KJiI4OZ+zTFg34mf/zqcGN2G9aBizmt+65ZmZHr
         p0hg==
X-Gm-Message-State: AOAM5325siqNP9tL/gC2BQRBfHgwN0ez9VpT3KyU4n4HfpA3G3f/ARMp
	mFWPZRGEA+kJiufdEhJ64Lw=
X-Google-Smtp-Source: ABdhPJyarc5RODcWOS1w69arP8oRZfT/nUzgDsgls+GJ2uKBPHId9ctTfkXq7bYESZ8Cl1ApuV6GiA==
X-Received: by 2002:a7b:cb8f:: with SMTP id m15mr581934wmi.95.1606162161946;
        Mon, 23 Nov 2020 12:09:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:414c:: with SMTP id h12ls162523wmm.2.gmail; Mon, 23
 Nov 2020 12:09:21 -0800 (PST)
X-Received: by 2002:a1c:4456:: with SMTP id r83mr586103wma.91.1606162161088;
        Mon, 23 Nov 2020 12:09:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162161; cv=none;
        d=google.com; s=arc-20160816;
        b=0LS7Ma6LJyB9zCyghd+fWvSccO7tymoSPpew199lKb5Ytbhw6Nzk+ZueDxvxrZg7se
         q7Ar7e4FqaClnnt24CthJLH45bxltjR01F/F4CIbG5ZH4+1WCRwC9d3TkD9TlEOWbGA6
         57/+q0Lm0ZSDtpOGGKLHNXqixsTRtSThexPa+V0bvzTCkTqlViMqn4tTPOL1ib42P/Pw
         u4HG2M3oi6f69TZgb/FNzCnY87vwhYPDQEf5tvyKbreuADk5SMx1eCoDwQPsIdr95Nn2
         3YQPYucpvu25SRBudVhr2MXFvsxJDhqY9s1tabu1qL2VwabsSLfdSdvA5cgbURJs/NT9
         2MZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=kdTeiC6bEKzUPa3TNqeHxs54z/byxLmKL5DCwQxTHnA=;
        b=L8hdzssa9RWv6vdWNLsNwgcRSVIiFaAf4118P9h9SF5unceVEWJ78I567L+qGvkG2n
         dXyUCwzhkbvNbAcwVb+IIwSUiDSokakrHM2WhFhu4wgN0tw1mEwIHrtFbu4qLfthcNiZ
         NzovZDU7+x4GmX6ng+sMpv57lV+YOnkxJub9v1PibSLhRb56KRiiIfQSqOwlPzKXboNM
         pN89ZBKrdh5gfeRKO7MGWbcydDf+AS9Q4m3iZkVMn+w/mcvpgnajcGb4Izw7pkWjbH7e
         882fYWp2++fkgAlDyp64gtpKM+03tsuslzW3REUuDfEGzDWwEGE+brK1cPcd07VUtrCN
         KZCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DoB1+tIa;
       spf=pass (google.com: domain of 38ba8xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=38Ba8XwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id o187si11554wma.2.2020.11.23.12.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 38ba8xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b3so4648601wrs.6
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:21 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6783:: with SMTP id
 v3mr1384499wru.45.1606162160695; Mon, 23 Nov 2020 12:09:20 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:47 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <44906a209d3a44f9c6f5a21841e90988e365601e.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 23/42] kasan: introduce CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DoB1+tIa;       spf=pass
 (google.com: domain of 38ba8xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=38Ba8XwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 61 ++++++++++++++++++++++++++++++++++-------------
 1 file changed, 44 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index c0e9e7874122..f5fa4ba126bf 100644
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
@@ -15,16 +18,19 @@ config CC_HAS_KASAN_GENERIC
 config CC_HAS_KASAN_SW_TAGS
 	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
 
+# This option is only required for software KASAN modes.
+# Old GCC versions don't have proper support for no_sanitize_address.
+# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=89124 for details.
 config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	def_bool !CC_IS_GCC || GCC_VERSION >= 80300
 
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
-	select CONSTRUCTORS
 	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
@@ -37,18 +43,24 @@ choice
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
+	  3. hardware tag-based KASAN (arm64 only, based on hardware
+	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
+
+	  All KASAN modes are strictly debugging features.
 
-	  Both generic and tag-based KASAN are strictly debugging features.
+	  For better error reports enable CONFIG_STACKTRACE.
 
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables generic KASAN mode.
 
@@ -61,8 +73,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -70,11 +80,15 @@ config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables software tag-based KASAN mode.
 
-	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang.
+	  This mode require software memory tagging support in the form of
+	  HWASan-like compiler instrumentation.
+
+	  Currently this mode is only implemented for arm64 CPUs and relies on
+	  Top Byte Ignore. This mode requires Clang.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
@@ -82,15 +96,27 @@ config KASAN_SW_TAGS
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
+	  This mode requires hardware memory tagging support, and can be used
+	  by any architecture that provides it.
+
+	  Currently this mode is only implemented for arm64 CPUs starting from
+	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
+
 endchoice
 
 choice
 	prompt "Instrumentation type"
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -114,6 +140,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44906a209d3a44f9c6f5a21841e90988e365601e.1606161801.git.andreyknvl%40google.com.
