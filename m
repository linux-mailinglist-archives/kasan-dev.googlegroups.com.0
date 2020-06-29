Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEEL473QKGQEKBBZB5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id C376520CDF6
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 12:42:24 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id a26sf6650218ejr.7
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 03:42:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593427344; cv=pass;
        d=google.com; s=arc-20160816;
        b=ExBMYiSxeR0AYj1De37EpLSG8D2DKkDkNTTuGz8+flW8KA96JeUKl01ONbHKb6cOn0
         clCSSIiBUXVPl6GDBfUbFhMM4PLmHOJwEkB7ImsWhVeXkUh8oyuCUT7F3eP33doXMDWK
         jpcwQZ3zbeOCn9gFy5ZoHTFK7RnHITo/eQcYjaJ1am2FvUbHqJbTKBUHGka1sOYzGp4O
         LTb1Q5rGg5aOA/QZJ8O+3VZyLCgHbr+zM3Qu8mQ9cO4xpz4uDSN02SoBN8KxAGEHimRs
         oBbZNyakK5ead9R2mGq+GRdjtLaAZ26m19c1bishllwomNLpVLxgPPZomdd+659gqVTY
         n6Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=dZWLzOdaEQBEt7sR20puhiKyZWst0BRMM2dOUs3d0WU=;
        b=zhGAJCcNm1HHQBCOvbQdROHUBFjQesdZVu3KPpusrMhmBFOriJ8JaXx+DrlupVJqVr
         aAgKJ2rAAUS1mq2q5VVdWCDe73K+6fMviyp1kb+3L5W8Ufdygqa6rMTz2uYeNH4GpG6v
         7FOSjdkZIWkiz6t1FwzuKa1Gz//Pd4SOHHdMgg2f9M2pQnnV/IMEhpQZspj5B9iM+Evs
         iSaIf5JVWTaskEo5EjoWcYJmOWpoWzOmw4KOFhwUCrAGWjQLGWPNhCV0CTc2wQtcnZ0j
         tP36BPxNu8vJ9+XYoy1pJhzb/9kyvxFWYY1/gCoNv/JzANMVg9wKkGuiPTtbLw4wtIPs
         ni9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EOmizTnm;
       spf=pass (google.com: domain of 3j8x5xgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3j8X5XgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=dZWLzOdaEQBEt7sR20puhiKyZWst0BRMM2dOUs3d0WU=;
        b=dmidxy4eqL/mWpzTVDj2evEhuGb8M0rawHK/89YOQmmCrTM1/qUK3eJYCZJZNr7J4g
         7AMqo/E1rXrfE9bULCb35ufiRaXN+KdSydnDnOw0Rs/hopIPmMuVh30TmPvdIBEWg6/u
         wwrg1h/vGJt7o8620mB0IhHLm8iC2iERsySLni4YovSLzDmnrhuxmORM0gCk0/reKjtZ
         aEzMRNnH9Y+u2vv87VdhSIMjOn+WPoQCxPp7illxRwKZEZMmBMII7GaWSX+lJvPxNKW2
         lxqG4hXkCtCHJkjB+TZiL4NXHGRZNO6Dl37O4j5r8M+2J8jgcIgZcoYz5/DGSbcv7aCO
         E0YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dZWLzOdaEQBEt7sR20puhiKyZWst0BRMM2dOUs3d0WU=;
        b=U5q/cTD+y/AQl1F52TT84QZ1YXN+MwqDnUMXoRxkhl7YiF4jDW2yU9fv96mL11BPQe
         k6FByeTqBEnFdWexw2HNJc12psxNZU1ZgEMSNWSAfTijC3DI/OWq8dPJf5U7Hk3g7d9g
         5BoWMMeLoEs27bL8qtaX1DQQTFs1Se0zv5Ibnmd1YZG/bYAp6OT3fYVDg+T2VsZvwIfV
         ml/4QYQSrHlaaAPy/xxDprJpyGJ3q8D6IC0ncK62xDt0AXLCU82gfabpVzB7Gew8ukS9
         75vOsiS0kxs1BQTZcgQXpPaZvyj4dlGuVfj5Fv4bwIEMkTZgaafXebM2e8jqVBMfZuZ4
         /vow==
X-Gm-Message-State: AOAM530TmKCSDEbgOuBkWXziC2jYaobn/1bn06iz7VFEfcaNUqdM1cOy
	LVcSxugyhVUS9KYDnXI0Uh0=
X-Google-Smtp-Source: ABdhPJxmKYMtCyC0rxjVLO5I40KLzS+DO5h9lcE99unqJzbRYQrXKF9wP/zt1+fEAIat+EbHaobQ0w==
X-Received: by 2002:a05:6402:354:: with SMTP id r20mr15977360edw.32.1593427344571;
        Mon, 29 Jun 2020 03:42:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d37:: with SMTP id dh23ls2907966edb.1.gmail; Mon,
 29 Jun 2020 03:42:24 -0700 (PDT)
X-Received: by 2002:aa7:d9c7:: with SMTP id v7mr12433176eds.36.1593427343950;
        Mon, 29 Jun 2020 03:42:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593427343; cv=none;
        d=google.com; s=arc-20160816;
        b=XhVghGw9JRsUT5g8jXMKhtrNy8nfQV9+aHCO+MSE7y/GXJ9ugWTSW0oCNTW1usvkOP
         qrX3clIJ0z6ir0cP512e7R8x7SJspEJUnt6VbUaHjxyZN0orPVuHpp1yD/8Et8I4snZl
         jQFW6eCH+qtK5eLVmGVBg1HCpE3NuWAZbCByBhjvN+dRu5+P0WVuHN0UfRlHifcsZf5a
         7XzxoQKeKotW+MoSpqBVkjEvo1uGakKKkmrd/OkOobxuj3HA0va0KxV/73i1cWlab0KU
         V3v+jEoxqPmdG9DgAPVJzlJNKPVOHarCWMrgvtCmJ0/8g+3fDSpFC+R7BVMI6k+RzDVK
         mHLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=cd/DuDkUFEfbY/EbJHKe01td49IpW+ZHgFOrWbd6mno=;
        b=WVYRcHU3GUCzoPmY9EQhevLK2qdzpgfaIxUqf0shCosHk2DX0qB6rwH74hZdGe+RpV
         7cy0PRU2PCuI7xH+LBGr9BcPBu1TmOXtZ3Y0XKPld1J17aZujm/fl0ySyitTsQErXHGt
         g97ziNh3/JoEysPqAbODee7TeWNNay65ZeBYiGYOd2sU7LCsEfZqAPA4HoJ8Np+/RSvA
         dqPZOvVlfoDXrRDPsrYWYaq2ZppfoPUF6VKS/UK2t8gQGCg76zx5g6DFh/jkBu5fZoUu
         7UaYsWuyrxAVKSbbPOKjLr3vpPzYz/i4KlMP2SQZIT4V5f2FNFBL/AZ1FTJBEeh8PwnH
         2igA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EOmizTnm;
       spf=pass (google.com: domain of 3j8x5xgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3j8X5XgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a23si1979236edn.0.2020.06.29.03.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 03:42:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j8x5xgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 59so9783323wrp.4
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 03:42:23 -0700 (PDT)
X-Received: by 2002:a7b:ce87:: with SMTP id q7mr16866593wmj.39.1593427343578;
 Mon, 29 Jun 2020 03:42:23 -0700 (PDT)
Date: Mon, 29 Jun 2020 12:41:56 +0200
Message-Id: <20200629104157.3242503-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.212.ge8ba1cc988-goog
Subject: [PATCH 1/2] kasan: Improve and simplify Kconfig.kasan
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	aryabinin@virtuozzo.com, ndesaulniers@google.com, walter-zh.wu@mediatek.com, 
	arnd@arndb.de, dja@axtens.net, linux-doc@vger.kernel.org, 
	clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EOmizTnm;       spf=pass
 (google.com: domain of 3j8x5xgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3j8X5XgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Turn 'KASAN' into a menuconfig, to avoid cluttering its parent menu with
the suboptions if enabled. Use 'if KASAN ... endif' instead of having
to 'depend on KASAN' for each entry.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kasan | 15 ++++++++-------
 1 file changed, 8 insertions(+), 7 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 34b84bcbd3d9..89053defc0d9 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -18,7 +18,7 @@ config CC_HAS_KASAN_SW_TAGS
 config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	def_bool !CC_IS_GCC || GCC_VERSION >= 80300
 
-config KASAN
+menuconfig KASAN
 	bool "KASAN: runtime memory debugger"
 	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
@@ -29,9 +29,10 @@ config KASAN
 	  designed to find out-of-bounds accesses and use-after-free bugs.
 	  See Documentation/dev-tools/kasan.rst for details.
 
+if KASAN
+
 choice
 	prompt "KASAN mode"
-	depends on KASAN
 	default KASAN_GENERIC
 	help
 	  KASAN has two modes: generic KASAN (similar to userspace ASan,
@@ -88,7 +89,6 @@ endchoice
 
 choice
 	prompt "Instrumentation type"
-	depends on KASAN
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -113,7 +113,6 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
-	depends on KASAN
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
@@ -134,7 +133,7 @@ config KASAN_STACK
 
 config KASAN_S390_4_LEVEL_PAGING
 	bool "KASan: use 4-level paging"
-	depends on KASAN && S390
+	depends on S390
 	help
 	  Compiling the kernel with KASan disables automatic 3-level vs
 	  4-level paging selection. 3-level paging is used by default (up
@@ -151,7 +150,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on KASAN && HAVE_ARCH_KASAN_VMALLOC
+	depends on HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
@@ -164,8 +163,10 @@ config KASAN_VMALLOC
 
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
-	depends on m && KASAN
+	depends on m
 	help
 	  This is a test module doing various nasty things like
 	  out of bounds accesses, use after free. It is useful for testing
 	  kernel debugging features like KASAN.
+
+endif # KASAN
-- 
2.27.0.212.ge8ba1cc988-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200629104157.3242503-1-elver%40google.com.
