Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4L473QKGQE57ZRFZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D2D2520CDF9
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 12:42:27 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id t184sf9656653lff.13
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 03:42:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593427347; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zn4QYRmJlY/7IVIXQORCIvhZSWicif6LItFAcG9ZmWkl/CaVvmAMnxDzxWgrlD3o1m
         Pv5bxw0GpLywIgZ5qxDV0OnOQFn6wiVZR9PHHI5hEYZgR8SCIOrtYS14Y33k/iC4hO6B
         gIU5GY6ZE58ne+AjiMlX8lYTiGv0QdbLPlyHhsSmD/kDiiw770QzF/Lkdqjs2T/WuLpI
         2HIxhYq0SYmcUzfjP9ysRTlabbdlqy59JBoq9eLj/y67TTIYSttfELBdsIFAVgnYeSKj
         IGgo+XAcrZoQdsEwCRgbcM/gEt10zEwxT4y21VXf+AwBGUk1wciGjtJrOjad1kzydaWV
         dhOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+qpWEXTh2J1/CQBKEdRom2u7WWqGv3NendC/lWoryKo=;
        b=B1zQOxXgSEDOEpSo1T6ieNvO7dl0sLl7LylUWeUFXNIKzkV1t+peKi78Ir3oePOlFA
         R5+p9wq9GdYrR+wfNN2II939PcDhuOvYXc+R8e6IP6uH4tWs/1ghUXLZot70S1E5XZzL
         lwfodrc7Kogxt2uQpbJEDxe2c3D7NcpUkeC141PpRd+zZ9Lmr2b1VH7Ld8UJ8/CeBlaA
         kNcfF1q/BLxSRdS/pZfLjQgeojVd0yuzKtQcrWvMbkR5uAAfAkV9sZYtlKzCdMh435am
         d5CSipi7mfSUFD/hDsMO5xPf/9keABx8cBuFzAjV9gOO4ygVUco5kxpe/rUOIt+sCrCm
         Z0pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nAWQ987y;
       spf=pass (google.com: domain of 3ksx5xgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ksX5XgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qpWEXTh2J1/CQBKEdRom2u7WWqGv3NendC/lWoryKo=;
        b=E5dTvxXuw4VVjZg5cMMbI/q3adrNCew9mHXl6pl20W/afrqD/2kWMmnl0aZECQwjFu
         Jzr0jDY6mw6Nftfcx16f6DIuDdLUrzeKpI1XfVKN/5+ipfWPvYwCwxguSyGaIkCuKUnB
         vey2LukosovYyHskBqy7min/lYdMSSMxCyIV3J39hTqIBh5iq//ImUeUgnwbZ6InnSQl
         pl26g8YT4ODysTPHDVLV8E5TD3f3UlZ0kqR13E/Ung2anPOWwx0NOVsm3t9Bde/iGZit
         kE8RMdqIN4kGh1vFBCU+SlPZGKUm/fTcL/b3jr/yHzfhOWu5KuYYZg+JAgd2sa1CNIBl
         juzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qpWEXTh2J1/CQBKEdRom2u7WWqGv3NendC/lWoryKo=;
        b=B6a9L8CFH2MVMVe/64larZzWes7J0TBZjU85TDx0fghVuRelYLKAghaerAxF2Y6D0O
         2y+5boRr8nW2TmkNkt7DhGcWJuac69ggp229F/iNf7j/7leIJS9wn701rHQi7EseCVoY
         RX0949AMDiM2JFRTC/ZYeJfxJknb328eUbnKh656IOHB0CXKa7nGmHONojeuGNXYouJQ
         euV5CtvzW7Ui9zgP7G+1RnMhRArLoLAqfNXTvJnrFhVuRa87XwZIi7wC2AR7UM2PVJHr
         n8haKisntLInIT6Huwd5F01w16G33wV+9F96P/6l+VVXqgK8VPHSV0gHjZ3GRuIcbc4F
         Czxw==
X-Gm-Message-State: AOAM530OuLanwIEAIVvhRfkGr/Yhw6/mggpxBw1wtYWhp1FTHq9IzxGn
	jH01d91Ne4IeG5j9hx7OfWc=
X-Google-Smtp-Source: ABdhPJxvBktEVZBcW3Et9784hSN/vE2WOGv0KbDPG9bJ1QhCYGuO1kzkyi7eWVPb/LT6zGTLZKlJ3g==
X-Received: by 2002:a19:7002:: with SMTP id h2mr8873574lfc.62.1593427347358;
        Mon, 29 Jun 2020 03:42:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c188:: with SMTP id r130ls2141474lff.2.gmail; Mon, 29
 Jun 2020 03:42:26 -0700 (PDT)
X-Received: by 2002:a19:c744:: with SMTP id x65mr9145349lff.133.1593427346635;
        Mon, 29 Jun 2020 03:42:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593427346; cv=none;
        d=google.com; s=arc-20160816;
        b=clWrTEktgG/2hZDqYLVybnHV2/X0s21EHL0THXhkNnTBWITAn+M59FzWNkTZl44G+3
         K6vBZGe91Urvvahu0qYtCbKDppZ76gPaZGap0Qj/xe299WeMgg/AqqyOqD7ggTDyosOL
         P9tqJcoAFcCEiVuwpMKVaCtcv0WWK59y2WUT3Cps09BURQ857aez88xgpnFhftLTVoTJ
         lvG9QsGUnjm88BSc+AS4FNdK6HT13DwLPjJT0NLzCU4aibSwFOoKwoVgQs4DDT2k+nln
         OkeQMSiG3c7ZF2Pl8wTlBwg++h98Mt/pEA5ddncfhB8m3hj5YOEgjrkq2AvsXtGR47Tb
         QmVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=YyMZU7GxNPbypFBfmDC57uoWU5tN/2mz7Tk7sznQPgo=;
        b=gVJ4EZiET/xMF6WxVpT+a1TH6Gfbla4V+WFoaaR8nW5PnmvqtAuTgg7rmjlXazwHr5
         8P/9PwI6ad2OEvCQ58zxAlWmSxvCtWqljGnoCfZi5LTKd2e/QSM86eJcDeowXsWk6x7w
         j+vLsanfYsszOPOmxhxMwlMcEcn+TwN8qn9AdmYxz78/kPyaim8ORSDO3cq0XTGGaAJg
         TO/ant5gBtoDLeAZJ2OE6qzta98IxFMsu69EXyGkPf64m3xZ9ffPI4+WONuNst1m6dwY
         sGbvqpAdngQQ9rW34quvNKetAQO7Upefj76GQhZ4JTy1rXsrjLSeo5nC9nZXXp+lcrZQ
         Tl+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nAWQ987y;
       spf=pass (google.com: domain of 3ksx5xgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ksX5XgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 7si1234244lfk.0.2020.06.29.03.42.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 03:42:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ksx5xgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id h25so12693035wmb.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 03:42:26 -0700 (PDT)
X-Received: by 2002:a1c:1b90:: with SMTP id b138mr15963963wmb.21.1593427346060;
 Mon, 29 Jun 2020 03:42:26 -0700 (PDT)
Date: Mon, 29 Jun 2020 12:41:57 +0200
In-Reply-To: <20200629104157.3242503-1-elver@google.com>
Message-Id: <20200629104157.3242503-2-elver@google.com>
Mime-Version: 1.0
References: <20200629104157.3242503-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.212.ge8ba1cc988-goog
Subject: [PATCH 2/2] kasan: Update required compiler versions in documentation
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
 header.i=@google.com header.s=20161025 header.b=nAWQ987y;       spf=pass
 (google.com: domain of 3ksx5xgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ksX5XgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

Updates the recently changed compiler requirements for KASAN. In
particular, we require GCC >= 8.3.0, and add a note that Clang 11
supports OOB detection of globals.

Fixes: 7b861a53e46b ("kasan: Bump required compiler version")
Fixes: acf7b0bf7dcf ("kasan: Fix required compiler version")
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kasan.rst |  7 ++-----
 lib/Kconfig.kasan                 | 24 +++++++++++++++---------
 2 files changed, 17 insertions(+), 14 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..15a2a53e77b0 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -13,11 +13,8 @@ KASAN uses compile-time instrumentation to insert validity checks before every
 memory access, and therefore requires a compiler version that supports that.
 
 Generic KASAN is supported in both GCC and Clang. With GCC it requires version
-4.9.2 or later for basic support and version 5.0 or later for detection of
-out-of-bounds accesses for stack and global variables and for inline
-instrumentation mode (see the Usage section). With Clang it requires version
-7.0.0 or later and it doesn't support detection of out-of-bounds accesses for
-global variables yet.
+8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
+out-of-bounds accesses for global variables is only supported since Clang 11.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 89053defc0d9..047b53dbfd58 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -40,6 +40,7 @@ choice
 	  software tag-based KASAN (a version based on software memory
 	  tagging, arm64 only, similar to userspace HWASan, enabled with
 	  CONFIG_KASAN_SW_TAGS).
+
 	  Both generic and tag-based KASAN are strictly debugging features.
 
 config KASAN_GENERIC
@@ -51,16 +52,18 @@ config KASAN_GENERIC
 	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
-	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
-	  or later for basic support and version 5.0 or later for detection of
-	  out-of-bounds accesses for stack and global variables and for inline
-	  instrumentation mode (CONFIG_KASAN_INLINE). With Clang it requires
-	  version 3.7.0 or later and it doesn't support detection of
-	  out-of-bounds accesses for global variables yet.
+
+	  This mode is supported in both GCC and Clang. With GCC it requires
+	  version 8.3.0 or later. With Clang it requires version 7.0.0 or
+	  later, but detection of out-of-bounds accesses for global variables
+	  is supported only since Clang 11.
+
 	  This mode consumes about 1/8th of available memory at kernel start
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
+
 	  For better error detection enable CONFIG_STACKTRACE.
+
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -73,15 +76,19 @@ config KASAN_SW_TAGS
 	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
+
 	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64.
-	  This mode requires Clang version 7.0.0 or later.
+	  is only supported for arm64. This mode requires Clang version 7.0.0
+	  or later.
+
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
 	  This mode may potentially introduce problems relating to pointer
 	  casting and comparison, as it embeds tags into the top byte of each
 	  pointer.
+
 	  For better error detection enable CONFIG_STACKTRACE.
+
 	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -107,7 +114,6 @@ config KASAN_INLINE
 	  memory accesses. This is faster than outline (in some workloads
 	  it gives about x2 boost over outline instrumentation), but
 	  make kernel's .text size much bigger.
-	  For CONFIG_KASAN_GENERIC this requires GCC 5.0 or later.
 
 endchoice
 
-- 
2.27.0.212.ge8ba1cc988-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200629104157.3242503-2-elver%40google.com.
