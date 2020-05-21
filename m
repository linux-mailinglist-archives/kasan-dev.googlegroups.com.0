Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH45TL3AKGQEDKAR6PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B5221DCF74
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:24 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id b29sf5817283ilb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070943; cv=pass;
        d=google.com; s=arc-20160816;
        b=FC4dGg4I08DTn5TTIH0+rEmLLtTVXj8wOcRlRBWsyaeH4qwZCQ4xS8gqs81AZBdKR7
         Trqhu0+ZAiJZBmbxOWIgHBmo9vBckIfbcO3pTx/783PzpiHNrEdV89rNAVNGeo97ti91
         Lp2sA7rZ7+pLAXyz4TFQu6PSkmXyXCoQ7B+E7Rh954iouqCv/C8DY5Lu7l9GBj+RGa/w
         Rm/2ZuAE9gzp+8fJ1BXQAJShs+GaiE7CYHFH+sb11FY1g0IwSJgWxlO+JQkrJPfYTmjg
         1G7iYXt1gCDWvjC16D0/VZHyjNLVyJiA6A03YL4ZhCqecktWnJT+pm27yr7Xz77hZUJ+
         O/2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oEMKdd9yCn3WLz1ZmGhTrcnpYR7ZJELFVG73h6c+Yk4=;
        b=gOnYP5mNENXJLc//txfMcj4ZI2+rTOI6xh8oZte2N+eEs9kHIy0yDJ8rMnBVUn710o
         mCNCqyRjK/l82zrNVJNbT7ol0PMrW0ql3qXrCJFZjkiUjdpz2bSBomnMtAhnmJL+Vhr6
         CPUL7iAAOOvt5Su8OXLHyo8MOp1vZKDSqFcfNjlUJVWgVSk4wXR3d0sjbRgovoA2shOV
         TLH7vrwYhlLAkuHR0DbWHrIpqmcElL2XZ+c5O2eASdfn+fbLekneAsYAImQak1YEXPNf
         yxSsIDitVqJsUoHxbX5g7AeB27q3/PIvPNvkfw86AKHa2FQMu/9qDXQEyTtB7RvzRSUf
         4Ujw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iok4xGuH;
       spf=pass (google.com: domain of 3no7gxgukcde18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3no7GXgUKCdE18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEMKdd9yCn3WLz1ZmGhTrcnpYR7ZJELFVG73h6c+Yk4=;
        b=Ts/Mc09BDflLn3GmNJZu3JO0qYb4QsZNW+ezUSjTiQW1V3PzRWPfXqas/iWeu2WcgU
         e8auzJLZ8FkuAoM6dHiOaRBDAAqLyGf3NTUXAqqKfRWfxiU1NjNevfcJtOab7gla0CFW
         CJRYRCRCQAm7cPDNIp2N14K0XSyLdBT6V0uYD3skYtJwUtA1420e/LzDVn3FUenD9lt6
         FX4z+9dJ7CZj5qYwOi71Hr6ZuEJ+6So1QqV21jGXOphXPmhXWzGOy//84UMsaiFIgu1B
         fBIVrSnk+xmQC5KKvKnBDP3N2Ijm/tRXzXDH21+UYjNEi9TWDT8kcBEvPWwb6zi9CbL4
         D6yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEMKdd9yCn3WLz1ZmGhTrcnpYR7ZJELFVG73h6c+Yk4=;
        b=jDdaGZhGv7H2MUe09sehrjcIqtWDThJ02STBotYvW5xIC+GwjNNJtqFWJLK+gIFfIo
         RudxV63DoP86hhXXRBzQymAmpJh1eL0G8m8IQQSNOXO+nN2bLl17MMrsPy94VhRtL6eo
         Xlc1eJGMbHUDdzAehHqiVmfN5mIkaceZdomqKzag03oaLT307D0PLMH6TAut/5RADbam
         0YIBzOjpUf6vaLyn5ko3LrEjSOXZ0uotjh59YvJDYu14+/B9PgowJ62Jm3ooy3Mt4Ise
         /9vEDx5X91zGpr8AvqyC9KQ/fCnSjB4LtE70AYDMJqx4/vnUERAqfYbpbI7lMSbb15zg
         j6pg==
X-Gm-Message-State: AOAM533Vx9cE7pC6M4SQ92GOliUqumjqim2+3zN9vflSWVc3W7QiHpTo
	2jQOalvDmteBSY1cRHIa9g8=
X-Google-Smtp-Source: ABdhPJyYaYLI0RaIC4gac/QIfJ2wTITAAFFO6+sO9o8VmH5gEakwD7L3Evzy4qlQthtdpr3/tQ9sNw==
X-Received: by 2002:a05:6e02:54b:: with SMTP id i11mr579187ils.50.1590070943524;
        Thu, 21 May 2020 07:22:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d68a:: with SMTP id p10ls665782iln.1.gmail; Thu, 21 May
 2020 07:22:23 -0700 (PDT)
X-Received: by 2002:a05:6e02:68c:: with SMTP id o12mr9124279ils.170.1590070943116;
        Thu, 21 May 2020 07:22:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070943; cv=none;
        d=google.com; s=arc-20160816;
        b=Ta52a1AOcZlNmwnzj3SDqHkTDCUCkLLBqHZ41ofm7x+zR3aV2mFiaZzPQGFxZyJWPc
         vo0MdvfYICyHG5xPvg9wEMcT+Cgw3WedGsHI9A0ZNIzVmbg15hlZ+muqsYOtbttUjU0n
         xyqBIflnNQQ9PfP5siGwNlMQzE5aTB4beuFtKLAIf7HzlB+VMWZFWL3Qesa9fYkslP2x
         8J4CppLdw+6f6p4u+Xe2aVzxN3jwISC4+L3uYuJRxFfuSBIYa4o6eUW0ZmvueliVsx4M
         V3epHjpaoTyMrFEZmYr/8bfEcIujjA6qqav9GS+HlDy/SUki9U2szGMNPFtzVKgfgjWW
         +Uxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Rd50Ui3HZ2EL9EcMGbbjqrEeCeIHgbARzkGzMmh8b1c=;
        b=EPJVTRb9bzD2vbZUwVRcN0UHGAT6uO/X177rOruwm1QhTeddt9kXF3uDbpZ1sqAWka
         /V8vvjUwSLaSBygOOgcTzEOlx8WA4UcOlIjoYMTGSGLpRAXQZtbvgo0LBdZ+AcPpg+ty
         MLZBvFWbPguuSXjWD38eObVYsqxjh33nbgC9EmY5rcxhndqo/SPE8IczMisQyXIFOF8n
         hK44BBAUExE0iIZfD9BJk2lsWkiVXF0yetmUMBHqzr9AoK4fW2BWSCn07yz8HLVwK41T
         x/A1d5KxXC7yT2tjZeRcdx8XLhl4Io9XVbp8QuvV2vg+rNDyUYosaXwjM2xIttGgENat
         Gptw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iok4xGuH;
       spf=pass (google.com: domain of 3no7gxgukcde18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3no7GXgUKCdE18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id d3si376897ilg.0.2020.05.21.07.22.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3no7gxgukcde18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id dm14so7291988qvb.7
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:23 -0700 (PDT)
X-Received: by 2002:a0c:9141:: with SMTP id q59mr9942670qvq.58.1590070942466;
 Thu, 21 May 2020 07:22:22 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:37 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-2-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 01/11] ubsan, kcsan: don't combine sanitizer with kcov
 on clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Iok4xGuH;       spf=pass
 (google.com: domain of 3no7gxgukcde18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3no7GXgUKCdE18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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

From: Arnd Bergmann <arnd@arndb.de>

Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
with -fsanitize=bounds or with ubsan:

clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]

To avoid the warning, check whether clang can handle this correctly
or disallow ubsan and kcsan when kcov is enabled.

Link: https://bugs.llvm.org/show_bug.cgi?id=45831
Link: https://lore.kernel.org/lkml/20200505142341.1096942-1-arnd@arndb.de
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
---
This patch is already in -rcu tree, but since since the series is based
on -tip, to avoid conflict it is required for the subsequent patches.
---
 lib/Kconfig.kcsan | 11 +++++++++++
 lib/Kconfig.ubsan | 11 +++++++++++
 2 files changed, 22 insertions(+)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index ea28245c6c1d..a7276035ca0d 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -3,9 +3,20 @@
 config HAVE_ARCH_KCSAN
 	bool
 
+config KCSAN_KCOV_BROKEN
+	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
+	depends on CC_IS_CLANG
+	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=thread -fsanitize-coverage=trace-pc)
+	help
+	  Some versions of clang support either KCSAN and KCOV but not the
+	  combination of the two.
+	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
+	  in newer releases.
+
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	depends on !KCSAN_KCOV_BROKEN
 	select STACKTRACE
 	help
 	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 48469c95d78e..3baea77bf37f 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -26,9 +26,20 @@ config UBSAN_TRAP
 	  the system. For some system builders this is an acceptable
 	  trade-off.
 
+config UBSAN_KCOV_BROKEN
+	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
+	depends on CC_IS_CLANG
+	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=bounds -fsanitize-coverage=trace-pc)
+	help
+	  Some versions of clang support either UBSAN or KCOV but not the
+	  combination of the two.
+	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
+	  in newer releases.
+
 config UBSAN_BOUNDS
 	bool "Perform array index bounds checking"
 	default UBSAN
+	depends on !UBSAN_KCOV_BROKEN
 	help
 	  This option enables detection of directly indexed out of bounds
 	  array accesses, where the array size is known at compile time.
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-2-elver%40google.com.
