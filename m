Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 631C5474D8C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id f13-20020adfe90d000000b001a15c110077sf449573wrm.8
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=rAnULXNoN+m1CItEfdz1OpKbF5yVlVzdT3VtBm2F1arJLDcwBwPZTQUhCXbaQg17EG
         aczCBu8ztDQfGeXeDYO16+IpG8LL1rMiPwWYrRk3ivP1Cepd69iN+kz/juGEijAWirVw
         7ZK5phuW7C+wPhYkVOxRb/Re22trIuU2wZxPwy7PNsUsbT+ousz0ddCMPOOYZz1+/jo7
         GNq3jPMzURQlLIudGPBpkekx9J6NQEBwhUA+R0xshrrZBo1FzvB4U8ZOPti81qMevUDT
         SOv8oufbp4GiJckd6TQ1P95ot6d3lJxSbM5gzorF0KQ2qHw0UpRmpNIlOCwAQ4NaPzUi
         b4Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Zj8PlcGiQ7JATBDC/YdsS2FhUBDC2rFWtiJnBwnat7A=;
        b=yva3Xpm9ocKh8wrxfS1EeFrJIDxY++OgGlYFkiRBZksDQIn1iiYZStAA3d8WGlKpuE
         nm5Tmcp59INY6X7ciOS9vWAKuA20K/Aw7ZQEQmBkfvJh/DNfQCG4Ghsm7cQEfy8hJumH
         g4O5fnfDo1F0CEctat6gvvButSy92SNKiV9SNqJVPKwZ1YKHIRrM94t2x96HWgC3clRE
         ABOtTmFIb/DMZd/DnQ4Ie6tAidgYXzD9iyzbYw+e783HIli2C1MIPlm+tUynTpznheCY
         EqaV97xblPp+tR0hQPrqTm0LscM9XJYU6QJKiTnK6O+uGGoG2ntS8Rne5PR7yNcsaEkr
         yUiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b9AsQcoZ;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zj8PlcGiQ7JATBDC/YdsS2FhUBDC2rFWtiJnBwnat7A=;
        b=luuoRXisojWdsmkjLsAopSJlXkCpaOO50/2Zu8Wx0JqvsqrF48ZF4sJuVoA54uZ1Y+
         JFQRUOcnylJWYRVMP4pFwXNhAE1P9B5gRb2IyOz6QQyMXnfd9dkD0UoEUVkGNpV/i2Fu
         kIRux70ogs5C/PfO+Qv7LAdNm1k2hPriFuDrdud3J6Cb7C9nb08V6uB6Rh7A5tvoZ5TM
         7OkevLbAQrRzKadrdG0myYDa6WUHjWABvhY+UCkTgAuq/UiMcJvzuXcixXiYD0N1Bvj1
         F/ZOhA0eFKygxOblAbvAcYnq3uIfwW6IdFKIM49IzIqOs7lzqdB9z0FNsZlDEKJObpfz
         JC3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zj8PlcGiQ7JATBDC/YdsS2FhUBDC2rFWtiJnBwnat7A=;
        b=p2KQSTXF+uruhTDQohbnGpniL5QuvB27zLVBgx3BUA4wmfEBANou3aYWgR0oQEWln7
         ysEEXXeKlwp5X1hUYrZ24fKDRT7ooCgF5QbY25eoSuOb/hOENYd1BVxaGR/NbjvvO7zA
         EkkWIxFJlgbTgUHcKSIaDdj5ijpTtNAhVYu7U4fKjXyY88H/KHXOOaXRYB7vyTbtm5ca
         iis5FwwMlyxmKlTNXIiHyhgp7oEF6RRRwScCmT5mb1F41agzCEIt9yit8ObF+3aTgIVV
         waxhlWwE3jc8LLB4Kx2hPmAMy67y0sUH3k6hlV+ZD09+gej19Fs50M3uKWyuf0nLH5Wx
         pBTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309c2oj1144cUcyg9riU2nc4aERxNX0z9omL6T2hhvehLDaaz0P
	LRSG0d/7kGCm2GdbRkdm3oE=
X-Google-Smtp-Source: ABdhPJycTdvmGKZwXcY8ltdcb+MfY3gGzHBCFY1J2WdIDeW6ci1mDKBdG7nZADTXzMyTouEn6mSNvg==
X-Received: by 2002:a5d:4448:: with SMTP id x8mr1777672wrr.508.1639519487107;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls207382wrp.1.gmail; Tue, 14 Dec
 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a5d:6c6a:: with SMTP id r10mr1700843wrz.211.1639519486212;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=hFYuTFe6uXQRXyZZY1C1V9kJOQ6/LSyDAf1WK9jlWVkqoyJ2+Sg3D0LiNw5zuyMCI0
         9iu9b93DPcrzWUId6T//7XYDJ4GPLf15k4r1DnKwWhHT1Ad8VI0XZrtqONOd85L+7Uzr
         6splq+HiCQLpd67d6UQjT5xFoM0CXPyJv/r7Ic5WGsMsAqlKQ/wofXQw0nboBiWxSEwE
         yQcNbiHqboJ1pBsiL8oylatklmH9Tz/VDTMsDTV0fIYPO+u8d4kp6vNi2hPuKU+OrvJN
         cZD5UVotJ0f5U9AJgg0f7cM4nFr/ZXuXahvAuu2aeSD38DzC4KrGiowkmRZOIaTj2dj6
         WOPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BRrRKQ2z4w0s5fTdIGE22ejSANUGvwD5r4NpZE+EIKU=;
        b=FaKSx2Mjzl+0do86YMFF0Bh67Ro4f3+XmBIp+8+1h95bSv7a37hXqX+Olnp5l9wj9N
         guI3WP8HQERfOE8efCWJ3ZPxA9CiR+iGaAXcs4s04iToiXj90NhfB443qFcnTsluBxg2
         AIE4O+EcDsTpOCsdyTP6S0xF8GJOJQOI5IGaduxGDJwPMYV8Qq7I/awoXWoFsd6NKo+o
         TuxR+nAORd0XPdL1/QpcBu8iWQ8+RaY1v+8oZPY3IbvZ3m61tGZq4SnVjd9WPJA18mA7
         tHoIjkVWConD1HFjMIA1dyMr8mTzo9YAG8/aQXFrBB38F7TfSYjfFja2yBosuSQWHUZN
         M/Jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b9AsQcoZ;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c10si180956wmq.4.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5AA4B61764;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3C1DAC3463A;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8A2C05C2147; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 25/29] kcsan: Support WEAK_MEMORY with Clang where no objtool support exists
Date: Tue, 14 Dec 2021 14:04:35 -0800
Message-Id: <20211214220439.2236564-25-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=b9AsQcoZ;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Clang and GCC behave a little differently when it comes to the
__no_sanitize_thread attribute, which has valid reasons, and depending
on context either one could be right.

Traditionally, user space ThreadSanitizer [1] still expects instrumented
builtin atomics (to avoid false positives) and __tsan_func_{entry,exit}
(to generate meaningful stack traces), even if the function has the
attribute no_sanitize("thread").

[1] https://clang.llvm.org/docs/ThreadSanitizer.html#attribute-no-sanitize-thread

GCC doesn't follow the same policy (for better or worse), and removes
all kinds of instrumentation if no_sanitize is added. Arguably, since
this may be a problem for user space ThreadSanitizer, we expect this may
change in future.

Since KCSAN != ThreadSanitizer, the likelihood of false positives even
without barrier instrumentation everywhere, is much lower by design.

At least for Clang, however, to fully remove all sanitizer
instrumentation, we must add the disable_sanitizer_instrumentation
attribute, which is available since Clang 14.0.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/compiler_types.h | 13 ++++++++++++-
 lib/Kconfig.kcsan              |  2 +-
 2 files changed, 13 insertions(+), 2 deletions(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 1d32f4c03c9ef..3c1795fdb5686 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -198,9 +198,20 @@ struct ftrace_likely_data {
 # define __no_kasan_or_inline __always_inline
 #endif
 
-#define __no_kcsan __no_sanitize_thread
 #ifdef __SANITIZE_THREAD__
+/*
+ * Clang still emits instrumentation for __tsan_func_{entry,exit}() and builtin
+ * atomics even with __no_sanitize_thread (to avoid false positives in userspace
+ * ThreadSanitizer). The kernel's requirements are stricter and we really do not
+ * want any instrumentation with __no_kcsan.
+ *
+ * Therefore we add __disable_sanitizer_instrumentation where available to
+ * disable all instrumentation. See Kconfig.kcsan where this is mandatory.
+ */
+# define __no_kcsan __no_sanitize_thread __disable_sanitizer_instrumentation
 # define __no_sanitize_or_inline __no_kcsan notrace __maybe_unused
+#else
+# define __no_kcsan
 #endif
 
 #ifndef __no_sanitize_or_inline
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index e4394ea8068b0..63b70b8c55519 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -198,7 +198,7 @@ config KCSAN_WEAK_MEMORY
 	# We can either let objtool nop __tsan_func_{entry,exit}() and builtin
 	# atomics instrumentation in .noinstr.text, or use a compiler that can
 	# implement __no_kcsan to really remove all instrumentation.
-	depends on STACK_VALIDATION || CC_IS_GCC
+	depends on STACK_VALIDATION || CC_IS_GCC || CLANG_VERSION >= 140000
 	help
 	  Enable support for modeling a subset of weak memory, which allows
 	  detecting a subset of data races due to missing memory barriers.
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-25-paulmck%40kernel.org.
