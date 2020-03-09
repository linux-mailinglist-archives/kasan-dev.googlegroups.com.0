Return-Path: <kasan-dev+bncBAABBOVGTLZQKGQE3MZ5EVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6906517E7D0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:27 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id n8sf1690269uak.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780666; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkHSWLR0CeKUG4COoOz44vjI4yTFNcdl3tXBovo0c/yNj6rEawP37g3byG0zGCUcTG
         OGUibbEmpPRipHuYHnodXySBa18SkOMeEG9G6StPPj4R1VZfy21Td/DepceRuFdz21Ea
         I2gWtafoL2OugkDq5sY9j/r7HHgtzPKNIaqe8m29N9VR0/ovMRtr1U9RUBhRBE/dTX+A
         s1k6npzQqnb1MQ4LLwiZKSeGTZ4KbjMTfv14MT7lCPF/f2NyxGa5i+1ShauVkx9dJB2y
         qUWIigAtmNKUiLH3GhICGe9NB5d945XOrS3N4NLSiWcrcBMEiUhIJ1jO52409DqhS4cc
         N0jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=WCtFp80wEwnwacLV+wgXKJwNbLoEF+U4KSOjQuI9cnA=;
        b=XhBM8AgxVRGxz3nCq1k54XWOfgv5hqHm2GdnC/thCHYsqEX/cirE8qsTrey3dW6c6a
         5Hqfp0ZLsykjSgKdVNhZz2ct8/Rd5YJLOoNymJZZ6B2fEPH9whQhBRPlf6dBtgWGJVWV
         NtN1D8twGLgE1tYamIdv316d5brz3Lvs6fpuVC7vQ+JaXRRK9CojHxyWh2QIUPa/ERiJ
         75O8MHUI0gT7lsmr+OjyM306EZfdmbvtm9rfTV4sCpY/xbTJcb7Xe1cB/9QeZZAiyscz
         i31VrdoJuc7OGRTdd9EoYe2EW9Xb6YhvNKDO+tI2lSwMHK1x2/N3sbsBAZV8tlfuYr1y
         Xt1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LLCKQzKR;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WCtFp80wEwnwacLV+wgXKJwNbLoEF+U4KSOjQuI9cnA=;
        b=rZvecxfrTipcuWWPUXjTaktMcDDdOmF+1TgfReUP3H5pcELb9hP9JeOsSv5u8I/FLQ
         5JVHcHT08cPlJ35crTvkeDOo577HcWh+6/Rek+HBjNUHExqHQ1eLVIIGjEu6+/QJCYzK
         VW71pu4z0TpJzB8SLj/PXM+SN5NWJisl4OUrzDn/brGyVLPE0he5Hzc2HMesZVHXWeLY
         NqiefXuwBVEQeVb0uVw21bBUShDXAfTstsODUPOFbdoFWsqsLLS6p+oHh9DxNsT0BFim
         l/fuVazAbHVUUmxC6ILVr7TLwQiMlkV2ncYZnO6Hh0AWSgggjDnJw1eTYUabfsgoACYU
         L+TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WCtFp80wEwnwacLV+wgXKJwNbLoEF+U4KSOjQuI9cnA=;
        b=GKyE9T3pUJorA26pYVXPOmyPWSsTK6AXrCT/e49+BkYV63jAa5kxPiq/lSwsvVUDBE
         FaWX+Thbe3QwbZqlBs3mJNvFLhwhiMmv1WLamwWRT7vWw7P0uVao5qlFhLMIMg1TShTH
         4Woc/RjY5KjZEQPYHmNNkgRCZaNYzJFwvgnExmwHxuxudgZG8cj7DZlYLGyn/x1b/J1R
         IfWwL4OuCHx382PEaAdwKGENWf8mtkhiNpXJ58g1uZi82zvFbOx6usc00UNvsNiY1DTI
         ZuiZwMEvFEp8aSuf7o46vLBk022DuFuYLcdQCYRyr1jY6D5K6RvfLmDgyk8vGWdOVTKl
         dKkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1Cx/D/5X6CQxXUt4kSH51A+x0RjP0YS4jhCVFXzHH8Ouzwk6Wa
	QaAh6wpberRz9g/Q0egh2YM=
X-Google-Smtp-Source: ADFU+vv6+FusJ1YQNjWoVZHoxmKBx03LF3kYgYXu+ugOHI3U8f04nv6PPaLryW32dUwc1ZED/Yyv8g==
X-Received: by 2002:ab0:1c44:: with SMTP id o4mr5960548uaj.59.1583780666429;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f50b:: with SMTP id u11ls444119vsn.4.gmail; Mon, 09 Mar
 2020 12:04:26 -0700 (PDT)
X-Received: by 2002:a67:ed0a:: with SMTP id l10mr10168572vsp.239.1583780666148;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780666; cv=none;
        d=google.com; s=arc-20160816;
        b=auh/8OvYxd3H4yPPcGopBRTD5xpZub3t6hOL5LqM7paa3XJb/Ns+7b5V3Auym4OYQk
         3jzsNc3jQKa+UCim6DEILmNQTm6eH3MxmNkYpYRsvS8fCShshfya9bSwGOevCB9Wr5wj
         GjijsGmk2WioZ64zf5n8V0EWpoD1jve28o8DR8vCsLrw8xRfxCkPaX9xgIQqpmVDVmQz
         vsWDoJB4n2WCkfChJSxShdmnIozJqbWszogqnjB4HewHuJMWGht9DGrPNTKlHVf/D3WN
         zC3dw6G+mj1aZYXDY7gZ6gt/Ntub1TFY/XzXh80W5f/2SxhZbElylgXbb868y4uXVSxW
         8Szg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=iBolY0lxP7pU+p8c4+lbD7T5UBtwQdW+/cUetIYHyJA=;
        b=dJHO5txXBPHpKXg3ow1fkU+NqE6eAulVCPFcjmTqV4s75q7iYIUzqiON5R+/kaxieA
         V7Y6CldQW8J2YFksdGGnXQUu6rxJd/IgWmTCgsoygHOhmCM1KrvJ8tGCJpCveaJvfRZ9
         iebsQoETpQzGSqp/ICcrtIIWm7zQnQDUUorq2d6SQgrjxFPRR+43NSzrXUjwEiuLSatL
         nxEGX960eBa0EIlW5YCowqAAtn5RjiuMHf4LGFjzOc7UQ5+PzMXShey7Q6b+/ZktQ6kE
         LEtdvxoyuREQTPzATh4eiXmcC/8goq6W0wxXT/Jqq4EoeZIyzDum42OiGH7cBsTbQDh4
         Lm7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LLCKQzKR;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g4si412211vke.3.2020.03.09.12.04.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1A46F2465A;
	Mon,  9 Mar 2020 19:04:25 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH kcsan 12/32] kcsan: Add option to assume plain aligned writes up to word size are atomic
Date: Mon,  9 Mar 2020 12:04:00 -0700
Message-Id: <20200309190420.6100-12-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=LLCKQzKR;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
aligned writes up to word size are assumed to be atomic, and also not
subject to other unsafe compiler optimizations resulting in data races.

This option has been enabled by default to reflect current kernel-wide
preferences.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 22 +++++++++++++++++-----
 lib/Kconfig.kcsan   | 27 ++++++++++++++++++++-------
 2 files changed, 37 insertions(+), 12 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 64b30f7..e3c7d8f 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -5,6 +5,7 @@
 #include <linux/delay.h>
 #include <linux/export.h>
 #include <linux/init.h>
+#include <linux/kernel.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/random.h>
@@ -169,10 +170,20 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static __always_inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool
+is_atomic(const volatile void *ptr, size_t size, int type)
 {
-	struct kcsan_ctx *ctx = get_ctx();
+	struct kcsan_ctx *ctx;
+
+	if ((type & KCSAN_ACCESS_ATOMIC) != 0)
+		return true;
 
+	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
+	    (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long) &&
+	    IS_ALIGNED((unsigned long)ptr, size))
+		return true; /* Assume aligned writes up to word size are atomic. */
+
+	ctx = get_ctx();
 	if (unlikely(ctx->atomic_next > 0)) {
 		/*
 		 * Because we do not have separate contexts for nested
@@ -193,7 +204,8 @@ static __always_inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static __always_inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool
+should_watch(const volatile void *ptr, size_t size, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -202,7 +214,7 @@ static __always_inline bool should_watch(const volatile void *ptr, int type)
 	 * should not count towards skipped instructions, and (2) to actually
 	 * decrement kcsan_atomic_next for consecutive instruction stream.
 	 */
-	if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
+	if (is_atomic(ptr, size, type))
 		return false;
 
 	if (this_cpu_dec_return(kcsan_skip) >= 0)
@@ -460,7 +472,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	if (unlikely(watchpoint != NULL))
 		kcsan_found_watchpoint(ptr, size, type, watchpoint,
 				       encoded_watchpoint);
-	else if (unlikely(should_watch(ptr, type)))
+	else if (unlikely(should_watch(ptr, size, type)))
 		kcsan_setup_watchpoint(ptr, size, type);
 }
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3552990..6612685 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -91,13 +91,13 @@ config KCSAN_REPORT_ONCE_IN_MS
 	  limiting reporting to avoid flooding the console with reports.
 	  Setting this to 0 disables rate limiting.
 
-# Note that, while some of the below options could be turned into boot
-# parameters, to optimize for the common use-case, we avoid this because: (a)
-# it would impact performance (and we want to avoid static branch for all
-# {READ,WRITE}_ONCE, atomic_*, bitops, etc.), and (b) complicate the design
-# without real benefit. The main purpose of the below options is for use in
-# fuzzer configs to control reported data races, and they are not expected
-# to be switched frequently by a user.
+# The main purpose of the below options is to control reported data races (e.g.
+# in fuzzer configs), and are not expected to be switched frequently by other
+# users. We could turn some of them into boot parameters, but given they should
+# not be switched normally, let's keep them here to simplify configuration.
+#
+# The defaults below are chosen to be very conservative, and may miss certain
+# bugs.
 
 config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
 	bool "Report races of unknown origin"
@@ -116,6 +116,19 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
 	  the data value of the memory location was observed to remain
 	  unchanged, do not report the data race.
 
+config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
+	bool "Assume that plain aligned writes up to word size are atomic"
+	default y
+	help
+	  Assume that plain aligned writes up to word size are atomic by
+	  default, and also not subject to other unsafe compiler optimizations
+	  resulting in data races. This will cause KCSAN to not report data
+	  races due to conflicts where the only plain accesses are aligned
+	  writes up to word size: conflicts between marked reads and plain
+	  aligned writes up to word size will not be reported as data races;
+	  notice that data races between two conflicting plain aligned writes
+	  will also not be reported.
+
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
 	help
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-12-paulmck%40kernel.org.
