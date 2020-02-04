Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHGQ43YQKGQEAU3S6GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5331A151F3D
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 18:21:33 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id m21sf1552565wmg.6
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 09:21:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580836893; cv=pass;
        d=google.com; s=arc-20160816;
        b=dWlkr/r/rFS/ZVQxIZikbGlYalbXQHL1cJ1QrWrketMtDBumd5m2BRwF6ZAz1E0jWa
         5C9nTnf4S/HBK3WhMTeHVWB8C/IR027WefDBxp7rCEcgm07kXsKq13wkWC9bYRMlVnMi
         4SX9gnVe/Duu3ewSkjE6Vs4ltBUKgqVcZ4M2dAfN+2rEkcWfAavs06MRuBE9ICEMpkyM
         iUiIglO/0MtAaTtNow6p4cO2iCGQWClPo/I7XhC9XZTAzOQmg+634aUC5YYM9HQx6d2s
         lR9FiDT+N2L7XO5VW1bXSdm5iLe+kd5cx7xF1B2zXh2gvcZdXkYDruQr4kLmC0WdjY/s
         P5oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=8OrJ/nOvSGU1L/O5fsbjxCwgPJ1aS86JY3SV9qfj6ZE=;
        b=m6zr6F3BIuNmCwPqz43RzNc0sYWgBqG0IwwxPXzORu69qJT1VHChii8ofJbUG7mnWH
         YDEFPyDlEA1N5ZMWGn2LB9wssdtV4zea+n1P5ZphHEAUgW0bHiGT8x9uPbascZZAAuoY
         jgYhkALePkrKiyEhz6IxqYDTNBrQfAPMyjGT5xQg1muSrhmA1My4XhQbWI8xKzRQ/upJ
         gHbyAmW4ouAppugMhyzd5FYCKa1CjdiMsoJXIh8FBaXRuaDP/QA6HLG3EMBwpB6qM5DE
         OHhYNyC3cQ0ezW/LQASQprTRea8qNOOl/gU7JB1+yBCSm9AaCX2ai5YD0MYfUkXPAl+k
         FZKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iHYYBpDM;
       spf=pass (google.com: domain of 3g6g5xgukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3G6g5XgUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8OrJ/nOvSGU1L/O5fsbjxCwgPJ1aS86JY3SV9qfj6ZE=;
        b=JEXUJAgUPqScOz1C2oHZZ/T5yfWkRrLjADmS+M8hMy4ovaab1LsVBjtXhiOF5zT335
         pJZfD6M3q/aeX83DLPtnzv7gQEIZmm/GXQHvq6eYAMtf1Yqf9mjDf7VXzDnm62Ja332S
         jf6RydYIHr/y2uhtYXIxzm6EjSEPZ922uP/ypbeJvl0AGviXy745Uzgg9NqLz3MDGDbJ
         LSt7yPp+VlpvnkRmdKdrQ8fVplqTe3BV0H9zopHTSkMl0WkluvEge9M0CSSPskYayubp
         1aeUdZnXZuFpwbKGmNU9Gm+2L5yUIsjgfjGk97huNho7SizJ/XFlvTnfBIzhRKZwW69/
         sjcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8OrJ/nOvSGU1L/O5fsbjxCwgPJ1aS86JY3SV9qfj6ZE=;
        b=GMddfdfLMcnARkqG3e9M2bE5AFGDxD/KSrtUXVascDF60WwIBSue7DbLjKwD3ivXX+
         2hMIggX0t+IX2NmeUcS1PX07FoDmBqLP8TDNuy/c7+H9eHnyzeWG7DVGCtSkd+/wcIlp
         VzKVfs/CxXILNV5UbdDVjGm2KVTh/X9m/NQFaZ9pWBb1P0Kde47eRD1qb0JAGmK2eHNP
         W/BMiONoFnyO6JOvD6taisOYnp6EiNJJd9JLwCtezNun37UhhHGMInv32eaHSs19hppl
         vzQ5VJrIkOd0uE4i+/ZoVIQz0Yi1i9vy9RU9P/4VuvjMpofXo7huNB866awf5VU0NPRD
         bpJQ==
X-Gm-Message-State: APjAAAX8y+jVYmkK8QeMOnBYXdbNwRCrR1hrAhdM1HxHHyx2dyHEjHBI
	nyvbNCQYSJ39Ql8O8+ew7fU=
X-Google-Smtp-Source: APXvYqyXvOFxBf9JXjzCdAJxSA5oPseTpV3Gcp8/rM7Eo+PT1/mS23Pn6q+QGPTBcYTlzHWGveBBQQ==
X-Received: by 2002:a1c:3b0a:: with SMTP id i10mr27105wma.177.1580836893005;
        Tue, 04 Feb 2020 09:21:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf15:: with SMTP id l21ls3270588wmg.0.canary-gmail; Tue,
 04 Feb 2020 09:21:32 -0800 (PST)
X-Received: by 2002:a7b:c416:: with SMTP id k22mr107052wmi.10.1580836892108;
        Tue, 04 Feb 2020 09:21:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580836892; cv=none;
        d=google.com; s=arc-20160816;
        b=jfSYWTuC/myOz15CbMnQP8VRtUYd02fx1+UZpjGKrekmFbhymi3+nx4Rs8nbPHpnFk
         3CEMw50nQ2tGPs0KCbyszYnSA46hDJDIndBCEcONoN8IKO15t0AhNZzubjz0QhljOEcS
         6cyh4Oy4alVADDNKQvtJ1skKbBc/zQBlnPJGRzrSB/XTusJH47RfrJbElINXrEjGuHSB
         TGfVb19uQFb7GIVchL+/vxQX0ahPCkmaiGYw5/+J1a7yqfHvPAyCsiB8311BVap8Rwb2
         hpRkol4f+FQPY+Aam9izVjZRPe+V5XFA2m4eGCEGvxTqj5KccjDab5otRikeFxgXEj0x
         ZPNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=kiVUGxEhpAM2mYb96Fzo4yFVjkxMzxjZ34CLdXp6/BA=;
        b=TrmaIbimVAmroB5ENPSPdDP2iMpn/5ud71j+P+bOy4DgQkIX/N6DjnRIVWBn21xxpU
         K79162VGVAulvV98J8GmFxksKN8sW1UMK5Qnv8h5mfa46QyMFbfQ0Qe9oXSJot6dXvIr
         qWqnJ0dLzUOr7CMO/xJTCX3fkOWUUYycvn2GWGHvvfmYDEuGrkpSadwoc6rlRdJgzVQd
         TeYeyj2IIrjJ2bhstDQ6RArvKkoxqgqyhR6YrfUpefIoMtPeAg5qF/ua4Fz6rfH8XAGI
         m1d14z+d01OKzMtp239OsOxMhCtiFV0ZKpbbA5vthLeFA4KCMBcn74GO0nxCqQ4hE5vx
         FOJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iHYYBpDM;
       spf=pass (google.com: domain of 3g6g5xgukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3G6g5XgUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d191si149461wmd.2.2020.02.04.09.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 09:21:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3g6g5xgukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t3so10549729wrm.23
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 09:21:32 -0800 (PST)
X-Received: by 2002:adf:90e7:: with SMTP id i94mr22040781wri.47.1580836891511;
 Tue, 04 Feb 2020 09:21:31 -0800 (PST)
Date: Tue,  4 Feb 2020 18:21:10 +0100
Message-Id: <20200204172112.234455-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 1/3] kcsan: Add option to assume plain aligned writes up to
 word size are atomic
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iHYYBpDM;       spf=pass
 (google.com: domain of 3g6g5xgukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3G6g5XgUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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

This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
aligned writes up to word size are assumed to be atomic, and also not
subject to other unsafe compiler optimizations resulting in data races.

This option has been enabled by default to reflect current kernel-wide
preferences.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Also check for alignment of writes.
---
 kernel/kcsan/core.c | 22 +++++++++++++++++-----
 lib/Kconfig.kcsan   | 27 ++++++++++++++++++++-------
 2 files changed, 37 insertions(+), 12 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 64b30f7716a12..e3c7d8f34f2ff 100644
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
index 3552990abcfe5..66126853dab02 100644
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
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204172112.234455-1-elver%40google.com.
