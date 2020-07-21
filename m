Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSUH3P4AKGQERW5FTQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C6F2227CFD
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:34 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id f7sf343724wrs.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327434; cv=pass;
        d=google.com; s=arc-20160816;
        b=F1bgvVAvt1+jIi6bn76EoGnluTE4Kd2opmYAqyfAP6EgSmCfuJ5H2g11fvT3IjYllU
         ji23IyYcjg/HA216FytrX3vXMiHZI9b3nKmc3Xs4aM/Ia5H1Joy7lRb0urCWFpaUmWVy
         uDvRFEZl6cnWiXfLDrALt7/hPfCvq5iryJDXzmkgO8pEez+j3t2u8nnUPk+7HUITykVk
         9V4r8gH8CXUtoc+jjWyKhgVMHLHwiCUC7KM/bag/iY/AlsRyi+zi5QT/9BkdmQ5nDULk
         gj3v62hk8QQSdh5exsjlihS0FFZgOmxbRFPAhZCvl+b8ia7mFQXHC5lxBgaDWV5HW3f9
         AZvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lFvBeZsEzCh8hd1Un4oTYoqJQBx3bs/L+0pC3PuAtYs=;
        b=hFA1j0aC2BxyDNk4zb4sU8P9m5Bva5wDV4TZiAk4IeP0eujEJbU1OVZeg4v53U8x9/
         nh67D37v+jc3QBOZHlz4ZIYdn0tqvBcleyVDRnRmLYIh8Lo00OU2zytAqpKaYAw6NUFh
         EsCAC8GF5zVNlgmmqI1+iui1mswlwYjizItYbKKVs0mELqnTLc5Pn7IeEamquILOXYQd
         UX3N1RqCqfd0kUgRRVEtechMbHd1QMC37fglGyjbSQahRM48Zp5VGHINpD27xlprt+9A
         B0wN+ijI4IQIUOUBMYJfZFWhHj+vrLmER/E3nEE6byKaPL89G2GbIJy7ZQOyqwfciHBU
         oDPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LT9NtZoo;
       spf=pass (google.com: domain of 3ycmwxwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ycMWXwUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lFvBeZsEzCh8hd1Un4oTYoqJQBx3bs/L+0pC3PuAtYs=;
        b=B9DE3gf+3oZo0qG0EiYgo5AFAnEFvehEIhaCQM4waCOp6pUNHk0txrU2mgXHizg58e
         U1a/UI3Wbyz/3N61OsXhmSq+17yLjYxXQYcC6lvugCX28J+JBtiVu+f4R9Mxd71HmbFC
         ZLFosxLj6+5aNPwxmZW06o90BPvzAbdvh+zEcIRNpUVpdOKutlp4f4RTLpAKjkkxzr2L
         3LTyT8Zjg1MbE5QnK45VzQqkEpM0hbkR3+XFOowFqpKz6eRd+2ehkcKpoGwS4r7YZcNo
         yeYUewd8n3W9/SGeSdMtiLw8o+fTLTCtL0vvCrr7Oa8WpkKOLUav8CkNwLPwCF7u4dEU
         oxUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lFvBeZsEzCh8hd1Un4oTYoqJQBx3bs/L+0pC3PuAtYs=;
        b=kkZx6dH4Jk+Xf7A92NGFthFFKFQ9BkViz78dNuIdCv5DW9PGCfjUYYut2LHmsKMUyO
         XVnDKnt4a2rnzyfSj/bMe1KPpn7w1pyeogvsaWR/B/+jzbKklTrhFf1iuPqADHB8gJmt
         HQ/BCOim3L6irD82Jlhk0lJw/MSRm8axpKmR5SHmWgwU78Dpzn74/CqLcCik7YAeRJ0E
         EEuPkcc+SawxPHBxUUWu4euY1j9fEYlmL6rgk8vQUPesGe2zMC6J9wlUcFhdE4YAGTab
         0L5BUU96txC9TLDua4E74Xu+LltXo+s5BGNbMSljc/dor+QwSehkrszEcWxGzplq8X5z
         Fmsw==
X-Gm-Message-State: AOAM531jjhWK6Y/uNAl5MNunj/axRlkW+1C7ku3IsnPXoWhnGIEc5Y3U
	EuOiKevW4aXCCpXmnpc2p+8=
X-Google-Smtp-Source: ABdhPJzIdZYczInp8nI3zngHjprRw00hQ5wQOTgaRkN7+09iKRplHp92MX/gRP+iiyZb8hVSCtpSZA==
X-Received: by 2002:adf:e4cc:: with SMTP id v12mr27286635wrm.92.1595327434162;
        Tue, 21 Jul 2020 03:30:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9ece:: with SMTP id h197ls1019019wme.1.canary-gmail;
 Tue, 21 Jul 2020 03:30:33 -0700 (PDT)
X-Received: by 2002:a05:600c:281:: with SMTP id 1mr3485872wmk.143.1595327433498;
        Tue, 21 Jul 2020 03:30:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327433; cv=none;
        d=google.com; s=arc-20160816;
        b=SyLveF5pkjWje0xiUDF1jbt9e2g3jyqFdAXrq8L+WCjBhUcfcB+fzu7Tc0+F5l/C/k
         ATWjETENffR+blAL4cdVTnxlQ9JE7kvZ6DVbOb5yCY/z98O3PvtuFRrsIYOrtLQIWo99
         tG4sPfiZQextmI8G32Dr9SOxEgOrSc29v9Io7mF7Woh4Fm/O/eGbukRJjBXObBDgS/hn
         uNghLf5f6v6HWpUtJj4Gnv2tx2d6q9Ypg1O5I3uhX4wdO/b6E4xQ7pK5F3TMyDQAyjeI
         ikk/RgNB/c8tK7w1PZ12YdPbvSbW0iWXFF5auYKvpl/7DGGPyObJl+QG9XVNdxQzXlrh
         VRYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QN03hGb1dtnU9kx2PScGQDyxb1uL0PGs7IgSGP8StbY=;
        b=Dg8ozGwrxFF6G7MObCDvMJGPhc5fBzKJJFgrIV3CLDxJLeXZsEQsoypFiGpD9zadYG
         XMpa8TJ4nkMGrWCj80qemwPNtrvKsl23DduVA6UOdfto+oZqjIv/GPZ0fOTqVPUouXjv
         WTV2s4PqI+LbjLKEPomreCktky3ZPa0ea+UyQyS7OHPGU5rF6/x9OT5278CnpT5u2wH7
         zyMy5FHo2Joi4FVbMuOUAY6zZ1AV2Q2Jnx/Mffv+mHWhSbHJYMwLjO3+uHGgjSCQFEjl
         YTbGMQKDqTZGdaW1XiNt/m/HWUc8mE3lWcOCCedu8roJtvAX1DU/UZzNOWiwiFf+5faJ
         VHcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LT9NtZoo;
       spf=pass (google.com: domain of 3ycmwxwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ycMWXwUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l4si665626wrm.3.2020.07.21.03.30.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ycmwxwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g138so832789wme.7
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:33 -0700 (PDT)
X-Received: by 2002:a7b:c84d:: with SMTP id c13mr3416944wml.170.1595327433015;
 Tue, 21 Jul 2020 03:30:33 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:09 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-2-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 1/8] kcsan: Support compounded read-write instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LT9NtZoo;       spf=pass
 (google.com: domain of 3ycmwxwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ycMWXwUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Add support for compounded read-write instrumentation if supported by
the compiler. Adds the necessary instrumentation functions, and a new
type which is used to generate a more descriptive report.

Furthermore, such compounded memory access instrumentation is excluded
from the "assume aligned writes up to word size are atomic" rule,
because we cannot assume that the compiler emits code that is atomic for
compound ops.

LLVM/Clang added support for the feature in:
https://github.com/llvm/llvm-project/commit/785d41a261d136b64ab6c15c5d35f2adc5ad53e3

The new instrumentation is emitted for sets of memory accesses in the
same basic block to the same address with at least one read appearing
before a write. These typically result from compound operations such as
++, --, +=, -=, |=, &=, etc. but also equivalent forms such as "var =
var + 1". Where the compiler determines that it is equivalent to emit a
call to a single __tsan_read_write instead of separate __tsan_read and
__tsan_write, we can then benefit from improved performance and better
reporting for such access patterns.

The new reports now show that the ops are both reads and writes, for
example:

	read-write to 0xffffffff90548a38 of 8 bytes by task 143 on cpu 3:
	 test_kernel_rmw_array+0x45/0xa0
	 access_thread+0x71/0xb0
	 kthread+0x21e/0x240
	 ret_from_fork+0x22/0x30

	read-write to 0xffffffff90548a38 of 8 bytes by task 144 on cpu 2:
	 test_kernel_rmw_array+0x45/0xa0
	 access_thread+0x71/0xb0
	 kthread+0x21e/0x240
	 ret_from_fork+0x22/0x30

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 45 ++++++++++++++++++++++++------------
 kernel/kcsan/core.c          | 23 ++++++++++++++----
 kernel/kcsan/report.c        |  4 ++++
 scripts/Makefile.kcsan       |  2 +-
 4 files changed, 53 insertions(+), 21 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 7b0b9c44f5f3..ab23b38ad93d 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -7,19 +7,13 @@
 #include <linux/compiler_attributes.h>
 #include <linux/types.h>
 
-/*
- * ACCESS TYPE MODIFIERS
- *
- *   <none>: normal read access;
- *   WRITE : write access;
- *   ATOMIC: access is atomic;
- *   ASSERT: access is not a regular access, but an assertion;
- *   SCOPED: access is a scoped access;
- */
-#define KCSAN_ACCESS_WRITE  0x1
-#define KCSAN_ACCESS_ATOMIC 0x2
-#define KCSAN_ACCESS_ASSERT 0x4
-#define KCSAN_ACCESS_SCOPED 0x8
+/* Access types -- if KCSAN_ACCESS_WRITE is not set, the access is a read. */
+#define KCSAN_ACCESS_WRITE	(1 << 0) /* Access is a write. */
+#define KCSAN_ACCESS_COMPOUND	(1 << 1) /* Compounded read-write instrumentation. */
+#define KCSAN_ACCESS_ATOMIC	(1 << 2) /* Access is atomic. */
+/* The following are special, and never due to compiler instrumentation. */
+#define KCSAN_ACCESS_ASSERT	(1 << 3) /* Access is an assertion. */
+#define KCSAN_ACCESS_SCOPED	(1 << 4) /* Access is a scoped access. */
 
 /*
  * __kcsan_*: Always calls into the runtime when KCSAN is enabled. This may be used
@@ -204,6 +198,15 @@ static inline void __kcsan_disable_current(void) { }
 #define __kcsan_check_write(ptr, size)                                         \
 	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
 
+/**
+ * __kcsan_check_read_write - check regular read-write access for races
+ *
+ * @ptr: address of access
+ * @size: size of access
+ */
+#define __kcsan_check_read_write(ptr, size)                                    \
+	__kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
+
 /**
  * kcsan_check_read - check regular read access for races
  *
@@ -221,18 +224,30 @@ static inline void __kcsan_disable_current(void) { }
 #define kcsan_check_write(ptr, size)                                           \
 	kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
 
+/**
+ * kcsan_check_read_write - check regular read-write access for races
+ *
+ * @ptr: address of access
+ * @size: size of access
+ */
+#define kcsan_check_read_write(ptr, size)                                      \
+	kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
+
 /*
  * Check for atomic accesses: if atomic accesses are not ignored, this simply
  * aliases to kcsan_check_access(), otherwise becomes a no-op.
  */
 #ifdef CONFIG_KCSAN_IGNORE_ATOMICS
-#define kcsan_check_atomic_read(...)	do { } while (0)
-#define kcsan_check_atomic_write(...)	do { } while (0)
+#define kcsan_check_atomic_read(...)		do { } while (0)
+#define kcsan_check_atomic_write(...)		do { } while (0)
+#define kcsan_check_atomic_read_write(...)	do { } while (0)
 #else
 #define kcsan_check_atomic_read(ptr, size)                                     \
 	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC)
 #define kcsan_check_atomic_write(ptr, size)                                    \
 	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
+#define kcsan_check_atomic_read_write(ptr, size)                               \
+	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND)
 #endif
 
 /**
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index f8dd9b2b8068..fb52de2facf3 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -223,7 +223,7 @@ is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx
 
 	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
 	    (type & KCSAN_ACCESS_WRITE) && size <= sizeof(long) &&
-	    IS_ALIGNED((unsigned long)ptr, size))
+	    !(type & KCSAN_ACCESS_COMPOUND) && IS_ALIGNED((unsigned long)ptr, size))
 		return true; /* Assume aligned writes up to word size are atomic. */
 
 	if (ctx->atomic_next > 0) {
@@ -771,7 +771,17 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	EXPORT_SYMBOL(__tsan_write##size);                                     \
 	void __tsan_unaligned_write##size(void *ptr)                           \
 		__alias(__tsan_write##size);                                   \
-	EXPORT_SYMBOL(__tsan_unaligned_write##size)
+	EXPORT_SYMBOL(__tsan_unaligned_write##size);                           \
+	void __tsan_read_write##size(void *ptr);                               \
+	void __tsan_read_write##size(void *ptr)                                \
+	{                                                                      \
+		check_access(ptr, size,                                        \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE);      \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_read_write##size);                                \
+	void __tsan_unaligned_read_write##size(void *ptr)                      \
+		__alias(__tsan_read_write##size);                              \
+	EXPORT_SYMBOL(__tsan_unaligned_read_write##size)
 
 DEFINE_TSAN_READ_WRITE(1);
 DEFINE_TSAN_READ_WRITE(2);
@@ -894,7 +904,8 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		check_access(ptr, bits / BITS_PER_BYTE,                                            \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
 		return __atomic_##op##suffix(ptr, v, memorder);                                    \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
@@ -922,7 +933,8 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		check_access(ptr, bits / BITS_PER_BYTE,                                            \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
 		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
@@ -933,7 +945,8 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		check_access(ptr, bits / BITS_PER_BYTE,                                            \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
 		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
 		return exp;                                                                        \
 	}                                                                                          \
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index ac5f8345bae9..d05052c23261 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -228,6 +228,10 @@ static const char *get_access_type(int type)
 		return "write";
 	case KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "write (marked)";
+	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
+		return "read-write";
+	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
+		return "read-write (marked)";
 	case KCSAN_ACCESS_SCOPED:
 		return "read (scoped)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_ATOMIC:
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index dd66206f4578..a20dd63dfd17 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,7 +13,7 @@ endif
 # of some options does not break KCSAN nor causes false positive reports.
 CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
-	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
+	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=1),$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1))) \
 	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-2-elver%40google.com.
