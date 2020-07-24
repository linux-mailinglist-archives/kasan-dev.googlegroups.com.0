Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCMO5L4AKGQES52FUWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3858E22BE67
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:27 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id y73sf5669131pfb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574026; cv=pass;
        d=google.com; s=arc-20160816;
        b=H7aUE96tcDqbV+cglvK+HF3gcXeekbr7xfoUVfcEr8YiAXYFc90QC7zkaCRlHkb2mz
         6qmSYwXsDy4BrnOig7s8yTno4sIZRkDZtkDgmtWzTw1hI2S+/PWZM8VGb5c9nzs1xwBF
         JG+P4R0Q913vMHTyK85cJOvgORbNpbaAtDOHhD8gdC9iXgWX7iSsLbvMDUJP+xKpUvpI
         ATfEjoKHTgwT6l2g7VgZbj9kCNuU1t3uPY9ovVLtqwls48IrgkRMbJjrLbI2UzwUjeMm
         Vyz3vAtNg4z7lqAiQO02BgehdsSFQJlnNh5JZZ+BunbewX5/kL1p0g4H5EIYp0eQlx6j
         LhYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6AfkYPzkOBpDc4AHYSndZLMXFpfoPY9KmSGLO8rp9sU=;
        b=cNh9iDSO0xQprvdeI66poisHkGPHxuI7K0ret9Ym4DAnbdCDimsv9d+wSCCXRbVArJ
         i6nXKBH6dT4nPvSHaAGf1im0ThkmVZ//MtT3+MX6wyPP3iTcniCy7/gWhd+4AEV/EVms
         UDjn8PmYmXEek/ZaCdiT1ESKAK08XmaJw60IQvq2SHfgt/HDyMuQEh3zNKU2cP3mveNN
         HZq9PQCTExerQAJ60drbMJnMNPQ+esj1MdVHqPIxeQh8cL4pST6DnPD2OzlIlCNDFb3b
         Cc5nly9F1z1p01ClPNjoXYrDVUBYP55YqzZmOm65051bOSCe+j9trsvxevyZkanOYvK0
         Qz1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gA9ZRpxK;
       spf=pass (google.com: domain of 3cicaxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3CIcaXwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6AfkYPzkOBpDc4AHYSndZLMXFpfoPY9KmSGLO8rp9sU=;
        b=Cz7Ae8x9nI5pke/4u9vsBhaj7VG5cT2DOD/Hzr64R3ARZmqX46aCF91Yq2kkLtL4b3
         v0LZBCzXJGcv2YiyBevnOiEWdxOjhy6XhtjY62LhiY6KSDBsiurNvqQPm2pAXxm7Z6yV
         wuizQcG1EIrVMbRJoG+5X7VCkDTnboWwKrd9Bk85g1HsSw2YsWMQF0bUTqM62en1D3G1
         jFpjGHq+BAGvN7IJ/nl3raXtHe4dxOz5++xpbtieTss1lSAL+mIfpRyDu66totltlgA8
         ipaoQOVVZ6miNt1fqBIw7ixiq+l3bUWDgbwir0UmSDCZGb8teN0CND/7dW7egcdmP42m
         AA0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6AfkYPzkOBpDc4AHYSndZLMXFpfoPY9KmSGLO8rp9sU=;
        b=rRWe3XhW/0cshHE69yUHY13yHd4FX7+dP51dyFLACVUjnroJ31BznMTH79u3PBMn7L
         EkFBnrcMQuJkVDYcNwPYs7V0oPQlOAfUkrnmgCqRl6R7DkVQX2gWaZ95oXdY2ujBUBuB
         Bx4nHUI/YHOi6pW7E1wmX/LS21KdMlfCqqX0/WSYHdDeJMSbwcENtC56ffsZGTA4CF/P
         +g+9LX/P1m0HcC9wxRRD9jljtuHWDf3YNDLVq2i6u6VbfppPwIS9QH+EsEft/M0gILSQ
         nrvmI0DjSBVp9q9Xq2T7UsSLRUHuURvTvZlxzuMB34yK/QJGPvf7K5z/Ga5TW57xEiAr
         QYEw==
X-Gm-Message-State: AOAM532njVCo+p2M0Mn1kKxfrEVgXHuRlcbPnO+WPBdvgYmau0u9QzaU
	r9lz3bb5lgpSA42EGz9fY6E=
X-Google-Smtp-Source: ABdhPJzeHINyJ803W0Gol1jKqrIxApApdzY1J05pY7fvopqJUkXcxfikBKLchI2+uAwGVyFaQIaaMA==
X-Received: by 2002:a62:2c48:: with SMTP id s69mr7446585pfs.63.1595574025901;
        Fri, 24 Jul 2020 00:00:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:684d:: with SMTP id q13ls2237338pgt.2.gmail; Fri, 24 Jul
 2020 00:00:25 -0700 (PDT)
X-Received: by 2002:a17:90a:334c:: with SMTP id m70mr4270048pjb.88.1595574025397;
        Fri, 24 Jul 2020 00:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574025; cv=none;
        d=google.com; s=arc-20160816;
        b=Bx17eUmoY/FjV6G7rtcmPPOMBba5euBVlyNC/CznLbk5AUNpncdAieiTEKziqbDd1W
         ZT3wx/wVBIv3//2W8g3iA8h9e96GbvLqa0ZoX8Dtz3FikYf+NuACLogsEU2HNEkx+xLP
         W0f7oxq/L17EXdCrHqiMuUqnIbRPAnzvM7O429o1DCnO3P7CA8Ghowl4Jhqk1oi0bKpL
         Yw+IKB24Sg2KwmbDOeanLnoexKWims1AXOq+Jeix41gFB6Qe/s2UGIx6qYP9gNcCnjC9
         Ctcn22ATAFXs3O0hRxS9h3Rzi9cn4wpobB4RSmE9PKbaArYyOH0Mdz154eUC5BQ7mQFA
         PqEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=oiqjDwoSaahExrPODqvjHVY3h1QlZozjy/GV5FCDjjk=;
        b=yyJvGd/yT2RRmY+6pyzisQR+W6WLMJWmNkb2UIKDtWzpTi5lcfC8d2BGdEvlNWvAM0
         iJUmto35Y/1cAra7XS4UsA8M9lVQSUfPwqbWAtkOVTpEMjsgMukzfS300f4Zscw/I1mF
         nynmm3KVJU98E59LgCjkYmsDswrcmS1qvTat8ZEQiNE7H8i3TqL/SY0fVVN33MvelWOb
         athYFtvItkvxQw44OHEbT7i7bpR+YJmhVa8goYQt2ZtofFQU/3vuJ1D7uf9TuOUbBZ33
         XRDbX8HsdfQq498kvLZCHKhHIIZrJ89z+KFPZYTT1UpGuTXBr5FqS1ZMKnCsNoLXfyvx
         5rTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gA9ZRpxK;
       spf=pass (google.com: domain of 3cicaxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3CIcaXwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id c4si348065pjo.0.2020.07.24.00.00.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cicaxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v5so174473qvr.1
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:25 -0700 (PDT)
X-Received: by 2002:a0c:f307:: with SMTP id j7mr8285987qvl.55.1595574024442;
 Fri, 24 Jul 2020 00:00:24 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:01 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-2-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 1/8] kcsan: Support compounded read-write instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gA9ZRpxK;       spf=pass
 (google.com: domain of 3cicaxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3CIcaXwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-2-elver%40google.com.
