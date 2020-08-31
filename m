Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 22DA725809E
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id g99sf4511192otg.0
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=SrpowsDETWv7/2AUQqkNsJYce6Xl8a9KrH3DXulloLDZ6PgzjiSIYg0Zm4Bs9ntu81
         8+xs0nygM9n2AbT/fC19EXik7xfFO12KchfwC42vX66KLdQC8+JFlOgN9NkhZ6kfOtDm
         3lcBsD7qahpgs7jeAKKjYUWeH3C8xMxcNqzZPQz9yYa+fak8Du8pUMHIx0uFbsuvwzy9
         7oJB7NRvAvSREciuLqOt2KyzF19hOYb5e6CATknnZhnx6RgYynbrhkApA6/yYZctSgr6
         n6XJYUy1bpi8lD6QT+t07UXA+Fhv01RZjJ5TpUJMqgo14NZpStdgb5GkXUWzymPIRH32
         WvXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=ghk6GvrhXt7BH+Vy9vLvH1hu9fenzscDhsqbnA3D9RM=;
        b=zW1473bEamU5KTKuWzexloVGmMPLx7aSMO1v6f890U6mxBJfs4pXac1iOqivCpQJ+t
         CNu/X06tW1ZGUN+uSACv3cLliTBltLS/tWFYFtrwcQXiVvVU4cqhtHTWXPHwTpHI9Pzc
         pM/VrmvnLuxmMJQaFsfCrmossyOlJIUpilO/Uv9WAD1rHHSjB9ewmlpJwcfYzbC3hpz0
         SM1EXwt/C0ZDywp9I0BhqMWvGIs6FcBa4Iw1OgX62DvMfa6J2lV7qWze6PQg70/tW8Wl
         1bs0JEnNmOTKdbxqVmo6lrWZ2PnE2fd4W2QENvZpi8sQOyia2u8zV6It9uNfCMjsoeeH
         ip3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ULobqQTD;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ghk6GvrhXt7BH+Vy9vLvH1hu9fenzscDhsqbnA3D9RM=;
        b=HGeH+xWCWSQD41jgUL61VBmdloaF8Ms7WqJxPQgsycXnjXhzbbqONix6tTFK6eX/r7
         kGaJuRqdlP1nhPCZeV7v1AGvNbjPTeCOCtjSaRT8EPzo6jUsp1HbO5YJX07w6U7CDgpI
         pXr72WriZHJw34v/iBpKt5GO/SN29UulF6OmeHwHgFcWLVwkmMXEIBRKoEzsOylvvYvR
         2zEju//RLFUFdbs1I/ED4FW3OcGcCmXW/9/i08hv9jHty6wG0dGUsoGFhjOdKAchK4hJ
         GiPmZCvEuphkS6ZRZ/CDAIogQH1bHOO+WH7mquLHNRPRYDobQa8t5GnK13WCwIW4Ggjl
         se0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ghk6GvrhXt7BH+Vy9vLvH1hu9fenzscDhsqbnA3D9RM=;
        b=cD6heKafvxEvdJKsvC0tnrBhcaduPKoRusgkj2wih5iO8IQLANVvKP4XSiwDHN/tqj
         h6E+D4MhdhUXfkuuPdEiW4XGcGlGtnOT8bNo+Rvo5DNCyMC6MTg1Jp1mjPGunehckrO3
         ceVI0JvMO2xKwWYwoCFvPQO8Lu37p/P0eiS9CyL5/0fa+tXTq7//8bg5rEF4ldMxfY2Z
         W7SBkDiIzMsUDTtAXeTJjRSoxMMrnYGLf7Ah+MsFRq7erepLBMBc3TBAonvDsTrs3ylB
         IDrcY1lfdptn6VogNA3ajXuckF8USfDL6mWgcrzTGuAD0Aifhbke4rDpNv5z1KvcomZN
         /O8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530V557ctJl3DUgfemoZAqtFdLe7vKbvdv8jWufKPoJ7jCom9BfB
	0Kpmqr1oouYoPOyquw7JJao=
X-Google-Smtp-Source: ABdhPJxqKNjP+ORHKEBrdPLJSig75sJ5MeZmgOmXqu4GOP4LhgPQjd70tyH6U3u7fALRieUgKvrsqQ==
X-Received: by 2002:a4a:6b09:: with SMTP id g9mr1566778ooc.91.1598897888069;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:157:: with SMTP id j23ls1406786otp.1.gmail; Mon, 31
 Aug 2020 11:18:07 -0700 (PDT)
X-Received: by 2002:a05:6830:f:: with SMTP id c15mr1805337otp.355.1598897887725;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897887; cv=none;
        d=google.com; s=arc-20160816;
        b=wZPlJMxISdmdLOi4QrrppPv+YhN94BbOs8IJTkRnj8nA5FccR35uieJ/358bCp7i5P
         EYSBGvKYLwQSZFfJO8lh6pCNshnrtLrSWAsn1xCLaPBWc9j/FTe4yOqDrZfvy/G9woZx
         BGXZmH0B6THxNRiKqF6zz+CvFXgg3XFyfO4UujJqLgZQmGIAD8VLTH3NfSMmZj5MVtnY
         AfbdQ4dN1iYJSrRwno6Br6fZYqelYlqWkhGx8bXFS96h3L9UvckyKH2rUv2TjUzoU9QR
         jzbc1jbLoIhPqo5rZHQyBUsujKSNANft80N/NfjaSwzne6lWcC8liYdGJ4ED4Nw3Hjtq
         t1QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=0p8nAsGKxPgjaYvnwfgkrZom2Y2G/OInns7OHL6pdr0=;
        b=Hg8SgwMIPFhxhpyxFH+H/qO81I3AIeP96jnqRRbNsjgeShZ3VWubRTurC05nDmRL9w
         a5UE1jVfR71GfRfl3+wd2ZAaMhRqPaFkSSLiEx5xn7E1882IR3aB1UE7zQHihavDB6w9
         T1heNfKJq3EWDOBNdPmXkCUjRHbUN1u7n6tOTx5WnaDQfkc2u52y0M5cKn880hrQtLFZ
         q6LYswj86VZIFeDLJvTIYcF8xmbEeaEqhwhUDEARJ3hKaRVlsAiro0/LqiezcZMyeEKM
         bCald5A88NYsNGsC+EvfKgRQv9aak2wi5EShWscjiYzxfm4sl/lXYAz+DpvaioFAJFyS
         oUyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ULobqQTD;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l19si215921oih.2.2020.08.31.11.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C9315214DB;
	Mon, 31 Aug 2020 18:18:06 +0000 (UTC)
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
Subject: [PATCH kcsan 04/19] kcsan: Support compounded read-write instrumentation
Date: Mon, 31 Aug 2020 11:17:50 -0700
Message-Id: <20200831181805.1833-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ULobqQTD;       spf=pass
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

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 45 +++++++++++++++++++++++++++++---------------
 kernel/kcsan/core.c          | 23 +++++++++++++++++-----
 kernel/kcsan/report.c        |  4 ++++
 scripts/Makefile.kcsan       |  2 +-
 4 files changed, 53 insertions(+), 21 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index c5f6c1d..cf14840 100644
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
@@ -205,6 +199,15 @@ static inline void __kcsan_disable_current(void) { }
 	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
 
 /**
+ * __kcsan_check_read_write - check regular read-write access for races
+ *
+ * @ptr: address of access
+ * @size: size of access
+ */
+#define __kcsan_check_read_write(ptr, size)                                    \
+	__kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
+
+/**
  * kcsan_check_read - check regular read access for races
  *
  * @ptr: address of access
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
index 682d9fd..4c8b40b 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -223,7 +223,7 @@ is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx
 
 	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
 	    (type & KCSAN_ACCESS_WRITE) && size <= sizeof(long) &&
-	    IS_ALIGNED((unsigned long)ptr, size))
+	    !(type & KCSAN_ACCESS_COMPOUND) && IS_ALIGNED((unsigned long)ptr, size))
 		return true; /* Assume aligned writes up to word size are atomic. */
 
 	if (ctx->atomic_next > 0) {
@@ -793,7 +793,17 @@ EXPORT_SYMBOL(__kcsan_check_access);
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
@@ -916,7 +926,8 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		check_access(ptr, bits / BITS_PER_BYTE,                                            \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
 		return __atomic_##op##suffix(ptr, v, memorder);                                    \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
@@ -944,7 +955,8 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		check_access(ptr, bits / BITS_PER_BYTE,                                            \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
 		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
@@ -955,7 +967,8 @@ EXPORT_SYMBOL(__tsan_init);
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
index 9d07e17..3e83a69 100644
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
index c50f27b..c37f951 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -11,5 +11,5 @@ endif
 # of some options does not break KCSAN nor causes false positive reports.
 CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
-	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
+	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=1),$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1))) \
 	$(call cc-param,tsan-distinguish-volatile=1)
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-4-paulmck%40kernel.org.
