Return-Path: <kasan-dev+bncBC7OBJGL2MHBB46FWXTQKGQE6WFJBNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7467B2CC16
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 18:33:57 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id a5sf7854220pla.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 09:33:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559061236; cv=pass;
        d=google.com; s=arc-20160816;
        b=dCE1+Pi9RN1Zlpv5C8ePJwb4E1cTTts2TsZToXtdmkSnfLXjhjF3xQrMAsXSIVrwvV
         vaCLTInN7ozlInJt8PL+GZMdZy+iRTUwA8aP4U/KNzE5xbrLNn/VMYlvJzbOvw7nNSff
         oNt0CQCm0E1PBxHI8FtiQ/NRPJ0Vm+amQkwx3bjTVN0NPwi4jDmACXSFEB6ccz40oAHI
         zTC+VFc4OqpxsZRarOFFdyu6M9YVQeZ2PMzfkwrDj905KFOMOiOn+kCI9je1wuE/sKFq
         uMGOBx7aSC5YbwiMH8T+XQL2YWFLdiErwCHHAmMTwf7qZjLyyZjYsG+pQERNaEH2SIH9
         LObA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yFy2OQHhdKoxHBPscv6V5Wj/nrGg2CSR+aiU5Z5xrXQ=;
        b=hxiANSSTSmWElBUQra9sFVs2Es60l8KMzxEHFzQxhUgUmnlutgmDtxseKhVU+RItFC
         lOutnBkOBKTmZzbmmeTUIJuYH31rLeId0CBDS+xOz7DeQe5GdXAkLsbFJ/J9/9OMEYYI
         jR9D9QVMX2w8ApJwioqMzVVeo7yuVzTXl+b5Q5Dwbg4DFHA/eKlmD46wH0jbJk/vxqat
         jI6G5rvd28S09SuydGmQkmMRgOhORRe3g7CrnUXHlikX4gAotRBK8CP5QkFtyqghjtOm
         eED82HIAEQu58tFTBMXQJvBqkITd96Utkn+tWgQJvDu8mRs9nwccM8GYXlVLu2VrpisG
         ciAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ahdsHDas;
       spf=pass (google.com: domain of 38mltxaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=38mLtXAUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yFy2OQHhdKoxHBPscv6V5Wj/nrGg2CSR+aiU5Z5xrXQ=;
        b=FdjzGTb+WeIs34P80Cx4z5IDxV1j2KZsp0RlwsVMUGsI4kBPh+7WyP8nPxans+0JXK
         5SnkPCjwSpwnVEiugg//jQQzU03J6BDqoSLnQwri9QFe2zWZ3q8NLxDW6Xp5+nJ2DBvY
         k8rTIGlPRAfD7jwJv8Bt6EGV7FAAGz1/51X8OjwE43QPKuR9FOopLHDNIDnLAHzXeTvs
         sCpQPV26r+wuCbXYKWEmViH3g3pcP8psW+QOjikNxBpRW39PHF61RV/9cW3g4oq4O0kr
         1x0YpQVF2YbS6dl9byMnVyQR3QaW+prkkbYk+3O+vVd2wf9wbvK/X7GLc2yBwBS7k9P0
         bP8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yFy2OQHhdKoxHBPscv6V5Wj/nrGg2CSR+aiU5Z5xrXQ=;
        b=eJS56XoXAk68QQFBf15bZuEHlmTKynHHnCOymVByiu41wbU03ld04PjlEVC4q3fEww
         THSrMOSu+EfIqXeP4nAcgP6PhNTP3XvXBzeUYa5XyWxDWI5B3PQvczBz2XkMRtlV4NGf
         a3xQFdOp8DHZxpKy1RC7iW3xFJ1Mbo87c7Qms1FH/X6mrYRs0t2xmFyKa8ZObioG06v4
         BZ7y8U/8zuLF0FsO5RYMI82tFeexjfBs8g1qDHyq1u5asYEtmo/vyvbER6l5JO6WIHaH
         qhhnSVhEgITE/uSzdB7QpeEvGVD/DKydRl7NfGgGwX/N/gVft6gy+3RQ21OyYTCyfe/Q
         6AZQ==
X-Gm-Message-State: APjAAAWSCKs4ZmkH1GA/AtSG7YXB4CADLk7VF38DXE1206xeAqRYGd88
	5nzrbdSG6aZ1YucHaTZGpRk=
X-Google-Smtp-Source: APXvYqxBQq0oSlqSoumb50PBngFM01DjvIfSqcuO3o5q7sFDCX09Z2DmZUNYpgSFzEAXh5Zr6VMFcg==
X-Received: by 2002:a63:1e62:: with SMTP id p34mr48110948pgm.49.1559061236015;
        Tue, 28 May 2019 09:33:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9ae3:: with SMTP id y3ls5552709pfp.6.gmail; Tue, 28 May
 2019 09:33:55 -0700 (PDT)
X-Received: by 2002:aa7:8a11:: with SMTP id m17mr122449531pfa.122.1559061235511;
        Tue, 28 May 2019 09:33:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559061235; cv=none;
        d=google.com; s=arc-20160816;
        b=ouOGI4Lvev5oGJElQKYo8N/XRJQYl5YeGz4Gg4LbbgjrnjlTM09n//vFvdXxp2rIbS
         wNMKTiafaoIp7l64KVvnKTrvnMQPLts3ByNhW7hUwLUoEXNkzBCYTqSYSVc/7uOpA0dK
         ay+MGYuuUgxpo8ePSLCigUhBbVY2bF5gIL+QJJ9LQb2UYCELisJCYXZO+W39MjnbzXGJ
         9RYVvWigOAwCOle6WZhgSRld7c2qVfB5jkdhpO6Ux0H29zbRG3wI2LjaFTmG3UzhtqYc
         t8RWDjaDNcjyQfeYQ4D0BjGSmoWrxxZEIHZc7qAgOeb1htrI5JwfJMA88lq4a/5yyfH2
         nSLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZEml5ys9WVqinhnvNvOa/aA3D0TQugVnoUG9KvpDVCo=;
        b=kbDJGggqnv0lJKpJfj+Ll7Ga4egy5ucjWO4CHz327X6IAaqU3CN98EgIWNyDOYsZrB
         e2lsAhzvegi45PBZIlzlNVbjglY4a7kxJAwLRmvF/rIC4E2+7si0kyjDOEFAT6+pq1dn
         siuEMd/Q326MG425Ttu/i68J0N0OzOfHMYTtfXx4oxyTWnOWXAyUzmIwvcsRQ0J9hFP6
         ZOrN/BXU9DYguaeJrCHJMvrlJTyXVUOwWTwAx28TSk+OJ3Z9AEYxF1Cps6oKgGORfABj
         e+u7RYCPaBKq6sAFCRbVaD323rsPsg7B58YwxT4FVeUXY60zk7pmNo712I252NbocOE7
         TQrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ahdsHDas;
       spf=pass (google.com: domain of 38mltxaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=38mLtXAUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x949.google.com (mail-ua1-x949.google.com. [2607:f8b0:4864:20::949])
        by gmr-mx.google.com with ESMTPS id bg12si540012plb.3.2019.05.28.09.33.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 May 2019 09:33:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38mltxaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) client-ip=2607:f8b0:4864:20::949;
Received: by mail-ua1-x949.google.com with SMTP id a6so5022859uah.3
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2019 09:33:55 -0700 (PDT)
X-Received: by 2002:a1f:551:: with SMTP id 78mr26066540vkf.45.1559061234381;
 Tue, 28 May 2019 09:33:54 -0700 (PDT)
Date: Tue, 28 May 2019 18:32:58 +0200
In-Reply-To: <20190528163258.260144-1-elver@google.com>
Message-Id: <20190528163258.260144-3-elver@google.com>
Mime-Version: 1.0
References: <20190528163258.260144-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ahdsHDas;       spf=pass
 (google.com: domain of 38mltxaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=38mLtXAUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

This adds a new header to asm-generic to allow optionally instrumenting
architecture-specific asm implementations of bitops.

This change includes the required change for x86 as reference and
changes the kernel API doc to point to bitops-instrumented.h instead.
Rationale: the functions in x86's bitops.h are no longer the kernel API
functions, but instead the arch_ prefixed functions, which are then
instrumented via bitops-instrumented.h.

Other architectures can similarly add support for asm implementations of
bitops.

The documentation text has been copied/moved, and *no* changes to it
have been made in this patch.

Tested: using lib/test_kasan with bitops tests (pre-requisite patch).

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/include/asm/bitops.h             | 210 ++++----------
 include/asm-generic/bitops-instrumented.h | 327 ++++++++++++++++++++++
 3 files changed, 380 insertions(+), 159 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
index a29c99d13331..65266fa1b706 100644
--- a/Documentation/core-api/kernel-api.rst
+++ b/Documentation/core-api/kernel-api.rst
@@ -51,7 +51,7 @@ The Linux kernel provides more basic utility functions.
 Bit Operations
 --------------
 
-.. kernel-doc:: arch/x86/include/asm/bitops.h
+.. kernel-doc:: include/asm-generic/bitops-instrumented.h
    :internal:
 
 Bitmap Operations
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index 8e790ec219a5..8ebf7af9a0f4 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -49,23 +49,8 @@
 #define CONST_MASK_ADDR(nr, addr)	WBYTE_ADDR((void *)(addr) + ((nr)>>3))
 #define CONST_MASK(nr)			(1 << ((nr) & 7))
 
-/**
- * set_bit - Atomically set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This function is atomic and may not be reordered.  See __set_bit()
- * if you do not require the atomic guarantees.
- *
- * Note: there are no guarantees that this function will not be reordered
- * on non x86 architectures, so if you are writing portable code,
- * make sure not to rely on its reordering guarantees.
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
 static __always_inline void
-set_bit(long nr, volatile unsigned long *addr)
+arch_set_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "orb %1,%0"
@@ -77,33 +62,17 @@ set_bit(long nr, volatile unsigned long *addr)
 			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
 	}
 }
+#define arch_set_bit arch_set_bit
 
-/**
- * __set_bit - Set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * Unlike set_bit(), this function is non-atomic and may be reordered.
- * If it's called on the same region of memory simultaneously, the effect
- * may be that only one operation succeeds.
- */
-static __always_inline void __set_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___set_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(bts) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
+#define arch___set_bit arch___set_bit
 
-/**
- * clear_bit - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * clear_bit() is atomic and may not be reordered.  However, it does
- * not contain a memory barrier, so if it is used for locking purposes,
- * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
- * in order to ensure changes are visible on other processors.
- */
 static __always_inline void
-clear_bit(long nr, volatile unsigned long *addr)
+arch_clear_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "andb %1,%0"
@@ -114,27 +83,25 @@ clear_bit(long nr, volatile unsigned long *addr)
 			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
 	}
 }
+#define arch_clear_bit arch_clear_bit
 
-/*
- * clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * clear_bit() is atomic and implies release semantics before the memory
- * operation. It can be used for an unlock.
- */
-static __always_inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch_clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	barrier();
-	clear_bit(nr, addr);
+	arch_clear_bit(nr, addr);
 }
+#define arch_clear_bit_unlock arch_clear_bit_unlock
 
-static __always_inline void __clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
+#define arch___clear_bit arch___clear_bit
 
-static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	bool negative;
 	asm volatile(LOCK_PREFIX "andb %2,%1"
@@ -143,48 +110,25 @@ static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile
 		: "ir" ((char) ~(1 << nr)) : "memory");
 	return negative;
 }
+#define arch_clear_bit_unlock_is_negative_byte                                 \
+	arch_clear_bit_unlock_is_negative_byte
 
-// Let everybody know we have it
-#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
-
-/*
- * __clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * __clear_bit() is non-atomic and implies release semantics before the memory
- * operation. It can be used for an unlock if no other CPUs can concurrently
- * modify other bits in the word.
- */
-static __always_inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
-	__clear_bit(nr, addr);
+	arch___clear_bit(nr, addr);
 }
+#define arch___clear_bit_unlock arch___clear_bit_unlock
 
-/**
- * __change_bit - Toggle a bit in memory
- * @nr: the bit to change
- * @addr: the address to start counting from
- *
- * Unlike change_bit(), this function is non-atomic and may be reordered.
- * If it's called on the same region of memory simultaneously, the effect
- * may be that only one operation succeeds.
- */
-static __always_inline void __change_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___change_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btc) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
+#define arch___change_bit arch___change_bit
 
-/**
- * change_bit - Toggle a bit in memory
- * @nr: Bit to change
- * @addr: Address to start counting from
- *
- * change_bit() is atomic and may not be reordered.
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static __always_inline void change_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch_change_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "xorb %1,%0"
@@ -195,43 +139,24 @@ static __always_inline void change_bit(long nr, volatile unsigned long *addr)
 			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
 	}
 }
+#define arch_change_bit arch_change_bit
 
-/**
- * test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(bts), *addr, c, "Ir", nr);
 }
+#define arch_test_and_set_bit arch_test_and_set_bit
 
-/**
- * test_and_set_bit_lock - Set a bit and return its old value for lock
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This is the same as test_and_set_bit on x86.
- */
 static __always_inline bool
-test_and_set_bit_lock(long nr, volatile unsigned long *addr)
+arch_test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
-	return test_and_set_bit(nr, addr);
+	return arch_test_and_set_bit(nr, addr);
 }
+#define arch_test_and_set_bit_lock arch_test_and_set_bit_lock
 
-/**
- * __test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- */
-static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -241,37 +166,17 @@ static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *
 	    : ADDR, "Ir" (nr) : "memory");
 	return oldbit;
 }
+#define arch___test_and_set_bit arch___test_and_set_bit
 
-/**
- * test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btr), *addr, c, "Ir", nr);
 }
+#define arch_test_and_clear_bit arch_test_and_clear_bit
 
-/**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- *
- * Note: the operation is performed atomically with respect to
- * the local CPU, but not other CPUs. Portable code should not
- * rely on this behaviour.
- * KVM relies on this behaviour on x86 for modifying memory that is also
- * accessed from a hypervisor on the same CPU if running in a VM: don't change
- * this without also updating arch/x86/kernel/kvm.c
- */
-static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -281,9 +186,10 @@ static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long
 		     : ADDR, "Ir" (nr) : "memory");
 	return oldbit;
 }
+#define arch___test_and_clear_bit arch___test_and_clear_bit
 
-/* WARNING: non atomic and it can be reordered! */
-static __always_inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -294,19 +200,14 @@ static __always_inline bool __test_and_change_bit(long nr, volatile unsigned lon
 
 	return oldbit;
 }
+#define arch___test_and_change_bit arch___test_and_change_bit
 
-/**
- * test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
 }
+#define arch_test_and_change_bit arch_test_and_change_bit
 
 static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
 {
@@ -326,16 +227,7 @@ static __always_inline bool variable_test_bit(long nr, volatile const unsigned l
 	return oldbit;
 }
 
-#if 0 /* Fool kernel-doc since it doesn't do macros yet */
-/**
- * test_bit - Determine whether a bit is set
- * @nr: bit number to test
- * @addr: Address to start counting from
- */
-static bool test_bit(int nr, const volatile unsigned long *addr);
-#endif
-
-#define test_bit(nr, addr)			\
+#define arch_test_bit(nr, addr)			\
 	(__builtin_constant_p((nr))		\
 	 ? constant_test_bit((nr), (addr))	\
 	 : variable_test_bit((nr), (addr)))
@@ -504,6 +396,8 @@ static __always_inline int fls64(__u64 x)
 
 #include <asm-generic/bitops/const_hweight.h>
 
+#include <asm-generic/bitops-instrumented.h>
+
 #include <asm-generic/bitops/le.h>
 
 #include <asm-generic/bitops/ext2-atomic-setbit.h>
diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
new file mode 100644
index 000000000000..52140a5626c3
--- /dev/null
+++ b/include/asm-generic/bitops-instrumented.h
@@ -0,0 +1,327 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for bit
+ * operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.), #define each provided arch_ function, and include
+ * this file after their definitions. For undefined arch_ functions, it is
+ * assumed that they are provided via asm-generic/bitops, which are implicitly
+ * instrumented.
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+
+#include <linux/kasan-checks.h>
+
+#if !defined(BITOPS_INSTRUMENT_RANGE)
+/*
+ * This may be defined by an arch's bitops.h, in case bitops do not operate on
+ * single bytes only. The default version here is conservative and assumes that
+ * bitops operate only on the byte with the target bit.
+ */
+#define BITOPS_INSTRUMENT_RANGE(addr, nr)                                  \
+	(const volatile char *)(addr) + ((nr) / BITS_PER_BYTE), 1
+#endif
+
+#if defined(arch_set_bit)
+/**
+ * set_bit - Atomically set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This function is atomic and may not be reordered.  See __set_bit()
+ * if you do not require the atomic guarantees.
+ *
+ * Note: there are no guarantees that this function will not be reordered
+ * on non x86 architectures, so if you are writing portable code,
+ * make sure not to rely on its reordering guarantees.
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch_set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___set_bit)
+/**
+ * __set_bit - Set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * Unlike set_bit(), this function is non-atomic and may be reordered.
+ * If it's called on the same region of memory simultaneously, the effect
+ * may be that only one operation succeeds.
+ */
+static inline void __set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch___set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_clear_bit)
+/**
+ * clear_bit - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * clear_bit() is atomic and may not be reordered.  However, it does
+ * not contain a memory barrier, so if it is used for locking purposes,
+ * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
+ * in order to ensure changes are visible on other processors.
+ */
+static inline void clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch_clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___clear_bit)
+/**
+ * __clear_bit - Clears a bit in memory
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * Unlike clear_bit(), this function is non-atomic and may be reordered.
+ * If it's called on the same region of memory simultaneously, the effect
+ * may be that only one operation succeeds.
+ */
+static inline void __clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch___clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_clear_bit_unlock)
+/**
+ * clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * clear_bit_unlock() is atomic and implies release semantics before the memory
+ * operation. It can be used for an unlock.
+ */
+static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch_clear_bit_unlock(nr, addr);
+}
+#endif
+
+#if defined(arch___clear_bit_unlock)
+/**
+ * __clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * __clear_bit_unlock() is non-atomic and implies release semantics before the
+ * memory operation. It can be used for an unlock if no other CPUs can
+ * concurrently modify other bits in the word.
+ */
+static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch___clear_bit_unlock(nr, addr);
+}
+#endif
+
+#if defined(arch_change_bit)
+/**
+ * change_bit - Toggle a bit in memory
+ * @nr: Bit to change
+ * @addr: Address to start counting from
+ *
+ * change_bit() is atomic and may not be reordered.
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch_change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___change_bit)
+/**
+ * __change_bit - Toggle a bit in memory
+ * @nr: the bit to change
+ * @addr: the address to start counting from
+ *
+ * Unlike change_bit(), this function is non-atomic and may be reordered.
+ * If it's called on the same region of memory simultaneously, the effect
+ * may be that only one operation succeeds.
+ */
+static inline void __change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	arch___change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_set_bit)
+/**
+ * test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is atomic and cannot be reordered.
+ * It also implies a memory barrier.
+ */
+static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch_test_and_set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___test_and_set_bit)
+/**
+ * __test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic and can be reordered.
+ * If two examples of this operation race, one can appear to succeed
+ * but actually fail.  You must protect multiple accesses with a lock.
+ */
+static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch___test_and_set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_set_bit_lock)
+/**
+ * test_and_set_bit_lock - Set a bit and return its old value, for lock
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is atomic and provides acquire barrier semantics if
+ * the returned value is 0.
+ * It can be used to implement bit locks.
+ */
+static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch_test_and_set_bit_lock(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_clear_bit)
+/**
+ * test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is atomic and cannot be reordered.
+ * It also implies a memory barrier.
+ */
+static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch_test_and_clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___test_and_clear_bit)
+/**
+ * __test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic and can be reordered.
+ * If two examples of this operation race, one can appear to succeed
+ * but actually fail.  You must protect multiple accesses with a lock.
+ *
+ * Note: the operation is performed atomically with respect to
+ * the local CPU, but not other CPUs. Portable code should not
+ * rely on this behaviour.
+ * KVM relies on this behaviour on x86 for modifying memory that is also
+ * accessed from a hypervisor on the same CPU if running in a VM: don't change
+ * this without also updating arch/x86/kernel/kvm.c
+ */
+static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch___test_and_clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_change_bit)
+/**
+ * test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is atomic and cannot be reordered.
+ * It also implies a memory barrier.
+ */
+static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch_test_and_change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___test_and_change_bit)
+/**
+ * __test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic and can be reordered.
+ * If two examples of this operation race, one can appear to succeed
+ * but actually fail.  You must protect multiple accesses with a lock.
+ */
+static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch___test_and_change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_bit)
+/**
+ * test_bit - Determine whether a bit is set
+ * @nr: bit number to test
+ * @addr: Address to start counting from
+ */
+static inline bool test_bit(long nr, const volatile unsigned long *addr)
+{
+	kasan_check_read(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch_test_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_clear_bit_unlock_is_negative_byte)
+/**
+ * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
+ *                                     byte is negative, for unlock.
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * This is a bit of a one-trick-pony for the filemap code, which clears
+ * PG_locked and tests PG_waiters,
+ */
+static inline bool
+clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(BITOPS_INSTRUMENT_RANGE(addr, nr));
+	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
+}
+/* Let everybody know we have it. */
+#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
+#endif
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190528163258.260144-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
