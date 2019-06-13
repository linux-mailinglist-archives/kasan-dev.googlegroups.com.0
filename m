Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLMFRHUAKGQEA6LFWAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 976B8435F0
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:33:51 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id a5sf11893272pla.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:33:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560429230; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJVqITpeadiiTi36Ywpc633aSQTpBLw9zmAynHiqoDqG/K3eScLD00lJQB/IZvRE1a
         RMUZ5+RRoU7YllG8xLyigzwThC5GOIR+Fh7c96havL4JD7xoDH2KzyhuWtSKIobFcx6H
         gMocZc7QCOHaj35mvWKNeSmiQPyur07w1UQQ3ALHGEoVwDmx+ejJAwQCAfJWP4fQT8z5
         5mZbWirW4nzDA1sAAJkrn9ZB+HjB5a8SG3w3yEeJcopedRzbVwobjjzECrfbDgQe/KU3
         6DYJ1UHwzpVeiHYey7FZM9KPIv71ko9LrVc7nimcGfsVfKdiOUM+SjrhB7wwRHqDnvdy
         lCkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=tC8WJrsbfy/2GZWZuoqBTs3Igt3a4jzALejisILv6zw=;
        b=RnBSTpOh2SmZDGL5lV9ytzzXLaVK0hGv0X8yZn5xHIck1Pfi7pjqavtpm4KKyorUah
         hS53ypTIKeq9WqPS2B8s8wsWmFnt7VJUq/WF9rBOvbkGUhXi1TtynW+ik6LSvXeQtqMY
         ZX8HJeweK4ipp1xmugIYcP+Frdh2Y5Ec3YABixkMMMj/LbOP3Zua/UqWHGqvBXztcQYP
         Fo/x9B7Et5y57EQeSI28D/ab7M1gIX1AxiNt+ZIlx+vilnj2FaKXxp72wmZNfjFdmIU4
         xok+Bt2egCBRC7WwcDNgjQh4jVqv2U9AM15RKQyuj7O6xrA9xKiOSkLzmXdIYu7lYoJk
         rPuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CnxsNOUI;
       spf=pass (google.com: domain of 3reicxqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c4a as permitted sender) smtp.mailfrom=3rEICXQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tC8WJrsbfy/2GZWZuoqBTs3Igt3a4jzALejisILv6zw=;
        b=k/HyRLtZaNvhct7kUqFFyZNgWOPPOehU33MDf7VOQcB81RdGJOMqGCzojzhUngPwic
         oceL+UmTAhqENJ4MVZH1ccKHPO1+AyCwSIvtdcCwnMmfu4tYdQFhJj1Q4ffbFIbDHVek
         XO6M2QEqlK3A6t0uEabHffsVbRM84WSLbLRK9UmcjO6uzb7/vXgL0GcNGDmXizmjQRDI
         PzGUrAYf9YHrGbHMsPQjPOQ5iZrji5BhWkVP1tonPp+fmXz4EZmGLnTbYeThGE3mEJB6
         kZWzcvOg4AxbHkhzLgw8eicZAUL+/HB67sVgU3TEmPqf26WaScMDV1q1zQ+IYmtLZeIt
         qJtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tC8WJrsbfy/2GZWZuoqBTs3Igt3a4jzALejisILv6zw=;
        b=d9Li6vaSQ9rg9coaIWUh61+vQEsz113sSgRyMyn7GoqnldCuqZ85hPn4u+jfVYxnM5
         9jDboyjeD2cuUIt+qdI30wiEx+JKOObLs+oWPtwjwuym3cpWzb5hObhZI0S9+Kfw3+5f
         fCZq5SKpTglLfsz6QCCebCH5CnFwjO+8UKR5DtfiONeTHlSe8fUCL5psu+WgW1Bqm4P+
         ksio6hHTT8FPmIOzY23OViiCpVWGsQdvfIMd3eBfnfIwf/SpHkSoWikkWtHGVvMQjUWP
         g3jTtIUgidD9aNBaHHRwoA6PrgcKVS+4m9OSgcXmIlfcfEwn5jGu52vfH8iak2h/Y3BS
         Cl7w==
X-Gm-Message-State: APjAAAWgkrNw8OjswpJm4GIJMnpg8u3xUmxaS+L64qXykbtHYunUDyIA
	CQDSlT3dztFwbe68bxVPlvQ=
X-Google-Smtp-Source: APXvYqyx5UUXK6YGWhKSxTtgNU+gmknZZSI5nW+WK1oDmbO0MOGmL9Aa95WrUUxiOz89qCkcATmwSg==
X-Received: by 2002:a17:90a:e38f:: with SMTP id b15mr5464777pjz.85.1560429229751;
        Thu, 13 Jun 2019 05:33:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:32d:: with SMTP id 42ls1403334pld.11.gmail; Thu, 13
 Jun 2019 05:33:49 -0700 (PDT)
X-Received: by 2002:a17:902:6acc:: with SMTP id i12mr10609361plt.214.1560429229280;
        Thu, 13 Jun 2019 05:33:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560429229; cv=none;
        d=google.com; s=arc-20160816;
        b=FfwK+IZxMPZXerK1BbZOXKQ31LrceHgczxJOeJPhjHJOexDRwXjyybPo86di/hw8s2
         OjF1AIG15Z6zjXXWv6RNZEJZapxIQIX1b3RiE98wqCQkNSm67EqqGuZHvgOUu7GiSSg6
         6EJMKg2lQ/cN4zjLXah43RGmwabkA7S2kKNXjp3ufio2Hby01WVnqOqpcwLm1aYMmoAe
         SgEz988h7/k29G5qN/n6sVEgLsoB/5mrmpAzmu8hS5ygSbTPdwOjFfNTCcAKJj4xyu7B
         EOeuEiNtFQUKQ7v6DZ4Q6WqaihwPCfdiBpSU3zMT4xYS6RrK5uYu7yeMvh/Sxy5iebfN
         Quuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nTyT6z08CUm2wRhb0PBuVFW+TkegThF+CqD5j6KVtL0=;
        b=CED3FPoAdQDaN7WALkKTtQ1oggIaEF0zFCdsWiulK7BXA9JjygHpjxijrK36qIxwBs
         hQXy1dvsioS9F4ivCMo20JPBDsWZDyWAdYLlR88r+7+VC1WZPasNBEAf+TqCipyhApWa
         RxP6tMbheULfCviID/yZE3LzHpi4Ml2E9NdutS05HVXw8c4YyKRO4h2p5jMjmQxaomM9
         KVJs4fEjLGHPGQka8JvrGc3W3JJO7e811P9ldblrLjTSxLK35YPq/eYRqXYalgXVHr3R
         OPUWkJXfUgcsR7BQ+2splptzDVnzQeOINNSsSXztW/Z7sFrMlhRJFIrKYso1M3En2XRd
         P/CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CnxsNOUI;
       spf=pass (google.com: domain of 3reicxqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c4a as permitted sender) smtp.mailfrom=3rEICXQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-xc4a.google.com (mail-yw1-xc4a.google.com. [2607:f8b0:4864:20::c4a])
        by gmr-mx.google.com with ESMTPS id v186si111399pgd.4.2019.06.13.05.33.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:33:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3reicxqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c4a as permitted sender) client-ip=2607:f8b0:4864:20::c4a;
Received: by mail-yw1-xc4a.google.com with SMTP id i136so11692821ywe.23
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 05:33:49 -0700 (PDT)
X-Received: by 2002:a81:6f84:: with SMTP id k126mr36223172ywc.496.1560429228329;
 Thu, 13 Jun 2019 05:33:48 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:30:28 +0200
In-Reply-To: <20190613123028.179447-1-elver@google.com>
Message-Id: <20190613123028.179447-4-elver@google.com>
Mime-Version: 1.0
References: <20190613123028.179447-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v4 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CnxsNOUI;       spf=pass
 (google.com: domain of 3reicxqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::c4a as permitted sender) smtp.mailfrom=3rEICXQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

The documentation text was derived from x86 and existing bitops
asm-generic versions: 1) references to x86 have been removed; 2) as a
result, some of the text had to be reworded for clarity and consistency.

Tested: using lib/test_kasan with bitops tests (pre-requisite patch).

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---
Changes in v3:
* Remove references to 'x86' in API documentation; as a result, had to
  reword doc text for clarify and consistency.
* Remove #ifdef, since it is assumed that if asm-generic bitops
  implementations are used, bitops-instrumented.h is not needed.

Changes in v2:
* Instrument word-sized accesses, as specified by the interface.
---
 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/include/asm/bitops.h             | 189 ++++------------
 include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
 3 files changed, 302 insertions(+), 152 deletions(-)
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
index 8e790ec219a5..ba15d53c1ca7 100644
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
@@ -78,32 +63,14 @@ set_bit(long nr, volatile unsigned long *addr)
 	}
 }
 
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
@@ -115,26 +82,21 @@ clear_bit(long nr, volatile unsigned long *addr)
 	}
 }
 
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
 
-static __always_inline void __clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
 
-static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	bool negative;
 	asm volatile(LOCK_PREFIX "andb %2,%1"
@@ -143,48 +105,23 @@ static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile
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
@@ -196,42 +133,20 @@ static __always_inline void change_bit(long nr, volatile unsigned long *addr)
 	}
 }
 
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
 
@@ -242,28 +157,13 @@ static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *
 	return oldbit;
 }
 
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
 
-/**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- *
+/*
  * Note: the operation is performed atomically with respect to
  * the local CPU, but not other CPUs. Portable code should not
  * rely on this behaviour.
@@ -271,7 +171,8 @@ static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *
  * accessed from a hypervisor on the same CPU if running in a VM: don't change
  * this without also updating arch/x86/kernel/kvm.c
  */
-static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -282,8 +183,8 @@ static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long
 	return oldbit;
 }
 
-/* WARNING: non atomic and it can be reordered! */
-static __always_inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -295,15 +196,8 @@ static __always_inline bool __test_and_change_bit(long nr, volatile unsigned lon
 	return oldbit;
 }
 
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
@@ -326,16 +220,7 @@ static __always_inline bool variable_test_bit(long nr, volatile const unsigned l
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
@@ -504,6 +389,8 @@ static __always_inline int fls64(__u64 x)
 
 #include <asm-generic/bitops/const_hweight.h>
 
+#include <asm-generic/bitops-instrumented.h>
+
 #include <asm-generic/bitops/le.h>
 
 #include <asm-generic/bitops/ext2-atomic-setbit.h>
diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
new file mode 100644
index 000000000000..ddd1c6d9d8db
--- /dev/null
+++ b/include/asm-generic/bitops-instrumented.h
@@ -0,0 +1,263 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for bit
+ * operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+
+#include <linux/kasan-checks.h>
+
+/**
+ * set_bit - Atomically set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_set_bit(nr, addr);
+}
+
+/**
+ * __set_bit - Set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * Unlike set_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___set_bit(nr, addr);
+}
+
+/**
+ * clear_bit - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ */
+static inline void clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit(nr, addr);
+}
+
+/**
+ * __clear_bit - Clears a bit in memory
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * Unlike clear_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit(nr, addr);
+}
+
+/**
+ * clear_bit_unlock - Clear a bit in memory, for unlock
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This operation is atomic and provides release barrier semantics.
+ */
+static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit_unlock(nr, addr);
+}
+
+/**
+ * __clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * This is a non-atomic operation but implies a release barrier before the
+ * memory operation. It can be used for an unlock if no other CPUs can
+ * concurrently modify other bits in the word.
+ */
+static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit_unlock(nr, addr);
+}
+
+/**
+ * change_bit - Toggle a bit in memory
+ * @nr: Bit to change
+ * @addr: Address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_change_bit(nr, addr);
+}
+
+/**
+ * __change_bit - Toggle a bit in memory
+ * @nr: the bit to change
+ * @addr: the address to start counting from
+ *
+ * Unlike change_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___change_bit(nr, addr);
+}
+
+/**
+ * test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit(nr, addr);
+}
+
+/**
+ * __test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_set_bit(nr, addr);
+}
+
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
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit_lock(nr, addr);
+}
+
+/**
+ * test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_clear_bit(nr, addr);
+}
+
+/**
+ * __test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_clear_bit(nr, addr);
+}
+
+/**
+ * test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_change_bit(nr, addr);
+}
+
+/**
+ * __test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_change_bit(nr, addr);
+}
+
+/**
+ * test_bit - Determine whether a bit is set
+ * @nr: bit number to test
+ * @addr: Address to start counting from
+ */
+static inline bool test_bit(long nr, const volatile unsigned long *addr)
+{
+	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_bit(nr, addr);
+}
+
+#if defined(arch_clear_bit_unlock_is_negative_byte)
+/**
+ * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
+ *                                     byte is negative, for unlock.
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * This operation is atomic and provides release barrier semantics.
+ *
+ * This is a bit of a one-trick-pony for the filemap code, which clears
+ * PG_locked and tests PG_waiters,
+ */
+static inline bool
+clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
+}
+/* Let everybody know we have it. */
+#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
+#endif
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
-- 
2.22.0.rc2.383.gf4fbbf30c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613123028.179447-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
