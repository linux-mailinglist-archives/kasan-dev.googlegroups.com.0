Return-Path: <kasan-dev+bncBDQ27FVWWUFRBV575XVAKGQE6HHXE6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C2FFB95497
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 04:50:00 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id h3sf3669943pgc.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 19:50:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566269399; cv=pass;
        d=google.com; s=arc-20160816;
        b=uQX1/AQ8lBqyQA21U+o8/Mw/ndqVrpuDA7j2KYdnoQnq3f583k1gaWbnayvTJQEVuo
         TYUzJIFkysa/8IbuBbKQKaf1IbzCt3VT+xGyFQXmWdpWB+6Ids8wszHEdhS4J7R8qeHC
         HdgjuMogQ4ZO1VWpZcBMAlE2j5W91IrDdDqZeXlvilKrr4jhHTxPTOtW52DlQp9sOEQm
         sguEdbVtN/0heNrKIdNQhjdpjib6au6vzS2EGjhzCAjNqFPwzO29gAijVA7DWjicGk7x
         LwI9Ofw5f6YEc8NYV7BAWtV+9Cqi5js2bzv7S9h2K8UcJWySr02yqxBpVyMtyhwIVvqN
         kRng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=E5qV5hV3VNuD0C2f+HIIn5UsIGaY7eYzj5t0N2dWZV8=;
        b=q5RcvouDGSr9HLlhgpBi2/dd0BOmUX81h+Kl9NG+pzo/NxXoCuUkxnYKzAPxlTTVz0
         pFTu9R498DuEtu7vqZkF99cN1UB19AXRgc+TMKTdRIdwMg3fX1j2v8/W+It2TEnBprr8
         Uixa4f7GhIeDnZq9hkqc7WywtKccztOOQtoG7HtvRMJfxd44p8JfFTYV23Nn5Z5BrhRb
         k9qVgMBK/Ia1CviwKEK8eb/JAvWVex41BmZ/atcNjojDRivhXYQEY6DUUFgIKgzk++rq
         fxUrN/o+RTNiBUnSXF0c7cHa1L7C5G130WIOC93tYj981pbbHj5EqjJtCxk6JZSb6d8W
         UCDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BeBnmjO7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E5qV5hV3VNuD0C2f+HIIn5UsIGaY7eYzj5t0N2dWZV8=;
        b=erTN+Qq+4MgX0ewmDQp+ClKrZnB6Fwa3Xu9wPMjoUPqlpxHq10ZM/6/E56oJlGVsjk
         FqMoGGTP9XpLw9MLGYqiJdICa7ZwsfNiDGDSEcgfuY6KHnA/07Ul5ZR+9KnIUbniYnLF
         5Kp6lKDZ3avsZsI13tOn1+yQqDb9rBK/z/PvUI1Rn83h9JOqNE2i7xjkyYqchmMX/o+I
         2fwyLnJTU+OixYLpugAqxViuNMCXJyPlMnitzYyfIHBJbNqu9bf5oSY1OpguuUn2weZe
         xdxUdXfeP4d2RiIpilJ47hbNVfFKzskiv5OPp9DItqCJyTHLK1oL5G6XiSYxLGIivrq2
         isnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E5qV5hV3VNuD0C2f+HIIn5UsIGaY7eYzj5t0N2dWZV8=;
        b=HCbzrnraaTb9yoy9x9mrzaD/K+gsPzbKcv9l6N7zsievB2HvYVwTZ6KXXU88PadIrQ
         OtO74bk6GsmIdHoCRU/zcVTDlo1JICOiwttupLqO7zlt4Hp+8UdAmc3SG4NChFbysGGU
         XbHOjNh7DS8BSAJmtI8cL1OY7wZ0MK4L03N2TtFQ1AlzX1TSzO1ci7gUzEPa8BB9hzoc
         h7Hm5xqrM7WshilBllY5QQhtoc7Kun06rWhK9BASe4VQwRu0VJek308FfBXKFfCxHXrC
         IrJ34aM0LymbfyjWvmzqfIbUEPUg4cUn5jLntf82IlQfbbDFwQJNLBOMqicWwT7cWhjU
         RnKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXbRptc8UomSgPPKrI6siJFJ2p3BG9jkZrPwCU/LDrxh3NncJ8G
	DFIe8sCuxtiOcV4YZ+kSGlA=
X-Google-Smtp-Source: APXvYqwUXvF/afIuDRv6tYgE3qvIajpLPyqKRerlX0ZbYONbGSCNS2pkg6X+J2n9RVKTWBeyBtpmhw==
X-Received: by 2002:a62:c584:: with SMTP id j126mr27640380pfg.21.1566269399119;
        Mon, 19 Aug 2019 19:49:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:334f:: with SMTP id m73ls430511pjb.5.canary-gmail;
 Mon, 19 Aug 2019 19:49:58 -0700 (PDT)
X-Received: by 2002:a17:902:bb81:: with SMTP id m1mr26183524pls.125.1566269398695;
        Mon, 19 Aug 2019 19:49:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566269398; cv=none;
        d=google.com; s=arc-20160816;
        b=zm7WzpPaTMrD1PyTIfMwioP/agGpLjqs1VXxY0aBCtVxLF0HT7zaJ7lX6jP61Qm8UU
         807q7Falac4AcimCBsBlJzIIOaaCDz7x6ZrWuUAUvOfb4aCAflUNcd0ZlhFmHfvWLMKL
         mYEo8sL7pmhMAwzzQZn2/9ryZCDFzT7A1on7muMu6+n4zP/FKcmlJNcpBg/5VzjdlVcM
         zB1setjf5HfYnIhMsrbQo6IJoXkP9X3Aa2A9HuZFSAML2jaSqrCZpJ4FfFAuIlk6m0qS
         fzGJIIAa2tFLr3ESTVapXeOD/udUk3lpJHBERq36UcXo+25OTUMI4rk0lpdQibsmyZrl
         XEJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=vxgmNxuTZeoSTH1hR3AySpOGIla0OX2TTxWnwSuTK0U=;
        b=mFPZFhm1/zyhuRuVjpU0IWkm3KN+1R0sfb71H5qpSHe8mebxi1CeQa2rcbj0q5nSld
         7Lj4CyT+yt5GRGsXq2bqTejpc2NObvEdyQbL8y5Jbx8Oodips3V3+LJP80YOhSLEE4Y3
         FuAOafLpXU/QC2/eOSeScZ3hjYqIyjhyB9RbK3JwDBmP/+fkGl4O67r7UdyDZpLlLAtZ
         USoq4yf6ZgjVK31Q3P2A8aQ0rpMGF/2KMe0qxNNhFXNXB7k2pMt1OBDLBjA2jyUv2jvm
         LTtTfA4M9beQHd3iwvXtsLo76ND9H7a3zBPufEiT/YelCCrgg9EdDelYzTFxrENQIxj7
         8A5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BeBnmjO7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id d9si627865plj.5.2019.08.19.19.49.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2019 19:49:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id d1so2311953pgp.4
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 19:49:58 -0700 (PDT)
X-Received: by 2002:a62:e401:: with SMTP id r1mr28514131pfh.193.1566269397968;
        Mon, 19 Aug 2019 19:49:57 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id z68sm15059447pgz.88.2019.08.19.19.49.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Aug 2019 19:49:57 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: christophe.leroy@c-s.fr,
	linux-s390@vger.kernel.org,
	linux-arch@vger.kernel.org,
	x86@kernel.org,
	linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
Date: Tue, 20 Aug 2019 12:49:40 +1000
Message-Id: <20190820024941.12640-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=BeBnmjO7;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Currently bitops-instrumented.h assumes that the architecture provides
atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
This is true on x86 and s390, but is not always true: there is a
generic bitops/non-atomic.h header that provides generic non-atomic
operations, and also a generic bitops/lock.h for locking operations.

powerpc uses the generic non-atomic version, so it does not have it's
own e.g. __set_bit that could be renamed arch___set_bit.

Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
split. This allows arches to only include the headers where they
have arch-specific versions to rename. Update x86 and s390.

(The generic operations are automatically instrumented because they're
written in C, not asm.)

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/core-api/kernel-api.rst         |  17 +-
 arch/s390/include/asm/bitops.h                |   4 +-
 arch/x86/include/asm/bitops.h                 |   4 +-
 include/asm-generic/bitops-instrumented.h     | 263 ------------------
 .../asm-generic/bitops/instrumented-atomic.h  | 100 +++++++
 .../asm-generic/bitops/instrumented-lock.h    |  81 ++++++
 .../bitops/instrumented-non-atomic.h          | 114 ++++++++
 7 files changed, 317 insertions(+), 266 deletions(-)
 delete mode 100644 include/asm-generic/bitops-instrumented.h
 create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
 create mode 100644 include/asm-generic/bitops/instrumented-lock.h
 create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h

diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
index 08af5caf036d..2e21248277e3 100644
--- a/Documentation/core-api/kernel-api.rst
+++ b/Documentation/core-api/kernel-api.rst
@@ -54,7 +54,22 @@ The Linux kernel provides more basic utility functions.
 Bit Operations
 --------------
 
-.. kernel-doc:: include/asm-generic/bitops-instrumented.h
+Atomic Operations
+~~~~~~~~~~~~~~~~~
+
+.. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
+   :internal:
+
+Non-atomic Operations
+~~~~~~~~~~~~~~~~~~~~~
+
+.. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
+   :internal:
+
+Locking Operations
+~~~~~~~~~~~~~~~~~~
+
+.. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
    :internal:
 
 Bitmap Operations
diff --git a/arch/s390/include/asm/bitops.h b/arch/s390/include/asm/bitops.h
index b8833ac983fa..0ceb12593a68 100644
--- a/arch/s390/include/asm/bitops.h
+++ b/arch/s390/include/asm/bitops.h
@@ -241,7 +241,9 @@ static inline void arch___clear_bit_unlock(unsigned long nr,
 	arch___clear_bit(nr, ptr);
 }
 
-#include <asm-generic/bitops-instrumented.h>
+#include <asm-generic/bitops/instrumented-atomic.h>
+#include <asm-generic/bitops/instrumented-non-atomic.h>
+#include <asm-generic/bitops/instrumented-lock.h>
 
 /*
  * Functions which use MSB0 bit numbering.
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index ba15d53c1ca7..4a2e2432238f 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -389,7 +389,9 @@ static __always_inline int fls64(__u64 x)
 
 #include <asm-generic/bitops/const_hweight.h>
 
-#include <asm-generic/bitops-instrumented.h>
+#include <asm-generic/bitops/instrumented-atomic.h>
+#include <asm-generic/bitops/instrumented-non-atomic.h>
+#include <asm-generic/bitops/instrumented-lock.h>
 
 #include <asm-generic/bitops/le.h>
 
diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
deleted file mode 100644
index ddd1c6d9d8db..000000000000
--- a/include/asm-generic/bitops-instrumented.h
+++ /dev/null
@@ -1,263 +0,0 @@
-/* SPDX-License-Identifier: GPL-2.0 */
-
-/*
- * This file provides wrappers with sanitizer instrumentation for bit
- * operations.
- *
- * To use this functionality, an arch's bitops.h file needs to define each of
- * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
- * arch___set_bit(), etc.).
- */
-#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
-#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
-
-#include <linux/kasan-checks.h>
-
-/**
- * set_bit - Atomically set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This is a relaxed atomic operation (no implied memory barriers).
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static inline void set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_set_bit(nr, addr);
-}
-
-/**
- * __set_bit - Set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * Unlike set_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___set_bit(nr, addr);
-}
-
-/**
- * clear_bit - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * This is a relaxed atomic operation (no implied memory barriers).
- */
-static inline void clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_clear_bit(nr, addr);
-}
-
-/**
- * __clear_bit - Clears a bit in memory
- * @nr: the bit to clear
- * @addr: the address to start counting from
- *
- * Unlike clear_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___clear_bit(nr, addr);
-}
-
-/**
- * clear_bit_unlock - Clear a bit in memory, for unlock
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This operation is atomic and provides release barrier semantics.
- */
-static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_clear_bit_unlock(nr, addr);
-}
-
-/**
- * __clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * This is a non-atomic operation but implies a release barrier before the
- * memory operation. It can be used for an unlock if no other CPUs can
- * concurrently modify other bits in the word.
- */
-static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___clear_bit_unlock(nr, addr);
-}
-
-/**
- * change_bit - Toggle a bit in memory
- * @nr: Bit to change
- * @addr: Address to start counting from
- *
- * This is a relaxed atomic operation (no implied memory barriers).
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static inline void change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_change_bit(nr, addr);
-}
-
-/**
- * __change_bit - Toggle a bit in memory
- * @nr: the bit to change
- * @addr: the address to start counting from
- *
- * Unlike change_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___change_bit(nr, addr);
-}
-
-/**
- * test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This is an atomic fully-ordered operation (implied full memory barrier).
- */
-static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_set_bit(nr, addr);
-}
-
-/**
- * __test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_set_bit(nr, addr);
-}
-
-/**
- * test_and_set_bit_lock - Set a bit and return its old value, for lock
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is atomic and provides acquire barrier semantics if
- * the returned value is 0.
- * It can be used to implement bit locks.
- */
-static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_set_bit_lock(nr, addr);
-}
-
-/**
- * test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This is an atomic fully-ordered operation (implied full memory barrier).
- */
-static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_clear_bit(nr, addr);
-}
-
-/**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_clear_bit(nr, addr);
-}
-
-/**
- * test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This is an atomic fully-ordered operation (implied full memory barrier).
- */
-static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_change_bit(nr, addr);
-}
-
-/**
- * __test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_change_bit(nr, addr);
-}
-
-/**
- * test_bit - Determine whether a bit is set
- * @nr: bit number to test
- * @addr: Address to start counting from
- */
-static inline bool test_bit(long nr, const volatile unsigned long *addr)
-{
-	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_bit(nr, addr);
-}
-
-#if defined(arch_clear_bit_unlock_is_negative_byte)
-/**
- * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
- *                                     byte is negative, for unlock.
- * @nr: the bit to clear
- * @addr: the address to start counting from
- *
- * This operation is atomic and provides release barrier semantics.
- *
- * This is a bit of a one-trick-pony for the filemap code, which clears
- * PG_locked and tests PG_waiters,
- */
-static inline bool
-clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
-}
-/* Let everybody know we have it. */
-#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
-#endif
-
-#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
new file mode 100644
index 000000000000..18ce3c9e8eec
--- /dev/null
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -0,0 +1,100 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for atomic bit
+ * operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
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
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
new file mode 100644
index 000000000000..ec53fdeea9ec
--- /dev/null
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -0,0 +1,81 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for bit
+ * locking operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
+
+#include <linux/kasan-checks.h>
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
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H */
diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
new file mode 100644
index 000000000000..95ff28d128a1
--- /dev/null
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -0,0 +1,114 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for non-atomic
+ * bit operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
+
+#include <linux/kasan-checks.h>
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
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190820024941.12640-1-dja%40axtens.net.
