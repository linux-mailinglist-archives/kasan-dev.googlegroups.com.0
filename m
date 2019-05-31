Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMUIYXTQKGQEGXAXLGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D0BDA310F2
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 17:11:47 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id f1sf7618570pfb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 08:11:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559315506; cv=pass;
        d=google.com; s=arc-20160816;
        b=Peci3wV/iIDhiTnqmKNl3ercJMiuYu4RUtB9DAZqkyCQJ7lRhPRj6Sz8G9mOQe2tgo
         lY4cDPJGdJkqlfg0+xdfFUwne4pP5YMNifCoyt4MOX86PCva2+Ino1obdY4kn5yGNkQp
         nzimYMrJ+8WAkDdq/Lo7mRXo52MQbkDmgTFiJ3i+jK15rc/1eYiM99ppSpVQ4WVIx4VE
         tsJfmxp5CgQ4iyIZ342xja8REcxX0uWxGzsaBRp4B/RE6YFBHsRkt09I9SulUbLmtEPV
         SKpBS4+HWUVxgJlrmTFjTX3vGnZN6YsmLiAhBGYUZCJqsdOj6KTl/uKY+VIUgY4IbElH
         nomQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=KjUJoZsZEtHUYM2IOezgr07wWEEAMRc+nKYbDsE8di0=;
        b=JcVGza4MbzqbQ+j2z2rw/WC2BovAOA8SBbeAuWutZLO0qldr+409JFNzxnnnH5yz1a
         4j7b9g+5d8wbpfbWgA7X0LcB5o5+jHVVhA6LDaDePFcelc/EdJsSUS70eFSP0IWCCGLR
         jSW/pAwrXeuummVFW0o3NgthGGWKAhSjxMkImqBH/SS3of/nuTk0Udm6Bb3YjGNYlWh2
         AQn8AXiPnwmJQ/RNrBJEQglM9XXt0smC4IYpTRN1CAxTTkxSzPeVm4dFwvn1Ws98g03j
         6iwQBZSZnXDL8+iZfEQjD9jkF+OKsfXPYjNBFg6uI3K9xNq/EZuP6B2jDqIRKGeOQnQZ
         sz6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ut411OXG;
       spf=pass (google.com: domain of 3metxxaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3METxXAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KjUJoZsZEtHUYM2IOezgr07wWEEAMRc+nKYbDsE8di0=;
        b=U9J4ptEpessS40sByjWYcASt8ahd0jTEtVwtVCOB5ZONy1jzf7yNzM71MEC8JR9bab
         X4EJfpPESaNyIMRD4Wp6Dlw0ECRBQmdRVZiJAEVfPtNWcUOInH1hcbGtrEjsrgz1A+Bi
         Vui/rW8ZjBSGq0yUj3IbPmX6BcV0+Ix3xmVBfrS5AFGyX0CgCioCniqDU7o0znVeCJct
         8eec9tfRVYbiMv00WVJa+5AsFUM0uxIeT0RZ4PkTAot3CN4Mq4RWZbbpMMsoXxtP2Bvq
         ydDs/e7npF47CAo7VScBepcIAehxDFuqmyeQCRTeC/kvNVUNSB0ok9Is6DLZbmAqARQ2
         eg/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KjUJoZsZEtHUYM2IOezgr07wWEEAMRc+nKYbDsE8di0=;
        b=BMODqk63SDWxz0IlKPEBvGyZsMIIHNeL5WrwimVMlNivtdJ1+BR9AsRYaVYQlqPDTh
         ouGcclmWwKFxPV9o+MHeBQ0AUvsm/1idZ8g0RbtWL4JwTsXwlS/gdPN3HhV6FYHJ/OaK
         dkD9dRYtogF1GbKLiP6pazGu2F/ESJZ6dLF4b4/apVWSW3E+5mZYar6EYNWFWsBAh+Hr
         OiDlmnRyst0+OnxSSw6a5RNMaTXY7fb1JhokK9Koza1R2TFDPm+OFsnJW9tmSnwN9y46
         FTtaU6aYX0kOHYSVjry62tMyTTzYw5sz0SJbs1w9Kc1bfPnGY9ILr5A3yT2MHSQhMEE1
         mPHw==
X-Gm-Message-State: APjAAAVRIRtdK3ofnUj6iTyPHeVF9YgjT8QNt50lUHhhj3hOu5N5HYMS
	BJB/ODf7NrqVvMYjqT5IJ3c=
X-Google-Smtp-Source: APXvYqzPXQ8waUwmiMPva0yUQXCkBOYIQfp4dICuxsJgfxj/1DoO4JFooh9jP9LBtNNGcDTrLaNJIg==
X-Received: by 2002:a63:5d20:: with SMTP id r32mr5424673pgb.393.1559315506118;
        Fri, 31 May 2019 08:11:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2482:: with SMTP id i2ls829747pje.3.canary-gmail;
 Fri, 31 May 2019 08:11:45 -0700 (PDT)
X-Received: by 2002:a17:902:b402:: with SMTP id x2mr10354528plr.128.1559315505577;
        Fri, 31 May 2019 08:11:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559315505; cv=none;
        d=google.com; s=arc-20160816;
        b=TdxKKsrLRTITQtkyV6bIENfR/E9BN9nl7FA4eib34EM6RJk8L3jYyIAdlpvFhzFrSU
         VTkzj9pItU5pnz4mpDJ31w33LXQlGSmfVtR1YD8AjCFeEKE0kZ6a7HWABYxfzxR5VYQN
         X2qI16LUmW5IVoqP3jhbM5RvuprAN1fMIEcSMyBfxFK0tDP66iCD7z8la0ED9X9lLMkY
         JUMHYnGQLSKdQAaKVw1lRKxvBKM2nFDLDHzsufqOp9WhNelGZAKytPvcTfSgj1W4/OtK
         8F4FQvmN6xOPs96hWFUPUDIdkJfrOwxRPDIH0tucPji3Nf6EqCdmD7t2XGHYNJBX6ZFv
         1D4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Zx2DDgtldzG1mx9/969MuYRWgy8Ne9+JiAfHrrBI1cs=;
        b=RDgH4rRcn6J6s6DFBNvdjgXTaLNmQYqACM7eFKS4iLt77pw13P0hPvaUl/xRJS8xJj
         NkzL29K81kcTClOvctOlGzyHM0u6PzfqxcMDj08s+BgA6PmIjowGJiFuwr3gnCp7cxdj
         t/BwmDUQHPrUo0ycnnCJBQY82Ud6k/FnMpm5uHslJc/PyFRSuuCvz8gSTU+wcRf7cm1X
         Df+eYZLc1O89q2BM3hEIZ4XKbdMLW5Cu77MMkvWfgWvoNRK+7ZXG5dy0wN7sk412VbxT
         l6P7e5+xvowbN7koZC83stNMomFPw6fAVpTFiyXwGfbpCPZbLl1cYJmx8Y+zzvZOw1q9
         b7jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ut411OXG;
       spf=pass (google.com: domain of 3metxxaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3METxXAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id d128si175065pgc.5.2019.05.31.08.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2019 08:11:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3metxxaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id s5so4110542vkd.0
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2019 08:11:45 -0700 (PDT)
X-Received: by 2002:a1f:c142:: with SMTP id r63mr4363047vkf.8.1559315504469;
 Fri, 31 May 2019 08:11:44 -0700 (PDT)
Date: Fri, 31 May 2019 17:08:31 +0200
In-Reply-To: <20190531150828.157832-1-elver@google.com>
Message-Id: <20190531150828.157832-4-elver@google.com>
Mime-Version: 1.0
References: <20190531150828.157832-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v3 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
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
 header.i=@google.com header.s=20161025 header.b=ut411OXG;       spf=pass
 (google.com: domain of 3metxxaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3METxXAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190531150828.157832-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
